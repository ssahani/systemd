/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/ipv6.h>

#include "alloc-util.h"
#include "io-util.h"
#include "nat464-ip.h"
#include "nat464-translate.h"
#include "nat464-icmp.h"
#include "nat464-checksum.h"
#include "nat464-dump.h"

static int nat464_process_ip4_protocol(sd_nat464 *nat, struct iphdr *iph, uint8_t *payload, size_t payload_size) {
        _cleanup_free_ struct ip6_hdr *ip6h = NULL;
        int offset, flags, r, n = 0;
        struct iovec iovec[3];
        bool is_fragment;

        assert(nat);
        assert(iph);
        assert(payload);
        assert(payload_size > 0);

        ip6h = new(struct ip6_hdr, 1);
        if (!ip6h)
                return -ENOMEM;

        r = build_ip6_header_from_ip4_packet(nat, iph, ip6h, payload_size);
        if (r < 0)
                return 0;

        offset = be16toh(iph->frag_off);
        flags = offset & ~IP_OFFMASK;
        offset = (offset & IP_OFFMASK) << 3;

        if (offset == 0) {
                r = fill_ip6_payload_from_ip4_packet(iph, ip6h, payload, payload_size);
                if (r < 0)
                        return 0;
        }

        iovec[n++] = IOVEC_MAKE(ip6h, sizeof(struct ip6_hdr));

        if ((flags & IP_MF) || offset > 0)
                is_fragment = true;
        else
                is_fragment = (flags & IP_DF) ? false : ((sizeof(struct ip6_hdr) + payload_size) > IPV6_MIN_MTU);

        if (is_fragment) {
                _cleanup_free_ struct ip6_frag *ip6_fragment = NULL;
                size_t frag_offset = 0;

                ip6_fragment = new(struct ip6_frag , 1);
                if (!ip6_fragment)
                        return -ENOMEM;

                ip6_fragment->ip6f_nxt = ip6h->ip6_nxt;
                ip6h->ip6_nxt = IPPROTO_FRAGMENT;
                ip6_fragment->ip6f_ident = htobe32(be16toh(iph->id));
                ip6_fragment->ip6f_reserved = 0;

                iovec[n++] = IOVEC_MAKE(&ip6_fragment, sizeof(struct ip6_frag));

                while (frag_offset < payload_size) {
                        int frag_payload_len = IPV6_MIN_MTU - (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag));
                        int mf = IP_MF;

                        if (frag_offset + frag_payload_len > payload_size) {
                                frag_payload_len = payload_size - frag_offset;
                                if (!(flags & IP_MF))
                                        mf = 0;
                        }

                        ip6h->ip6_plen = htobe16(frag_payload_len + sizeof(struct ip6_frag));
                        ip6_fragment->ip6f_offlg = htobe16((offset + frag_offset) | mf >> 13);

                        iovec[n++] = IOVEC_MAKE(payload + frag_offset, frag_payload_len);
                        r = writev(nat->fd, iovec, n);
                        if (r < 0)
                                return -errno;

                        frag_offset += frag_payload_len;
                }
        } else {
                iovec[n++] = IOVEC_MAKE(payload, payload_size);
                r = writev(nat->fd, iovec, n);
                if (r < 0)
                        return -errno;
        }

        return 0;
}

int nat464_process_ip4_packet(sd_nat464 *nat, uint8_t *ip_packet, size_t packet_length) {
        struct iphdr *iph = (struct iphdr *) ip_packet;
        size_t iph_len, payload_size;
        bool is_fragmented;
        uint8_t *payload;

        assert(nat);
        assert(ip_packet);

        if (packet_length < sizeof(struct iphdr))
                return 0;

        iph_len = iph->ihl * 4;;
        if (iph->version != 4 || iph_len < sizeof(struct iphdr) ||
            iph_len > packet_length || iph->ttl == 0 ||
            nat464_checksum(iph, iph_len) != 0)
                return 0;

        payload = ip_packet + iph_len;
        payload_size = packet_length - iph_len;
        is_fragmented = iph->frag_off & htobe16(IP_OFFMASK | IP_MF);

        if (iph->protocol == IPPROTO_ICMP) {
                if (is_fragmented)
                        return 0;
                else
                        return nat464_translate_icmp4_to_icmp6(nat, iph, payload, payload_size);
        }

        return nat464_process_ip4_protocol(nat, iph, payload, payload_size);
}

static int nat464_process_next_protocol(sd_nat464 *nat, struct ip6_hdr *ip6h, struct ip6_frag *ip6_fragment, uint8_t *payload, int payload_size) {
        _cleanup_free_ struct iphdr *iph = NULL;
        struct iovec iovec[2];
        int offset;
        int r, n = 0;

        assert(nat);
        assert(ip6h);

        iph = new(struct iphdr, 1);
        if (!iph)
                return -ENOMEM;

        r = build_ip4_header_from_ip6_packet(nat, ip6h, ip6_fragment, iph, payload_size);
        if (r < 0)
                return 0;

        offset = (ip6_fragment) ? be16toh(ip6_fragment->ip6f_offlg & IP6F_OFF_MASK) : 0;
        if (offset == 0) {
                r = fill_ip4_protocol_from_ip6_packet(iph, ip6h, payload, payload_size);;
                if (r < 0)
                        return 0;
        }

        dump_ip(iph);

        iovec[n++] = IOVEC_MAKE(iph, sizeof(struct iphdr));
        iovec[n++] = IOVEC_MAKE(payload, payload_size);

        r = writev(nat->fd, iovec, n);
        if (r < 0)
                return -errno;

        return 0;
}

int nat464_process_ip6_packet(sd_nat464 *nat, uint8_t *ip6_packet, size_t packet_size) {
        struct ip6_hdr *ip6h = (struct ip6_hdr *) ip6_packet;
        struct ip6_frag *ip6_fragment = NULL;
        size_t payload_size;
        uint8_t next_protocol;
        uint8_t *payload;

        assert(nat);
        assert(ip6_packet);

        if (packet_size < sizeof(struct ip6_hdr))
                return 0;

        if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst))
                return 0;

        if ((ip6h->ip6_vfc >> 4) != 6 || ip6h->ip6_hops == 0)
                return 0;
/*
        if (!ADDR_MATCH_PREFIX(ip6h->ip6_dst, nat->dst_prefix) && !ADDR_MATCH_PREFIX(ip6h->ip6_dst, nat->src_prefix)) {
                if (ip6h->ip6_nxt != IPPROTO_ICMPV6)
                        icmp6_send_error(nat, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADMIN, &nat->gateway6, &ip6h->ip6_src, ip6_packet, packet_size, 0);
                return 0;
        }
*/
        payload = ip6_packet + sizeof(struct ip6_hdr);
        payload_size = packet_size - sizeof(struct ip6_hdr);
        next_protocol = ip6h->ip6_nxt;

        if (next_protocol == IPPROTO_ICMPV6)
                return nat464_translate_icmp6_to_icmp4(nat, ip6h, payload, payload_size);
        else if (next_protocol == IPPROTO_FRAGMENT) {
                if (payload_size < sizeof(struct ip6_frag))
                        return 0;

                ip6_fragment = (struct ip6_frag *)payload;
                if (ip6_fragment->ip6f_nxt == IPPROTO_ICMPV6)
                        return 0;

                payload += sizeof(struct ip6_frag);
                payload_size -= sizeof(struct ip6_frag);
        }

        // debug
        dump_ip6(ip6h);

        return nat464_process_next_protocol(nat, ip6h, ip6_fragment, payload, payload_size);
}
