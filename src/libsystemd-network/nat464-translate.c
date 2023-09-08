/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "nat464-checksum.h"
#include "nat464-translate.h"

static bool translate_ipv6_addr_to_ipv4_addr(struct in6_addr *ip6, in_addr_t *ip){
        *ip = ip6->s6_addr32[3];
        return true;
}

static void translate_ipv4_addr_to_ipv6_addr(in_addr_t ip, struct in6_addr *ip6, struct in6_addr *prefix){
        *ip6 = *prefix;
        ip6->s6_addr32[3] = ip;
}

int build_ip6_header_from_ip4_packet(sd_nat464 *nat, struct iphdr *iph, struct ip6_hdr *ip6h, size_t payload_length) {
        ip6h->ip6_vfc = htobe32((0x6 << 28) | (iph->tos << 20));
        ip6h->ip6_plen = htobe16(payload_length);
        ip6h->ip6_nxt = (iph->protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : iph->protocol;
        ip6h->ip6_hops = iph->ttl;

        translate_ipv4_addr_to_ipv6_addr(iph->saddr, &ip6h->ip6_src, &nat->src_prefix);
        translate_ipv4_addr_to_ipv6_addr(iph->daddr, &ip6h->ip6_dst, &nat->dst_prefix);

        return 0;
}

int fill_ip6_payload_from_ip4_packet(struct iphdr *iph, struct ip6_hdr *ip6h, uint8_t *payload, size_t payload_length) {
        assert(iph);
        assert(ip6h);
        assert(payload);
        assert(payload_length > 0);

        switch (iph->protocol) {
        case IPPROTO_TCP: {
                struct tcphdr *tcph;

                if (payload_length < sizeof(struct tcphdr))
                        return -EINVAL;

                tcph = (struct tcphdr *) payload;
                tcph->check = nat464_checksum_fixup_from_ip4_to_ip6(tcph->check, iph, ip6h);
                break;
        }
        case IPPROTO_UDP: {
                struct udphdr *udph;

                if (payload_length < sizeof(struct udphdr))
                        return -EINVAL;

                udph = (struct udphdr *) payload;
                udph->check = nat464_checksum_fixup_from_ip4_to_ip6(udph->check, iph, ip6h);
                break;
        }
        case IPPROTO_ICMP: {
                struct icmp6_hdr *icmp6h;
                uint16_t checksum;

                if (payload_length < sizeof(struct icmp6_hdr))
                        return -EINVAL;

                icmp6h = (struct icmp6_hdr *) payload;

                checksum = ~ip6_pseudo_header_checksum(ip6h, htobe16(ip6h->ip6_plen) - sizeof(struct icmp6_hdr), IPPROTO_ICMPV6);
                checksum = packet_checksum(checksum, icmp6h->icmp6_cksum);

                switch (icmp6h->icmp6_type) {
                case ICMP6_ECHO_REQUEST:
                        icmp6h->icmp6_type = ICMP_ECHO;
                        icmp6h->icmp6_cksum = packet_checksum(checksum, ICMP6_ECHO_REQUEST - ICMP_ECHO);
                        break;
                case ICMP6_ECHO_REPLY:
                        icmp6h->icmp6_type = ICMP_ECHOREPLY;
                        icmp6h->icmp6_cksum = packet_checksum(checksum, ICMP6_ECHO_REPLY - ICMP_ECHOREPLY);
                        break;
                default:
                        return -ENOTSUP;
                }
                break;
        }}

        return 0;
}

int fill_ip4_protocol_from_ip6_packet(struct iphdr *iph, struct ip6_hdr *ip6h, uint8_t *payload, size_t payload_length) {
        switch (iph->protocol) {
        case IPPROTO_TCP: {
                struct tcphdr *tcp_header = (struct tcphdr *)payload;

                if (payload_length < sizeof(struct tcphdr))
                        return -1;

                tcp_header->check = nat464_checksum_fixup_from_ip4_to_ip6(tcp_header->check, iph, ip6h);
                break;
        }
        case IPPROTO_UDP: {
                struct udphdr *udp_header = (struct udphdr *)payload;

                if (payload_length < sizeof(struct udphdr))
                        if (udp_header->check == 0)
                                return -1; // Drop UDP packets with no checksum
                udp_header->check = nat464_checksum_fixup_from_ip4_to_ip6(udp_header->check, iph, ip6h);
                break;
        }
        case IPPROTO_ICMP: {
                struct icmphdr *icmp_header = (struct icmphdr *)payload;
                uint16_t checksum;

                if (payload_length < sizeof(struct icmphdr))
                        return -1;

                checksum = ~ip6_pseudo_header_checksum(ip6h, htobe16(ip6h->ip6_plen) - sizeof(struct icmp6_hdr), IPPROTO_ICMPV6);
                checksum = packet_checksum(icmp_header->checksum, checksum);

                switch (icmp_header->type) {
                case ICMP_ECHOREPLY:
                        icmp_header->type = ICMP6_ECHO_REPLY;
                        icmp_header->checksum = packet_checksum(checksum, ~(ICMP6_ECHO_REPLY - ICMP_ECHOREPLY));
                        break;
                case ICMP_ECHO:
                        icmp_header->type = ICMP6_ECHO_REQUEST;
                        icmp_header->checksum = packet_checksum(checksum, ~(ICMP6_ECHO_REQUEST - ICMP_ECHO));
                        break;
                default:
                        return -ENOTSUP;
                }
                break;
        }
        default:
                return 0;
        }

        return 0;
}

int build_ip4_header_from_ip6_packet(sd_nat464 *nat, struct ip6_hdr *ip6h, struct ip6_frag *ip6_fragment, struct iphdr *iph, size_t payload_length) {
        assert(iph);
        assert(ip6h);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = (ntohl(ip6h->ip6_vfc) >> 20) & 0xff;
        iph->tot_len = htobe16(payload_length + sizeof(struct iphdr));
        iph->ttl = ip6h->ip6_hops;
        iph->check = 0;

        if (ip6_fragment) {
                iph->id = htobe16(ntohl(ip6_fragment->ip6f_ident) & 0xffff);
                iph->frag_off = htobe16(be16toh(ip6_fragment->ip6f_offlg) >> 3);
                if (ip6_fragment->ip6f_offlg & IP6F_MORE_FRAG)
                        iph->frag_off |= htobe16(IP_MF);
                iph->protocol = (ip6_fragment->ip6f_nxt == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6_fragment->ip6f_nxt;
        } else {
                iph->id = 0;
                iph->frag_off = htobe16(IP_DF);
                iph->protocol = (ip6h->ip6_nxt == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6h->ip6_nxt;
        }

        if (!translate_ipv6_addr_to_ipv4_addr(&ip6h->ip6_dst, &iph->daddr) || !translate_ipv6_addr_to_ipv4_addr(&ip6h->ip6_src, &iph->saddr))
                return log_nat464_errno(nat, SYNTHETIC_ERRNO(EINVAL),
                                        "Failed to translate IPv6 address to IPv4 address: %m");

        iph->check = nat464_checksum(iph, sizeof(struct iphdr));
        return 0;
}
