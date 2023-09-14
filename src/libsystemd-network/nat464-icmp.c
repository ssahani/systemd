/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "alloc-util.h"
#include "io-util.h"
#include "nat464-icmp.h"
#include "nat464-checksum.h"
#include "nat464-translate.h"

static int translate_payload_icmp4_to_icmp6(sd_nat464 *nat, struct iphdr *iph, struct icmphdr *icmph, uint8_t *data, int data_length) {
        _cleanup_free_ ICMP6Packet *h = NULL;
        struct iovec iovec[2];
        int r, n = 0;

        assert(nat);
        assert(icmph);
        assert(iph);

        h = new(ICMP6Packet, 1);
        if (!h)
                return -ENOMEM;

        switch (icmph->type) {
        case ICMP_ECHOREPLY:
                h->icmp6.icmp6_type = ICMP6_ECHO_REPLY;
                h->icmp6.icmp6_code = 0;
                h->icmp6.icmp6_id = icmph->un.echo.id;
                h->icmp6.icmp6_seq = icmph->un.echo.sequence;
                break;
        case ICMP_ECHO:
                h->icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
                h->icmp6.icmp6_code = 0;
                h->icmp6.icmp6_id = icmph->un.echo.id;
                h->icmp6.icmp6_seq = icmph->un.echo.sequence;
                break;
        default:
                return -ENOTSUP;
        }

        build_ip6_header_from_ip4_packet(nat, iph, &h->ip6, data_length + sizeof(struct icmp6_hdr));

        h->icmp6.icmp6_cksum = 0;
        h->icmp6.icmp6_cksum = packet_checksum(ip6_pseudo_header_checksum(&h->ip6, sizeof(struct icmp6_hdr) + data_length, IPPROTO_ICMPV6),
                                               nat464_checksum(&h->icmp6, sizeof(struct icmp6_hdr)));
        h->icmp6.icmp6_cksum = packet_checksum(h->icmp6.icmp6_cksum, nat464_checksum(data, data_length));

        iovec[n++] = IOVEC_MAKE(h, sizeof(ICMP6Packet));
        iovec[n++] = IOVEC_MAKE(data, data_length);

        r = writev(nat->fd, iovec, n);
        if (r < 0)
                return -errno;

        return 0;
}

int nat464_translate_icmp4_to_icmp6(sd_nat464 *nat, struct iphdr *iph, uint8_t *payload, size_t payload_length) {
        struct icmphdr *icmph = (struct icmphdr *)payload;
        uint8_t *data = payload + sizeof(struct icmphdr);
        int data_length = payload_length - sizeof(struct icmphdr);

        assert(nat);
        assert(iph);
        assert(icmph);

        return translate_payload_icmp4_to_icmp6(nat, iph, icmph, data, data_length);
}

static int translate_payload_icmp6_to_icmp4(sd_nat464 *nat, struct ip6_hdr *ip6h, struct icmp6_hdr *icmp6h, uint8_t *data, size_t data_length) {
        _cleanup_free_ ICMPPacket *h = NULL;
        struct iovec iovec[2];
        int r, n = 0;

        assert(nat);
        assert(ip6h);
        assert(icmp6h);

        h = new(ICMPPacket, 1);
        if (!h)
                return -ENOMEM;

        switch (icmp6h->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
                h->icmp.code = ICMP_ECHO;
                h->icmp.type = 0;
                h->icmp.un.echo.id = icmp6h->icmp6_id;
                h->icmp.un.echo.sequence = icmp6h->icmp6_seq;
                break;
        case ICMP6_ECHO_REPLY:
                h->icmp.code = ICMP_ECHOREPLY;
                h->icmp.type = 0;
                h->icmp.un.echo.id = icmp6h->icmp6_id;
                h->icmp.un.echo.sequence = icmp6h->icmp6_seq;
                break;
        default:
                return -ENOTSUP;
        }

        r = build_ip4_header_from_ip6_packet(nat, ip6h, NULL, &h->ip, sizeof(struct icmphdr) + data_length);
        if (r < 0)
                return 0;

        h->icmp.checksum = 0;
        h->icmp.checksum = packet_checksum(nat464_checksum(&h->icmp, sizeof(h->icmp)), nat464_checksum(data, data_length));

        iovec[n++] = IOVEC_MAKE(h, sizeof(ICMP6Packet));
        iovec[n++] = IOVEC_MAKE(data, data_length);

        r = writev(nat->fd, iovec, n);
        if (r < 0)
                return -errno;

        return 0;
}

int nat464_translate_icmp6_to_icmp4(sd_nat464 *nat, struct ip6_hdr *ip6h, uint8_t *payload, size_t payload_length) {
        struct icmp6_hdr *icmp6h = (struct icmp6_hdr *) payload;
        uint8_t *data = payload + sizeof(struct icmp6_hdr);
        int data_length = payload_length - sizeof(struct icmp6_hdr);

        assert(nat);
        assert(ip6h);
        assert(payload);
        assert(icmp6h);

        return translate_payload_icmp6_to_icmp4(nat, ip6h, icmp6h, data, data_length);
}
