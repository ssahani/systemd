/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/uio.h>

#include "io-util.h"
#include "nat464-icmp.h"
#include "nat464-checksum.h"
#include "nat464-translate.h"

static int translate_payload_icmp4_to_icmp6(sd_nat464 *nat, struct iphdr *iph, struct icmphdr *icmph, uint8_t *data, int data_length) {
        ICMP6Packet header = {};
        struct iovec iovec[2];
        int r, n = 0;

        assert(nat);
        assert(icmph);
        assert(iph);

        switch (icmph->type) {
        case ICMP_ECHOREPLY:
                header.icmp6.icmp6_type = ICMP6_ECHO_REPLY;
                header.icmp6.icmp6_code = 0;
                header.icmp6.icmp6_id = icmph->un.echo.id;
                header.icmp6.icmp6_seq = icmph->un.echo.sequence;
                break;
        case ICMP_ECHO:
                header.icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
                header.icmp6.icmp6_code = 0;
                header.icmp6.icmp6_id = icmph->un.echo.id;
                header.icmp6.icmp6_seq = icmph->un.echo.sequence;
                break;
        default:
                return -ENOTSUP;
        }

        build_ip6_header_from_ip4_packet(nat, iph, &header.ip6, data_length + sizeof(struct icmp6_hdr));

        header.icmp6.icmp6_cksum = 0;
        header.icmp6.icmp6_cksum = packet_checksum(ip6_pseudo_header_checksum(&header.ip6, sizeof(struct icmp6_hdr) + data_length, IPPROTO_ICMPV6),
                                                   nat464_checksum(&header.icmp6, sizeof(struct icmp6_hdr)));
        header.icmp6.icmp6_cksum = packet_checksum(header.icmp6.icmp6_cksum, nat464_checksum(data, data_length));

        iovec[n++] = IOVEC_MAKE(&header, sizeof(ICMP6Packet));
        iovec[n++] = IOVEC_MAKE(data, data_length);

        r = writev(nat->fd, iovec, n);
        if (r < 0)
                return -errno;

        return 0;
}

int translate_icmp4_to_icmp6(sd_nat464 *nat, struct iphdr *iph, uint8_t *payload, size_t payload_length) {
        struct icmphdr *icmph = (struct icmphdr *)payload;
        uint8_t *data = payload + sizeof(struct icmphdr);
        int data_length = payload_length - sizeof(struct icmphdr);

        assert(nat);
        assert(iph);
        assert(icmph);

        return translate_payload_icmp4_to_icmp6(nat, iph, icmph, data, data_length);
}

static int translate_payload_icmp6_to_icmp4(sd_nat464 *nat, struct ip6_hdr *ip6h, struct icmp6_hdr *icmp6h, uint8_t *data, size_t data_length) {
        ICMPPacket header = {};
        struct iovec iovec[2];
        int r, n = 0;

        assert(nat);
        assert(ip6h);
        assert(icmp6h);

        switch (icmp6h->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
                header.icmp.code = ICMP_ECHO;
                header.icmp.type = 0;
                header.icmp.un.echo.id = icmp6h->icmp6_id;
                header.icmp.un.echo.sequence = icmp6h->icmp6_seq;
                break;
        case ICMP6_ECHO_REPLY:
                header.icmp.code = ICMP_ECHOREPLY;
                header.icmp.type = 0;
                header.icmp.un.echo.id = icmp6h->icmp6_id;
                header.icmp.un.echo.sequence = icmp6h->icmp6_seq;
                break;
        default:
                return -ENOTSUP;
        }

        r = build_ip4_header_from_ip6_packet(nat, ip6h, NULL, &header.ip, sizeof(struct icmphdr) + data_length);
        if (r < 0)
                return 0;

        header.icmp.checksum = 0;
        header.icmp.checksum = packet_checksum(nat464_checksum(&header.icmp, sizeof(header.icmp)),
                                               nat464_checksum(data, data_length));

        iovec[n++] = IOVEC_MAKE(&header, sizeof(ICMP6Packet));
        iovec[n++] = IOVEC_MAKE(data, data_length);

        r = writev(nat->fd, iovec, n);
        if (r < 0)
                return -errno;

        return 0;
}

int translate_icmp6_to_icmp4(sd_nat464 *nat, struct ip6_hdr *ip6h, uint8_t *payload, size_t payload_length) {
        struct icmp6_hdr *icmp6h = (struct icmp6_hdr *) payload;
        uint8_t *data = payload + sizeof(struct icmp6_hdr);
        int data_length = payload_length - sizeof(struct icmp6_hdr);

        assert(nat);
        assert(ip6h);
        assert(payload);
        assert(icmp6h);

        return translate_payload_icmp6_to_icmp4(nat, ip6h, icmp6h, data, data_length);
}
