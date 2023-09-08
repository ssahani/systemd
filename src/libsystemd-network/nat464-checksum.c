/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>

#include "nat464-checksum.h"

static uint32_t nat464_checksum_add(uint32_t checksum, const void *data, int length) {
        const uint16_t *c = (uint16_t *) data;
        uint32_t sum;

        for (sum = checksum; length > 1; c++, length -= 2)
                sum += *c;

        if (length)
                sum += *(uint8_t *) c;

        return sum;
}

static uint16_t nat464_checksum_finish(uint32_t sum) {
        for(;sum > 0xffff;)
                sum = (sum >> 16) + (sum & 0xffff);

        return ~sum;
}

uint16_t nat464_checksum(const void *data, int length) {
        return nat464_checksum_finish(nat464_checksum_add(0, data, length));
}

uint16_t nat464_checksum_fixup_from_ip4_to_ip6(uint16_t chksum, struct iphdr *iph, struct ip6_hdr *ip6h) {
        uint32_t sum = be16toh(~chksum);

        sum += be16toh(~iph->saddr >> 16) + be16toh(~iph->saddr & 0xffff);
        sum += be16toh(~iph->daddr >> 16) + be16toh(~iph->daddr & 0xffff);

        for (size_t i = 0; i < 8; i++) {
                sum += be16toh(ip6h->ip6_src.s6_addr16[i]);
                sum += be16toh(ip6h->ip6_dst.s6_addr16[i]);
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return ~htobe16(sum);
}

uint16_t nat464_checksum_fixup_from_ip6_to_ip4(uint16_t chksum, struct iphdr *iph, struct ip6_hdr *ip6h) {
        uint32_t sum = be16toh(~chksum);

        for (size_t i = 0; i < 8; i++) {
                sum += be16toh(~ip6h->ip6_src.s6_addr16[i]);
                sum += be16toh(~ip6h->ip6_dst.s6_addr16[i]);
        }

        sum += be16toh(iph->saddr >> 16) + be16toh(iph->saddr & 0xffff);
        sum += be16toh(iph->daddr >> 16) + be16toh(iph->daddr & 0xffff);

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return ~htobe16(sum);
}

uint16_t packet_checksum(uint16_t a, uint16_t b) {
        uint32_t sum = (uint16_t)~a + (uint16_t)~b;
        return ~((sum >> 16) + (sum & 0xffff));
}

uint16_t ip6_pseudo_header_checksum(struct ip6_hdr *ip6h, uint32_t payload_length, uint8_t protocol) {
        uint32_t length = htobe32(payload_length);
        uint32_t next = htobe32(protocol);
        uint32_t sum = 0;

        sum = nat464_checksum_add(sum, &ip6h->ip6_src, sizeof(struct in6_addr));
        sum = nat464_checksum_add(sum, &ip6h->ip6_dst, sizeof(struct in6_addr));
        sum = nat464_checksum_add(sum, &length, sizeof(length));
        sum = nat464_checksum_add(sum, &next, sizeof(next));

        return nat464_checksum_finish(sum);
}
