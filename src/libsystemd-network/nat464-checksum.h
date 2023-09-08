

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

uint16_t nat464_checksum(const void *data, int length);
uint16_t nat464_checksum_fixup_from_ip4_to_ip6(uint16_t chksum, struct iphdr *ip_header, struct ip6_hdr *ip6_header);
uint16_t nat464_checksum_fixup_from_ip6_to_ip4(uint16_t chksum, struct iphdr *ip_header, struct ip6_hdr *ip6_header);
uint16_t packet_checksum(uint16_t a, uint16_t b);
uint16_t ip6_pseudo_header_checksum(struct ip6_hdr *ip6_header, uint32_t payload_length, uint8_t protocol);
