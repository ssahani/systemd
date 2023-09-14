/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "nat464-internal.h"

typedef struct ICMP6Packet {
        struct ip6_hdr ip6;
        struct icmp6_hdr icmp6;
} ICMP6Packet;

typedef struct ICMPPacket {
        struct iphdr ip;
        struct icmphdr icmp;
} ICMPPacket;

int nat464_translate_icmp4_to_icmp6(sd_nat464 *nat, struct iphdr *iph, uint8_t *payload, size_t payload_size);
int nat464_translate_icmp6_to_icmp4(sd_nat464 *nat, struct ip6_hdr *ip6h, uint8_t *payload, size_t payload_size);
