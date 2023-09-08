/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "nat464-internal.h"

struct ICMP6Packet{
        struct ip6_hdr ip6;
        struct icmp6_hdr icmp6;
};

typedef struct ICMP6Packet ICMP6Packet;

struct ICMPPacket{
        struct iphdr ip;
        struct icmphdr icmp;
};

typedef struct ICMPPacket ICMPPacket;

int translate_icmp4_to_icmp6(sd_nat464 *nat, struct iphdr *ip_header, uint8_t *payload, size_t payload_length);
int translate_icmp6_to_icmp4(sd_nat464 *nat, struct ip6_hdr *ip6_header, uint8_t *payload, size_t payload_length);
