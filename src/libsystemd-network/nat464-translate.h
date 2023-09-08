/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "nat464-internal.h"

int build_ip6_header_from_ip4_packet(sd_nat464 *nat, struct iphdr *ip_header, struct ip6_hdr *ip6_header, size_t payload_length);
int fill_ip4_protocol_from_ip6_packet(struct iphdr *ip_header, struct ip6_hdr *ip6_header, uint8_t *payload, size_t payload_length);
int build_ip4_header_from_ip6_packet(sd_nat464 *nat, struct ip6_hdr *ip6_header, struct ip6_frag *ip6_fragment, struct iphdr *ip_header, size_t payload_length);
int fill_ip6_payload_from_ip4_packet(struct iphdr *ip_header, struct ip6_hdr *ip6_header, uint8_t *payload, size_t payload_length);
