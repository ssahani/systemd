/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>

#include "nat464-internal.h"

int nat464_process_ip4_packet(sd_nat464 *nat, uint8_t *ip_packet, size_t packet_size);
int nat464_process_ip6_packet(sd_nat464 *nat, uint8_t *ip6_packet, size_t packet_size);
