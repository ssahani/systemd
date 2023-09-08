/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-nat464.h"

#include "network-common.h"
#include "time-util.h"

#define MTU_MIN 68

struct sd_nat464 {
        unsigned n_ref;

        int ifindex;
        int fd;
        uint16_t max_mtu;
        char *ifname;

        in_addr_t ip, gateway;
        struct in6_addr src_prefix, dst_prefix, gateway6;

        sd_event *event;
        int event_priority;

        sd_event_source *recv_event_source;
        void *userdata;
};

#define log_nat464_errno(nat464, error, fmt, ...)       \
        log_interface_prefix_full_errno(                \
                "NAT464: ",                             \
                sd_nat464, nat464,                      \
                error, fmt, ##__VA_ARGS__)
#define log_nat464(nat464, fmt, ...)                    \
        log_interface_prefix_full_errno_zerook(         \
                "NAT464: ",                             \
                sd_nat464, nat464,                      \
                0, fmt, ##__VA_ARGS__)
