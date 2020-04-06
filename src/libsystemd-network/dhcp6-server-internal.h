/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-dhcp6-server.h"
#include "sd-event.h"
#include "sd-dhcp6-lease.h"

#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"
#include "hashmap.h"
#include "log.h"
#include "time-util.h"

typedef struct DHCP6Message DHCP6Message;

typedef struct DHCP6ClientId {
        size_t length;
        void *data;
} DHCP6ClientId;

typedef struct DHCP6Pool {
        char *name;

        struct in6_addr min;
        struct in6_addr max;
} DHCP6Pool;

struct sd_dhcp6_server {
        unsigned n_ref;

        sd_event *event;
        int event_priority;
        sd_event_source *receive_message;
        int fd;

        int ifindex;
        struct in6_addr address;

        DHCP6Pool pool;

        char *timezone;

        struct in6_addr *ntp, *dns;
        unsigned n_ntp, n_dns;

        bool emit_router;

        Hashmap *leases_by_client_id;
        sd_dhcp6_lease **bound_leases;

        uint32_t max_lease_time, default_lease_time;
};

typedef struct DHCP6Request {
        /* received message */
        DHCP6Message *message;

        /* options */
        DHCP6ClientId client_id;
        size_t max_optlen;
        be32_t server_id;
        be32_t requested_ip;
        uint32_t lifetime;
} DHCP6Request;

#define log_dhcp6_server(client, fmt, ...) log_internal(LOG_DEBUG, 0, PROJECT_FILE, __LINE__, __func__, "DHCP6 SERVER: " fmt, ##__VA_ARGS__)
#define log_dhcp6_server_errno(client, error, fmt, ...) log_internal(LOG_DEBUG, error, PROJECT_FILE, __LINE__, __func__, "DHCP6 SERVER: " fmt, ##__VA_ARGS__)

int dhcp6_server_handle_message(sd_dhcp6_server *server, DHCP6Message *message, size_t length);
int dhcp6_server_send_packet(sd_dhcp6_server *server,
                             DHCP6Request *req, DHCP6Message *packet,
                             int type, size_t optoffset);

void client6_id_hash_func(const DHCP6ClientId *p, struct siphash *state);
int client6_id_compare_func(const DHCP6ClientId *a, const DHCP6ClientId *b);
