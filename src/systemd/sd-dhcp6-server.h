/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef foosddhcp6serverhfoo
#define foosddhcp6serverhfoo

#include <inttypes.h>
#include <netinet/in.h>

#include "sd-dhcp6-lease.h"
#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp6_server sd_dhcp6_server;

int sd_dhcp6_server_new(sd_dhcp6_server **ret, int ifindex);

sd_dhcp6_server *sd_dhcp6_server_ref(sd_dhcp6_server *server);
sd_dhcp6_server *sd_dhcp6_server_unref(sd_dhcp6_server *server);

int sd_dhcp6_server_attach_event(sd_dhcp6_server *client, sd_event *event, int64_t priority);
int sd_dhcp6_server_detach_event(sd_dhcp6_server *client);
sd_event *sd_dhcp6_server_get_event(sd_dhcp6_server *client);

int sd_dhcp6_server_is_running(sd_dhcp6_server *server);

int sd_dhcp6_server_start(sd_dhcp6_server *server);
int sd_dhcp6_server_stop(sd_dhcp6_server *server);

int sd_dhcp6_server_configure_pool(sd_dhcp6_server *server, struct in6_addr *min, struct in6_addr *max);

int sd_dhcp6_server_set_timezone(sd_dhcp6_server *server, const char *timezone);
int sd_dhcp6_server_set_dns(sd_dhcp6_server *server, const struct in_addr dns[], unsigned n);
int sd_dhcp6_server_set_ntp(sd_dhcp6_server *server, const struct in_addr ntp[], unsigned n);
int sd_dhcp6_server_set_emit_router(sd_dhcp6_server *server, int enabled);

int sd_dhcp6_server_set_max_lease_time(sd_dhcp6_server *server, uint32_t t);
int sd_dhcp6_server_set_default_lease_time(sd_dhcp6_server *server, uint32_t t);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp6_server, sd_dhcp6_server_unref);

_SD_END_DECLARATIONS;

#endif
