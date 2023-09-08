/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef foosdnat464foo
#define foosdnat464foo

#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "_sd-common.h"
#include "sd-event.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_nat464 sd_nat464;

int sd_nat464_new(sd_nat464 **ret);

sd_nat464 *sd_nat464_ref(sd_nat464 *nat);
sd_nat464 *sd_nat464_unref(sd_nat464 *nat);

int sd_nat464_attach_event(sd_nat464 *nat, sd_event *event, int64_t priority);
int sd_nat464_detach_event(sd_nat464 *nat);
sd_event *sd_nat464_get_event(sd_nat464 *nat);
int sd_nat464_get_ifname(sd_nat464 *nd, const char **ret);

int sd_nat464_start(sd_nat464 *nat);
int sd_nat464_stop(sd_nat464 *nat);

int sd_nat464_set_tun_name(sd_nat464 *t, const char *ifname);
int sd_nat464_set_max_mtu(sd_nat464 *nat, const uint16_t mtu);

int sd_nat464_open_tun(sd_nat464 *t);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_nat464, sd_nat464_unref);

_SD_END_DECLARATIONS;

#endif
