/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "sd-nat464.h"

#include "event-util.h"
#include "missing_network.h"
#include "networkd-address-generation.h"
#include "networkd-address.h"
#include "networkd-dhcp6.h"
#include "networkd-manager.h"
#include "networkd-nat464.h"
#include "networkd-queue.h"
#include "networkd-route.h"
#include "networkd-state-file.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sysctl-util.h"

static bool link_nat464_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        return link->network->nat464;
}

static int nat464_configure(Link *link) {
        int r;

        assert(link);

        if (link->nat464)
                return -EBUSY; /* Already configured. */

        r = sd_nat464_new(&link->nat464);
        if (r < 0)
                return r;

        r = sd_nat464_set_max_mtu(link->nat464, link->max_mtu);
        if (r < 0)
                return r;

        r = sd_nat464_set_tun_name(link->nat464, link->ifname);
        if (r < 0)
                return r;

        r = sd_nat464_open_tun(link->nat464);
        if (r < 0)
                return r;

        return sd_nat464_attach_event(link->nat464, link->manager->event, 0);
}

int nat464_start(Link *link) {
        int r;

        assert(link);

        if (!link->nat464)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (!link_nat464_enabled(link))
                return 0;

        log_link_debug(link, "Starting NAT464 ...");

        r = sd_nat464_start(link->nat464);
        if (r < 0)
                return r;

        return 1;
}

static int nat464_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        r = nat464_configure(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure NAT464: %m");

        r = nat464_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start NAT464: %m");

        log_link_debug(link, "NAT464 is configured%s.",
                       r > 0 ? " and started" : "");
        return 1;
}

int link_request_nat464(Link *link) {
        int r;

        assert(link);

        if (!link_nat464_enabled(link))
                return 0;

        if (link->nat464)
                return 0;

        r = link_queue_request(link, REQUEST_TYPE_NAT464, nat464_process_request, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuring of the NAT464: %m");

        log_link_debug(link, "Requested configuring of the NAT464.");
        return 0;
}

int nat464_stop(Link *link) {
        assert(link);

        link->nat464_expire = sd_event_source_disable_unref(link->nat464_expire);

        return sd_nat464_stop(link->nat464);
}
