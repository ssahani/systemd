/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-dhcp6-server.h"

#include "networkd-dhcp6-server.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "strv.h"
#include "string-table.h"
#include "string-util.h"

static Address* link_find_dhcp6_server_address(Link *link) {
        Address *address;

        assert(link);
        assert(link->network);

        /* The first statically configured address if there is any */
        LIST_FOREACH(addresses, address, link->network->static_addresses) {

                if (address->family != AF_INET6)
                        continue;

                if (in_addr_is_null(address->family, &address->in_addr))
                        continue;

                return address;
        }

        /* If that didn't work, find a suitable address we got from the pool */
        LIST_FOREACH(addresses, address, link->pool_addresses) {
                if (address->family != AF_INET6)
                        continue;

                return address;
        }

        return NULL;
}

int dhcp6_server_configure(Link *link) {
        bool acquired_uplink = false;
        sd_dhcp_option *p;
        Link *uplink = NULL;
        Address *address;
        Iterator i;
        int r;

        address = link_find_dhcp6_server_address(link);
        if (!address)
                return log_link_error_errno(link, SYNTHETIC_ERRNO(EBUSY),
                                            "Failed to find suitable address for DHCPv6 server instance.");
      if (!sd_dhcp6_server_is_running(link->dhcp6_server)) {
                r = sd_dhcp6_server_start(link->dhcp6_server);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not start DHCPv6 server instance: %m");
       }

        return 0;
}
