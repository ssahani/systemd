/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dns-resolver-internal.h"
#include "networkd-forward.h"

typedef struct DHCPServerEncryptedDNS {
        Network *network;
        ConfigSection *section;

        sd_dns_resolver resolver;
} DHCPServerEncryptedDNS;

typedef enum DHCPServerPersistLeases {
        DHCP_SERVER_PERSIST_LEASES_NO,
        DHCP_SERVER_PERSIST_LEASES_YES,
        DHCP_SERVER_PERSIST_LEASES_RUNTIME,
        _DHCP_SERVER_PERSIST_LEASES_MAX,
        _DHCP_SERVER_PERSIST_LEASES_INVALID = -EINVAL,
} DHCPServerPersistLeases;

int network_adjust_dhcp_server(Network *network, Set **addresses);
void network_drop_invalid_dhcp_server_encrypted_dns(Network *network);
int address_acquire_from_dhcp_server_leases_file(Link *link, const Address *address, union in_addr_union *ret);
int link_request_dhcp_server(Link *link);

int link_start_dhcp4_server(Link *link);
void manager_toggle_dhcp4_server_state(Manager *manager, bool start);

CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_relay_agent_suboption);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_emit);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_address);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_ipv6_only_preferred);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_persist_leases);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_encrypted_dns_name);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_encrypted_dns_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_encrypted_dns_addresses);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_encrypted_dns_transport);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_encrypted_dns_port);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_server_encrypted_dns_dohpath);
