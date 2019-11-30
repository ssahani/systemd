/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-ovsdb.h"

#include "alloc-util.h"
#include "arp-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "list.h"
#include "ovsdb-internal.h"
#include "macro.h"
#include "random-util.h"
#include "siphash24.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"


static int ovsdb_build_inc_next_cfg_message(sd_ovsdb *v, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_build(&m,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("op", JSON_BUILD_STRING("mutate")),
                                       JSON_BUILD_PAIR("table", JSON_BUILD_STRING("Open_vSwitch")),
                                       JSON_BUILD_PAIR("mutations",
                                                       JSON_BUILD_ARRAY(JSON_BUILD_ARRAY(JSON_BUILD_STRING("next_cfg"),
                                                                                         JSON_BUILD_STRING("+="),
                                                                                         JSON_BUILD_UNSIGNED(1))),
                                                       JSON_BUILD_PAIR("where", JSON_BUILD_ARRAY(JSON_BUILD_ARRAY(JSON_BUILD_STRING("_uuid"),
                                                                                                                  JSON_BUILD_STRING("=="),
                                                                                                                  JSON_BUILD_ARRAY(
                                                                                                                                  JSON_BUILD_STRING("uuid"),
                                                                                                                                  JSON_BUILD_STRING(v->db_uuid))))))));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

static int ovsdb_build_insert_bridge_table_message(sd_ovsdb *v, const char *bridge, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_build(&m,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("op", JSON_BUILD_STRING("insert")),
                                       JSON_BUILD_PAIR("table", JSON_BUILD_STRING("Bridge")),
                                       JSON_BUILD_PAIR("row",
                                                       JSON_BUILD_OBJECT(
                                                                       JSON_BUILD_PAIR("name", JSON_BUILD_STRING(bridge)),
                                                                       JSON_BUILD_PAIR("ports", JSON_BUILD_ARRAY(
                                                                                                       JSON_BUILD_STRING("set"),
                                                                                                       JSON_BUILD_ARRAY(
                                                                                                                       JSON_BUILD_ARRAY(
                                                                                                                                       JSON_BUILD_STRING("named-uuid"),
                                                                                                                                       JSON_BUILD_STRING("rowPort"))))))),
                                       JSON_BUILD_PAIR("uuid-name", JSON_BUILD_STRING("rowBridge"))));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

static int ovsdb_build_insert_port_table_message(sd_ovsdb *v, const char *port, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_build(&m,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("op", JSON_BUILD_STRING("insert")),
                                       JSON_BUILD_PAIR("table", JSON_BUILD_STRING("Port")),
                                       JSON_BUILD_PAIR("row",
                                                       JSON_BUILD_OBJECT(
                                                                       JSON_BUILD_PAIR("name", JSON_BUILD_STRING(port)),
                                                                       JSON_BUILD_PAIR("interfaces", JSON_BUILD_ARRAY(
                                                                                                       JSON_BUILD_STRING("set"),
                                                                                                       JSON_BUILD_ARRAY(
                                                                                                                       JSON_BUILD_ARRAY(
                                                                                                                                       JSON_BUILD_STRING("named-uuid"),
                                                                                                                                       JSON_BUILD_STRING("rowInterface"))))))),
                                       JSON_BUILD_PAIR("uuid-name", JSON_BUILD_STRING("rowPort"))));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

static int ovsdb_build_insert_interface_table_message(sd_ovsdb *v, const char *interface, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_build(&m,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("op", JSON_BUILD_STRING("insert")),
                                       JSON_BUILD_PAIR("table", JSON_BUILD_STRING("Interface")),
                                       JSON_BUILD_PAIR("row",
                                                       JSON_BUILD_OBJECT(
                                                                       JSON_BUILD_PAIR("name", JSON_BUILD_STRING(interface)),
                                                                       JSON_BUILD_PAIR("type", JSON_BUILD_STRING("internal")),
                                                                       JSON_BUILD_PAIR("options", JSON_BUILD_ARRAY(
                                                                                                       JSON_BUILD_STRING("map"),
                                                                                                       JSON_BUILD_ARRAY(""))))),
                                       JSON_BUILD_PAIR("uuid-name", JSON_BUILD_STRING("rowInterface"))));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

static int ovsdb_build_existing_bridges_set_message(sd_ovsdb *v, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("op", JSON_BUILD_STRING("wait")),
                                       JSON_BUILD_PAIR("table", JSON_BUILD_STRING("Open_vSwitch")),
                                       JSON_BUILD_PAIR("timeout", JSON_BUILD_UNSIGNED(0)),
                                       JSON_BUILD_PAIR("columns", JSON_BUILD_ARRAY(JSON_BUILD_STRING("bridges"))),
                                       JSON_BUILD_PAIR("until", JSON_BUILD_STRING("==")),
                                       JSON_BUILD_PAIR("rows", JSON_BUILD_ARRAY(
                                                                       JSON_BUILD_OBJECT(JSON_BUILD_PAIR("bridges", JSON_BUILD_ARRAY(JSON_BUILD_STRING("set"),
                                                                                                                                     JSON_BUILD_ARRAY(""))))),
                                                       JSON_BUILD_PAIR("where", JSON_BUILD_ARRAY(JSON_BUILD_ARRAY(JSON_BUILD_STRING("_uuid"),
                                                                                                                  JSON_BUILD_STRING("=="),
                                                                                                                  JSON_BUILD_ARRAY(JSON_BUILD_STRING("uuid"),
                                                                                                                                   JSON_BUILD_STRING(v->db_uuid))))))));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

static int ovsdb_build_new_bridges_set_message(sd_ovsdb *v, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = json_build(&m,
                       JSON_BUILD_OBJECT(JSON_BUILD_PAIR("op", JSON_BUILD_STRING("update")),
                                         JSON_BUILD_PAIR("table", JSON_BUILD_STRING("Open_vSwitch")),
                                         JSON_BUILD_PAIR("row", JSON_BUILD_OBJECT(JSON_BUILD_PAIR("bridges", JSON_BUILD_ARRAY(
                                                                                                                  JSON_BUILD_STRING("set"),
                                                                                                                  JSON_BUILD_ARRAY(
                                                                                                                                  JSON_BUILD_ARRAY(
                                                                                                                                                  JSON_BUILD_STRING("named-uuid"),
                                                                                                                                                  JSON_BUILD_STRING("rowBridge")))))),
                                                         JSON_BUILD_PAIR("where", JSON_BUILD_ARRAY(JSON_BUILD_ARRAY(
                                                                                                                   JSON_BUILD_STRING("_uuid"),
                                                                                                                   JSON_BUILD_STRING("=="),
                                                                                                                   JSON_BUILD_ARRAY(JSON_BUILD_STRING("uuid"),
                                                                                                                                    JSON_BUILD_STRING(v->db_uuid))))))));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

int ovsdb_build_query_add_ovs_bridge(sd_ovsdb *v, JsonVariant **ret) {
        JsonVariant *bridges = NULL, *port = NULL, *interface = NULL, *next_cfg = NULL,
                *existing_bridges = NULL, *new_bridges = NULL;
        uint32_t n;
        int r;

        r = ovsdb_build_inc_next_cfg_message(v, &next_cfg);
        if (r < 0)
                return r;

        r = ovsdb_build_existing_bridges_set_message(v, &existing_bridges);
        if (r < 0)
                return r;

        r = ovsdb_build_new_bridges_set_message(v, &new_bridges);
        if (r < 0)
                return r;

        r = ovsdb_build_insert_port_table_message(v, "test-port", &port);
        if (r < 0)
                return r;

        r = ovsdb_build_insert_bridge_table_message(v, "test-bridge", &bridges);
        if (r < 0)
                return r;

        r = ovsdb_build_insert_interface_table_message(v, "test-interface", &interface);
        if (r < 0)
                return r;

        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("id", JSON_BUILD_UNSIGNED(++v->sequence)),
                                          JSON_BUILD_PAIR("method", JSON_BUILD_STRING("transact")),
                                          JSON_BUILD_PAIR("params", JSON_BUILD_ARRAY(JSON_BUILD_STRING("Open_vSwitch"),
                                                                                     JSON_BUILD_VARIANT(next_cfg),
                                                                                     JSON_BUILD_VARIANT(existing_bridges),
                                                                                     JSON_BUILD_VARIANT(new_bridges),
                                                                                     JSON_BUILD_VARIANT(port),
                                                                                     JSON_BUILD_VARIANT(bridges),
                                                                                     JSON_BUILD_VARIANT(interface)))));
}

int ovsdb_build_query_get_ovs(sd_ovsdb *v, JsonVariant **ret) {
        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("method", JSON_BUILD_STRING("transact")),
                                          JSON_BUILD_PAIR("params", JSON_BUILD_ARRAY(JSON_BUILD_STRING("Open_vSwitch"),
                                                                                     JSON_BUILD_OBJECT(JSON_BUILD_PAIR("op", JSON_BUILD_STRING("select")),
                                                                                                       JSON_BUILD_PAIR("table", JSON_BUILD_STRING("Open_vSwitch")),
                                                                                                       JSON_BUILD_PAIR("where", JSON_BUILD_ARRAY(""))))),
                                          JSON_BUILD_PAIR("id", JSON_BUILD_UNSIGNED(v->sequence++))));
}

int ovsdb_build_query_get_bridges(sd_ovsdb *v, JsonVariant **ret) {
        return json_build(ret,
                          JSON_BUILD_OBJECT(JSON_BUILD_PAIR("method", JSON_BUILD_STRING("transact")),
                                            JSON_BUILD_PAIR("params", JSON_BUILD_ARRAY(
                                                                            JSON_BUILD_STRING("Open_vSwitch"),
                                                                            JSON_BUILD_OBJECT(JSON_BUILD_PAIR("op", JSON_BUILD_STRING("select")),
                                                                                              JSON_BUILD_PAIR("table", JSON_BUILD_STRING("Bridge")),
                                                                                              JSON_BUILD_PAIR("where", JSON_BUILD_ARRAY(""))))),
                                            JSON_BUILD_PAIR("id", JSON_BUILD_UNSIGNED(v->sequence++))));
}
