/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef foosdovsdbfoo
#define foosdovsdbfoo

#pragma once

#include "sd-event.h"

#include "json.h"


#include <netinet/in.h>

#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_ovsdb_port sd_ovsdb_port;
typedef struct sd_ovsdb_bridge sd_ovsdb_bridge;
typedef struct sd_ovsdb_message sd_ovsdb_message;
typedef struct sd_ovsdb sd_ovsdb;
typedef void (*sd_ovsdb_callback_t)(sd_ovsdb *ovsdb, int event, void *userdata);

int sd_ovsdb_detach_event(sd_ovsdb *ovsdb);
int sd_ovsdb_attach_event(sd_ovsdb *ovsdb, sd_event *event, int64_t priority);
int sd_ovsdb_set_callback(sd_ovsdb *ovsdb, sd_ovsdb_callback_t cb, void *userdata);
int sd_ovsdb_is_running(sd_ovsdb *ovsdb);
int sd_ovsdb_start(sd_ovsdb *ovsdb);
int sd_ovsdb_stop(sd_ovsdb *ovsdb);
int sd_ovs_db_connect(sd_ovsdb *v);

/* Enqueue method call, not expecting a reply */
int sd_sd_ovsdb_send(sd_ovsdb *v, const char *method, JsonVariant *parameters);
int sd_ovsdb_reply(sd_ovsdb *v, JsonVariant *parameters);

sd_ovsdb *sd_ovsdb_ref(sd_ovsdb *ovsdb);
sd_ovsdb *sd_ovsdb_unref(sd_ovsdb *ovsdb);
int sd_ovsdb_new(sd_ovsdb **ret);

sd_ovsdb_bridge *sd_ovsdb_bridge_ref(sd_ovsdb_bridge *b);
sd_ovsdb_bridge *sd_ovsdb_bridge_unref(sd_ovsdb_bridge *b);
int sd_ovsdb_bridge_new(sd_ovsdb_bridge **ret);

sd_ovsdb_port *sd_ovsdb_port_ref(sd_ovsdb_port *p);
sd_ovsdb_port *sd_ovsdb_port_unref(sd_ovsdb_port *p);
int sd_ovsdb_port_new(sd_ovsdb_port **ret);

sd_ovsdb_message *sd_ovsdb_message_ref(sd_ovsdb_message *m);
sd_ovsdb_message *sd_ovsdb_message_unref(sd_ovsdb_message *m);
int sd_ovsdb_message_new(JsonVariant *v, uint64_t id, sd_ovsdb_message **ret);

int sd_ovsdb_send(sd_ovsdb *v, const char *method, JsonVariant *parameters);
int sd_ovsdb_process(sd_ovsdb *v);
int sd_ovsdb_send_echo(sd_ovsdb *v);
int sd_ovsdb_send_get_bridges(sd_ovsdb *v);
int sd_ovsdb_send_get_ovs(sd_ovsdb *v);
int sd_ovsdb_send_add_ovs_bridge(sd_ovsdb *v);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ovsdb, sd_ovsdb_unref);

_SD_END_DECLARATIONS;

#endif
