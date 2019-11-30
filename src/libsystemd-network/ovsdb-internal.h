#pragma once

#include "sd-ovsdb.h"
#include "hashmap.h"

typedef enum OVSDBClientState {
        OVSDB_INIT,
        OVSDB_IDLE_CLIENT,
        OVSDB_DB_UUID_REQUEST,
        OVSDB_DB_UUID_SET,
        OVSDB_BRIDGE_REQUEST,
        OVSDB_DB_BRIDGE_SET,
        OVSDB_CREATE_BRIDGE_REQUEST,
        OVSDB_DISCONNECTED,
        OVSDB_STOP,
        _OVSDB_MAX,
        _OVSDB_INVALID = -1
} OVSDBClientState;

struct sd_ovsdb_interface {
        unsigned n_ref;

        char *uuid;
        char *name;
};

struct sd_ovsdb_port {
        unsigned n_ref;

        char *uuid;
        char *name;

        Hashmap *interfaces;
};

struct sd_ovsdb_bridge {
        unsigned n_ref;

        char *uuid;
        char *name;

        char **ports;
};

struct sd_ovsdb_message {
        unsigned n_ref;
        uint64_t id;

        JsonVariant *v;
};

struct sd_ovsdb {
        unsigned n_ref;

        OVSDBClientState state;
        int fd;

        Hashmap *bridges;
        Hashmap *requests;
        JsonVariant *reply;

        char *input_buffer;
        char *db_uuid;

        sd_event_source *receive_message_event_source;

        bool socket_disconnected:1;

        uint64_t sequence;

        sd_event *event;
        int event_priority;
        sd_ovsdb_callback_t callback;
        void *userdata;
};


int json_dispatch_ovs_response_result_array(sd_ovsdb *v, JsonVariant *c);
int json_dispatch_ovs_response_result_object(sd_ovsdb *v, JsonVariant *c);

int ovsdb_build_query_add_ovs_bridge(sd_ovsdb *v, JsonVariant **ret);
int ovsdb_build_query_get_ovs(sd_ovsdb *v, JsonVariant **ret);
int ovsdb_build_query_get_bridges(sd_ovsdb *v, JsonVariant **ret);
