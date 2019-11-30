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

#define OVSDB_BUFFER_MAX (16U*1024U*1024U)
#define OVSDB_READ_SIZE (64U*1024U)

#define log_ovsdb_errno(ovsdb, error, fmt, ...) log_internal(LOG_DEBUG, error, PROJECT_FILE, __LINE__, __func__, "OVSDB: " fmt, ##__VA_ARGS__)
#define log_ovsdb(ovsdb, fmt, ...) log_ovsdb_errno(ovsdb, 0, fmt, ##__VA_ARGS__)

static sd_ovsdb_message *sd_ovsdb_message_free(sd_ovsdb_message *m) {
        assert(m);

        json_variant_unref(m->v);

        return mfree(m);
}

int sd_ovsdb_message_new(JsonVariant *v, uint64_t id, sd_ovsdb_message **ret) {
        sd_ovsdb_message *m;

        assert_return(ret, -EINVAL);
        assert_return(v, -EINVAL);

        m = new(sd_ovsdb_message, 1);
        if (!m)
                return -ENOMEM;

        *m = (sd_ovsdb_message) {
                .n_ref = 1,
                .v = v,
                .id = id,
        };

       *ret = TAKE_PTR(m);
        return 0;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_ovsdb_message, sd_ovsdb_message, sd_ovsdb_message_free);

static void ovsdb_set_state(sd_ovsdb *v, OVSDBClientState st) {
        assert(v);
        assert(st < _OVSDB_MAX);

        v->state = st;
}

static void ovsdb_reset(sd_ovsdb *v) {
        assert(v);

        v->receive_message_event_source = sd_event_source_unref(v->receive_message_event_source);

        v->fd = safe_close(v->fd);
        ovsdb_set_state(v, OVSDB_INIT);
}

int sd_ovsdb_detach_event(sd_ovsdb *v) {
        assert_return(v, -EINVAL);

        v->event = sd_event_unref(v->event);

        return 0;
}

static sd_ovsdb *ovsdb_free(sd_ovsdb *v) {
        assert(v);

        v->receive_message_event_source = sd_event_source_unref(v->receive_message_event_source);

        ovsdb_reset(v);
        sd_ovsdb_detach_event(v);

        return mfree(v);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_ovsdb, sd_ovsdb, ovsdb_free);

int sd_ovsdb_new(sd_ovsdb **ret) {
        _cleanup_(sd_ovsdb_unrefp) sd_ovsdb *v = NULL;

        assert_return(ret, -EINVAL);

        v = new(sd_ovsdb, 1);
        if (!v)
                return -ENOMEM;

        *v = (sd_ovsdb) {
                .n_ref = 1,
                .state = OVSDB_INIT,
                .fd = -1,
                .sequence = 1,
                .bridges = hashmap_new(&string_hash_ops),
        };

        if (!v->bridges)
                return log_oom();

        *ret = TAKE_PTR(v);

        return 0;
}

static sd_ovsdb_bridge *ovsdb_bridge_free(sd_ovsdb_bridge *b) {
        assert(b);

        free(b->uuid);
        free(b->name);

        strv_free(b->ports);

        return mfree(b);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_ovsdb_bridge, sd_ovsdb_bridge, ovsdb_bridge_free);

int sd_ovsdb_bridge_new(sd_ovsdb_bridge **ret) {
        sd_ovsdb_bridge *b;

        assert_return(ret, -EINVAL);

        b = new(sd_ovsdb_bridge, 1);
        if (!b)
                return -ENOMEM;

        *b = (sd_ovsdb_bridge) {
                .n_ref = 1,
        };

        *ret = TAKE_PTR(b);

        return 0;
}

static sd_ovsdb_port *ovsdb_port_free(sd_ovsdb_port *p) {
        assert(p);

        free(p->uuid);
        free(p->name);

        return mfree(p);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_ovsdb_port, sd_ovsdb_port, ovsdb_port_free);

int sd_ovsdb_port_new(sd_ovsdb_port **ret) {
        sd_ovsdb_port *p;

        assert_return(ret, -EINVAL);

        p = new(sd_ovsdb_port, 1);
        if (!p)
                return -ENOMEM;

        *p = (sd_ovsdb_port) {
                .n_ref = 1,
                .interfaces = hashmap_new(&string_hash_ops),
        };

        if (!p->interfaces)
                return log_oom();

        *ret = TAKE_PTR(p);

        return 0;
}

static void ovsdb_client_notify(sd_ovsdb *v, int event) {
        assert(v);

        if (!v->callback)
                return;

        v->callback(v, event, v->userdata);
}

int sd_ovsdb_stop(sd_ovsdb *v) {
        assert_return(v, -EINVAL);

        ovsdb_reset(v);

        log_ovsdb(v, "STOPPED");

        ovsdb_client_notify(v, OVSDB_STOP);

        return 0;
}

static int ovsdb_sanitize_parameters(JsonVariant **v) {
        assert(v);

        /* ovsdb always wants a parameters list, hence make one if the caller doesn't want any */
        if (!*v)
                return json_variant_new_object(v, NULL, 0);
        else if (!json_variant_is_object(*v))
                return -EINVAL;

        return 0;
}

static int ovsdb_write(sd_ovsdb *v, JsonVariant *m) {
        _cleanup_free_ sd_ovsdb_message *req = NULL;
        _cleanup_free_ char *text = NULL;
        int r, k;

        assert(v);

        assert(v->fd >= 0);

        r = json_variant_format(m, 0, &text);
        if (r < 0)
                return r;

        assert(text[r] == '\0');
        k = r;

        r = send(v->fd, text, k, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (r < 0) {
                if (errno == EAGAIN)
                        return 0;

                if (ERRNO_IS_DISCONNECT(errno)) {
                        v->socket_disconnected = true;
                        return 1;
                }

                return -errno;
        }

        printf("----------%s--------%d\n", text, r);

        r = hashmap_ensure_allocated(&v->requests, &trivial_hash_ops);
        if (r < 0)
                return r;

        r = sd_ovsdb_message_new(m, v->sequence, &req);
        if (r < 0)
                return r;

        r = hashmap_put(v->requests, UINT64_TO_PTR(req->id), req);
        if (r < 0)
                return r;

        sd_ovsdb_message_ref(req);

        return 0;
}

int sd_ovsdb_send_add_ovs_bridge(sd_ovsdb *v) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = ovsdb_build_query_add_ovs_bridge(v, &m);
        if (r < 0)
                return r;

        return ovsdb_write(v, m);
}

int sd_ovsdb_send_get_ovs(sd_ovsdb *v) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;
        _cleanup_free_ char *s = NULL;

        r = ovsdb_build_query_get_ovs(v, &m);
        if (r < 0)
                return r;

        r = ovsdb_write(v, m);
        if (r < 0)
                return r;

        ovsdb_set_state(v, OVSDB_DB_UUID_REQUEST);

        return 0;
}

int sd_ovsdb_send_get_bridges(sd_ovsdb *v) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = ovsdb_build_query_get_bridges(v, &m);
        if (r < 0)
                return r;

        r = ovsdb_write(v, m);
        if (r < 0)
                return r;

        ovsdb_set_state(v, OVSDB_BRIDGE_REQUEST);

        return 0;
}

static int ovsdb_build_query_echo(JsonVariant **ret) {
        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("method", JSON_BUILD_STRING("echo")),
                                          JSON_BUILD_PAIR("id", JSON_BUILD_STRING("echo")),
                                          JSON_BUILD_PAIR("params", JSON_BUILD_ARRAY(""))));
}

int sd_ovsdb_send_echo(sd_ovsdb *v) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        r = ovsdb_build_query_echo(&m);
        if (r < 0)
                return r;

        return ovsdb_write(v, m);
}

int sd_ovsdb_send(sd_ovsdb *v, const char *method, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == OVSDB_DISCONNECTED)
                return -ENOTCONN;

        r = ovsdb_sanitize_parameters(&parameters);
        if (r < 0)
                return r;

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("id", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("params", JSON_BUILD_VARIANT(parameters))));
        if (r < 0)
                return r;

        return ovsdb_write(v, m);
}



static int json_parse_db_uuid(sd_ovsdb *v, JsonVariant *c) {
        JsonVariant *k;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(k, c) {
                if (json_variant_is_string(k)) {
                        r = free_and_strdup(&v->db_uuid, json_variant_string(k));
                        if (r < 0)
                                return r;

                        ovsdb_set_state(v, OVSDB_DB_UUID_SET);
                }
        }

        return 0;
}

int json_dispatch_ovs_response_result_object(sd_ovsdb *v, JsonVariant *c) {
        JsonVariant *a;
        const char *b;
        int r;

        JSON_VARIANT_OBJECT_FOREACH(b, a, c) {
                if (json_variant_is_array(a))
                        json_dispatch_ovs_response_result_array(v, a);

                if (v->state == OVSDB_DB_UUID_REQUEST) {
                        if (streq(b, "_uuid")) {
                                r = json_parse_db_uuid(v, a);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (v->state == OVSDB_DB_UUID_SET)
                return sd_ovsdb_send_get_bridges(v);

        return 0;
}

int json_dispatch_ovs_response_result_array(sd_ovsdb *v, JsonVariant *c) {
        JsonVariant *k;

        JSON_VARIANT_ARRAY_FOREACH(k, c) {
                if (json_variant_is_object(k))
                        json_dispatch_ovs_response_result_object(v, k);
        }

        return 0;
}

static int ovs_dispatch_bridge_uuid(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        char ***lists = userdata;
        size_t i;
        int r;

        if (!streq("_uuid", name))
                return 0;

        for (i = 0; i < json_variant_elements(variant); i++) {
                _cleanup_free_ char *c = NULL;
                JsonVariant *e, *u;
                const char *a;

                e = json_variant_by_index(variant, i);
                if (!json_variant_is_string(e))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field is not an array of strings.");

                if (streq("uuid", json_variant_string(e))) {
                        u = json_variant_by_index(variant, ++i);

                        if (!json_variant_is_string(u))
                                continue;

                        r = strv_extend(&l, json_variant_string(u));
                        if (r < 0)
                                return json_log(e, flags, r, "Failed to append array element: %m");
                }
        }

        r = strv_extend_strv(lists, l, true);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to merge bridge uuid arrays: %m");

        return 0;
}

static int parse_one_port_uuid(JsonVariant *variant, JsonDispatchFlags flags, char ***l) {
        size_t i;
        int r;

        for (i = 0; i < json_variant_elements(variant); i++) {
                _cleanup_free_ char *c = NULL;
                JsonVariant *e, *u;
                const char *a;

                e = json_variant_by_index(variant, i);
                if (!json_variant_is_string(e))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field is not an array of strings.");

                if (streq("uuid", json_variant_string(e))) {
                        u = json_variant_by_index(variant, ++i);

                        if (!json_variant_is_string(u))
                                continue;

                        r = strv_extend(l, json_variant_string(u));
                        if (r < 0)
                                return json_log(e, flags, r, "Failed to append array element: %m");

                        printf("%s<<<<bbb>>>\n", json_variant_string(u));

                }
        }

        return 0;
}

static int ovs_dispatch_bridge_port(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        char ***lists = userdata;
        JsonVariant *v, *y;
        size_t i;
        int r;

        v = json_variant_by_index(variant, 1);
        if (!json_variant_is_array(v)) {
                r = parse_one_port_uuid(variant, flags, &l);
                if (r < 0)
                        return json_log(variant, flags, r, "Failed to merge one port uuid array: %m");
        } else {
                /* set */
                for (i = 0; i < json_variant_elements(v); i++) {
                        y = json_variant_by_index(v, i);
                        if (!y)
                                return json_log(y, flags, r, "Failed to merge one port uuid array: %m");

                        r = parse_one_port_uuid(y, flags, &l);
                        if (r < 0)
                                json_log(y, flags, r, "Failed to merge one port uuid array: %m");
                }
        }

        r = strv_extend_strv(lists, l, true);
        if (r < 0)
                return log_oom();

        return 0;
}

static int json_dispatch_ovs_response_bridge_result_array(sd_ovsdb *v, JsonVariant *c) {
        sd_ovsdb_bridge *br;
        JsonVariant *k;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(k, c) {
                static const JsonDispatch table[] = {
                        {"name",  JSON_VARIANT_STRING, json_dispatch_string, offsetof(struct sd_ovsdb_bridge, name), JSON_MANDATORY },
                        { "_uuid",  JSON_VARIANT_ARRAY, ovs_dispatch_bridge_uuid, offsetof(struct sd_ovsdb_bridge, uuid), JSON_MANDATORY },
                        { "ports",  JSON_VARIANT_ARRAY, ovs_dispatch_bridge_port, offsetof(struct sd_ovsdb_bridge, ports), JSON_MANDATORY },
                        {},
                };

                r = sd_ovsdb_bridge_new(&br);
                if (r < 0)
                        return r;

                r = json_dispatch(k, table, ovs_dispatch_bridge_uuid, 0, br);
                if (r < 0)
                        return r;

                r = hashmap_put(v->bridges, br->name, br);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        printf("hashmap size = %d\n", hashmap_size(v->bridges));

        return 0;
}

static int json_dispatch_ovs_response_bridge_result_object(sd_ovsdb *v, JsonVariant *c) {
        JsonVariant *a;
        const char *b;

        JSON_VARIANT_OBJECT_FOREACH(b, a, c) {
                (void) b;

                if (json_variant_is_array(a))
                        json_dispatch_ovs_response_bridge_result_array(v, a);
        }

        return 0;
}


static int json_dispatch_ovs_parse_bridge(sd_ovsdb *v, JsonVariant *c) {
        JsonVariant *k, *rows;

        JSON_VARIANT_ARRAY_FOREACH(k, c) {
                rows = json_variant_by_key(k, "rows");
                if (!rows)
                        printf("rows not found\n");

               if (json_variant_is_object(k))
                       json_dispatch_ovs_response_bridge_result_object(v, k);
        }

        ovsdb_set_state(v, OVSDB_DB_BRIDGE_SET);
        return 0;
}

static int json_dispatch_ovs_response(sd_ovsdb *v, JsonVariant *variant) {
        JsonVariant *value;
        const char *key;
        int r;

        if (!json_variant_is_object(variant)) {
                _cleanup_free_ char *s = NULL;

                (void) json_variant_format(variant, 0, &s);

                return json_log(variant, 0, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an object.", strna(s));
        }

        JSON_VARIANT_OBJECT_FOREACH(key, value, variant) {
                if (streq("id", key))
                        printf("object key = %s ---%lu---------\n", key, json_variant_unsigned(value));

                if (streq("result", key)) {
                        if (json_variant_is_array(value)) {
                                if (v->state == OVSDB_BRIDGE_REQUEST) {
                                        r = json_dispatch_ovs_parse_bridge(v, value);
                                        if (r < 0)
                                                return r;

                                        if (v->state == OVSDB_DB_BRIDGE_SET)
                                                return sd_ovsdb_send_add_ovs_bridge(v);
                                } else
                                        json_dispatch_ovs_response_result_array(v, value);
                        }
                }
        }

        return 0;
}

static int ovsdb_parse_message(sd_ovsdb *v) {
        int r;

        assert(v);

        log_ovsdb(v, "New incoming message: %s", v->input_buffer);

        r = json_parse(v->input_buffer, &v->reply, NULL, NULL);
        if (r < 0)
                return r;

        v->input_buffer = mfree(v->input_buffer);

        json_dispatch_ovs_response(v, v->reply);

        return 1;
}

static int ovsdb_read(sd_ovsdb *v) {
        ssize_t n, ms;

        assert(v);

        assert(v->fd >= 0);

        ms = next_datagram_size_fd(v->fd);
        if (ms <= 0)
                return ms;

        v->input_buffer = malloc0(ms);
        if (!v->input_buffer)
                return log_oom();

        n = recv(v->fd, v->input_buffer, ms, MSG_DONTWAIT);
        if (n < 0 && errno == EAGAIN)
                return 0;

        if (ERRNO_IS_DISCONNECT(errno)) {
                v->socket_disconnected = true;
                return 1;
        }

        if (n == 0) { /* EOF */
                v->socket_disconnected = true;
                return 1;
        }

        return 1;
}

int sd_ovsdb_process(sd_ovsdb *v) {
        int r;

        assert_return(v, -EINVAL);

        if (v->state == OVSDB_DISCONNECTED)
                return -ENOTCONN;

        r = ovsdb_read(v);
        if (r <= 0)
                return r;

        return ovsdb_parse_message(v);
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_ovsdb *v = userdata;

        assert(s);
        assert(v);

        (void) sd_ovsdb_process(v);

        return 1;
}

int sd_ovsdb_attach_event(sd_ovsdb *v, sd_event *event, int64_t priority) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(!v->event, -EBUSY);

        if (event)
                v->event = sd_event_ref(event);
        else {
                r = sd_event_default(&v->event);
                if (r < 0)
                        return r;
        }

        v->event_priority = priority;

        return 0;
}

int sd_ovsdb_set_callback(sd_ovsdb *v, sd_ovsdb_callback_t cb, void *userdata) {
        assert_return(v, -EINVAL);

        v->callback = cb;
        v->userdata = userdata;

        return 0;
}

int sd_ovsdb_is_running(sd_ovsdb *v) {
        assert_return(v, false);

        return v->state != OVSDB_INIT;
}

int sd_ovs_db_connect(sd_ovsdb *v) {
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/openvswitch/db.sock",
        };
        _cleanup_close_ int fd = -1;
        int r;

        r = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (r < 0)
                return log_debug_errno(errno, "Failed to create socket for OpenvSwitch DB: %m");

        fd = r;

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
        if (r < 0)
                return log_debug_errno(errno, "Failed to connect to OpenvSwitch DB: %m");

        safe_close(v->fd);
        v->fd = TAKE_FD(fd);

        return 0;
}

int sd_ovsdb_start(sd_ovsdb *v) {
        int r;

        assert_return(v, -EINVAL);

        r = sd_ovs_db_connect(v);
        if (r < 0)
                return r;

        r = sd_ovsdb_attach_event(v, NULL, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        r = sd_event_add_io(v->event, &v->receive_message_event_source, v->fd, EPOLLIN, io_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->receive_message_event_source, v->event_priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->receive_message_event_source, "ovsdb-receive-message");

        return sd_ovsdb_send_get_ovs(v);

 fail:
        ovsdb_reset(v);
        return r;
}
