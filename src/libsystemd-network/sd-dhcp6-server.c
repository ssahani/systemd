/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/ioctl.h>

#include <arpa/inet.h>

#include "sd-dhcp6-server.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "dhcp6-internal.h"
#include "dhcp6-server-internal.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "siphash24.h"
#include "socket-util.h"
#include "string-util.h"
#include "unaligned.h"

#define DHCP6_DEFAULT_LEASE_TIME_USEC USEC_PER_HOUR
#define DHCP6_MAX_LEASE_TIME_USEC (USEC_PER_HOUR*12)

int sd_dhcp6_server_configure_pool(sd_dhcp6_server *server, struct in6_addr *min, struct in6_addr *max) {

        assert_return(server, -EINVAL);
        assert_return(min, -EINVAL);
        assert_return(max, -EINVAL);


       /* Drop any leases associated with the old address range */
        hashmap_clear(server->leases_by_client_id);

        return 0;
}

int sd_dhcp6_server_is_running(sd_dhcp6_server *server) {
        assert_return(server, false);

        return !!server->receive_message;
}

void client6_id_hash_func(const DHCP6ClientId *id, struct siphash *state) {
        assert(id);
        assert(id->length);
        assert(id->data);

        siphash24_compress(&id->length, sizeof(id->length), state);
        siphash24_compress(id->data, id->length, state);
}

int client6_id_compare_func(const DHCP6ClientId *a, const DHCP6ClientId *b) {
        int r;

        assert(!a->length || a->data);
        assert(!b->length || b->data);

        r = CMP(a->length, b->length);
        if (r != 0)
                return r;

        return memcmp(a->data, b->data, a->length);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(dhcp6_lease_hash_ops, DHCP6ClientId, client6_id_hash_func, client6_id_compare_func,
                                              sd_dhcp6_lease, sd_dhcp6_lease_unref);

static sd_dhcp6_server *dhcp6_server_free(sd_dhcp6_server *server) {
        assert(server);

        log_dhcp6_server(server, "UNREF");

        sd_dhcp6_server_stop(server);

        sd_event_unref(server->event);

        hashmap_free(server->leases_by_client_id);

        free(server->bound_leases);
        return mfree(server);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_server, sd_dhcp6_server, dhcp6_server_free);

int sd_dhcp6_server_new(sd_dhcp6_server **ret, int ifindex) {
        _cleanup_(sd_dhcp6_server_unrefp) sd_dhcp6_server *server = NULL;

        assert_return(ret, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);

        server = new0(sd_dhcp6_server, 1);
        if (!server)
                return -ENOMEM;

        server->n_ref = 1;
        server->fd = -1;
        server->address = in6addr_any;
        server->ifindex = ifindex;

        server->leases_by_client_id = hashmap_new(&dhcp6_lease_hash_ops);
        if (!server->leases_by_client_id)
                return -ENOMEM;

        server->default_lease_time = DIV_ROUND_UP(DHCP6_DEFAULT_LEASE_TIME_USEC, USEC_PER_SEC);
        server->max_lease_time = DIV_ROUND_UP(DHCP6_MAX_LEASE_TIME_USEC, USEC_PER_SEC);

        *ret = TAKE_PTR(server);

        return 0;
}

int sd_dhcp6_server_attach_event(sd_dhcp6_server *server, sd_event *event, int64_t priority) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(!server->event, -EBUSY);

        if (event)
                server->event = sd_event_ref(event);
        else {
                r = sd_event_default(&server->event);
                if (r < 0)
                        return r;
        }

        server->event_priority = priority;

        return 0;
}

int sd_dhcp6_server_detach_event(sd_dhcp6_server *server) {
        assert_return(server, -EINVAL);

        server->event = sd_event_unref(server->event);

        return 0;
}

sd_event *sd_dhcp6_server_get_event(sd_dhcp6_server *server) {
        assert_return(server, NULL);

        return server->event;
}

int sd_dhcp6_server_stop(sd_dhcp6_server *server) {
        assert_return(server, -EINVAL);

        server->receive_message = sd_event_source_unref(server->receive_message);
        server->fd = safe_close(server->fd);

        log_dhcp6_server(server, "STOPPED");

        return 0;
}

static int dhcp6_server_send_udp(sd_dhcp6_server *server, struct in6_addr *destination,
                                 DHCP6Message *message, size_t len) {
        union sockaddr_union dest = (union sockaddr_union) {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(DHCP6_PORT_CLIENT),
                .in6.sin6_addr = *destination,
        };
        struct iovec iov = {
                            .iov_base = message,
                .iov_len = len,
        };
        uint8_t cmsgbuf[CMSG_LEN(sizeof(struct in6_pktinfo))] = {};
        struct msghdr msg = {
                .msg_name = &dest,
                .msg_namelen = sizeof(dest.in6),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
        };
        struct cmsghdr *cmsg;
        struct in6_pktinfo *pktinfo;

        assert(server);
        assert(server->fd >= 0);
        assert(message);
        assert(len > sizeof(DHCP6Message));

        cmsg = CMSG_FIRSTHDR(&msg);
        assert(cmsg);

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        /* we attach source interface and address info to the message
           rather than binding the socket. This will be mostly useful
           when we gain support for arbitrary number of server addresses
         */
        pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsg);
        assert(pktinfo);

        pktinfo->ipi6_ifindex = server->ifindex;
        pktinfo->ipi6_addr = server->address;

        if (sendmsg(server->fd, &msg, 0) < 0)
                return -errno;

        return 0;
}

static int dhcp6_server_option_parse(DHCP6Message *message, size_t len) {
        bool clientid = false;
        size_t pos = 0;
        int r;

        assert(message);
        assert(len >= sizeof(DHCP6Message));

        len -= sizeof(DHCP6Message);

        while (pos < len) {
                DHCP6Option *option = (DHCP6Option *) &message->options[pos];
                uint16_t optcode, optlen;
                be32_t iaid_lease;
                uint8_t *optval;
                int status;

                if (len < pos + offsetof(DHCP6Option, data))
                        return -ENOBUFS;

                optcode = be16toh(option->code);
                optlen = be16toh(option->len);
                optval = option->data;

                if (len < pos + offsetof(DHCP6Option, data) + optlen)
                        return -ENOBUFS;

                switch (optcode) {
                default:

                        printf("%d -----------------\n" ,optcode);
                        break;
                }

                pos += offsetof(DHCP6Option, data) + optlen;
        }

        return 0;
}

static void dhcp6_request_free(DHCP6Request *req) {
        if (!req)
                return;

        free(req->client_id.data);
        free(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DHCP6Request*, dhcp6_request_free);

#define HASH_KEY SD_ID128_MAKE(0d,1d,fe,bd,f1,24,bd,b3,47,f1,dd,6e,73,21,93,30)

int dhcp6_server_handle_message(sd_dhcp6_server *server, DHCP6Message *message, size_t length) {
        _cleanup_(dhcp6_request_freep) DHCP6Request *req = NULL;
        _cleanup_free_ char *error_message = NULL;
        int type, r;

        assert(server);
        assert(message);

        req = new0(DHCP6Request, 1);
        if (!req)
                return -ENOMEM;

        type = dhcp6_server_option_parse(message, length);
        if (type < 0)
                return 0;

        switch(message->type) {
        case DHCP6_SOLICIT:
                printf("DHCP6_SOLICIT: ----------------------\n");
                break;
        case DHCP6_REQUEST:
        case DHCP6_CONFIRM:
        case DHCP6_RENEW:
        case DHCP6_REBIND:
        case DHCP6_RELEASE:
        case DHCP6_DECLINE:
        case DHCP6_INFORMATION_REQUEST:
        case DHCP6_RELAY_FORW:
        case DHCP6_RELAY_REPL:
                return 0;

        case DHCP6_ADVERTISE:
        case DHCP6_REPLY:
        case DHCP6_RECONFIGURE:
                break;

        default:
                log_dhcp6_server(client, "Unknown message type %d", message->type);
                return 0;
        }

       return 0;
}

static int dhcp6_server_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ DHCP6Message *message = NULL;
        uint8_t cmsgbuf[CMSG_LEN(sizeof(struct in6_pktinfo))];
        sd_dhcp6_server *server = userdata;
        struct iovec iov = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
        };
        struct cmsghdr *cmsg;
        ssize_t buflen, len;
        int r;
        assert(server);

        buflen = next_datagram_size_fd(fd);
        if (buflen < 0)
                return buflen;

        message = malloc(buflen);
        if (!message)
                return -ENOMEM;

        iov = IOVEC_MAKE(message, buflen);

        len = recvmsg(fd, &msg, 0);
        if (len < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0;

                return -errno;
        }
        if ((size_t)len < sizeof(DHCP6Message))
                return 0;

        printf("receive message ------------------\n");

        CMSG_FOREACH(cmsg, &msg) {
                if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                    cmsg->cmsg_type == IPV6_PKTINFO &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
                        struct in6_pktinfo *info = (struct in6_pktinfo*)CMSG_DATA(cmsg);

                        /* TODO figure out if this can be done as a filter on
                         * the socket, like for IPv6 */
                        if (server->ifindex != info->ipi6_ifindex)
                                return 0;

                        break;
                }
        }

        r = dhcp6_server_handle_message(server, message, (size_t) len);
        if (r < 0)
                log_dhcp6_server_errno(server, r, "Couldn't process incoming message: %m");

        return 0;
}

#define ALL_SERVERS                  "FF05::1:3"
#define ALL_RELAY_AGENTS_AND_SERVERS "FF02::1:2"

static int dhcp6_server_init_udp_socket(sd_dhcp6_server *server) {
        union sockaddr_union src = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = server->address,
                .in6.sin6_port = htobe16(DHCP6_PORT_SERVER),
                .in6.sin6_scope_id = server->ifindex,
        };
        _cleanup_close_ int s = -1;
        struct ipv6_mreq mreq6;
        int r;

        assert(server);

        s = socket(PF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
        if (s < 0)
                return -errno;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return r;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, false);
        if (r < 0)
                return r;

        r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = socket_bind_to_ifindex(s, server->ifindex);
        if (r < 0)
                return r;

        r = bind(s, &src.sa, sizeof(src.in6));
        if (r < 0)
                return -errno;

        mreq6.ipv6mr_interface = server->ifindex;

        r = inet_pton(AF_INET6, ALL_RELAY_AGENTS_AND_SERVERS, &mreq6.ipv6mr_multiaddr);
        if (r <= 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
        if (r < 0)
                return r;

        r = inet_pton(AF_INET6, ALL_SERVERS, &mreq6.ipv6mr_multiaddr);
        if (r <= 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
        if (r < 0)
                return r;

        server->fd = TAKE_FD(s);
        return 0;
}

int sd_dhcp6_server_start(sd_dhcp6_server *server) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(server->event, -EINVAL);
        assert_return(!server->receive_message, -EBUSY);
        assert_return(server->fd < 0, -EBUSY);

        r = dhcp6_server_init_udp_socket(server);
        if (r < 0) {
                sd_dhcp6_server_stop(server);
                return r;
        }

        r = sd_event_add_io(server->event, &server->receive_message, server->fd, EPOLLIN, dhcp6_server_receive_message, server);
        if (r < 0) {
                sd_dhcp6_server_stop(server);
                return r;
        }

        r = sd_event_source_set_priority(server->receive_message, server->event_priority);
        if (r < 0) {
                sd_dhcp6_server_stop(server);
                return r;
        }

        printf("---------------------fd = %d\n", server->fd);

        log_dhcp6_server(server, "STARTED");

        return 0;
}

int sd_dhcp6_server_set_timezone(sd_dhcp6_server *server, const char *tz) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(timezone_is_valid(tz, LOG_DEBUG), -EINVAL);

        if (streq_ptr(tz, server->timezone))
                return 0;

        r = free_and_strdup(&server->timezone, tz);
        if (r < 0)
                return r;

        return 1;
}

int sd_dhcp6_server_set_max_lease_time(sd_dhcp6_server *server, uint32_t t) {
        assert_return(server, -EINVAL);

        if (t == server->max_lease_time)
                return 0;

        server->max_lease_time = t;
        return 1;
}

int sd_dhcp6_server_set_default_lease_time(sd_dhcp6_server *server, uint32_t t) {
        assert_return(server, -EINVAL);

        if (t == server->default_lease_time)
                return 0;

        server->default_lease_time = t;
        return 1;
}
