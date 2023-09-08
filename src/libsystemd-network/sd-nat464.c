/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <unistd.h>

#include "sd-nat464.h"

#include "alloc-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "memory-util.h"
#include "network-common.h"
#include "nat464-ip.h"
#include "socket-util.h"

int sd_nat464_new(sd_nat464 **ret) {
        _cleanup_(sd_nat464_unrefp) sd_nat464 *nat = NULL;

        assert_return(ret, -EINVAL);

        nat = new(sd_nat464, 1);
        if (!nat)
                return -ENOMEM;

        *nat = (sd_nat464) {
                .n_ref = 1,
                .fd = -EBADF,
        };

        *ret = TAKE_PTR(nat);

        return 0;
}

int sd_nat464_attach_event(sd_nat464 *nat, sd_event *event, int64_t priority) {
        int r;

        assert_return(nat, -EINVAL);
        assert_return(!nat->event, -EBUSY);

        if (event)
                nat->event = sd_event_ref(event);
        else {
                r = sd_event_default(&nat->event);
                if (r < 0)
                        return 0;
        }

        nat->event_priority = priority;

        return 0;
}

int sd_nat464_detach_event(sd_nat464 *nat) {

        assert_return(nat, -EINVAL);

        nat->event = sd_event_unref(nat->event);
        return 0;
}

sd_event *sd_nat464_get_event(sd_nat464 *nat) {
        assert_return(nat, NULL);

        return nat->event;
}

int sd_nat464_get_ifname(sd_nat464 *nd, const char **ret) {
        int r;

        assert_return(nd, -EINVAL);

        r = get_ifname(nd->ifindex, &nd->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = nd->ifname;

        return 0;
}

static void nat464_reset(sd_nat464 *nat) {
        assert(nat);

        (void) event_source_disable(nat->recv_event_source);

        nat->recv_event_source = sd_event_source_disable_unref(nat->recv_event_source);
}

static sd_nat464 *nat464_free(sd_nat464 *nat) {
        if (!nat)
                return NULL;

        nat464_reset(nat);

        sd_event_source_unref(nat->recv_event_source);
        sd_nat464_detach_event(nat);

        nat->fd = safe_close(nat->fd);
        free(nat->ifname);

        return mfree(nat);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_nat464, sd_nat464, nat464_free);

static int nat464_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ uint8_t *packet = NULL;
        sd_nat464 *nat = ASSERT_PTR(userdata);
        int ver, r = 0;
        ssize_t n;

        log_nat464(nat, "Received NAT464 message ...");

        packet = malloc(nat->max_mtu);
        if (!packet) {
               log_oom_debug();
               return 0;
        }

        n = read(fd, packet, nat->max_mtu);
        if (n < 0) {
                log_nat464_errno(nat, errno, "Could not receive packet, ignoring: %m");
                return 0;
        }

        ver = packet[0] >> 4;
        if (ver == 4)
                r = nat464_process_ip4_packet(nat, packet, n);
        else if (ver == 6)
                r = nat464_process_ip6_packet(nat, packet, n);
        else
                log_nat464_errno(nat, r, "Malformed IP packet verion '%d', ignoring: %m", ver);

        return 0;
}

int sd_nat464_stop(sd_nat464 *nat) {
        if (!nat)
                return 0;

        if (nat->fd < 0)
                return 0;

        log_nat464(nat, "Stopping NAT464 ...");

        nat464_reset(nat);
        return 1;
}

int sd_nat464_start(sd_nat464 *nat) {
        int r;

        assert_return(nat, -EINVAL);
        assert_return(nat->event, -EINVAL);

        r = sd_event_add_io(nat->event, &nat->recv_event_source, nat->fd, EPOLLIN, nat464_receive_message, nat);
        if (r < 0)
                goto on_error;

        r = sd_event_source_set_priority(nat->recv_event_source, nat->event_priority);
        if (r < 0)
                goto on_error;

        (void) sd_event_source_set_description(nat->recv_event_source, "nat464-receive-packets");

        log_nat464(nat, "STARTED");

        return 0;

 on_error:
        sd_nat464_stop(nat);
        return r;
}

int sd_nat464_set_tun_name(sd_nat464 *nat, const char *ifname) {
        assert_return(nat, -EINVAL);
        assert_return(ifname, -EINVAL);

        nat->ifname = strdup(ifname);
        if (!nat->ifname)
                return -ENOMEM;

        return 0;
}

int sd_nat464_set_max_mtu(sd_nat464 *nat, const uint16_t mtu) {
        assert_return(nat, -EINVAL);
        assert_return(mtu, -EINVAL);

        nat->max_mtu = mtu;

        return 0;
}

int sd_nat464_open_tun(sd_nat464 *nat) {
        _cleanup_close_ int fd = -EBADF;
        struct ifreq ifr = {
                .ifr_flags = IFF_TUN | IFF_NO_PI,
        };
        int r;

        assert_return(nat, -EINVAL);

        fd = open("/dev/net/tun", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return log_nat464_errno(nat, errno,  "Failed to open NAT464 tun device '/dev/net/tun': %m");

        strncpy(ifr.ifr_name, nat->ifname, IFNAMSIZ);

        r = ioctl(fd, TUNSETIFF, &ifr);
        if (r < 0)
                return log_nat464_errno(nat, errno, "TUNSETIFF failed: %m");

        nat->fd = TAKE_FD(fd);
        strncpy(nat->ifname, ifr.ifr_name, IFNAMSIZ);

        return 0;
}
