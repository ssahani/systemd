/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#if !HAVE_GNUTLS
#error This source file requires GnuTLS to be available.
#endif

#include "timesyncd-manager.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(gnutls_session_t, gnutls_deinit);

int get_record(unsigned char *data, int length, int *type, int *blength, void *ret);
int is_message_complete(unsigned char *data, int length);
int ntske_tls_send_request(Manager *m);
int ntske_tls_receive_response(sd_event_source *source, int fd, uint32_t revents, void *userdata);

int ntske_tls_connect(Manager *manager);
void ntske_tls_bye(Manager *m);

ssize_t ntske_tls_write(Manager *m, const char *buf, size_t count);
ssize_t ntske_tls_read(Manager *m, void *buf, size_t count);

int ntske_tls_manager_init(Manager *manager);
void ntske_tls_manager_free(Manager *manager);
