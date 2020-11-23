/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !HAVE_GNUTLS
#error This source file requires GnuTLS to be available.
#endif

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "log.h"
#include "timesyncd-ntske-client.h"
#include "timesyncd-ntske-protocol.h"

int ntske_tls_send_request(Manager *m) {
        _cleanup_(ntske_packet_freep) NTSKEPacket *packet = NULL;
        int r;

        r = ntske_build_request_packet(&packet);
        if (r < 0)
                return r;

        r = gnutls_record_send(m->tls_session, packet->data, packet->size);
        if (r < 0) {
                if (gnutls_error_is_fatal(r))
                        return r;
        }

        return 0;
}

int ntske_tls_receive_response(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_(ntske_packet_freep) NTSKEPacket *packet = NULL;
        Manager *m = userdata;
        ServerName *s;
        int r;

        assert(source);
        assert(m);

        if (revents & (EPOLLHUP|EPOLLERR)) {
                log_warning("Server connection returned error.");
                goto error;
        }

        if (!m->ntske_packet) {
                r = nts_ke_packet_new(NTS_KE_MESSAGE_SIZE_MAX, &packet);
                if (r < 0)
                        goto error;
        }

        r = gnutls_record_recv(m->tls_session, packet->data + packet->read, NTS_KE_MESSAGE_SIZE_MAX - packet->read);
        if (r < 0) {
                if (IN_SET(r, GNUTLS_E_INTERRUPTED, GNUTLS_E_AGAIN))
                        return 1;

                if (gnutls_error_is_fatal(r)) {
                        log_debug_errno(r,
                                        "Failed to invoke gnutls_record_recv: %s",
                                        gnutls_strerror(r));
                        goto error;
                }

                r = 0;
        }

        packet->size += r;
        packet->payload = true;

        log_debug("Received %ld bytes from ntske server", packet->size);

        r = ntske_parse_packet(packet);
        if (r < 0) {
                log_error_errno(r, "Failed to parse ntske packet: %m");
                goto error;
        }

        log_debug("Setting NTP server %s received from ntske.", packet->server);

        r = server_name_new(m, &s, SERVER_SYSTEM, packet->server);
        if (r < 0) {
                log_error_errno(r, "Failed to add NTP server '%s' received from ntske server: %m", packet->server);
                goto error;
        }

        /* Drop the payload */
        ntske_packet_payload_free(packet);

        m->ntske_packet = TAKE_PTR(packet);
        m->ntske_done = true;

 error:
        return manager_connect(m);
}

int ntske_tls_connect(Manager *m) {
        _cleanup_(gnutls_deinitp) gnutls_session_t tls_session = NULL;
        gnutls_datum_t alpn = {
                .data = (uint8_t *) "ntske/1",
                .size = sizeof("ntske/1") - 1,
        };
        int r;

        assert(m);

        r = ntske_tls_manager_init(m);
        if (r < 0)
                return r;

        r = gnutls_init(&tls_session, GNUTLS_CLIENT | GNUTLS_NO_SIGNAL);
        if (r < 0)
                return r;

        gnutls_transport_set_int(tls_session, m->ntske_server_socket);

        r = gnutls_server_name_set(tls_session, GNUTLS_NAME_DNS, m->current_ntske_server_name->string, strlen(m->current_ntske_server_name->string));
        if (r < 0)
                return r;

        r = gnutls_priority_init2(&m->priority_cache,
                                  "-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2:-VERS-DTLS-ALL",
                                  NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND);

        r = gnutls_priority_set(tls_session, m->priority_cache);
        if (r < 0)
                return r;

        r = gnutls_credentials_set(tls_session, GNUTLS_CRD_CERTIFICATE, m->cert_cred);
        if (r < 0)
                return r;

        r = gnutls_alpn_set_protocols(tls_session, &alpn, 1, 0);
        if (r < 0)
                return r;

        m->handshake = gnutls_handshake(tls_session);
        if (m->handshake < 0 && gnutls_error_is_fatal(m->handshake))
                return -ECONNREFUSED;

        m->tls_session = TAKE_PTR(tls_session);
        return 0;
}

void ntske_tls_bye(Manager *m) {
        int r;

        assert(m);

        if (!m->tls_session)
                return;

        r = gnutls_bye(m->tls_session, GNUTLS_SHUT_RDWR);
        if (r < 0) {
                if (gnutls_error_is_fatal(r))
                        log_error_errno(r, "GnuTLS Shutdown failed woth '%s': %m", gnutls_strerror(r));
        }

        gnutls_deinit(m->tls_session);
        m->tls_session = NULL;
}

int ntske_tls_manager_init(Manager *manager) {
        int r;
        assert(manager);

        r = gnutls_certificate_allocate_credentials(&manager->cert_cred);
        if (r < 0)
                return -ENOMEM;

        r = gnutls_certificate_set_x509_system_trust(manager->cert_cred);
        if (r < 0)
                log_warning("Failed to load system trust store: %s", gnutls_strerror(r));

        return 0;
}

void ntske_tls_manager_free(Manager *manager) {
        assert(manager);

        if (manager->cert_cred)
                gnutls_certificate_free_credentials(manager->cert_cred);
}
