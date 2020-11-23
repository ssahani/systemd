/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dns-domain.h"
#include "parse-util.c"
#include "timesyncd-ntske-protocol.h"


/* rfc8915 The NTS Key Establishment Protocol
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |C|         Record Type         |          Body Length          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * .                                                               .
 * .                           Record Body                         .
 * .                                                               .
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

int nts_ke_packet_new(size_t max_size, NTSKEPacket **ret) {
        _cleanup_(ntske_packet_freep) NTSKEPacket *p = NULL;

        assert(ret);
        assert(max_size <= NTS_KE_MESSAGE_SIZE_MAX);

        if (max_size > NTS_KE_MESSAGE_SIZE_MAX)
                max_size = NTS_KE_MESSAGE_SIZE_MAX;

        p = new0(NTSKEPacket, 1);
        if (!p)
                return -ENOMEM;

        if (max_size) {
                p->data = malloc0(max_size);
                if (!p->data)
                        return -ENOMEM;

                p->size = max_size;
        }

        *ret = TAKE_PTR(p);
        return 0;
}

NTSKEPacket *ntske_packet_free(NTSKEPacket *p) {
        if (!p)
                return NULL;

        free(p->data);
        free(p->server);
        return mfree(p);
}

void ntske_packet_payload_free(NTSKEPacket *p) {
        if (!p)
                return;

        p->data = mfree(p->data);
        p->size = 0;
        p->read = 0;
        p->offset = 0;
        p->payload = false;
}

int ntske_append_record(NTSKEPacket *packet, uint16_t record_type, const void *data, size_t data_size, bool critical) {
        NTSKERecord h = {
                .record_type = htobe16(!!critical * NTS_KE_RECORD_CRITICAL_BIT | record_type),
                .body_size = htobe16(data_size),
        };
        uint8_t *new_data;

        assert(packet);

        if (packet->size + sizeof(NTSKERecord) + data_size > NTS_KE_MESSAGE_SIZE_MAX)
                return -E2BIG;

        new_data = realloc(packet->data, sizeof(NTSKERecord) + data_size);
        if (!new_data)
                return -ENOMEM;

        packet->data = new_data;

        memcpy(packet->data + packet->size, &h, sizeof(NTSKERecord));
        packet->size += sizeof(NTSKERecord);

        if (data_size > 0) {
                memcpy(packet->data + packet->size, data, data_size);
                packet->size += data_size;
        }

        return 0;
}

int ntske_read_record(NTSKEPacket *packet, uint16_t *record_type, uint8_t **data, size_t *data_size, bool *critical)  {
        size_t body_size, record_size;
        NTSKERecord h;

        assert(packet);

        if (packet->size < packet->offset + sizeof(NTSKERecord) || !packet->payload)
                return 0;

        memcpy(&h, packet->data + packet->offset, sizeof(NTSKERecord));

        body_size = be16toh(h.body_size);
        record_size = sizeof(NTSKERecord) + body_size;

        if (record_type)
                *record_type = be16toh(h.record_type) & ~NTS_KE_RECORD_CRITICAL_BIT;

        if (data)
                *data = packet->data + packet->offset + sizeof(NTSKERecord);

        if (data_size)
                *data_size = body_size;

        if (critical)
                *critical = !!(be16toh(h.record_type) & NTS_KE_RECORD_CRITICAL_BIT);

        packet->offset += record_size;
        return 1;
}

int ntske_parse_packet(NTSKEPacket *packet) {
        bool error = false, end = false, critical = false;
        uint16_t record_type;
        size_t data_size;
        uint8_t *data;
        int r;

        for(; !end && !error && ntske_read_record(packet, &record_type, &data, &data_size, &critical);) {
                uint16_t *p = (uint16_t *) data;

                switch (record_type & ~NTS_KE_RECORD_CRITICAL_BIT) {
                case NTS_KE_RECORD_END_OF_MESSAGE:
                        end = true;
                        break;
                case NTS_KE_RECORD_NEXT_PROTOCOL:
                        if (!critical || data_size != 2 || be16toh(*p) != NTS_KE_NEXT_PROTOCOL_NTPV4)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Next protocol field has wrong size or type, ignoring packet");
                        break;
                case NTS_KE_RECORD_ERROR:
                        error = true;
                        break;
                case NTS_KE_RECORD_WARNING:
                        break;
                case NTS_KE_RECORD_AEAD_ALGORITHM:
                        if (data_size != 2 || be16toh(*p) != AEAD_AES_SIV_CMAC_256)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "AEAD algorithm field has wrong size or type, ignoring packet");

                        packet->aead_algorithm = AEAD_AES_SIV_CMAC_256;
                        break;
                case NTS_KE_RECORD_COOKIE:
                        break;
                case NTS_KE_RECORD_NTPV4_SERVER_NEGOTIATION: {
                        _cleanup_free_ char *d = NULL;

                        if (data_size == 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTP4 server negotation field has wrong size or type, ignoring packet");

                        d = memdup(data, data_size);
                        if (!d)
                                return -ENOMEM;

                        r = dns_name_is_valid_or_address(d);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to check validity of NTP server name or address '%s': %m", d);
                        if (r == 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Invalid NTP server name or address '%s', ignoring : %m", d);

                        packet->server = TAKE_PTR(d);                }
                        break;
                case NTS_KE_RECORD_NTPV4_PORT_NEGOTIATION: {
                        if (data_size > 0 && data_size != sizeof(uint16_t)) {
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTP4 port negotation field has wrong size or type, ignoring packet");
                        }  else
                                packet->port = be32toh(*p);
                }
                        break;
                default:
                        break;
                }
        }

        ntske_packet_reset_parse(packet);

        return 0;
}

int ntske_build_request_packet(NTSKEPacket **ret) {
        _cleanup_free_ NTSKEPacket *packet = NULL;
        uint16_t d;
        int r;

        r = nts_ke_packet_new(0, &packet);
        if (r < 0)
                return r;

        d = htobe16(NTS_KE_NEXT_PROTOCOL_NTPV4);
        r = ntske_append_record(packet, NTS_KE_RECORD_NEXT_PROTOCOL, &d, sizeof(uint16_t), true);
        if (r < 0)
                return r;

        d = htobe16(AEAD_AES_SIV_CMAC_256);
        r = ntske_append_record(packet, NTS_KE_RECORD_AEAD_ALGORITHM, &d, sizeof(uint16_t), true);
        if (r < 0)
                return r;

        r = ntske_append_record(packet, NTS_KE_RECORD_END_OF_MESSAGE, NULL, 0, true);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(packet);
        return 0;
}
