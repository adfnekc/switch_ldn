#include "ldn.h"

#include <openssl/sha.h>

#include "common.h"

/* ------------------------------------------------------------------ */
/* Session info                                                       */
/* ------------------------------------------------------------------ */

int ldn_session_info_encode(const LdnSessionInfo *info, uint8_t out[32])
{
    memset(out, 0, 32);
    wr_be64(out, info->local_communication_id);
    wr_be16(out + 0x0A, info->game_mode);
    memcpy(out + 0x10, info->ssid, 16);
    return 0;
}

int ldn_session_info_decode(const uint8_t raw[32], LdnSessionInfo *info)
{
    memset(info, 0, sizeof(*info));
    info->local_communication_id = rd_be64(raw);
    info->game_mode = rd_be16(raw + 0x0A);
    memcpy(info->ssid, raw + 0x10, 16);
    return 0;
}

size_t ldn_participant_offset(int index)
{
    return LDN_ADV_DATA_OFF_PARTICIPANTS + (size_t)index * LDN_PARTICIPANT_SIZE;
}

/* ------------------------------------------------------------------ */
/* Advertisement data serialisation                                   */
/* ------------------------------------------------------------------ */

static size_t adv_data_serialize(const LdnAdvertiseData *ad, uint8_t out[LDN_ADV_DATA_SIZE_MAX])
{
    memset(out, 0, LDN_ADV_DATA_SIZE_MAX);

    memcpy(out + 0x00, ad->server_random, 16);
    wr_be16(out + 0x10, ad->security_level);
    out[0x12] = ad->station_accept_policy;
    out[0x13] = 0;
    wr_be16(out + 0x14, ldn_encode_channel(ad->band, ad->channel));
    out[0x16] = ad->node_count_max;
    out[0x17] = ad->node_count;

    for (int i = 0; i < LDN_NODE_MAX; i++) {
        size_t off = ldn_participant_offset(i);
        const LdnParticipant *n = &ad->nodes[i];
        wr_be32(out + off + 0x00, n->ipv4);
        memcpy(out + off + 0x04, n->mac, 6);
        out[off + 0x0A] = n->is_connected ? 1 : 0;
        out[off + 0x0B] = n->platform;
        memcpy(out + off + 0x0C, n->username, 32);
        wr_be16(out + off + 0x2C, n->app_communication_version);
    }

    /* 0x1D8 padding, 0x1DA app data size */
    wr_be16(out + 0x1DA, ad->app_data_size);
    if (ad->app_data_size) {
        size_t n = ad->app_data_size > LDN_APP_DATA_SIZE ? LDN_APP_DATA_SIZE
                                                         : ad->app_data_size;
        memcpy(out + 0x1DC, ad->app_data, n);
    }
    /* 0x35C padding stays zero */
    memcpy(out + 0x4F8, ad->auth_token, 8);

    return LDN_ADV_DATA_SIZE_MAX;
}

/* ------------------------------------------------------------------ */
/* AES-CTR counter block expansion                                    */
/* ------------------------------------------------------------------ */
/*
 * RESOLVED. The wiki documents a 4-byte "nonce for the AES algorithm" at
 * advertisement payload offset 0x24 but never says how it expands into
 * AES-CTR's 16-byte counter block.
 *
 * The reference is kinnay/LDN, which hosts LDN networks and therefore must
 * decrypt advertisements correctly:
 *
 *     AES.new(key, AES.MODE_CTR, nonce=self.nonce)
 *
 * PyCryptodome builds the counter block as the nonce prefix followed by a
 * zero-initialised big-endian counter, i.e. `nonce || 0^12`. The increment
 * spans the whole 128-bit block, which is identical to incrementing only the
 * low 12 bytes for any realistic payload (it would take 2^96 blocks to differ).
 *
 * Verified byte-for-byte against PyCryptodome; tests/ctr_vectors.h locks it in.
 */
static void ldn_ctr_counter_block(const uint8_t nonce[4], uint8_t counter[16])
{
    memcpy(counter, nonce, 4);
    memset(counter + 4, 0, 12);
}

/* ------------------------------------------------------------------ */
/* Build an advertisement frame                                       */
/* ------------------------------------------------------------------ */

int ldn_build_advertisement_action_frame(uint8_t *out, size_t out_len,
                                         const uint8_t mac[6],
                                         const LdnSessionInfo *session_info,
                                         const LdnAdvertiseData *adv_data,
                                         const ProdKeys *prodkeys,
                                         uint8_t security_level,
                                         uint8_t nonce_in[4],
                                         uint8_t *adv_key_out)
{
    size_t need = IEEE80211_HDRLEN + LDN_ACTION_BODY_PREFIX_SIZE + LDN_ADVERTISEMENT_PAYLOAD_SIZE;
    if (out_len < need) {
        return -1;
    }

    uint8_t session_info_raw[32];
    ldn_session_info_encode(session_info, session_info_raw);

    /* Derive the advertisement key: needs session_info only. */
    uint8_t adv_key[16];
    if (ldn_adv_key(prodkeys, session_info_raw, adv_key) != 0) {
        return -1;
    }
    if (adv_key_out) {
        memcpy(adv_key_out, adv_key, 16);
    }

    uint8_t adv_data_raw[LDN_ADV_DATA_SIZE_MAX];
    size_t adv_data_len = adv_data_serialize(adv_data, adv_data_raw);

    /* Assemble the plaintext payload header (everything up to 0x28). */
    uint8_t payload[LDN_ADVERTISEMENT_PAYLOAD_SIZE];
    memset(payload, 0, sizeof(payload));
    memcpy(payload, session_info_raw, 32);
    payload[0x20] = LDN_VERSION_3;
    payload[0x21] = LDN_ENC_TYPE_AES_CTR;
    wr_be16(payload + 0x22, (uint16_t)adv_data_len);
    memcpy(payload + 0x24, nonce_in, 4);

    /*
     * The advertise data has to be in place BEFORE hashing. It used to be
     * copied in after the SHA-256, so the hash covered a payload whose
     * 0x48..0x548 was still zero - a console that verifies it rejects the
     * frame, which makes the network visible but impossible to join.
     */
    memcpy(payload + 0x48, adv_data_raw, adv_data_len);

    /* hash over the whole payload with the hash field zeroed */
    uint8_t digest[32];
    SHA256(payload, sizeof(payload), digest);
    memcpy(payload + 0x28, digest, 32);

    /* AES-CTR over hash||data: 0x28 .. 0x548 (the whole rest of the payload) */
    uint8_t counter[16];
    ldn_ctr_counter_block(payload + 0x24, counter);
    size_t ct_len = LDN_ADVERTISEMENT_PAYLOAD_SIZE - 0x28;
    aes128_ctr_xor(adv_key, counter, payload + 0x28, payload + 0x28, ct_len);

    /* --- 802.11 header -------------------------------------------------- */
    memset(out, 0, IEEE80211_HDRLEN);
    /*
     * 802.11 header fields are LITTLE-endian. Writing the frame control with
     * wr_be16 produced 00 d0 instead of d0 00, so the kernel read the frame as
     * type/subtype 0xd000 and rejected the whole thing with -EINVAL. Everything
     * on our side agreed with itself, because the receive path used the same
     * byte order, which is why only real hardware could show it.
     */
    wr_le16(out + 0, 0x00D0); /* management, action */
    wr_le16(out + 2, 0x0000); /* duration */
    memset(out + 4, 0xFF, 6); /* addr1 = broadcast */
    memcpy(out + 10, mac, 6); /* addr2 = BSSID (us) */
    memcpy(out + 16, mac, 6); /* addr3 */
    /* seq left 0; the kernel/driver fills it for injected frames */

    uint8_t *body = out + IEEE80211_HDRLEN;
    body[0] = LDN_CATEGORY_VENDOR_SPECIFIC;
    body[1] = LDN_OUI_0;
    body[2] = LDN_OUI_1;
    body[3] = LDN_OUI_2;
    body[4] = LDN_PROTOCOL_ID;
    body[5] = 0;
    wr_be16(body + 6, LDN_PACKET_ADVERTISEMENT);
    wr_be16(body + 8, 0);
    wr_be16(body + 10, 0);

    memcpy(body + 12, payload, sizeof(payload));

    return (int)need;
}

/* ------------------------------------------------------------------ */
/* Parse an advertisement (diagnostics / future guest mode)           */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Authentication / disconnect control frames (ethertype 0x88B7)       */
/* ------------------------------------------------------------------ */

static void build_88b7_header(uint8_t *body, uint16_t packet_type)
{
    body[0] = LDN_OUI_0;
    body[1] = LDN_OUI_1;
    body[2] = LDN_OUI_2;
    wr_be16(body + 3, packet_type);
    body[5] = 0;
}

/*
 * Authentication frame layout, cross-checked against kinnay/LDN's
 * AuthenticationFrame.encode() (offsets are relative to the 0x88B7 body):
 *
 *   0x00  u24  OUI 00:22:AA
 *   0x03  u16  258
 *   0x05  u8   padding
 *   0x06  u8   version
 *   0x07  u8   payload size, low byte
 *   0x08  u8   status code
 *   0x09  u8   is_response
 *   0x0A  u8   payload size, high byte
 *   0x0B  u8   format: 0 = plain, 1 = AES-GCM
 *   0x0C  u16  padding
 *   0x0E  32   network id, LITTLE-endian
 *   0x2E  16   server random
 *   0x3E  16   client random
 *   0x4E  ...  payload
 *
 * The wiki calls 0x0C "padding (always 0)"; kinnay writes the format byte at
 * 0x0B. Because plaintext is format 0, the two descriptions agree on the wire.
 *
 * NOT ENCRYPTED, and deliberately so. kinnay only encrypts authentication
 * frames for its internal "protocol 3" cipher suite, which pairs with AES-GCM
 * advertisements; the AES-CTR path (what a real console on LDN version 2 or 3
 * expects) sends them in the clear. An earlier revision applied AES-CTR with
 * an all-zero counter block whenever a data key was supplied, which produces
 * garbage - the caller passing NULL was the only thing keeping it working.
 */
int ldn_build_auth_frame(uint8_t *out, size_t out_len, const uint8_t mac[6],
                         const uint8_t bssid[6], const LdnAuthData *auth,
                         size_t *payload_len)
{
    /*
     * A response is 0x4E + 0x84 bytes; the caller only has to supply that.
     * Zero-filling it means platform + 0x83 zero bytes come out for free.
     */
    size_t need = IEEE80211_HDRLEN + LDN_AUTH_HEADER_SIZE + LDN_AUTH_RESPONSE_PAYLOAD;
    if (out_len < need) {
        return -1;
    }

    memset(out, 0, need);

    wr_le16(out + 0, 0x0008); /* data frame, QoS-less (802.11 is little-endian) */
    wr_le16(out + 2, 0);
    memcpy(out + 4, bssid, 6);   /* addr1 = BSSID */
    memcpy(out + 10, mac, 6);    /* addr2 = source */
    memcpy(out + 16, bssid, 6);  /* addr3 */
    wr_le16(out + 22, 0);        /* seq, little-endian */

    uint8_t *body = out + IEEE80211_HDRLEN;
    build_88b7_header(body, LDN_PACKET_AUTHENTICATION);

    uint8_t *p = body + 6;
    p[0] = LDN_VERSION_3;
    p[1] = (uint8_t)(auth->payload_size & 0xFF);
    p[2] = auth->status_code;
    p[3] = auth->is_response;
    p[4] = (uint8_t)((auth->payload_size >> 8) & 0xFF);
    p[5] = 0;   /* format: plaintext */
    p[6] = 0;   /* padding */
    p[7] = 0;

    /*
     * The network id is little-endian, and the session info we were given is
     * in big-endian (title id first). Byte-swap it, otherwise a console reads
     * the wrong title id and refuses the join.
     */
    for (int i = 0; i < 32; i++) {
        p[8 + i] = auth->session_info[32 - 1 - i];
    }
    memcpy(p + 0x28, auth->server_random, 16);
    memcpy(p + 0x38, auth->client_random, 16);

    if (auth->is_response) {
        /* platform + 0x83 zero bytes; the buffer is already zeroed. */
        p[0x48] = auth->platform;
    } else {
        if (auth->payload_size != LDN_AUTH_REQUEST_PAYLOAD) {
            LOG_W("ldn: request payload size is %u, expected %u",
                  auth->payload_size, LDN_AUTH_REQUEST_PAYLOAD);
        }
        memcpy(p + 0x48, auth->username, 32);
        wr_be16(p + 0x48 + 0x20, auth->app_communication_version);
        p[0x48 + 0x22] = auth->platform;
    }

    if (payload_len) {
        *payload_len = auth->payload_size;
    }
    return (int)need;
}

int ldn_parse_auth_frame(const uint8_t *frame, size_t frame_len, LdnAuthData *auth)
{
    size_t min = IEEE80211_HDRLEN + 6 + 0x48;
    if (frame_len < min) {
        return -1;
    }
    if (rd_be16(frame + IEEE80211_HDRLEN + 3) != LDN_PACKET_AUTHENTICATION) {
        return -1;
    }

    memset(auth, 0, sizeof(*auth));

    /*
     * Big enough for a version-3 request (0x4E + 0x364). The old 0x100 buffer
     * truncated it, which quietly discarded the challenge - harmless only
     * because we ignore it, and fatal if anything ever needs to read it.
     */
    uint8_t buf[LDN_AUTH_HEADER_SIZE + LDN_AUTH_REQUEST_PAYLOAD];
    size_t n = frame_len - IEEE80211_HDRLEN - 6;
    if (n > sizeof(buf)) {
        n = sizeof(buf);
    }
    memcpy(buf, frame + IEEE80211_HDRLEN + 6, n);


    auth->payload_size = (uint32_t)buf[1] | ((uint32_t)buf[4] << 8);
    auth->status_code = buf[2];
    auth->is_response = buf[3];
    memcpy(auth->session_info, buf + 8, 32);
    memcpy(auth->server_random, buf + 0x28, 16);
    memcpy(auth->client_random, buf + 0x38, 16);

    if (n > 0x48) {
        if (auth->is_response) {
            auth->platform = buf[0x48];
            auth->has_challenge = n > 0x48 + 0x84;
            if (auth->has_challenge) {
                auth->challenge_ok = buf[0x48 + 0x84];
            }
        } else {
            memcpy(auth->username, buf + 0x48, 32);
            auth->username[31] = '\0';
            if (n > 0x48 + 0x22) {
                auth->app_communication_version = rd_be16(buf + 0x48 + 0x20);
                auth->platform = buf[0x48 + 0x22];
            }
        }
    }

    auth->version = buf[0];
    LOG_D("auth frame: version=%u status=%u %s payload=%u username='%s'",
          auth->version, auth->status_code, auth->is_response ? "response" : "request",
          auth->payload_size, auth->username);
    return 0;
}
