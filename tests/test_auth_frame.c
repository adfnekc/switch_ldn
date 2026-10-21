/*
 * Authentication frame layout, pinned against kinnay/LDN's
 * AuthenticationFrame.encode().
 *
 * kinnay is the reference for the two things the wiki gets wrong or omits:
 *   - offset 0x0B is a *format* byte (0 = plain, 1 = AES-GCM), not padding;
 *     plaintext is 0, so the two readings agree on the wire;
 *   - the network id at 0x0E is little-endian, and a big-endian copy makes a
 *     console read the wrong title id and refuse the join.
 */
#include <assert.h>
#include <string.h>

#include "common.h"
#include "ldn.h"

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    const uint8_t mac[6] = {0x02, 0x4A, 0x57, 0x53, 0x44, 0x01};

    LdnSessionInfo session;
    memset(&session, 0, sizeof(session));
    session.local_communication_id = 0x01001B300B9BE000ull;
    session.game_mode = 7;

    uint8_t session_be[32];
    ldn_session_info_encode(&session, session_be);

    LdnAuthData auth;
    memset(&auth, 0, sizeof(auth));
    auth.version = LDN_VERSION_3;
    auth.is_response = 1;
    auth.status_code = 0;
    auth.payload_size = LDN_AUTH_RESPONSE_PAYLOAD;
    auth.platform = LDN_PLATFORM_SWITCH;
    memcpy(auth.session_info, session_be, 32);
    auth.server_random[0] = 0xAA;
    auth.client_random[0] = 0xBB;

    uint8_t out[LDN_AUTH_HEADER_SIZE + LDN_AUTH_RESPONSE_PAYLOAD + 64];
    size_t payload_len = 0;
    int n = ldn_build_auth_frame(out, sizeof(out), mac, mac, &auth, &payload_len);
    if (n < 0) {
        printf("build failed\n");
        return 1;
    }

    /*
     * --- 802.11 frame control is LITTLE-endian ---
     *
     * It is written with wr_le16(out + 0, 0x0008), so byte 0 is 0x08. Writing
     * it big-endian put 00 08 on the wire, which the kernel reads as
     * type/subtype 0x0800 - not a management frame - and rejects with -EINVAL.
     * Nothing on our own side noticed, because the receive path used the same
     * wrong byte order; only a real NIC found it. Pin the two bytes so it
     * cannot come back.
     */
    assert(out[0] == 0x08 && out[1] == 0x00);

    const uint8_t *body = out + IEEE80211_HDRLEN;

    /* --- body prefix: OUI, packet type 258, pad --- */
    assert(body[0] == LDN_OUI_0 && body[1] == LDN_OUI_1 && body[2] == LDN_OUI_2);
    assert(rd_be16(body + 3) == LDN_PACKET_AUTHENTICATION);
    assert(body[5] == 0);

    /* --- auth header starts at body+6 --- */
    const uint8_t *p = body + 6;
    assert(p[0] == LDN_VERSION_3);
    assert(p[1] == (LDN_AUTH_RESPONSE_PAYLOAD & 0xFF));
    assert(p[2] == 0);                       /* status: success */
    assert(p[3] == 1);                       /* is_response */
    assert(p[4] == 0);                       /* size high byte */
    assert(p[5] == 0);                        /* format: plaintext */
    assert(p[6] == 0 && p[7] == 0);          /* padding */

    /* --- network id at 0x0E is the session info byte-reversed --- */
    int reversals = 0;
    for (int i = 0; i < 32; i++) {
        if (p[8 + i] == session_be[31 - i]) {
            reversals++;
        }
    }
    assert(reversals == 32);
    /*
     * session_be holds the title id big-endian in bytes 0-7; after reversal it
     * occupies p[32..39], so a little-endian u64 read recovers it.
     */
    assert(rd_le64(p + 32) == 0x01001B300B9BE000ull);

    assert(p[0x28] == 0xAA); /* server random */
    assert(p[0x38] == 0xBB); /* client random */

    /* --- payload: platform then 0x83 zero bytes --- */
    assert(p[LDN_AUTH_HEADER_SIZE - 6] == LDN_PLATFORM_SWITCH);
    for (int i = 1; i < LDN_AUTH_RESPONSE_PAYLOAD; i++) {
        assert(p[LDN_AUTH_HEADER_SIZE - 6 + i] == 0);
    }

    assert((size_t)n == IEEE80211_HDRLEN + LDN_AUTH_HEADER_SIZE +
                           LDN_AUTH_RESPONSE_PAYLOAD);
    assert(payload_len == LDN_AUTH_RESPONSE_PAYLOAD);

    /* --- round trip through the parser --- */
    LdnAuthData back;
    if (ldn_parse_auth_frame(out, (size_t)n, &back) != 0) {
        printf("parse failed\n");
        return 1;
    }
    assert(back.is_response == 1);
    assert(back.status_code == 0);
    assert(back.payload_size == LDN_AUTH_RESPONSE_PAYLOAD);
    assert(back.version == LDN_VERSION_3);
    assert(back.server_random[0] == 0xAA);
    assert(back.client_random[0] == 0xBB);
    assert(back.platform == LDN_PLATFORM_SWITCH);

    /* --- a version-3 request must not truncate --- */
    uint8_t req[LDN_AUTH_HEADER_SIZE + LDN_AUTH_REQUEST_PAYLOAD];
    LdnAuthData rq;
    memset(&rq, 0, sizeof(rq));
    rq.version = LDN_VERSION_3;
    rq.payload_size = LDN_AUTH_REQUEST_PAYLOAD;
    snprintf(rq.username, sizeof(rq.username), "Player1");
    rq.app_communication_version = 0x1234;
    rq.platform = LDN_PLATFORM_SWITCH;
    int rn = ldn_build_auth_frame(req, sizeof(req), mac, mac, &rq, &payload_len);
    if (rn < 0) {
        printf("request build failed\n");
        return 1;
    }
    /* the parser must not reject it for not fitting its buffer */
    LdnAuthData rback;
    assert(ldn_parse_auth_frame(req, (size_t)rn, &rback) == 0);
    assert(rback.payload_size == LDN_AUTH_REQUEST_PAYLOAD);
    assert(!strcmp(rback.username, "Player1"));
    assert(rback.app_communication_version == 0x1234);

    printf("authentication frame layout matches kinnay/LDN\n");
    return 0;
}
