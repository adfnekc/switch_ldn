/*
 * The advertised SHA-256 must cover the advertise data.
 *
 * ldn_build_advertisement_action_frame() assembles session_info + version +
 * encryption type + data length + nonce + SHA-256 + advertise data, then
 * AES-CTR-encrypts everything from 0x28 on. A console that accepts the frame
 * decrypts it, zeroes the hash field and re-hashes the whole payload to check
 * it - so if the hash was computed while 0x48.. was still zero the frame fails
 * that check, which shows up as a room that is visible but impossible to join.
 *
 * That is exactly the bug this test was written for: the SHA-256 ran before the
 * advertise data was copied in.
 */
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "ldn.h"

static int fail;

static void expect(const char *what, int ok)
{
    printf("  %-52s %s\n", what, ok ? "ok" : "FAILED");
    if (!ok) {
        fail = 1;
    }
}

int main(void)
{
    ProdKeys keys;
    if (prodkeys_load(&keys, "tests/interop/prod.keys") != 0) {
        fprintf(stderr, "cannot load tests/interop/prod.keys\n");
        return 1;
    }

    LdnSessionInfo si;
    memset(&si, 0, sizeof(si));
    si.local_communication_id = 0x01006F8002320000ull;
    memcpy(si.ssid, "0123456789ABCDEF", 16);

    LdnAdvertiseData adv;
    memset(&adv, 0, sizeof(adv));
    /* Something non-trivial so a zeroed tail would actually change the hash. */
    snprintf(adv.nodes[0].username, sizeof(adv.nodes[0].username), "%s", "Tester");
    adv.node_count = 1;

    uint8_t nonce[4] = {0x79, 0x0A, 0x70, 0x16};
    uint8_t frame[4096];
    int n = ldn_build_advertisement_action_frame(
        frame, sizeof(frame), (const uint8_t *)"\x02\x4A\x57\x53\x53\x4B", &si, &adv,
        &keys, 1, nonce, NULL);
    expect("advertisement builds", n > 0);

    const uint8_t *payload = frame + IEEE80211_HDRLEN + LDN_ACTION_BODY_PREFIX_SIZE;
    size_t payload_len = (size_t)n - IEEE80211_HDRLEN - LDN_ACTION_BODY_PREFIX_SIZE;
    expect("payload is the full 0x548",
           payload_len == LDN_ADVERTISEMENT_PAYLOAD_SIZE);

    /* the advertise data we asked for really is on the wire at 0x48 */
    expect("advertise data present at 0x48",
           memcmp(payload + 0x48, adv.nodes[0].username, 6) != 0 || adv.node_count == 0);

    /* now do what a console does: derive the key, decrypt, re-hash. */
    uint8_t siraw[32];
    ldn_session_info_encode(&si, siraw);
    uint8_t key[16];
    expect("advertise key derives", ldn_adv_key(&keys, siraw, key) == 0);

    uint8_t counter[16];
    memcpy(counter, payload + 0x24, 4);
    memset(counter + 4, 0, 12);

    uint8_t plain[LDN_ADVERTISEMENT_PAYLOAD_SIZE - 0x28];
    aes128_ctr_xor(key, counter, payload + 0x28, plain, sizeof(plain));

    /* the hash the advertisement carries */
    uint8_t carried[32];
    memcpy(carried, plain, 32);

    /* re-hash the whole payload with the hash field zeroed */
    uint8_t full[LDN_ADVERTISEMENT_PAYLOAD_SIZE];
    memcpy(full, payload, 0x28);
    memcpy(full + 0x28, plain, sizeof(plain));
    memset(full + 0x28, 0, 32);

    uint8_t digest[32];
    SHA256(full, sizeof(full), digest);
    expect("re-hashed payload matches the advertised SHA-256",
           memcmp(digest, carried, 32) == 0);

    /* and prove the advertise data actually influenced it */
    uint8_t without_data[LDN_ADVERTISEMENT_PAYLOAD_SIZE];
    memcpy(without_data, full, sizeof(full));
    memset(without_data + 0x48, 0, LDN_ADVERTISEMENT_PAYLOAD_SIZE - 0x48);
    uint8_t digest2[32];
    SHA256(without_data, sizeof(without_data), digest2);
    expect("zeroing the advertise data would change the hash",
           memcmp(digest, digest2, 32) != 0);

    printf("\n%s\n", fail ? "FAILED" : "all advertisement hash tests passed");
    return fail;
}
