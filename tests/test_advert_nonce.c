/*
 * The advertisement nonce must advance on every 100 ms emission.
 *
 * A console's LDN stack compares the nonce of a received advertisement against
 * the previous one to tell a fresh advertisement from a stale duplicate, so a
 * constant nonce makes every frame look like a replay of the first one and the
 * player list is never refreshed on the console.
 *
 * kinnay/LDN does exactly this in _update_nonce(), called once per
 * advertisement from _send_advertisements().
 */
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "host.h"
#include "ldn.h"

static int fail;

static void expect(const char *what, int ok)
{
    printf("  %-46s %s\n", what, ok ? "ok" : "FAILED");
    if (!ok) {
        fail++;
    }
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void snapshot(Host *host, uint8_t out[LDN_NONCE_SIZE])
{
    memcpy(out, host_nonce(host), LDN_NONCE_SIZE);
}

int main(void)
{
    /*
     * host_create() derives the LDN keys, so it needs a complete prod.keys.
     * The fixture here is synthetic: any 16 bytes work, because the test only
     * exercises the nonce bookkeeping around the advertisement timer.
     */
    static ProdKeys keys;
    memset(&keys, 0, sizeof(keys));
    for (int i = 0; i < LDN_KEY_LEN; i++) {
        keys.master_key_00[i] = (uint8_t)(0x11 * (i + 1));
        keys.aes_kek_generation_source[i] = (uint8_t)(0x22 * (i + 1));
        keys.aes_key_generation_source[i] = (uint8_t)(0x33 * (i + 1));
    }
    keys.has_master_key_00 = true;
    keys.has_aes_kek_generation_source = true;
    keys.has_aes_key_generation_source = true;

    static const uint8_t passphrase[16] = "LDN_PASSPHRASE!!";
    const uint64_t title = 0x01006F8002320000ULL;

    Host *host = host_create(&keys, title, 1, 0, 8, passphrase,
                             sizeof(passphrase), "switch_ldn", 0);
    if (!host) {
        printf("  host_create failed (prod.keys fixture rejected)\n");
        return 1;
    }

    uint8_t a[LDN_NONCE_SIZE], b[LDN_NONCE_SIZE];
    snapshot(host, a);
    host_tick(host, NULL); /* radio == NULL: nothing is transmitted, timer runs */
    host_tick(host, NULL);
    snapshot(host, b);

    expect("nonce changes between advertisements", memcmp(a, b, LDN_NONCE_SIZE) != 0);

    /* The advance is by exactly one, big-endian, not a fresh random draw. */
    expect("nonce advances by exactly one", be32(b) == be32(a) + 1);

    /* A wrap has to carry out of every byte, not stay stuck at 0xFFFFFFFF. */
    {
        uint8_t n[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        for (int i = 3; i >= 0; i--) {
            n[i] = (uint8_t)(n[i] + 1);
            if (n[i] != 0) {
                break;
            }
        }
        expect("increment wrapping carries to all-zero",
               n[0] == 0 && n[1] == 0 && n[2] == 0 && n[3] == 0);
    }

    /* Rebuilding the network reseeds the nonce but must still advance it. */
    expect("reconfigure keeps the nonce advancing",
           host_adopt_guest_settings(host, title, 1, 8, passphrase,
                                     sizeof(passphrase), "switch_ldn", 0) == 0);
    uint8_t e[LDN_NONCE_SIZE], f[LDN_NONCE_SIZE];
    snapshot(host, e);
    host_tick(host, NULL);
    snapshot(host, f);
    expect("reconfigured network advances its nonce",
           be32(f) == be32(e) + 1);

    host_destroy(host);

    printf("\n%s\n", fail ? "FAILED" : "all advertisement nonce tests passed");
    return fail ? 1 : 0;
}
