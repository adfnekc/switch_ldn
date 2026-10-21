#include "crypto.h"

#include <ctype.h>
#include "common.h"

#include <errno.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

/* ------------------------------------------------------------------ */
/* prod.keys                                                          */
/* ------------------------------------------------------------------ */

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t n = strlen(hex);
    if (n != out_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi, lo;
        char c = (char)tolower((unsigned char)hex[i * 2]);
        char d = (char)tolower((unsigned char)hex[i * 2 + 1]);
        if (c >= '0' && c <= '9') {
            hi = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            hi = c - 'a' + 10;
        } else {
            return -1;
        }
        if (d >= '0' && d <= '9') {
            lo = d - '0';
        } else if (d >= 'a' && d <= 'f') {
            lo = d - 'a' + 10;
        } else {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Returns 1 if the entry was consumed, 0 if it is not one we need, -1 on error. */
static int parse_key_line(ProdKeys *keys, const char *name, const char *value)
{
    uint8_t *dst = NULL;
    bool *flag = NULL;

    if (!strcmp(name, "master_key_00")) {
        dst = keys->master_key_00;
        flag = &keys->has_master_key_00;
    } else if (!strcmp(name, "aes_kek_generation_source")) {
        dst = keys->aes_kek_generation_source;
        flag = &keys->has_aes_kek_generation_source;
    } else if (!strcmp(name, "aes_key_generation_source")) {
        dst = keys->aes_key_generation_source;
        flag = &keys->has_aes_key_generation_source;
    }

    if (!dst) {
        return 0; /* not a key we care about */
    }
    if (hex_to_bytes(value, dst, LDN_KEY_LEN) != 0) {
        LOG_W("prod.keys: bad hex value for %s", name);
        return -1;
    }
    *flag = true;
    return 1;
}

int prodkeys_load(ProdKeys *keys, const char *path)
{
    memset(keys, 0, sizeof(*keys));
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_E("cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    char line[512];
    int lineno = 0, loaded = 0;
    /* A master key from another key generation: present, but not the one the
     * LDN derivation uses. Worth naming separately - see the error below. */
    bool saw_other_generation = false;
    while (fgets(line, sizeof(line), f)) {
        lineno++;

        char *hash = strchr(line, '#');
        if (hash) {
            *hash = '\0';
        }

        char *eq = strchr(line, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';

        /* trim */
        char *name = line;
        while (*name && isspace((unsigned char)*name)) name++;
        char *ne = name + strlen(name);
        while (ne > name && isspace((unsigned char)ne[-1])) *--ne = '\0';

        char *value = eq + 1;
        while (*value && isspace((unsigned char)*value)) value++;
        size_t vlen = strlen(value);
        while (vlen && isspace((unsigned char)value[vlen - 1])) value[--vlen] = '\0';

        if (strncmp(name, "master_key_", 11) == 0 && strcmp(name, "master_key_00") != 0) {
            saw_other_generation = true;
        }
        if (parse_key_line(keys, name, value) < 0) {
            LOG_W("prod.keys:%d: ignoring malformed entry '%s'", lineno, name);
        }
    }
    fclose(f);

    if (!prodkeys_ready(keys)) {
        LOG_E("%s is missing required keys (need master_key_00, "
              "aes_kek_generation_source, aes_key_generation_source)", path);
        if (saw_other_generation && !keys->has_master_key_00) {
            /*
             * A file with master_key_01..0N but no master_key_00 fails here, and
             * "missing keys" is a confusing thing to be told when the file
             * visibly has master keys in it. Either the file was taken from a
             * console on another key generation, or it was trimmed; in both
             * cases the fix is a prod.keys that has master_key_00, not a
             * different aes_*_generation_source.
             */
            LOG_E("%s has a master key from another key generation, but local "
                  "wireless derives its advertisement key from master_key_00; "
                  "use a prod.keys that contains master_key_00", path);
        }
        return -1;
    }

    (void)loaded;
    LOG_I("loaded LDN key material from %s", path);
    return 0;
}

bool prodkeys_ready(const ProdKeys *keys)
{
    return keys->has_master_key_00 && keys->has_aes_kek_generation_source &&
           keys->has_aes_key_generation_source;
}

int prodkeys_derive_key(const ProdKeys *keys, const uint8_t input_key[16],
                        uint8_t out[16])
{
    if (!prodkeys_ready(keys)) {
        LOG_E("prod.keys incomplete; cannot derive LDN keys");
        return -1;
    }

    /* step 1 */
    uint8_t kek_gen_src[16];
    aes128_ecb_decrypt(keys->master_key_00, keys->aes_kek_generation_source,
                       kek_gen_src);

    /* step 2 */
    uint8_t unwrapped[16];
    aes128_ecb_decrypt(kek_gen_src, input_key, unwrapped);

    /* step 3 */
    aes128_ecb_decrypt(unwrapped, keys->aes_key_generation_source, out);
    return 0;
}

int ldn_final_key(const uint8_t key[16], const void *buffer, size_t len,
                  uint8_t out[16])
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)buffer, len, digest);
    aes128_ecb_decrypt(key, digest, out);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Well-known LDN input keys (NintendoClients/wiki/LDN-Protocol)       */
/* ------------------------------------------------------------------ */

static const uint8_t ADV_INPUT_KEY[16] = {
    0x19, 0x18, 0x84, 0x74, 0x3e, 0x24, 0xc7, 0x7d,
    0x87, 0xc6, 0x9e, 0x42, 0x07, 0xd0, 0xc4, 0x38,
};

static const uint8_t DATA_INPUT_KEY[16] = {
    0xf1, 0xe7, 0x01, 0x84, 0x19, 0xa8, 0x4f, 0x71,
    0x1d, 0xa7, 0x14, 0xc2, 0xcf, 0x91, 0x9c, 0x9c,
};

/* HMAC-SHA256 key used by the LDN v3+ authentication challenge. */
static const uint8_t CHALLENGE_HMAC_KEY[32] = {
    0xf8, 0x4b, 0x48, 0x7f, 0xb3, 0x72, 0x51, 0xc2,
    0x63, 0xbf, 0x11, 0x60, 0x90, 0x36, 0x58, 0x92,
    0x66, 0xaf, 0x70, 0xca, 0x79, 0xb4, 0x4c, 0x93,
    0xc7, 0x37, 0x0c, 0x57, 0x69, 0xc0, 0xf6, 0x02,
};

int ldn_adv_key(const ProdKeys *keys, const uint8_t session_info[32], uint8_t out[16])
{
    uint8_t derived[16];
    if (prodkeys_derive_key(keys, ADV_INPUT_KEY, derived) != 0) {
        return -1;
    }
    return ldn_final_key(derived, session_info, 32, out);
}

int ldn_data_key(const ProdKeys *keys, const uint8_t *server_random,
                 const uint8_t *passphrase, size_t passphrase_len, uint8_t out[16])
{
    uint8_t derived[16];
    if (prodkeys_derive_key(keys, DATA_INPUT_KEY, derived) != 0) {
        return -1;
    }
    uint8_t buffer[16 + 64];
    if (passphrase_len > 64) {
        return -1;
    }
    memcpy(buffer, server_random, 16);
    memcpy(buffer + 16, passphrase, passphrase_len);
    return ldn_final_key(derived, buffer, 16 + passphrase_len, out);
}

void ldn_challenge_hmac_sha256(const void *data, size_t len, uint8_t out[32])
{
    unsigned int outlen = 0;
    HMAC(EVP_sha256(), CHALLENGE_HMAC_KEY, sizeof(CHALLENGE_HMAC_KEY),
         (const unsigned char *)data, len, out, &outlen);
}

/* ------------------------------------------------------------------ */
/* AES primitives                                                     */
/* ------------------------------------------------------------------ */

void aes128_ecb_decrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    AES_KEY k;
    AES_set_decrypt_key(key, 128, &k);
    AES_decrypt(in, out, &k);
}

void aes128_ctr_xor(const uint8_t key[16], const uint8_t counter_block[16],
                    const uint8_t *in, uint8_t *out, size_t len)
{
    AES_KEY k;
    AES_set_encrypt_key(key, 128, &k);

    uint8_t counter[16];
    memcpy(counter, counter_block, 16);

    uint8_t stream[16];
    size_t off = 0;
    while (off < len) {
        AES_encrypt(counter, stream, &k);

        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; i++) {
            out[off + i] = in[off + i] ^ stream[i];
        }
        off += n;

        for (int i = 15; i >= 0; i--) {
            if (++counter[i]) {
                break;
            }
        }
    }
}
