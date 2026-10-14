#ifndef SWITCH_LDN_CRYPTO_H
#define SWITCH_LDN_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * prod.keys handling + Nintendo "key source" unwrapping.
 *
 * Everything here mirrors the derivation documented in
 * NintendoClients/wiki "LDN-Protocol" -> "Encryption Keys":
 *
 *   1. aes_kek_generation_source  decrypted with master_key_00
 *   2. input_key                  decrypted with the result of (1)
 *   3. aes_key_generation_source  decrypted with the result of (2)
 *   4. SHA256(input_buffer)[:16]  decrypted with the result of (3)
 *
 * prod.keys ships the already-unwrapped master keys, so we only need plain
 * AES-128 ECB decryption; no keyblob handling is required.
 */

#define LDN_KEY_LEN 16
#define LDN_ADV_HASH_LEN 32

typedef struct {
    uint8_t master_key_00[LDN_KEY_LEN];
    uint8_t aes_kek_generation_source[LDN_KEY_LEN];
    uint8_t aes_key_generation_source[LDN_KEY_LEN];

    bool has_master_key_00;
    bool has_aes_kek_generation_source;
    bool has_aes_key_generation_source;
} ProdKeys;

/* Parse a prod.keys file (ignores content keys and irrelevant entries). */
int prodkeys_load(ProdKeys *keys, const char *path);

bool prodkeys_ready(const ProdKeys *keys);

/*
 * Perform steps 1-3 of the derivation for `input_key`.
 * Returns 0 on success, -1 if prod.keys is missing required entries.
 */
int prodkeys_derive_key(const ProdKeys *keys, const uint8_t input_key[16],
                        uint8_t out[16]);

/* Step 4: decrypt SHA256(buffer)[:16] with `key`. */
int ldn_final_key(const uint8_t key[16], const void *buffer, size_t len,
                  uint8_t out[16]);

/*
 * Advertisement frame key (LDN-Protocol "Encryption Keys"):
 *   input_key  = 191884743e24c77d87c69e4207d0c438
 *   input_buf  = session_info (32 bytes)
 */
int ldn_adv_key(const ProdKeys *keys, const uint8_t session_info[32],
                uint8_t out[16]);

/*
 * Data frame key:
 *   input_key  = f1e7018419a84f711da714c2cf919c9c
 *   input_buf  = server_random(16) || game passphrase
 */
int ldn_data_key(const ProdKeys *keys, const uint8_t *server_random,
                 const uint8_t *passphrase, size_t passphrase_len, uint8_t out[16]);

/* AES-128 ECB single block. */
void aes128_ecb_decrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/*
 * AES-128 CTR. `counter_block` is the initial 16-byte counter: for LDN it is
 * the 4-byte advertisement nonce followed by 12 zero bytes. See the resolved
 * note in ldn.c for where that layout comes from.
 */
void aes128_ctr_xor(const uint8_t key[16], const uint8_t counter_block[16],
                    const uint8_t *in, uint8_t *out, size_t len);

/* HMAC-SHA256 over data[0..len), key = the fixed LDN challenge key. */
void ldn_challenge_hmac_sha256(const void *data, size_t len, uint8_t out[32]);

#endif /* SWITCH_LDN_CRYPTO_H */
