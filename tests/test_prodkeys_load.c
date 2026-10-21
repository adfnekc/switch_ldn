/*
 * test_prodkeys_load.c -- what prod.keys parsing accepts, rejects and tolerates.
 *
 * The bridge reads exactly three values out of a file that usually contains
 * hundreds: master_key_00, aes_kek_generation_source and aes_key_generation_source.
 * Those are the *common* console keys, identical on every Switch, which is why
 * any console's modern prod.keys works and why the default lookup can be loose
 * about which file it finds.
 *
 * Two things can go wrong quietly here and both are pinned below:
 *   1. A file that has master_key_01..0N but not master_key_00 must fail, not
 *      silently use a zero key. The difference is an advertisement no console
 *      can decrypt, with no error anywhere.
 *   2. Junk lines must be skipped, not abort the parse: real prod.keys files
 *      carry unrelated entries and annotations.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/crypto.h"

static char g_dir[256];

static const char *write_file(const char *name, const char *text)
{
    static char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fputs(text, f);
    fclose(f);
    return path;
}

int main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/switch_ldn_keys.XXXXXX");
    assert(mkdtemp(g_dir) != NULL);

    ProdKeys keys;

    /* --- a complete file loads --- */
    const char *good = write_file("good.keys",
        "# comment\n"
        "master_key_00 = 000102030405060708090a0b0c0d0e0f\n"
        "aes_kek_generation_source = 101112131415161718191a1b1c1d1e1f\n"
        "aes_key_generation_source = 202122232425262728292a2b2c2d2e2f\n");
    assert(prodkeys_load(&keys, good) == 0);
    assert(memcmp(keys.master_key_00, "\x00\x01\x02\x03\x04\x05\x06\x07"
                                     "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16) == 0);

    /* --- the generation trap: master_key_01 without master_key_00 ---
     * This is the shape of a file from a console on a later key generation, if
     * the generation mattered. It must be a hard failure, because a zero-filled
     * master key would produce an advertisement that looks fine here and that
     * no console can read. */
    const char *gen1 = write_file("gen1.keys",
        "master_key_01 = 000102030405060708090a0b0c0d0e0f\n"
        "aes_kek_generation_source = 101112131415161718191a1b1c1d1e1f\n"
        "aes_key_generation_source = 202122232425262728292a2b2c2d2e2f\n");
    assert(prodkeys_load(&keys, gen1) != 0);
    /* And the failure must leave nothing half-loaded that a caller could use. */
    assert(keys.master_key_00[0] == 0 && keys.master_key_00[15] == 0);

    /* --- missing one of the two generation sources --- */
    const char *partial = write_file("partial.keys",
        "master_key_00 = 000102030405060708090a0b0c0d0e0f\n"
        "aes_kek_generation_source = 101112131415161718191a1b1c1d1e1f\n");
    assert(prodkeys_load(&keys, partial) != 0);

    /* --- junk is skipped, comments and unrelated keys are tolerated --- */
    const char *noisy = write_file("noisy.keys",
        "; not a comment by our rules, but harmless\n"
        "not a key at all\n"
        "master_key_00 = 000102030405060708090a0b0c0d0e0f   # trailing\n"
        "title_key_ffffffffffffffff = 00112233445566778899aabbccddeeff\n"
        "aes_kek_generation_source = 101112131415161718191a1b1c1d1e1f\n"
        "aes_key_generation_source = 202122232425262728292a2b2c2d2e2f\n");
    assert(prodkeys_load(&keys, noisy) == 0);

    /* Values are case-insensitive hex, and may be padded with spaces. */
    const char *hexcase = write_file("hexcase.keys",
        "master_key_00 =   AAbbCCddEEff00112233445566778899  \n"
        "aes_kek_generation_source = 101112131415161718191a1b1c1d1e1f\n"
        "aes_key_generation_source = 202122232425262728292a2b2c2d2e2f\n");
    assert(prodkeys_load(&keys, hexcase) == 0);
    assert(keys.master_key_00[0] == 0xAA && keys.master_key_00[1] == 0xBB &&
           keys.master_key_00[15] == 0x99);

    /* A short value must be rejected rather than zero-extended: 16 bytes are
     * needed and a truncated key is indistinguishable from a wrong one. */
    const char *shortv = write_file("short.keys",
        "master_key_00 = 000102\n"
        "aes_kek_generation_source = 101112131415161718191a1b1c1d1e1f\n"
        "aes_key_generation_source = 202122232425262728292a2b2c2d2e2f\n");
    assert(prodkeys_load(&keys, shortv) != 0);

    /* --- a missing file must fail, and must not leave stale keys behind --- */
    char missing[512];
    snprintf(missing, sizeof(missing), "%s/does-not-exist.keys", g_dir);
    assert(prodkeys_load(&keys, missing) != 0);
    assert(keys.master_key_00[0] == 0);

    /* An empty file is a failure, not an empty key set. */
    const char *empty = write_file("empty.keys", "");
    assert(prodkeys_load(&keys, empty) != 0);

    /* Clean up the temp files; the dump says which directory if this is noisy. */
    for (size_t i = 0; i < 8; i++) {
        static const char *const names[] = {"good", "gen1", "partial", "noisy",
                                            "hexcase", "short", "empty", NULL};
        if (!names[i]) {
            break;
        }
        char p[512];
        snprintf(p, sizeof(p), "%s/%s.keys", g_dir, names[i]);
        unlink(p);
    }
    rmdir(g_dir);

    printf("OK: prod.keys loading (accepts common keys, rejects the rest)\n");
    return 0;
}
