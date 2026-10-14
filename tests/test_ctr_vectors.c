/*
 * Locks in the AES-CTR counter-block layout, the one thing the LDN wiki does
 * not specify. Reference vectors come from kinnay/LDN's exact call.
 */
#include <string.h>

#include "crypto.h"
#include "common.h"
#include "ctr_vectors.h"

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    for (int i = 0; i < CTR_VECTOR_COUNT; i++) {
        const CtrVector *v = &k_ctr_vectors[i];

        uint8_t out[512];
        if (v->len > sizeof(out)) {
            fprintf(stderr, "vector too large\n");
            return 1;
        }

        uint8_t counter[16];
        memcpy(counter, v->nonce, 4);
        memset(counter + 4, 0, 12);

        aes128_ctr_xor(v->key, counter, v->plain, out, v->len);

        if (memcmp(out, v->ct, v->len) != 0) {
            printf("%s: MISMATCH (%zu bytes)\n", v->name, v->len);
            hex_dump("  ours: ", out, 32);
            hex_dump("  ref : ", v->ct, 32);
            return 1;
        }
        printf("%s: %zu bytes match\n", v->name, v->len);
    }
    return 0;
}
