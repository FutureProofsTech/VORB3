#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

#define SIGNATURE_LEN 13672
#define SEED_LEN 36
#define ENTROPY_LEN 32
#define PK_LEN 72
#define MAX_MSG_LEN 8192
#define CASES 12

extern int vorb3_ct_keygen(const unsigned char *seed, unsigned char *public_key);
extern int vorb3_ct_sign(const unsigned char *seed, const unsigned char *entropy,
                         const unsigned char *message, size_t message_len,
                         unsigned char *signature);

static void fill(unsigned char *bytes, size_t len, uint32_t state) {
    for (size_t i = 0; i < len; i++) {
        state = state * 1664525u + 1013904223u;
        bytes[i] = (unsigned char)(state >> 24);
    }
}

int main(void) {
    static const size_t lengths[CASES] = {0, 1, 63, 64, 65, 127, 128, 129, 257, 1024, 4096, 8192};
    unsigned char seed[SEED_LEN];
    unsigned char entropy[ENTROPY_LEN];
    unsigned char message[MAX_MSG_LEN];
    unsigned char expected_pk[PK_LEN];
    unsigned char expected_sig[SIGNATURE_LEN];
    unsigned char pk[PK_LEN];
    unsigned char sig[SIGNATURE_LEN];

    for (size_t c = 0; c < CASES; c++) {
        fill(seed, sizeof(seed), 0x12345678u + (uint32_t)c * 0x9e3779b9u);
        fill(entropy, sizeof(entropy), 0xdeadbeefu + (uint32_t)c * 0x85ebca6bu);
        fill(message, lengths[c], 0xc2b2ae35u + (uint32_t)c);

        if (vorb3_ct_keygen(seed, expected_pk) != 0) {
            fprintf(stderr, "baseline keygen failed at case %zu\n", c);
            return 2;
        }
        if (vorb3_ct_sign(seed, entropy, message, lengths[c], expected_sig) != 0) {
            fprintf(stderr, "baseline sign failed at case %zu\n", c);
            return 3;
        }

        VALGRIND_MAKE_MEM_UNDEFINED(seed, sizeof(seed));
        VALGRIND_MAKE_MEM_UNDEFINED(entropy, sizeof(entropy));
        if (vorb3_ct_keygen(seed, pk) != 0) {
            fprintf(stderr, "poisoned keygen failed at case %zu\n", c);
            return 4;
        }
        VALGRIND_MAKE_MEM_DEFINED(pk, sizeof(pk));
        if (memcmp(pk, expected_pk, sizeof(pk)) != 0) {
            fprintf(stderr, "poisoned keygen mismatch at case %zu\n", c);
            return 5;
        }

        VALGRIND_MAKE_MEM_UNDEFINED(seed, sizeof(seed));
        VALGRIND_MAKE_MEM_UNDEFINED(entropy, sizeof(entropy));
        if (vorb3_ct_sign(seed, entropy, message, lengths[c], sig) != 0) {
            fprintf(stderr, "poisoned sign failed at case %zu\n", c);
            return 6;
        }
        VALGRIND_MAKE_MEM_DEFINED(sig, sizeof(sig));
        if (memcmp(sig, expected_sig, sizeof(sig)) != 0) {
            fprintf(stderr, "poisoned sign mismatch at case %zu\n", c);
            return 7;
        }
    }

    puts("CTGRIND: no secret-dependent branch or address observed outside the public-key validity check");
    return 0;
}
