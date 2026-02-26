// fast_hash.c — SHAKE128 (tiny_sha3), CRC32 (IEEE), FNV-1a 32-bit.
//
// SHAKE128/Keccak-f[1600]: tiny_sha3 by Markku-Juhani O. Saarinen <mjos@iki.fi>
//   https://github.com/mjosaarinen/tiny_sha3  (MIT / CC0)
//   Revised for FIPS PUB 202 "SHA-3" compliance.
// CRC32/FNV1a: standard algorithms.

#include "fast_hash.h"
#include <string.h>

// ══════════════════════════════════════════════════════════════
//  Keccak-f[1600] — from tiny_sha3 (Markku-Juhani O. Saarinen)
// ══════════════════════════════════════════════════════════════

#define KECCAKF_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static void sha3_keccakf(uint64_t st[25])
{
    static const uint64_t keccakf_rndc[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };
    static const int keccakf_rotc[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    static const int keccakf_piln[24] = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    int i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < KECCAKF_ROUNDS; r++) {

        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        // Iota
        st[0] ^= keccakf_rndc[r];
    }
}

// ══════════════════════════════════════════════════════════════
//  SHAKE128 sponge — using tiny_sha3 absorb/squeeze
// ══════════════════════════════════════════════════════════════

void shake128_init(shake128_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void shake128_update(shake128_ctx *ctx, const uint8_t *input, size_t input_len) {
    // SHAKE128: rate = 168 bytes (1344 bits), capacity = 256 bits
    const int rsiz = 168;
    uint8_t *st = (uint8_t *)ctx->state_q;
    int pt = (int)ctx->absorb_pos;

    for (size_t i = 0; i < input_len; i++) {
        st[pt++] ^= input[i];
        if (pt >= rsiz) {
            sha3_keccakf(ctx->state_q);
            pt = 0;
        }
    }

    ctx->absorb_pos = (uint32_t)pt;
}

void shake128_finalize(shake128_ctx *ctx) {
    if (ctx->finalized) {
        return;
    }

    const int rsiz = 168;
    uint8_t *st = (uint8_t *)ctx->state_q;

    // Finalize absorb: SHAKE domain separator (0x1F) + pad10*1
    st[ctx->absorb_pos] ^= 0x1F;
    st[rsiz - 1] ^= 0x80;
    sha3_keccakf(ctx->state_q);
    ctx->squeeze_pos = 0;
    ctx->finalized = 1;
}

void shake128_read(shake128_ctx *ctx, uint8_t *output, size_t output_len) {
    const int rsiz = 168;
    uint8_t *st = (uint8_t *)ctx->state_q;

    if (!ctx->finalized) {
        shake128_finalize(ctx);
    }

    // Squeeze
    int j = (int)ctx->squeeze_pos;
    for (size_t i = 0; i < output_len; i++) {
        if (j >= rsiz) {
            sha3_keccakf(ctx->state_q);
            st = (uint8_t *)ctx->state_q;
            j = 0;
        }
        output[i] = st[j++];
    }
    ctx->squeeze_pos = (uint32_t)j;
}

void shake128(const uint8_t *input, size_t input_len,
              uint8_t *output, size_t output_len) {
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_update(&ctx, input, input_len);
    shake128_read(&ctx, output, output_len);
}

// ══════════════════════════════════════════════════════════════
//  CRC32 (IEEE 802.3, reflected polynomial 0xEDB88320)
// ══════════════════════════════════════════════════════════════

static uint32_t crc32_table[256];
static int crc32_table_ready = 0;

static void crc32_init_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ ((c & 1) ? 0xEDB88320u : 0);
        crc32_table[i] = c;
    }
    crc32_table_ready = 1;
}

uint32_t crc32_hash(const uint8_t *data, size_t len) {
    if (!crc32_table_ready) crc32_init_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFu;
}

// ══════════════════════════════════════════════════════════════
//  FNV-1a 32-bit
// ══════════════════════════════════════════════════════════════

uint32_t fnv1a32(const uint8_t *data, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}
