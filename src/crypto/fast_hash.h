// fast_hash.h — Optimized non-TLS hash functions (Keccak/SHAKE128, CRC32, FNV1a32)
// Replaces Zig stdlib with C implementations for consistent performance.

#ifndef FAST_HASH_H
#define FAST_HASH_H

#include <stdint.h>
#include <stddef.h>

// ── SHAKE128 (Keccak XOF) ──
// Absorbs `input_len` bytes, squeezes `output_len` bytes.
typedef struct {
    uint64_t state_q[25];
    uint32_t absorb_pos;
    uint32_t squeeze_pos;
    uint8_t finalized;
} shake128_ctx;

void shake128_init(shake128_ctx *ctx);
void shake128_update(shake128_ctx *ctx, const uint8_t *input, size_t input_len);
void shake128_finalize(shake128_ctx *ctx);
void shake128_read(shake128_ctx *ctx, uint8_t *output, size_t output_len);

// One-shot helper (equivalent to init+update+read).
void shake128(const uint8_t *input, size_t input_len,
              uint8_t *output, size_t output_len);

// ── CRC32 (IEEE 802.3, polynomial 0xEDB88320) ──
uint32_t crc32_hash(const uint8_t *data, size_t len);

// ── FNV-1a 32-bit ──
uint32_t fnv1a32(const uint8_t *data, size_t len);

#endif // FAST_HASH_H
