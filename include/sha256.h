/**
 * @file sha256.h
 * @brief SHA-256 hash implementation
 *
 * Created by kitbyte on 08.11.2025.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define SHA256_HEX_SIZE 65  /* 64 hex chars + null terminator */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_ctx_t;


TURBO_ASAR_API void sha256_init(sha256_ctx_t *ctx);
TURBO_ASAR_API void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
TURBO_ASAR_API void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
TURBO_ASAR_API void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);
TURBO_ASAR_API void sha256_to_hex(const uint8_t digest[SHA256_DIGEST_SIZE], char hex[SHA256_HEX_SIZE]);
/**
 * One-shot SHA256 hash to hex string
 */
TURBO_ASAR_API void sha256_hash_hex(const uint8_t *data, size_t len, char hex[SHA256_HEX_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* SHA256_H */
