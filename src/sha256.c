/**
 * @file sha256.c
 * @brief Optimized SHA-256 implementation with SHA-NI (x86) and ARMv8 Crypto Extensions
 */

#include "sha256.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * Compiler & Architecture Detection
 * ============================================================================ */

#if defined(_MSC_VER)
    #include <intrin.h>
    #define FORCE_INLINE __forceinline
    #define BSWAP32(x) _byteswap_ulong(x)
    #define ALIGN(n) __declspec(align(n))

    #if defined(_M_X64) || defined(_M_IX86)
        #define SHA256_X86 1
    #elif defined(_M_ARM64)
        #define SHA256_ARM64 1
        #include <arm_neon.h>
    #endif

#elif defined(__GNUC__) || defined(__clang__)
    #define FORCE_INLINE inline __attribute__((always_inline))
    #define BSWAP32(x) __builtin_bswap32(x)
    #define ALIGN(n) __attribute__((aligned(n)))

    #if defined(__x86_64__) || defined(__i386__)
        #include <cpuid.h>
        #include <immintrin.h>
        #define SHA256_X86 1
    #elif defined(__aarch64__)
        #define SHA256_ARM64 1
        #include <arm_neon.h>
    #endif
#else
    #define FORCE_INLINE inline
    #define BSWAP32(x) (((x) << 24) | (((x) & 0xFF00) << 8) | (((x) >> 8) & 0xFF00) | ((x) >> 24))
    #define ALIGN(n)
#endif

/*
 * FEATURE DETECTION:
 * Some compilers define __ARM_FEATURE_CRYPTO (old standard), others __ARM_FEATURE_SHA2.
 * We check both to determine if we can compile the accelerated functions.
 */
#if defined(SHA256_ARM64)
    #if defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_SHA2)
        #define HAS_ARM64_SHA_INTRINSICS 1
    #endif
#endif

/* ============================================================================
 * SHA-256 Constants & Macros
 * ============================================================================ */

#define ROTR(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))

ALIGN(64) static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

typedef void (*sha256_transform_fn)(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks);

static void sha256_transform_scalar(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks);
static void sha256_select_implementation(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks);

#ifdef SHA256_X86
static void sha256_transform_shani(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks);
#endif

/* Only declare/define this if we actually have the intrinsics enabled */
#ifdef HAS_ARM64_SHA_INTRINSICS
static void sha256_transform_arm64(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks);
#endif

static sha256_transform_fn volatile transform_func = sha256_select_implementation;

/* ============================================================================
 * X86 SHA-NI Implementation
 * ============================================================================ */

#ifdef SHA256_X86

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("sha,sse4.1")))
#endif
static void sha256_transform_shani(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks)
{
    __m128i state0, state1, msg, tmp;
    __m128i msg0, msg1, msg2, msg3;
    __m128i abef_save, cdgh_save;
    const __m128i shuf_mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    tmp = _mm_loadu_si128((const __m128i *)&ctx->state[0]);
    state1 = _mm_loadu_si128((const __m128i *)&ctx->state[4]);

    tmp = _mm_shuffle_epi32(tmp, 0xB1);
    state1 = _mm_shuffle_epi32(state1, 0x1B);
    state0 = _mm_alignr_epi8(tmp, state1, 8);
    state1 = _mm_blend_epi16(state1, tmp, 0xF0);

    while (num_blocks--) {
        /* Prefetch next block */
        _mm_prefetch((const char *)(data + 64), _MM_HINT_T0);

        abef_save = state0;
        cdgh_save = state1;

        msg0 = _mm_loadu_si128((const __m128i *)(data + 0));
        msg0 = _mm_shuffle_epi8(msg0, shuf_mask);
        msg = _mm_add_epi32(msg0, _mm_load_si128((const __m128i *)&K[0]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        msg1 = _mm_loadu_si128((const __m128i *)(data + 16));
        msg1 = _mm_shuffle_epi8(msg1, shuf_mask);
        msg = _mm_add_epi32(msg1, _mm_load_si128((const __m128i *)&K[4]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        msg2 = _mm_loadu_si128((const __m128i *)(data + 32));
        msg2 = _mm_shuffle_epi8(msg2, shuf_mask);
        msg = _mm_add_epi32(msg2, _mm_load_si128((const __m128i *)&K[8]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        msg3 = _mm_loadu_si128((const __m128i *)(data + 48));
        msg3 = _mm_shuffle_epi8(msg3, shuf_mask);
        msg = _mm_add_epi32(msg3, _mm_load_si128((const __m128i *)&K[12]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        #define ROUND(i, m0, m1, m2, m3) \
            msg = _mm_add_epi32(m0, _mm_load_si128((const __m128i *)&K[i])); \
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg); \
            tmp = _mm_alignr_epi8(m0, m3, 4); \
            m1 = _mm_add_epi32(m1, tmp); \
            m1 = _mm_sha256msg2_epu32(m1, m0); \
            msg = _mm_shuffle_epi32(msg, 0x0E); \
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg); \
            m3 = _mm_sha256msg1_epu32(m3, m0)

        ROUND(16, msg0, msg1, msg2, msg3);
        ROUND(20, msg1, msg2, msg3, msg0);
        ROUND(24, msg2, msg3, msg0, msg1);
        ROUND(28, msg3, msg0, msg1, msg2);
        ROUND(32, msg0, msg1, msg2, msg3);
        ROUND(36, msg1, msg2, msg3, msg0);
        ROUND(40, msg2, msg3, msg0, msg1);
        ROUND(44, msg3, msg0, msg1, msg2);
        ROUND(48, msg0, msg1, msg2, msg3);
        #undef ROUND

        msg = _mm_add_epi32(msg1, _mm_load_si128((const __m128i *)&K[52]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        msg = _mm_add_epi32(msg2, _mm_load_si128((const __m128i *)&K[56]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        msg = _mm_add_epi32(msg3, _mm_load_si128((const __m128i *)&K[60]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);
        data += 64;
    }

    tmp = _mm_shuffle_epi32(state0, 0x1B);
    state1 = _mm_shuffle_epi32(state1, 0xB1);
    state0 = _mm_blend_epi16(tmp, state1, 0xF0);
    state1 = _mm_alignr_epi8(state1, tmp, 8);

    _mm_storeu_si128((__m128i *)&ctx->state[0], state0);
    _mm_storeu_si128((__m128i *)&ctx->state[4], state1);
}
#endif /* SHA256_X86 */

/* ============================================================================
 * ARM64 Crypto Implementation
 * ============================================================================ */

#ifdef HAS_ARM64_SHA_INTRINSICS

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("+crypto")))
#endif
static void sha256_transform_arm64(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks)
{
    uint32x4_t msg0, msg1, msg2, msg3;
    uint32x4_t state0, state1, save0, save1, tmp;

    state0 = vld1q_u32(&ctx->state[0]);
    state1 = vld1q_u32(&ctx->state[4]);

    while (num_blocks--) {
        __builtin_prefetch(data + 64);

        save0 = state0;
        save1 = state1;

        /* Rounds 0-3 */
        msg0 = vld1q_u32((const uint32_t*)(data + 0));
        msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
        tmp = vaddq_u32(msg0, vld1q_u32(&K[0]));
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, state0, tmp);

        /* Rounds 4-7 */
        msg1 = vld1q_u32((const uint32_t*)(data + 16));
        msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
        tmp = vaddq_u32(msg1, vld1q_u32(&K[4]));
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, state0, tmp);

        /* Rounds 8-11 */
        msg2 = vld1q_u32((const uint32_t*)(data + 32));
        msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
        tmp = vaddq_u32(msg2, vld1q_u32(&K[8]));
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, state0, tmp);

        /* Rounds 12-15 */
        msg3 = vld1q_u32((const uint32_t*)(data + 48));
        msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));
        tmp = vaddq_u32(msg3, vld1q_u32(&K[12]));
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, state0, tmp);

        /* Unrolled Schedule + Rounds 16-63 */
        for (int i = 0; i < 12; i++) {
             uint32x4_t *m0_ptr, *m1_ptr, *m2_ptr, *m3_ptr;
             int k_idx = 16 + i*4;

             /* Rotate pointers to simulate sliding window */
             switch (i % 4) {
                 case 0: m0_ptr = &msg0; m1_ptr = &msg1; m2_ptr = &msg2; m3_ptr = &msg3; break;
                 case 1: m0_ptr = &msg1; m1_ptr = &msg2; m2_ptr = &msg3; m3_ptr = &msg0; break;
                 case 2: m0_ptr = &msg2; m1_ptr = &msg3; m2_ptr = &msg0; m3_ptr = &msg1; break;
                 case 3: m0_ptr = &msg3; m1_ptr = &msg0; m2_ptr = &msg1; m3_ptr = &msg2; break;
             }

             *m0_ptr = vsha256su0q_u32(*m0_ptr, *m1_ptr);
             *m0_ptr = vsha256su1q_u32(*m0_ptr, *m2_ptr, *m3_ptr);
             tmp = vaddq_u32(*m0_ptr, vld1q_u32(&K[k_idx]));
             state0 = vsha256hq_u32(state0, state1, tmp);
             state1 = vsha256h2q_u32(state1, state0, tmp);
        }

        state0 = vaddq_u32(state0, save0);
        state1 = vaddq_u32(state1, save1);
        data += 64;
    }

    vst1q_u32(&ctx->state[0], state0);
    vst1q_u32(&ctx->state[4], state1);
}
#endif /* HAS_ARM64_SHA_INTRINSICS */


/* ============================================================================
 * Scalar Implementation (Fallback)
 * ============================================================================ */

#define EP0(x)       (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)       (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)      (ROTR(x, 7)  ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

#define ROUND_00_15(a, b, c, d, e, f, g, h, i) do {         \
    uint32_t t1 = (h) + EP1(e) + CH(e,f,g) + K[i] + w[i];   \
    uint32_t t2 = EP0(a) + MAJ(a,b,c);                      \
    (d) += t1;                                              \
    (h) = t1 + t2;                                          \
} while(0)

#define ROUND_16_63(a, b, c, d, e, f, g, h, i) do {         \
    w[(i)&15] += SIG1(w[((i)-2)&15]) + w[((i)-7)&15] + SIG0(w[((i)-15)&15]); \
    uint32_t t1 = (h) + EP1(e) + CH(e,f,g) + K[i] + w[(i)&15]; \
    uint32_t t2 = EP0(a) + MAJ(a,b,c);                      \
    (d) += t1;                                              \
    (h) = t1 + t2;                                          \
} while(0)

static void sha256_transform_scalar(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks)
{
    while (num_blocks--) {
        #if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(data + 64);
        #endif

        uint32_t a, b, c, d, e, f, g, h;
        uint32_t w[16];
        uint32_t tmp;

        /* Unroll load for better ILP */
        for (int i = 0; i < 16; i++) {
            memcpy(&tmp, data + (i * 4), 4);
            w[i] = BSWAP32(tmp);
        }

        a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
        e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

        /* Unrolled Rounds */
        ROUND_00_15(a, b, c, d, e, f, g, h, 0);
        ROUND_00_15(h, a, b, c, d, e, f, g, 1);
        ROUND_00_15(g, h, a, b, c, d, e, f, 2);
        ROUND_00_15(f, g, h, a, b, c, d, e, 3);
        ROUND_00_15(e, f, g, h, a, b, c, d, 4);
        ROUND_00_15(d, e, f, g, h, a, b, c, 5);
        ROUND_00_15(c, d, e, f, g, h, a, b, 6);
        ROUND_00_15(b, c, d, e, f, g, h, a, 7);
        ROUND_00_15(a, b, c, d, e, f, g, h, 8);
        ROUND_00_15(h, a, b, c, d, e, f, g, 9);
        ROUND_00_15(g, h, a, b, c, d, e, f, 10);
        ROUND_00_15(f, g, h, a, b, c, d, e, 11);
        ROUND_00_15(e, f, g, h, a, b, c, d, 12);
        ROUND_00_15(d, e, f, g, h, a, b, c, 13);
        ROUND_00_15(c, d, e, f, g, h, a, b, 14);
        ROUND_00_15(b, c, d, e, f, g, h, a, 15);

        for (int i = 16; i < 64; i += 8) {
             ROUND_16_63(a, b, c, d, e, f, g, h, i+0);
             ROUND_16_63(h, a, b, c, d, e, f, g, i+1);
             ROUND_16_63(g, h, a, b, c, d, e, f, i+2);
             ROUND_16_63(f, g, h, a, b, c, d, e, i+3);
             ROUND_16_63(e, f, g, h, a, b, c, d, i+4);
             ROUND_16_63(d, e, f, g, h, a, b, c, i+5);
             ROUND_16_63(c, d, e, f, g, h, a, b, i+6);
             ROUND_16_63(b, c, d, e, f, g, h, a, i+7);
        }

        ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
        ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;

        data += 64;
    }
}

/* ============================================================================
 * Implementation Selection / Main Interface
 * ============================================================================ */

static void sha256_select_implementation(sha256_ctx_t *ctx, const uint8_t *data, size_t num_blocks)
{
    sha256_transform_fn selected = sha256_transform_scalar;

#ifdef SHA256_X86
    unsigned int eax, ebx, ecx, edx;
    int has_sha_ni = 0, has_sse41 = 0;

    #if defined(_MSC_VER)
        int regs[4];
        __cpuid(regs, 0);
        if (regs[0] >= 7) {
            __cpuid(regs, 1);
            has_sse41 = (regs[2] & (1 << 19)) != 0;
            __cpuidex(regs, 7, 0);
            has_sha_ni = (regs[1] & (1 << 29)) != 0;
        }
    #elif defined(__GNUC__) || defined(__clang__)
        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) has_sse41 = (ecx & (1 << 19)) != 0;
        if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) has_sha_ni = (ebx & (1 << 29)) != 0;
    #endif

    if (has_sha_ni && has_sse41) selected = sha256_transform_shani;
#endif

/* For ARM64, we rely on compile-time flags + CMake.
 * If you built with -march=armv8-a+crypto, this macro will be true.
 */
#ifdef HAS_ARM64_SHA_INTRINSICS
    selected = sha256_transform_arm64;
#endif

    transform_func = selected;
    selected(ctx, data, num_blocks);
}

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t buffer_fill = (size_t)(ctx->count & (SHA256_BLOCK_SIZE - 1));
    ctx->count += len;

    if (buffer_fill > 0) {
        size_t space = SHA256_BLOCK_SIZE - buffer_fill;
        if (len < space) {
            memcpy(ctx->buffer + buffer_fill, data, len);
            return;
        }
        memcpy(ctx->buffer + buffer_fill, data, space);
        transform_func(ctx, ctx->buffer, 1);
        data += space;
        len -= space;
    }

    size_t num_blocks = len / SHA256_BLOCK_SIZE;
    if (num_blocks > 0) {
        transform_func(ctx, data, num_blocks);
        size_t processed_bytes = num_blocks * SHA256_BLOCK_SIZE;
        data += processed_bytes;
        len -= processed_bytes;
    }

    if (len > 0) memcpy(ctx->buffer, data, len);
}

void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
    size_t buffer_fill = (size_t)(ctx->count & (SHA256_BLOCK_SIZE - 1));
    uint64_t bit_count = ctx->count << 3;

    ctx->buffer[buffer_fill++] = 0x80;

    if (buffer_fill > 56) {
        memset(ctx->buffer + buffer_fill, 0, SHA256_BLOCK_SIZE - buffer_fill);
        transform_func(ctx, ctx->buffer, 1);
        buffer_fill = 0;
    }

    memset(ctx->buffer + buffer_fill, 0, 56 - buffer_fill);

    /* Store length in bits (Big Endian) */
    for (int i = 0; i < 8; i++) ctx->buffer[56 + i] = (uint8_t)(bit_count >> (56 - 8*i));

    transform_func(ctx, ctx->buffer, 1);

    for (size_t i = 0; i < 8; i++) {
        uint32_t s = BSWAP32(ctx->state[i]);
        memcpy(digest + i * 4, &s, 4);
    }
    memset(ctx, 0, sizeof(*ctx));
}

void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

void sha256_to_hex(const uint8_t digest[SHA256_DIGEST_SIZE], char hex[SHA256_HEX_SIZE])
{
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        hex[i * 2]     = hex_chars[(digest[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
    }
    hex[64] = '\0';
}

void sha256_hash_hex(const uint8_t *data, size_t len, char hex[SHA256_HEX_SIZE])
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_hash(data, len, digest);
    sha256_to_hex(digest, hex);
}