/**
 * @file test_sha256.c
 * @brief Tests for SHA256 implementation
 *
 * Created by kitbyte on 13.11.2025.
 */

#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name);
#define PASS() do { printf("PASSED\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); tests_failed++; } while(0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)

/* Test vectors from NIST */
static void test_empty_string(void)
{
    TEST("empty string");
    
    char hex[SHA256_HEX_SIZE];
    sha256_hash_hex((const uint8_t *)"", 0, hex);
    
    /* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    ASSERT(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
           "hash mismatch");
    
    PASS();
}

static void test_abc(void)
{
    TEST("abc");
    
    char hex[SHA256_HEX_SIZE];
    sha256_hash_hex((const uint8_t *)"abc", 3, hex);
    
    /* SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    ASSERT(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
           "hash mismatch");
    
    PASS();
}

static void test_448_bits(void)
{
    TEST("448-bit message");
    
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char hex[SHA256_HEX_SIZE];
    sha256_hash_hex((const uint8_t *)msg, strlen(msg), hex);
    
    /* SHA256 of 448-bit message */
    ASSERT(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
           "hash mismatch");
    
    PASS();
}

static void test_incremental(void)
{
    TEST("incremental hashing");
    
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    
    sha256_update(&ctx, (const uint8_t *)"a", 1);
    sha256_update(&ctx, (const uint8_t *)"b", 1);
    sha256_update(&ctx, (const uint8_t *)"c", 1);
    
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_final(&ctx, digest);
    
    char hex[SHA256_HEX_SIZE];
    sha256_to_hex(digest, hex);
    
    /* Should match SHA256("abc") */
    ASSERT(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
           "hash mismatch");
    
    PASS();
}

static void test_large_data(void)
{
    TEST("large data (1MB)");
    
    size_t size = 1024 * 1024;  /* 1MB */
    uint8_t *data = malloc(size);
    ASSERT(data != NULL, "malloc failed");
    
    /* Fill with pattern */
    for (size_t i = 0; i < size; i++) {
        data[i] = (uint8_t)(i & 0xFF);
    }
    
    char hex[SHA256_HEX_SIZE];
    sha256_hash_hex(data, size, hex);
    
    /* Just verify it produces a valid-looking hash */
    ASSERT(strlen(hex) == 64, "hash length incorrect");
    
    free(data);
    PASS();
}

static void test_block_boundary(void)
{
    TEST("block boundary");
    
    /* Test data exactly at block boundary (64 bytes) */
    char data[64];
    memset(data, 'a', 64);
    
    char hex[SHA256_HEX_SIZE];
    sha256_hash_hex((const uint8_t *)data, 64, hex);
    
    /* SHA256 of 64 'a' characters */
    ASSERT(strcmp(hex, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb") == 0,
           "hash mismatch");
    
    PASS();
}

int main(void)
{
    printf("=== SHA256 Tests ===\n\n");
    
    test_empty_string();
    test_abc();
    test_448_bits();
    test_incremental();
    test_large_data();
    test_block_boundary();
    
    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
