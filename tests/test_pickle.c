/**
 * @file test_pickle.c
 * @brief Tests for pickle serialization
 *
 * Created by kitbyte on 13.11.2025.
 */

#include "pickle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name);
#define PASS() do { printf("PASSED\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); tests_failed++; } while(0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)

static void test_write_read_uint32(void)
{
    TEST("write/read uint32");
    
    pickle_writer_t writer;
    ASSERT(pickle_writer_init(&writer), "init writer");
    
    ASSERT(pickle_write_uint32(&writer, 0), "write 0");
    ASSERT(pickle_write_uint32(&writer, 42), "write 42");
    ASSERT(pickle_write_uint32(&writer, 0xFFFFFFFF), "write max");
    
    size_t size;
    uint8_t *data = pickle_writer_copy(&writer, &size);
    ASSERT(data != NULL, "get data");
    
    pickle_reader_t reader;
    ASSERT(pickle_reader_init(&reader, data, size), "init reader");
    
    uint32_t val;
    ASSERT(pickle_read_uint32(&reader, &val), "read 0");
    ASSERT(val == 0, "value == 0");
    
    ASSERT(pickle_read_uint32(&reader, &val), "read 42");
    ASSERT(val == 42, "value == 42");
    
    ASSERT(pickle_read_uint32(&reader, &val), "read max");
    ASSERT(val == 0xFFFFFFFF, "value == max");
    
    free(data);
    pickle_writer_free(&writer);
    
    PASS();
}

static void test_write_read_string(void)
{
    TEST("write/read string");
    
    pickle_writer_t writer;
    ASSERT(pickle_writer_init(&writer), "init writer");
    
    const char *test1 = "Hello, World!";
    const char *test2 = "";
    const char *test3 = "JSON test: {\"files\":{}}";
    
    ASSERT(pickle_write_string(&writer, test1, strlen(test1)), "write test1");
    ASSERT(pickle_write_string(&writer, test2, strlen(test2)), "write test2");
    ASSERT(pickle_write_string(&writer, test3, strlen(test3)), "write test3");
    
    size_t size;
    uint8_t *data = pickle_writer_copy(&writer, &size);
    ASSERT(data != NULL, "get data");
    
    pickle_reader_t reader;
    ASSERT(pickle_reader_init(&reader, data, size), "init reader");
    
    char *str;
    
    ASSERT(pickle_read_string_copy(&reader, &str), "read test1");
    ASSERT(strcmp(str, test1) == 0, "value == test1");
    free(str);
    
    ASSERT(pickle_read_string_copy(&reader, &str), "read test2");
    ASSERT(strcmp(str, test2) == 0, "value == test2");
    free(str);
    
    ASSERT(pickle_read_string_copy(&reader, &str), "read test3");
    ASSERT(strcmp(str, test3) == 0, "value == test3");
    free(str);
    
    free(data);
    pickle_writer_free(&writer);
    
    PASS();
}

static void test_asar_header_format(void)
{
    TEST("ASAR header format");
    
    /* Test that we can create a valid ASAR-style header */
    const char *json = "{\"files\":{\"test.txt\":{\"size\":5,\"offset\":\"0\"}}}";
    
    /* Create header pickle */
    pickle_writer_t header_writer;
    ASSERT(pickle_writer_init(&header_writer), "init header writer");
    ASSERT(pickle_write_string(&header_writer, json, strlen(json)), "write json");
    
    size_t header_size;
    const uint8_t *header_data = pickle_writer_data(&header_writer, &header_size);
    
    /* Create size pickle */
    pickle_writer_t size_writer;
    ASSERT(pickle_writer_init(&size_writer), "init size writer");
    ASSERT(pickle_write_uint32(&size_writer, (uint32_t)header_size), "write size");
    
    size_t size_len;
    const uint8_t *size_data = pickle_writer_data(&size_writer, &size_len);
    
    /* Combine into full header */
    size_t total = size_len + header_size;
    uint8_t *full_header = malloc(total);
    ASSERT(full_header != NULL, "alloc full header");
    memcpy(full_header, size_data, size_len);
    memcpy(full_header + size_len, header_data, header_size);
    
    /* Now read it back */
    pickle_reader_t size_reader;
    ASSERT(pickle_reader_init(&size_reader, full_header, size_len), "read size pickle");
    
    uint32_t read_header_size;
    ASSERT(pickle_read_uint32(&size_reader, &read_header_size), "read header size");
    ASSERT(read_header_size == header_size, "header size matches");
    
    pickle_reader_t header_reader;
    ASSERT(pickle_reader_init(&header_reader, full_header + size_len, read_header_size), "read header pickle");
    
    char *read_json;
    ASSERT(pickle_read_string_copy(&header_reader, &read_json), "read json");
    ASSERT(strcmp(read_json, json) == 0, "json matches");
    
    free(read_json);
    free(full_header);
    pickle_writer_free(&size_writer);
    pickle_writer_free(&header_writer);
    
    PASS();
}

int main(void)
{
    printf("=== Pickle Tests ===\n\n");
    
    test_write_read_uint32();
    test_write_read_string();
    test_asar_header_format();
    
    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
