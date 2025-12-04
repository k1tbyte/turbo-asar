/**
 * @file test_asar.c
 * @brief Tests for ASAR archive operations
 *
 * Created by kitbyte on 13.11.2025.
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#endif

#include "turbo_asar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>

static inline int test_mkdir(const char *path, int mode) {
    (void) mode;
    return _mkdir(path);
}

#define mkdir test_mkdir
#define unlink _unlink

static void remove_directory_recursive(const char *path) {
    WIN32_FIND_DATAA find_data;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", path);
    
    HANDLE find = FindFirstFileA(search_path, &find_data);
    if (find == INVALID_HANDLE_VALUE) return;
    
    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0)
            continue;
        
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", path, find_data.cFileName);
        
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            remove_directory_recursive(full_path);
        } else {
            _unlink(full_path);
        }
    } while (FindNextFileA(find, &find_data));
    
    FindClose(find);
    _rmdir(path);
}

#else
#include <unistd.h>
#include <dirent.h>
#include <ftw.h>

/* POSIX recursive directory removal using nftw */
static int remove_callback(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(path);
}

static void remove_directory_recursive(const char *path) {
    nftw(path, remove_callback, 64, FTW_DEPTH | FTW_PHYS);
}

#endif

/* ========== Test Framework ========== */

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name); fflush(stdout);
#define PASS() do { printf("PASSED\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); tests_failed++; return; } while(0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); } } while(0)

/* ========== Test Data Generation ========== */

#define TEST_DIR "tmp/test_data"
#define TEST_ARCHIVE "tmp/test.asar"
#define TEST_EXTRACT_DIR "tmp/test_extract"

static void generate_random_data(uint8_t *buffer, size_t size, unsigned int seed) {
    srand(seed);
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (uint8_t)(rand() % 256);
    }
}

static int create_file(const char *path, const void *data, size_t size) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    if (size > 0 && data != NULL) {
        fwrite(data, 1, size, fp);
    }
    fclose(fp);
    return 0;
}

static int create_random_file(const char *path, size_t size, unsigned int seed) {
    if (size == 0) {
        return create_file(path, NULL, 0);
    }
    
    uint8_t *buffer = malloc(size);
    if (!buffer) return -1;
    
    generate_random_data(buffer, size, seed);
    int result = create_file(path, buffer, size);
    free(buffer);
    return result;
}

/* Create test directory structure with various file types and sizes */
static int setup_test_data(void) {
    /* Create directories */
    mkdir("tmp", 0755);
    mkdir(TEST_DIR, 0755);
    mkdir(TEST_DIR "/dir1", 0755);
    mkdir(TEST_DIR "/dir2", 0755);
    mkdir(TEST_DIR "/dir2/subdir", 0755);
    mkdir(TEST_DIR "/empty_dir", 0755);
    
    /* File with known content for verification */
    if (create_file(TEST_DIR "/dir1/file1.txt", "file one.", 9) != 0) return -1;
    
    /* Small files */
    if (create_file(TEST_DIR "/file0.txt", "file0 content", 13) != 0) return -1;
    if (create_file(TEST_DIR "/dir2/file2.txt", "file two.", 9) != 0) return -1;
    if (create_file(TEST_DIR "/dir2/file3.txt", "123", 3) != 0) return -1;
    if (create_file(TEST_DIR "/dir2/subdir/nested.txt", "nested content", 14) != 0) return -1;
    
    /* Empty file */
    if (create_file(TEST_DIR "/emptyfile.txt", NULL, 0) != 0) return -1;
    
    /* Hidden file */
    if (create_file(TEST_DIR "/.hiddenfile.txt", "hidden", 6) != 0) return -1;
    
    /* Medium file (100KB) */
    if (create_random_file(TEST_DIR "/dir1/medium.bin", 100 * 1024, 12345) != 0) return -1;
    
    /* Binary file (simulate PNG header) */
    uint8_t png_header[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (create_file(TEST_DIR "/dir2/image.png", png_header, sizeof(png_header)) != 0) return -1;
    
    return 0;
}

static void cleanup_test_data(void) {
    remove_directory_recursive(TEST_DIR);
    remove_directory_recursive(TEST_EXTRACT_DIR);
    remove_directory_recursive("tmp/test_roundtrip_extract");
    unlink(TEST_ARCHIVE);
    unlink("tmp/test_roundtrip.asar");
    unlink("tmp/test_no_hidden.asar");
}

/* ========== Tests ========== */

static void test_pack_basic(void) {
    TEST("pack basic");
    
    turbo_asar_pack_options_t options = {0};
    options.calculate_integrity = true;
    
    turbo_asar_error_t err = turbo_asar_pack(TEST_DIR, TEST_ARCHIVE, &options);
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    
    /* Verify archive was created */
    struct stat st;
    ASSERT(stat(TEST_ARCHIVE, &st) == 0, "archive file not created");
    ASSERT(st.st_size > 0, "archive file is empty");
    
    PASS();
}

static void test_list_archive(void) {
    TEST("list archive");
    
    char **files;
    size_t count;
    turbo_asar_error_t err = turbo_asar_list(TEST_ARCHIVE, &files, &count);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(count > 0, "no files found");
    
    /* Check for expected files */
    int found_dir1 = 0, found_file1 = 0, found_empty = 0, found_hidden = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(files[i], "dir1") && !strstr(files[i], "file")) found_dir1 = 1;
        if (strstr(files[i], "file1.txt")) found_file1 = 1;
        if (strstr(files[i], "emptyfile.txt")) found_empty = 1;
        if (strstr(files[i], ".hiddenfile.txt")) found_hidden = 1;
    }
    
    turbo_asar_free_list(files, count);
    
    ASSERT(found_dir1, "dir1 not found");
    ASSERT(found_file1, "file1.txt not found");
    ASSERT(found_empty, "emptyfile.txt not found");
    ASSERT(found_hidden, ".hiddenfile.txt not found");
    
    PASS();
}

static void test_extract_file(void) {
    TEST("extract file");
    
    uint8_t *buffer;
    size_t size;
    turbo_asar_error_t err = turbo_asar_extract_file(TEST_ARCHIVE, "dir1/file1.txt", &buffer, &size);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(buffer != NULL, "buffer is NULL");
    ASSERT(size == 9, "incorrect size");
    ASSERT(memcmp(buffer, "file one.", 9) == 0, "content mismatch");
    
    free(buffer);
    PASS();
}

static void test_extract_empty_file(void) {
    TEST("extract empty file");
    
    uint8_t *buffer;
    size_t size;
    turbo_asar_error_t err = turbo_asar_extract_file(TEST_ARCHIVE, "emptyfile.txt", &buffer, &size);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(size == 0, "size should be 0 for empty file");
    
    free(buffer);
    PASS();
}

static void test_extract_binary_file(void) {
    TEST("extract binary file");
    
    uint8_t *buffer;
    size_t size;
    turbo_asar_error_t err = turbo_asar_extract_file(TEST_ARCHIVE, "dir2/image.png", &buffer, &size);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(size == 8, "incorrect size for binary file");
    
    /* Check PNG header */
    uint8_t png_header[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    ASSERT(memcmp(buffer, png_header, 8) == 0, "binary content mismatch");
    
    free(buffer);
    PASS();
}

static void test_extract_medium_file(void) {
    TEST("extract medium file (100KB)");
    
    uint8_t *buffer;
    size_t size;
    turbo_asar_error_t err = turbo_asar_extract_file(TEST_ARCHIVE, "dir1/medium.bin", &buffer, &size);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(size == 100 * 1024, "incorrect size for medium file");
    
    /* Verify content by regenerating with same seed */
    uint8_t *expected = malloc(size);
    generate_random_data(expected, size, 12345);
    ASSERT(memcmp(buffer, expected, size) == 0, "medium file content mismatch");
    
    free(expected);
    free(buffer);
    PASS();
}

static void test_get_header(void) {
    TEST("get header");
    
    char *header;
    turbo_asar_error_t err = turbo_asar_get_header(TEST_ARCHIVE, &header);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(header != NULL, "header is NULL");
    ASSERT(strstr(header, "files") != NULL, "no 'files' in header");
    ASSERT(strstr(header, "size") != NULL, "no 'size' in header");
    
    free(header);
    PASS();
}

static void test_stat_file(void) {
    TEST("stat file");
    
    turbo_asar_entry_t entry;
    turbo_asar_error_t err = turbo_asar_stat(TEST_ARCHIVE, "dir1/file1.txt", &entry);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(entry.type == TURBO_ASAR_ENTRY_FILE, "not a file");
    ASSERT(entry.size == 9, "incorrect size");
    
    turbo_asar_free_entry(&entry);
    PASS();
}

static void test_stat_directory(void) {
    TEST("stat directory");
    
    turbo_asar_entry_t entry;
    turbo_asar_error_t err = turbo_asar_stat(TEST_ARCHIVE, "dir1", &entry);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(entry.type == TURBO_ASAR_ENTRY_DIRECTORY, "not a directory");
    
    turbo_asar_free_entry(&entry);
    PASS();
}

static void test_extract_all(void) {
    TEST("extract all");
    
    turbo_asar_error_t err = turbo_asar_extract_all(TEST_ARCHIVE, TEST_EXTRACT_DIR);
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    
    /* Verify file exists */
    char path[256];
    snprintf(path, sizeof(path), "%s/dir1/file1.txt", TEST_EXTRACT_DIR);
    
    FILE *fp = fopen(path, "rb");
    ASSERT(fp != NULL, "extracted file not found");
    
    char content[256];
    size_t len = fread(content, 1, sizeof(content) - 1, fp);
    content[len] = '\0';
    fclose(fp);
    
    ASSERT(strcmp(content, "file one.") == 0, "extracted content mismatch");
    
    PASS();
}

static void test_roundtrip(void) {
    TEST("roundtrip (pack->extract->compare)");
    
    const char *asar = "tmp/test_roundtrip.asar";
    const char *extract_dest = "tmp/test_roundtrip_extract";
    
    /* Pack */
    turbo_asar_pack_options_t options = {0};
    options.calculate_integrity = true;
    
    turbo_asar_error_t err = turbo_asar_pack(TEST_DIR, asar, &options);
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    
    /* Extract */
    err = turbo_asar_extract_all(asar, extract_dest);
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    
    /* Verify extracted file content */
    char path[256];
    snprintf(path, sizeof(path), "%s/dir1/file1.txt", extract_dest);
    
    FILE *fp = fopen(path, "rb");
    ASSERT(fp != NULL, "extracted file not found");
    
    char content[256];
    size_t len = fread(content, 1, sizeof(content) - 1, fp);
    content[len] = '\0';
    fclose(fp);
    
    ASSERT(strcmp(content, "file one.") == 0, "content mismatch after roundtrip");
    
    PASS();
}

static void test_pack_exclude_hidden(void) {
    TEST("pack exclude hidden files");
    
    const char *asar = "tmp/test_no_hidden.asar";
    
    turbo_asar_pack_options_t options = {0};
    options.exclude_hidden = true;
    
    turbo_asar_error_t err = turbo_asar_pack(TEST_DIR, asar, &options);
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    
    /* List and check hidden file is not present */
    char **files;
    size_t count;
    err = turbo_asar_list(asar, &files, &count);
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    
    int found_hidden = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(files[i], ".hiddenfile")) found_hidden = 1;
    }
    
    turbo_asar_free_list(files, count);
    
    ASSERT(!found_hidden, "hidden file should not be in archive");
    
    PASS();
}

static void test_error_handling(void) {
    TEST("error handling");
    
    /* Test non-existent file */
    char **files;
    size_t count;
    turbo_asar_error_t err = turbo_asar_list("nonexistent.asar", &files, &count);
    ASSERT(err == TURBO_ASAR_ERR_FILE_NOT_FOUND, "should return file not found");
    
    /* Test null parameters */
    err = turbo_asar_list(NULL, &files, &count);
    ASSERT(err == TURBO_ASAR_ERR_NULL_PARAM, "should return null param error");
    
    /* Test file not in archive */
    uint8_t *buffer;
    size_t size;
    err = turbo_asar_extract_file(TEST_ARCHIVE, "nonexistent.txt", &buffer, &size);
    ASSERT(err == TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE, "should return not found in archive");
    
    PASS();
}

static void test_nested_directories(void) {
    TEST("nested directories");
    
    uint8_t *buffer;
    size_t size;
    turbo_asar_error_t err = turbo_asar_extract_file(TEST_ARCHIVE, "dir2/subdir/nested.txt", &buffer, &size);
    
    ASSERT(err == TURBO_ASAR_OK, turbo_asar_strerror(err));
    ASSERT(size == 14, "incorrect size");
    ASSERT(memcmp(buffer, "nested content", 14) == 0, "content mismatch");
    
    free(buffer);
    PASS();
}

/* ========== Main ========== */

int main(void) {
    printf("=== ASAR Tests ===\n\n");
    
    /* Setup test data */
    printf("Setting up test data...\n");
    if (setup_test_data() != 0) {
        printf("Failed to setup test data!\n");
        return 1;
    }
    printf("Test data created successfully.\n\n");
    
    /* Run tests */
    test_pack_basic();
    test_list_archive();
    test_extract_file();
    test_extract_empty_file();
    test_extract_binary_file();
    test_extract_medium_file();
    test_get_header();
    test_stat_file();
    test_stat_directory();
    test_extract_all();
    test_roundtrip();
    test_pack_exclude_hidden();
    test_nested_directories();
    test_error_handling();
    
    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
    
    /* Cleanup */
    printf("\nCleaning up test data...\n");
    cleanup_test_data();
    
    return tests_failed > 0 ? 1 : 0;
}
