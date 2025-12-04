/**
 * @file benchmark_asar.c
 * @brief Benchmarks for ASAR operations
 *
 * Created by kitbyte on 01.12.2025.
 */


#ifndef _WIN32
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#endif

#include "turbo_asar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#define unlink _unlink

static double get_time_ms(void) {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)freq.QuadPart;
}

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
#include <sys/time.h>
#include <unistd.h>
#include <ftw.h>

static double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

/* POSIX recursive directory removal using nftw */
static int remove_callback(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(path);
}

static void remove_directory_recursive(const char *path) {
    nftw(path, remove_callback, 64, FTW_DEPTH | FTW_PHYS);
}
#endif

/* Benchmark configuration */
#define WARMUP_RUNS 1
#define BENCHMARK_RUNS 5

/* Test data configuration */
#define BENCH_DIR "tmp/bench_data"
#define BENCH_ARCHIVE "tmp/bench.asar"
#define BENCH_EXTRACT_DIR "tmp/bench_extract"

/* Large test configuration: 100 directories, 10 files each, ~100KB per file = ~100MB total */
#define LARGE_DIR_COUNT 100
#define FILES_PER_DIR 10
#define FILE_SIZE (100 * 1024)  /* 100KB per file */

typedef struct {
    double min_ms;
    double max_ms;
    double avg_ms;
    double total_ms;
} benchmark_result_t;

/* ========== Data Generation ========== */

static void generate_random_data(uint8_t *buffer, size_t size, unsigned int seed) {
    /* Use a simple LCG for speed - we don't need cryptographic randomness */
    uint32_t state = seed;
    for (size_t i = 0; i < size; i++) {
        state = state * 1103515245 + 12345;
        buffer[i] = (uint8_t)(state >> 16);
    }
}

/* Create a file with random content */
static int create_random_file(const char *path, size_t size, unsigned int seed) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    
    /* Write in chunks to handle large files */
    const size_t chunk_size = 1024 * 1024; /* 1MB chunks */
    uint8_t *buffer = malloc(chunk_size < size ? chunk_size : size);
    if (!buffer) {
        fclose(fp);
        return -1;
    }
    
    size_t remaining = size;
    uint32_t chunk_seed = seed;
    
    while (remaining > 0) {
        size_t to_write = remaining < chunk_size ? remaining : chunk_size;
        generate_random_data(buffer, to_write, chunk_seed++);
        if (fwrite(buffer, 1, to_write, fp) != to_write) {
            free(buffer);
            fclose(fp);
            return -1;
        }
        remaining -= to_write;
    }
    
    free(buffer);
    fclose(fp);
    return 0;
}

static int setup_small_test_data(void) {
    mkdir("tmp", 0755);
    mkdir(BENCH_DIR, 0755);
    mkdir(BENCH_DIR "/dir1", 0755);
    mkdir(BENCH_DIR "/dir2", 0755);
    
    /* Create a few small files */
    FILE *fp = fopen(BENCH_DIR "/dir1/file1.txt", "w");
    if (!fp) return -1;
    fprintf(fp, "file one.");
    fclose(fp);
    
    fp = fopen(BENCH_DIR "/dir2/file2.txt", "w");
    if (!fp) return -1;
    fprintf(fp, "file two content here.");
    fclose(fp);
    
    fp = fopen(BENCH_DIR "/file0.txt", "w");
    if (!fp) return -1;
    fprintf(fp, "root file content");
    fclose(fp);
    
    return 0;
}

/* Setup large test data (~100MB) */
static int setup_large_test_data(void) {
    printf("Generating large test data (~%d MB)...\n", 
           (int)((LARGE_DIR_COUNT * FILES_PER_DIR * FILE_SIZE) / (1024 * 1024)));
    
    mkdir("tmp", 0755);
    remove_directory_recursive(BENCH_DIR);
    mkdir(BENCH_DIR, 0755);
    
    int total_files = 0;
    double start = get_time_ms();
    
    for (int d = 0; d < LARGE_DIR_COUNT; d++) {
        char dir_path[256];
        snprintf(dir_path, sizeof(dir_path), "%s/dir%03d", BENCH_DIR, d);
        mkdir(dir_path, 0755);
        
        for (int f = 0; f < FILES_PER_DIR; f++) {
            char file_path[256];
            snprintf(file_path, sizeof(file_path), "%s/file%02d.dat", dir_path, f);
            
            /* Use directory and file index as seed for reproducibility */
            unsigned int seed = (unsigned int)(d * 1000 + f);
            if (create_random_file(file_path, FILE_SIZE, seed) != 0) {
                printf("Failed to create %s\n", file_path);
                return -1;
            }
            total_files++;
        }
        
        /* Progress indicator */
        if ((d + 1) % 10 == 0) {
            printf("  Created %d/%d directories (%d files)...\n", 
                   d + 1, LARGE_DIR_COUNT, total_files);
        }
    }
    
    double elapsed = get_time_ms() - start;
    printf("Test data generation complete: %d files in %.2f ms\n\n", total_files, elapsed);
    
    return 0;
}

static void cleanup_test_data(void) {
    remove_directory_recursive(BENCH_DIR);
    remove_directory_recursive(BENCH_EXTRACT_DIR);
    unlink(BENCH_ARCHIVE);
}

/* ========== Benchmarks ========== */

static void print_result(const char *name, benchmark_result_t *result) {
    printf("%-30s min: %8.2f ms  avg: %8.2f ms  max: %8.2f ms\n",
           name, result->min_ms, result->avg_ms, result->max_ms);
}

static void benchmark_pack(int with_integrity) {
    const char *name = with_integrity ? "pack (with integrity)" : "pack (no integrity)";
    printf("\nBenchmarking %s\n", name);
    
    benchmark_result_t result = {0};
    result.min_ms = 1e9;
    
    turbo_asar_pack_options_t options = {0};
    options.calculate_integrity = with_integrity;
    
    /* Warmup */
    for (int i = 0; i < WARMUP_RUNS; i++) {
        char dest[256];
        snprintf(dest, sizeof(dest), "tmp/bench_warmup_%d.asar", i);
        turbo_asar_pack(BENCH_DIR, dest, &options);
        unlink(dest);
    }
    
    /* Benchmark */
    for (int i = 0; i < BENCHMARK_RUNS; i++) {
        char dest[256];
        snprintf(dest, sizeof(dest), "tmp/bench_pack_%d.asar", i);
        
        double start = get_time_ms();
        turbo_asar_error_t err = turbo_asar_pack(BENCH_DIR, dest, &options);
        double end = get_time_ms();
        
        if (err != TURBO_ASAR_OK) {
            printf("Error: %s\n", turbo_asar_strerror(err));
            return;
        }
        
        double elapsed = end - start;
        result.total_ms += elapsed;
        if (elapsed < result.min_ms) result.min_ms = elapsed;
        if (elapsed > result.max_ms) result.max_ms = elapsed;
        
        /* Keep last archive for extract benchmarks */
        if (i < BENCHMARK_RUNS - 1) {
            unlink(dest);
        } else {
            /* Rename to standard archive name */
            unlink(BENCH_ARCHIVE);
            rename(dest, BENCH_ARCHIVE);
        }
    }
    
    result.avg_ms = result.total_ms / BENCHMARK_RUNS;
    print_result(name, &result);
}

static void benchmark_list(void) {
    printf("\nBenchmarking list\n");
    
    benchmark_result_t result = {0};
    result.min_ms = 1e9;
    
    /* Warmup */
    for (int i = 0; i < WARMUP_RUNS; i++) {
        char **files;
        size_t count;
        turbo_asar_list(BENCH_ARCHIVE, &files, &count);
        turbo_asar_free_list(files, count);
    }
    
    /* Benchmark */
    for (int i = 0; i < BENCHMARK_RUNS; i++) {
        char **files;
        size_t count;
        
        double start = get_time_ms();
        turbo_asar_error_t err = turbo_asar_list(BENCH_ARCHIVE, &files, &count);
        double end = get_time_ms();
        
        if (err != TURBO_ASAR_OK) {
            printf("Error: %s\n", turbo_asar_strerror(err));
            return;
        }
        
        double elapsed = end - start;
        result.total_ms += elapsed;
        if (elapsed < result.min_ms) result.min_ms = elapsed;
        if (elapsed > result.max_ms) result.max_ms = elapsed;
        
        turbo_asar_free_list(files, count);
    }
    
    result.avg_ms = result.total_ms / BENCHMARK_RUNS;
    print_result("list", &result);
}

static void benchmark_extract_file(void) {
    printf("\nBenchmarking extract_file (100 iterations)\n");
    
    int iterations = 100;
    
    /* Use a file from the middle of the archive */
    const char *file_path = "dir050/file05.dat";
    
    double start = get_time_ms();
    for (int i = 0; i < iterations; i++) {
        uint8_t *buffer;
        size_t size;
        turbo_asar_error_t err = turbo_asar_extract_file(BENCH_ARCHIVE, file_path, &buffer, &size);
        if (err == TURBO_ASAR_OK) {
            free(buffer);
        }
    }
    double end = get_time_ms();
    
    double total = end - start;
    printf("%-30s total: %8.2f ms  per-op: %8.4f ms\n",
           "extract_file", total, total / iterations);
}

static void benchmark_extract_all(void) {
    printf("\nBenchmarking extract_all\n");
    
    benchmark_result_t result = {0};
    result.min_ms = 1e9;
    
    /* Warmup */
    for (int i = 0; i < WARMUP_RUNS; i++) {
        char dest[256];
        snprintf(dest, sizeof(dest), "tmp/bench_extract_warmup_%d", i);
        turbo_asar_extract_all(BENCH_ARCHIVE, dest);
        remove_directory_recursive(dest);
    }
    
    /* Benchmark */
    for (int i = 0; i < BENCHMARK_RUNS; i++) {
        char dest[256];
        snprintf(dest, sizeof(dest), "tmp/bench_extract_%d", i);
        
        double start = get_time_ms();
        turbo_asar_error_t err = turbo_asar_extract_all(BENCH_ARCHIVE, dest);
        double end = get_time_ms();
        
        if (err != TURBO_ASAR_OK) {
            printf("Error: %s\n", turbo_asar_strerror(err));
            return;
        }
        
        double elapsed = end - start;
        result.total_ms += elapsed;
        if (elapsed < result.min_ms) result.min_ms = elapsed;
        if (elapsed > result.max_ms) result.max_ms = elapsed;
        
        remove_directory_recursive(dest);
    }
    
    result.avg_ms = result.total_ms / BENCHMARK_RUNS;
    print_result("extract_all", &result);
}

static void print_separator(void) {
    printf("========================================\n");
}

int main(int argc, char *argv[]) {
    printf("turbo-asar Benchmarks\n");
    printf("Version: %s\n", turbo_asar_version());
    print_separator();
    
    /* Check for custom data size */
    int use_large_data = 1;
    if (argc > 1 && strcmp(argv[1], "--small") == 0) {
        use_large_data = 0;
        printf("\nUsing small test data (--small flag)\n");
    }

    int setup_result;
    if (use_large_data) {
        setup_result = setup_large_test_data();
    } else {
        setup_result = setup_small_test_data();
    }
    
    if (setup_result != 0) {
        printf("Failed to setup test data!\n");
        return 1;
    }

    long total_size = 0;
    if (use_large_data) {
        total_size = (long)LARGE_DIR_COUNT * FILES_PER_DIR * FILE_SIZE;
    }
    
    printf("Test data: %s\n", BENCH_DIR);
    if (total_size > 0) {
        printf("Total size: %.2f MB\n", total_size / (1024.0 * 1024.0));
    }
    
    print_separator();
    
    /* Run benchmarks */
    benchmark_pack(1);  /* with integrity */
    benchmark_pack(0);  /* without integrity */
    benchmark_list();
    benchmark_extract_file();
    benchmark_extract_all();
    
    print_separator();
    printf("\nBenchmarks complete.\n");
    
    /* Cleanup */
    printf("\nCleaning up test data...\n");
    cleanup_test_data();
    
    return 0;
}
