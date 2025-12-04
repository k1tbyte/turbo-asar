/**
 * @file benchmark_sha256.c
 * @brief SHA256 performance comparison: turbo-asar vs OpenSSL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
static double get_time_ms(void) {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)freq.QuadPart;
}
#else
#include <sys/time.h>
static double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}
#endif

#include "sha256.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

#define WARMUP_ITERATIONS 5
#define BENCHMARK_ITERATIONS 20

typedef struct {
    double min_ms;
    double max_ms;
    double avg_ms;
    double throughput_mbps;
} benchmark_result_t;

static void generate_test_data(uint8_t *buffer, size_t size) {
    /* Use a simple LCG for reproducible pseudo-random data */
    uint32_t state = 0xDEADBEEF;
    for (size_t i = 0; i < size; i++) {
        state = state * 1103515245 + 12345;
        buffer[i] = (uint8_t)(state >> 16);
    }
}

static benchmark_result_t benchmark_turbo_sha256(const uint8_t *data, size_t size) {
    benchmark_result_t result = {0};
    result.min_ms = 1e9;
    
    uint8_t digest[SHA256_DIGEST_SIZE];
    
    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        sha256_hash(data, size, digest);
    }
    
    /* Benchmark */
    double total_ms = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        double start = get_time_ms();
        sha256_hash(data, size, digest);
        double elapsed = get_time_ms() - start;
        
        total_ms += elapsed;
        if (elapsed < result.min_ms) result.min_ms = elapsed;
        if (elapsed > result.max_ms) result.max_ms = elapsed;
    }
    
    result.avg_ms = total_ms / BENCHMARK_ITERATIONS;
    result.throughput_mbps = (size / (1024.0 * 1024.0)) / (result.avg_ms / 1000.0);
    
    return result;
}

static benchmark_result_t benchmark_openssl_sha256(const uint8_t *data, size_t size) {
    benchmark_result_t result = {0};
    result.min_ms = 1e9;
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    
    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        SHA256(data, size, digest);
    }
    
    /* Benchmark */
    double total_ms = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        double start = get_time_ms();
        SHA256(data, size, digest);
        double elapsed = get_time_ms() - start;
        
        total_ms += elapsed;
        if (elapsed < result.min_ms) result.min_ms = elapsed;
        if (elapsed > result.max_ms) result.max_ms = elapsed;
    }
    
    result.avg_ms = total_ms / BENCHMARK_ITERATIONS;
    result.throughput_mbps = (size / (1024.0 * 1024.0)) / (result.avg_ms / 1000.0);
    
    return result;
}

static benchmark_result_t benchmark_openssl_evp_sha256(const uint8_t *data, size_t size) {
    benchmark_result_t result = {0};
    result.min_ms = 1e9;
    
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("ERROR: Failed to create EVP_MD_CTX\n");
        return result;
    }
    
    /* Warmup - reuse context */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, data, size);
        EVP_DigestFinal_ex(ctx, digest, &digest_len);
    }
    
    /* Benchmark - reuse context */
    double total_ms = 0;
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        double start = get_time_ms();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, data, size);
        EVP_DigestFinal_ex(ctx, digest, &digest_len);
        double elapsed = get_time_ms() - start;
        
        total_ms += elapsed;
        if (elapsed < result.min_ms) result.min_ms = elapsed;
        if (elapsed > result.max_ms) result.max_ms = elapsed;
    }
    
    EVP_MD_CTX_free(ctx);
    
    result.avg_ms = total_ms / BENCHMARK_ITERATIONS;
    result.throughput_mbps = (size / (1024.0 * 1024.0)) / (result.avg_ms / 1000.0);
    
    return result;
}

static void verify_correctness(const uint8_t *data, size_t size) {
    /* Verify both implementations produce the same hash */
    uint8_t pico_digest[SHA256_DIGEST_SIZE];
    unsigned char openssl_digest[SHA256_DIGEST_LENGTH];
    
    sha256_hash(data, size, pico_digest);
    SHA256(data, size, openssl_digest);
    
    if (memcmp(pico_digest, openssl_digest, SHA256_DIGEST_SIZE) != 0) {
        printf("ERROR: Hash mismatch between turbo-asar and OpenSSL!\n");
        printf("  turbo-asar: ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) printf("%02x", pico_digest[i]);
        printf("\n  OpenSSL:   ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", openssl_digest[i]);
        printf("\n");
        exit(1);
    }
}

static void print_separator(void) {
    printf("+---------------+------------+------------+------------+--------------+\n");
}

static void print_header(void) {
    print_separator();
    printf("| %-13s | %-10s | %-10s | %-10s | %-12s |\n",
           "Data Size", "Min (ms)", "Avg (ms)", "Max (ms)", "Throughput");
    print_separator();
}

static void print_result(const char *label, const benchmark_result_t *r) {
    printf("| %-13s | %10.3f | %10.3f | %10.3f | %8.2f MB/s |\n",
           label, r->min_ms, r->avg_ms, r->max_ms, r->throughput_mbps);
}

int main(void) {
    printf("==========================================================================\n");
    printf("              SHA256 Performance Comparison: turbo-asar vs OpenSSL\n");
    printf("==========================================================================\n\n");
    printf("Iterations per test: %d (+ %d warmup)\n", BENCHMARK_ITERATIONS, WARMUP_ITERATIONS);
    printf("\n");
    
    /* Test data sizes: 1KB, 64KB, 1MB, 10MB, 100MB */
    size_t sizes[] = {
        1 * 1024,           /* 1 KB */
        64 * 1024,          /* 64 KB */
        1 * 1024 * 1024,    /* 1 MB */
        10 * 1024 * 1024,   /* 10 MB */
        100 * 1024 * 1024   /* 100 MB */
    };
    const char *size_labels[] = {"1 KB", "64 KB", "1 MB", "10 MB", "100 MB"};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    
    /* Allocate arrays to store benchmark results */
    benchmark_result_t *pico_results = malloc(num_sizes * sizeof(benchmark_result_t));
    benchmark_result_t *openssl_results = malloc(num_sizes * sizeof(benchmark_result_t));
    benchmark_result_t *evp_results = malloc(num_sizes * sizeof(benchmark_result_t));
    
    /* Allocate test buffer for largest size */
    uint8_t *test_data = malloc(sizes[num_sizes - 1]);
    if (!test_data || !pico_results || !openssl_results || !evp_results) {
        printf("Failed to allocate memory\n");
        free(test_data);
        free(pico_results);
        free(openssl_results);
        free(evp_results);
        return 1;
    }
    
    printf("Generating test data...\n");
    generate_test_data(test_data, sizes[num_sizes - 1]);
    printf("Done.\n\n");
    
    /* Verify correctness first */
    printf("Verifying hash correctness...\n");
    for (int i = 0; i < num_sizes; i++) {
        verify_correctness(test_data, sizes[i]);
    }
    printf("All hashes match. ✓\n\n");
    
    /* Run benchmarks for each size and store results */
    for (int i = 0; i < num_sizes; i++) {
        size_t size = sizes[i];
        const char *label = size_labels[i];
        
        printf("Benchmarking %s:\n", label);
        
        printf("\n  turbo-asar SHA256:\n");
        print_header();
        pico_results[i] = benchmark_turbo_sha256(test_data, size);
        print_result(label, &pico_results[i]);
        print_separator();
        
        printf("\n  OpenSSL SHA256 (legacy):\n");
        print_header();
        openssl_results[i] = benchmark_openssl_sha256(test_data, size);
        print_result(label, &openssl_results[i]);
        print_separator();
        
        printf("\n  OpenSSL EVP SHA256:\n");
        print_header();
        evp_results[i] = benchmark_openssl_evp_sha256(test_data, size);
        print_result(label, &evp_results[i]);
        print_separator();
        
        /* Print comparison */
        printf("\n  Summary for %s:\n", label);
        printf("  ┌───────────────────┬──────────────┬────────────────────┐\n");
        printf("  │ Implementation    │ Throughput   │ vs turbo-asar       │\n");
        printf("  ├───────────────────┼──────────────┼────────────────────┤\n");
        printf("  │ turbo-asar         │ %8.2f MB/s │ (baseline)         │\n", pico_results[i].throughput_mbps);
        printf("  │ OpenSSL (legacy)  │ %8.2f MB/s │ %+.1f%%             │\n",
               openssl_results[i].throughput_mbps,
               ((openssl_results[i].throughput_mbps / pico_results[i].throughput_mbps) - 1.0) * 100.0);
        printf("  │ OpenSSL EVP       │ %8.2f MB/s │ %+.1f%%             │\n",
               evp_results[i].throughput_mbps,
               ((evp_results[i].throughput_mbps / pico_results[i].throughput_mbps) - 1.0) * 100.0);
        printf("  └───────────────────┴──────────────┴────────────────────┘\n");
        printf("\n");
    }
    
    /* Final summary table - using stored results */
    printf("\n");
    printf("==========================================================================\n");
    printf("                         FINAL COMPARISON TABLE\n");
    printf("==========================================================================\n\n");
    
    printf("┌────────────┬─────────────────────────────────────────────────────────────┐\n");
    printf("│ Data Size  │                    Throughput (MB/s)                        │\n");
    printf("│            ├───────────────┬───────────────┬───────────────┬─────────────┤\n");
    printf("│            │  turbo-asar    │ OpenSSL       │ OpenSSL EVP   │ Winner      │\n");
    printf("├────────────┼───────────────┼───────────────┼───────────────┼─────────────┤\n");
    
    for (int i = 0; i < num_sizes; i++) {
        const char *winner;
        if (pico_results[i].throughput_mbps >= openssl_results[i].throughput_mbps && 
            pico_results[i].throughput_mbps >= evp_results[i].throughput_mbps) {
            winner = "turbo-asar";
        } else if (openssl_results[i].throughput_mbps >= evp_results[i].throughput_mbps) {
            winner = "OpenSSL";
        } else {
            winner = "OpenSSL EVP";
        }
        
        printf("│ %-10s │ %10.2f    │ %10.2f    │ %10.2f    │ %-11s │\n",
               size_labels[i], pico_results[i].throughput_mbps, 
               openssl_results[i].throughput_mbps, evp_results[i].throughput_mbps, winner);
    }
    
    printf("└────────────┴───────────────┴───────────────┴───────────────┴─────────────┘\n");
    
    free(test_data);
    free(pico_results);
    free(openssl_results);
    free(evp_results);
    
    printf("\nBenchmark complete.\n");
    return 0;
}
