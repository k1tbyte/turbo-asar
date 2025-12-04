/**
 * @file asar.c
 * @brief Main ASAR archive implementation
 *
 * Created by kitbyte on 08.11.2025.
 */

/* Feature test macros for mmap/madvise on Linux */
#if !defined(__WINDOWS__)
#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "turbo_asar.h"
#include "glob.h"
#include "pickle.h"
#include "sha256.h"
#include "filesystem.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>


#ifdef __WINDOWS__
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#define stat _stat
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m) 0
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#endif

#define BLOCK_SIZE (4 * 1024 * 1024)  /* 4MB blocks for integrity */
#define MAX_PATH_LEN 4096
#define READ_BUFFER_SIZE (1024 * 1024)  /* 1MB read buffer for better I/O throughput */

static turbo_asar_error_t mkdir_recursive(const char *path)
{
    char tmp[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;
    
    len = strlen(path);
    if (len >= MAX_PATH_LEN) {
        return TURBO_ASAR_ERR_PATH_TOO_LONG;
    }
    
    memcpy(tmp, path, len + 1);
    
    /* Remove trailing separator */
    if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') {
        tmp[len - 1] = '\0';
    }
    
    /* Create directories */
    for (p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            #ifdef __WINDOWS__
            CreateDirectoryA(tmp, NULL);
            #else
            mkdir(tmp, 0755);
            #endif
            *p = PATH_SEPARATOR;
        }
    }
    
    #ifdef __WINDOWS__
    if (!CreateDirectoryA(tmp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return TURBO_ASAR_ERR_MKDIR_FAILED;
    }
    #else
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return TURBO_ASAR_ERR_MKDIR_FAILED;
    }
    #endif
    
    return TURBO_ASAR_OK;
}

/* Helper to get file size */
static int64_t get_file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    return st.st_size;
}

static bool is_executable(const char *path)
{
    #ifdef __WINDOWS__
    return false;  /* Windows doesn't have exec bit */
    #else
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return (st.st_mode & 0100) != 0;  /* Check owner execute bit */
    #endif
}

/* Calculate file integrity (SHA256 hash and block hashes) - optimized version */
static bool calculate_integrity(
    const char *path,
    char *hash_out,
    char ***blocks_out,
    size_t *block_count_out
)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Pre-calculate block count */
    size_t block_count = (file_size > 0) ? ((file_size + BLOCK_SIZE - 1) / BLOCK_SIZE) : 1;
    
    /* Allocate all block hash strings at once for better cache locality */
    char **blocks = malloc(block_count * sizeof(char*));
    if (!blocks) {
        fclose(fp);
        return false;
    }
    
    /* Allocate a single buffer for all hex strings */
    char *hex_buffer = malloc(block_count * SHA256_HEX_SIZE);
    if (!hex_buffer) {
        free(blocks);
        fclose(fp);
        return false;
    }
    for (size_t i = 0; i < block_count; i++) {
        blocks[i] = hex_buffer + (i * SHA256_HEX_SIZE);
    }
    
#if !defined(__WINDOWS__)
    /* Try mmap for large files (>4MB) on Linux for better performance */
    if (file_size > (4 * 1024 * 1024)) {
        int fd = fileno(fp);
        void *mapped = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mapped != MAP_FAILED) {
            /* Use madvise for sequential access hint (ignore failure - non-fatal) */
            (void)madvise(mapped, file_size, MADV_SEQUENTIAL);
            
            const uint8_t *data = (const uint8_t*)mapped;
            sha256_ctx_t file_ctx;
            sha256_init(&file_ctx);
            
            size_t current_block = 0;
            size_t offset = 0;
            
            while (offset < (size_t)file_size) {
                size_t block_size = BLOCK_SIZE;
                if (offset + block_size > (size_t)file_size) {
                    block_size = (size_t)file_size - offset;
                }
                
                /* Calculate block hash */
                sha256_ctx_t block_ctx;
                sha256_init(&block_ctx);
                sha256_update(&block_ctx, data + offset, block_size);
                uint8_t block_digest[SHA256_DIGEST_SIZE];
                sha256_final(&block_ctx, block_digest);
                sha256_to_hex(block_digest, blocks[current_block]);
                
                /* Also update file hash */
                sha256_update(&file_ctx, data + offset, block_size);
                
                current_block++;
                offset += block_size;
            }
            
            /* Handle empty file case */
            if (current_block == 0) {
                sha256_ctx_t block_ctx;
                sha256_init(&block_ctx);
                uint8_t block_digest[SHA256_DIGEST_SIZE];
                sha256_final(&block_ctx, block_digest);
                sha256_to_hex(block_digest, blocks[0]);
                current_block = 1;
            }
            
            /* Finalize file hash */
            uint8_t file_digest[SHA256_DIGEST_SIZE];
            sha256_final(&file_ctx, file_digest);
            sha256_to_hex(file_digest, hash_out);
            
            munmap(mapped, file_size);
            fclose(fp);
            
            *blocks_out = blocks;
            *block_count_out = current_block;
            return true;
        }
        /* mmap failed, fall through to buffered I/O */
    }
#endif

    /* Fallback: Use buffered I/O with sequential read hint (ignore failure - non-fatal) */
#if !defined(__WINDOWS__) && defined(POSIX_FADV_SEQUENTIAL)
    (void)posix_fadvise(fileno(fp), 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

    /* Use larger aligned buffer for better read performance */
    uint8_t *buffer = malloc(READ_BUFFER_SIZE);
    if (!buffer) {
        free(hex_buffer);
        free(blocks);
        fclose(fp);
        return false;
    }
    
    sha256_ctx_t file_ctx;
    sha256_init(&file_ctx);
    
    sha256_ctx_t block_ctx;
    sha256_init(&block_ctx);
    
    size_t current_block = 0;
    size_t block_bytes = 0;
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, READ_BUFFER_SIZE, fp)) > 0) {
        /* Update file hash with entire read */
        sha256_update(&file_ctx, buffer, bytes_read);
        
        /* Process blocks */
        size_t offset = 0;
        while (offset < bytes_read) {
            size_t space_in_block = BLOCK_SIZE - block_bytes;
            size_t to_add = bytes_read - offset;
            if (to_add > space_in_block) {
                to_add = space_in_block;
            }
            
            sha256_update(&block_ctx, buffer + offset, to_add);
            block_bytes += to_add;
            offset += to_add;
            
            if (block_bytes >= BLOCK_SIZE) {
                /* Finalize this block */
                uint8_t digest[SHA256_DIGEST_SIZE];
                sha256_final(&block_ctx, digest);
                sha256_to_hex(digest, blocks[current_block]);
                current_block++;
                block_bytes = 0;
                sha256_init(&block_ctx);
            }
        }
    }
    
    /* Finalize last partial block */
    if (block_bytes > 0 || current_block == 0) {
        uint8_t digest[SHA256_DIGEST_SIZE];
        sha256_final(&block_ctx, digest);
        sha256_to_hex(digest, blocks[current_block]);
        current_block++;
    }
    
    /* Finalize file hash */
    uint8_t file_digest[SHA256_DIGEST_SIZE];
    sha256_final(&file_ctx, file_digest);
    sha256_to_hex(file_digest, hash_out);
    
    free(buffer);
    fclose(fp);
    
    *blocks_out = blocks;
    *block_count_out = current_block;
    return true;
}

static void free_integrity_blocks(char **blocks, size_t count)
{
    (void)count; /* Now unused since we allocate a single buffer */
    if (!blocks) return;
    /* blocks[0] points to the start of the single allocation */
    if (blocks[0]) {
        free(blocks[0]);
    }
    free(blocks);
}

/* File entry for crawling */
typedef struct file_entry {
    char *path;
    bool is_dir;
    bool is_link;
    bool unpacked;
    struct file_entry *next;
} file_entry_t;

/* Crawl directory recursively */
static file_entry_t* crawl_directory(const char *dir_path, bool exclude_hidden)
{
    file_entry_t *head = NULL;
    file_entry_t *tail = NULL;
    
#ifdef __WINDOWS__
    char search_path[MAX_PATH_LEN];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);
    
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle = FindFirstFileA(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    
    do {
        const char *name = find_data.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (exclude_hidden && name[0] == '.') continue;
        
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, name);
        
        file_entry_t *entry = calloc(1, sizeof(file_entry_t));
        if (!entry) continue;
        
        entry->path = strdup(full_path);
        entry->is_dir = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        entry->is_link = (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        
        if (!head) {
            head = tail = entry;
        } else {
            tail->next = entry;
            tail = entry;
        }
        
        /* Recurse into directories */
        if (entry->is_dir && !entry->is_link) {
            file_entry_t *subdir = crawl_directory(full_path, exclude_hidden);
            if (subdir) {
                tail->next = subdir;
                while (tail->next) tail = tail->next;
            }
        }
    } while (FindNextFileA(find_handle, &find_data));
    
    FindClose(find_handle);
#else
    DIR *dir = opendir(dir_path);
    if (!dir) return NULL;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (exclude_hidden && name[0] == '.') continue;
        
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);
        
        struct stat st;
        if (lstat(full_path, &st) != 0) continue;
        
        file_entry_t *fe = calloc(1, sizeof(file_entry_t));
        if (!fe) continue;
        
        fe->path = strdup(full_path);
        fe->is_dir = S_ISDIR(st.st_mode);
        fe->is_link = S_ISLNK(st.st_mode);
        
        if (!head) {
            head = tail = fe;
        } else {
            tail->next = fe;
            tail = fe;
        }
        
        /* Recurse into directories (but not symlinks) */
        if (fe->is_dir && !fe->is_link) {
            file_entry_t *subdir = crawl_directory(full_path, exclude_hidden);
            if (subdir) {
                tail->next = subdir;
                while (tail->next) tail = tail->next;
            }
        }
    }
    
    closedir(dir);
#endif
    
    return head;
}

static void free_file_entries(file_entry_t *entries)
{
    while (entries) {
        file_entry_t *next = entries->next;
        free(entries->path);
        free(entries);
        entries = next;
    }
}

static char* read_symlink(const char *path)
{
#ifdef __WINDOWS__
    return NULL;  /* Not supported on Windows */
#else
    char target[MAX_PATH_LEN];
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len < 0) return NULL;
    target[len] = '\0';
    return strdup(target);
#endif
}

/* ----- Public API Implementation ----- */

const char* turbo_asar_version(void)
{
    return TURBO_ASAR_VERSION;
}

const char* turbo_asar_strerror(turbo_asar_error_t err)
{
    switch (err) {
        case TURBO_ASAR_OK: return "Success";
        case TURBO_ASAR_ERR_NULL_PARAM: return "Null parameter";
        case TURBO_ASAR_ERR_FILE_NOT_FOUND: return "File not found";
        case TURBO_ASAR_ERR_FILE_READ: return "File read error";
        case TURBO_ASAR_ERR_FILE_WRITE: return "File write error";
        case TURBO_ASAR_ERR_INVALID_ARCHIVE: return "Invalid archive";
        case TURBO_ASAR_ERR_INVALID_HEADER: return "Invalid header";
        case TURBO_ASAR_ERR_OUT_OF_MEMORY: return "Out of memory";
        case TURBO_ASAR_ERR_PATH_TOO_LONG: return "Path too long";
        case TURBO_ASAR_ERR_MKDIR_FAILED: return "Failed to create directory";
        case TURBO_ASAR_ERR_JSON_PARSE: return "JSON parse error";
        case TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE: return "File not found in archive";
        case TURBO_ASAR_ERR_IS_DIRECTORY: return "Path is a directory";
        case TURBO_ASAR_ERR_SYMLINK_OUTSIDE: return "Symlink points outside archive";
        default: return "Unknown error";
    }
}

static turbo_asar_error_t read_archive_header(
    const char *archive_path,
    char **header_json,
    size_t *header_size,
    size_t *data_offset
)
{
    FILE *fp = fopen(archive_path, "rb");
    if (!fp) {
        return TURBO_ASAR_ERR_FILE_NOT_FOUND;
    }
    
    /* Read size pickle (first 8 bytes: 4 byte header size pickle) */
    uint8_t size_buf[8];
    if (fread(size_buf, 1, 8, fp) != 8) {
        fclose(fp);
        return TURBO_ASAR_ERR_INVALID_ARCHIVE;
    }
    
    pickle_reader_t size_pickle;
    if (!pickle_reader_init(&size_pickle, size_buf, 8)) {
        fclose(fp);
        return TURBO_ASAR_ERR_INVALID_ARCHIVE;
    }
    
    uint32_t hdr_size;
    if (!pickle_read_uint32(&size_pickle, &hdr_size)) {
        fclose(fp);
        return TURBO_ASAR_ERR_INVALID_ARCHIVE;
    }
    
    /* Read header pickle */
    uint8_t *header_buf = malloc(hdr_size);
    if (!header_buf) {
        fclose(fp);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    
    if (fread(header_buf, 1, hdr_size, fp) != hdr_size) {
        free(header_buf);
        fclose(fp);
        return TURBO_ASAR_ERR_INVALID_ARCHIVE;
    }
    
    pickle_reader_t header_pickle;
    if (!pickle_reader_init(&header_pickle, header_buf, hdr_size)) {
        free(header_buf);
        fclose(fp);
        return TURBO_ASAR_ERR_INVALID_ARCHIVE;
    }
    
    char *json_str;
    if (!pickle_read_string_copy(&header_pickle, &json_str)) {
        free(header_buf);
        fclose(fp);
        return TURBO_ASAR_ERR_INVALID_HEADER;
    }
    
    *header_json = json_str;
    *header_size = hdr_size;
    *data_offset = 8 + hdr_size;
    
    free(header_buf);
    fclose(fp);
    return TURBO_ASAR_OK;
}

turbo_asar_error_t turbo_asar_pack(
    const char *src_dir,
    const char *dest_path,
    const turbo_asar_pack_options_t *options
)
{
    if (!src_dir || !dest_path) {
        return TURBO_ASAR_ERR_NULL_PARAM;
    }

    turbo_asar_pack_options_t default_opts = {0};
    default_opts.calculate_integrity = true;
    if (!options) {
        options = &default_opts;
    }


    asar_filesystem_t *fs = asar_filesystem_create(src_dir);
    if (!fs) {
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    file_entry_t *entries = crawl_directory(src_dir, options->exclude_hidden);

    char* unpack_pattern = NULL;
    if (options->unpack) {
        unpack_pattern = normalize_glob_pattern(options->unpack);
    }
    
    /* First pass: insert all entries into filesystem */
    for (file_entry_t *entry = entries; entry; entry = entry->next) {
        const char *rel_path = get_relative_path(fs, entry->path);

        bool should_unpack = false;
        if (unpack_pattern) {
            should_unpack = glob_match(unpack_pattern, rel_path);
        }

        entry->unpacked = should_unpack;

        if (entry->is_link) {
            char *target = read_symlink(entry->path);
            if (target) {
                asar_filesystem_insert_link(fs, rel_path, target, should_unpack);
                free(target);
            }
        } else if (entry->is_dir) {
            asar_filesystem_insert_directory(fs, rel_path, should_unpack);
        } else {
            int64_t size = get_file_size(entry->path);
            if (size < 0) continue;
            
            bool executable = is_executable(entry->path);
            
            char hash[SHA256_HEX_SIZE] = {0};
            char **blocks = NULL;
            size_t block_count = 0;
            
            if (options->calculate_integrity && size > 0) {
                calculate_integrity(entry->path, hash, &blocks, &block_count);
            }
            
            asar_filesystem_insert_file(
                fs, rel_path, (uint64_t)size, executable, should_unpack,
                options->calculate_integrity ? hash : NULL,
                (const char **)blocks, block_count, BLOCK_SIZE
            );
            
            free_integrity_blocks(blocks, block_count);
        }
    }

    if (unpack_pattern) {
        free(unpack_pattern);
    }

    char *header_json;
    if (!asar_filesystem_serialize_header(fs, &header_json)) {
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    pickle_writer_t header_pickle;
    if (!pickle_writer_init(&header_pickle)) {
        cJSON_free(header_json);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    
    if (!pickle_write_string(&header_pickle, header_json, strlen(header_json))) {
        pickle_writer_free(&header_pickle);
        cJSON_free(header_json);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    cJSON_free(header_json);
    
    size_t header_size;
    const uint8_t *header_data = pickle_writer_data(&header_pickle, &header_size);

    pickle_writer_t size_pickle;
    if (!pickle_writer_init(&size_pickle)) {
        pickle_writer_free(&header_pickle);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    
    if (!pickle_write_uint32(&size_pickle, (uint32_t)header_size)) {
        pickle_writer_free(&size_pickle);
        pickle_writer_free(&header_pickle);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    
    /* Ensure output directory exists */
    char *dir_copy = strdup(dest_path);
    if (dir_copy) {
        char *last_sep = strrchr(dir_copy, '/');
        #ifdef __WINDOWS__
        char *last_sep_win = strrchr(dir_copy, '\\');
        if (last_sep_win > last_sep) last_sep = last_sep_win;
        #endif
        if (last_sep) {
            *last_sep = '\0';
            mkdir_recursive(dir_copy);
        }
        free(dir_copy);
    }
    
    /* Write output file */
    FILE *out = fopen(dest_path, "wb");
    if (!out) {
        pickle_writer_free(&size_pickle);
        pickle_writer_free(&header_pickle);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_FILE_WRITE;
    }

    size_t size_len;
    const uint8_t *size_data = pickle_writer_data(&size_pickle, &size_len);
    fwrite(size_data, 1, size_len, out);
    fwrite(header_data, 1, header_size, out);
    
    pickle_writer_free(&size_pickle);
    pickle_writer_free(&header_pickle);
    
    /* Write file contents */
    uint8_t *buffer = malloc(READ_BUFFER_SIZE);
    if (!buffer) {
        fclose(out);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    /* Second pass: write file data */
    for (file_entry_t *entry = entries; entry; entry = entry->next) {
        if (entry->is_dir || entry->is_link || entry->unpacked) continue;
        
        FILE *in = fopen(entry->path, "rb");
        if (!in) continue;
        
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, READ_BUFFER_SIZE, in)) > 0) {
            fwrite(buffer, 1, bytes_read, out);
        }
        
        fclose(in);
    }
    
    free(buffer);
    fclose(out);
    free_file_entries(entries);
    asar_filesystem_free(fs);
    
    return TURBO_ASAR_OK;
}

/* Simple hash table for caching created directories */
#define DIR_CACHE_SIZE 1024
#define DIR_CACHE_MASK (DIR_CACHE_SIZE - 1)

typedef struct dir_cache_entry {
    char *path;
    struct dir_cache_entry *next;
} dir_cache_entry_t;

typedef struct {
    dir_cache_entry_t *buckets[DIR_CACHE_SIZE];
} dir_cache_t;

static unsigned int dir_hash(const char *str) {
    unsigned int hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (unsigned char)*str++;
    }
    return hash & DIR_CACHE_MASK;
}

static dir_cache_t *dir_cache_create(void) {
    dir_cache_t *cache = calloc(1, sizeof(dir_cache_t));
    return cache;
}

static void dir_cache_free(dir_cache_t *cache) {
    if (!cache) return;
    for (int i = 0; i < DIR_CACHE_SIZE; i++) {
        dir_cache_entry_t *entry = cache->buckets[i];
        while (entry) {
            dir_cache_entry_t *next = entry->next;
            free(entry->path);
            free(entry);
            entry = next;
        }
    }
    free(cache);
}

static bool dir_cache_contains(dir_cache_t *cache, const char *path) {
    unsigned int h = dir_hash(path);
    dir_cache_entry_t *entry = cache->buckets[h];
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            return true;
        }
        entry = entry->next;
    }
    return false;
}

static void dir_cache_add(dir_cache_t *cache, const char *path) {
    unsigned int h = dir_hash(path);
    dir_cache_entry_t *entry = malloc(sizeof(dir_cache_entry_t));
    if (entry) {
        entry->path = strdup(path);
        if (!entry->path) {
            free(entry);
            return;  /* strdup failed, don't add to cache */
        }
        entry->next = cache->buckets[h];
        cache->buckets[h] = entry;
    }
}

/* Helper to create parent directory for a file path with caching */
static void create_parent_directory_cached(char *path, dir_cache_t *cache) {
    char *last_sep = strrchr(path, '/');
    #ifdef __WINDOWS__
    char *last_sep_win = strrchr(path, '\\');
    if (last_sep_win > last_sep) last_sep = last_sep_win;
    #endif
    if (last_sep) {
        char saved = *last_sep;
        *last_sep = '\0';
        
        /* Only create if not in cache */
        if (!dir_cache_contains(cache, path)) {
            mkdir_recursive(path);
            dir_cache_add(cache, path);
        }
        
        *last_sep = saved;
    }
}

/* Helper to create parent directory for a file path (modifies path in-place temporarily) */
static void create_parent_directory(char *path) {
    char *last_sep = strrchr(path, '/');
    #ifdef __WINDOWS__
    char *last_sep_win = strrchr(path, '\\');
    if (last_sep_win > last_sep) last_sep = last_sep_win;
    #endif
    if (last_sep) {
        char saved = *last_sep;
        *last_sep = '\0';
        mkdir_recursive(path);
        *last_sep = saved;
    }
}

turbo_asar_error_t turbo_asar_extract_all(
    const char *archive_path,
    const char *dest_dir
)
{
    if (!archive_path || !dest_dir) {
        return TURBO_ASAR_ERR_NULL_PARAM;
    }

    char *header_json;
    size_t header_size;
    size_t data_offset;
    turbo_asar_error_t err = read_archive_header(archive_path, &header_json, &header_size, &data_offset);
    if (err != TURBO_ASAR_OK) {
        return err;
    }

    cJSON *header = cJSON_Parse(header_json);
    free(header_json);
    if (!header) {
        return TURBO_ASAR_ERR_JSON_PARSE;
    }

    asar_filesystem_t *fs = asar_filesystem_create(archive_path);
    if (!fs) {
        cJSON_Delete(header);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    asar_filesystem_set_header(fs, header, header_size);

    err = mkdir_recursive(dest_dir);
    if (err != TURBO_ASAR_OK) {
        asar_filesystem_free(fs);
        return err;
    }
    
    /* List all files */
    char **files;
    size_t file_count;
    if (!asar_filesystem_list_files(fs, &files, &file_count)) {
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    /* Get archive file size for mmap */
    FILE *archive = fopen(archive_path, "rb");
    if (!archive) {
        turbo_asar_free_list(files, file_count);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_FILE_NOT_FOUND;
    }
    
    fseek(archive, 0, SEEK_END);
    long archive_size = ftell(archive);
    fseek(archive, 0, SEEK_SET);

#if !defined(__WINDOWS__)
    /* Try to mmap the archive for faster extraction */
    void *archive_map = NULL;
    int archive_fd = fileno(archive);
    
    if (archive_size > 0) {
        archive_map = mmap(NULL, archive_size, PROT_READ, MAP_PRIVATE, archive_fd, 0);
        if (archive_map != MAP_FAILED) {
            /* Sequential access hint for better performance */
            (void)madvise(archive_map, archive_size, MADV_SEQUENTIAL);
        } else {
            archive_map = NULL;  /* Fall back to standard I/O */
        }
    }
#endif

    uint8_t *buffer = malloc(READ_BUFFER_SIZE);
    if (!buffer) {
#if !defined(__WINDOWS__)
        if (archive_map) munmap(archive_map, archive_size);
#endif
        fclose(archive);
        turbo_asar_free_list(files, file_count);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    
    /* Create directory cache to avoid redundant mkdir calls */
    dir_cache_t *dir_cache = dir_cache_create();
    
    /* Extract each file */
    for (size_t i = 0; i < file_count; i++) {
        const char *rel_path = files[i];
        while (*rel_path == '/' || *rel_path == '\\') rel_path++;
        
        char dest_path[MAX_PATH_LEN];
        snprintf(dest_path, sizeof(dest_path), "%s%c%s", dest_dir, PATH_SEPARATOR, rel_path);
        
        asar_entry_info_t info;
        #ifdef __WINDOWS__
        bool follow_links = true;  /* Windows: extract links as files */
        #else
        bool follow_links = false;
        #endif
        
        if (!asar_filesystem_get_entry(fs, files[i], follow_links, &info)) {
            continue;
        }
        
        if (info.type == ASAR_ENTRY_DIRECTORY) {
            if (!dir_cache || !dir_cache_contains(dir_cache, dest_path)) {
                mkdir_recursive(dest_path);
                if (dir_cache) dir_cache_add(dir_cache, dest_path);
            }
        }
        else if (info.type == ASAR_ENTRY_LINK) {
            #ifndef __WINDOWS__
            if (dir_cache) {
                create_parent_directory_cached(dest_path, dir_cache);
            } else {
                create_parent_directory(dest_path);
            }
            
            /* Remove existing file/link */
            unlink(dest_path);
            
            /* Create symlink (ignore failure - we can't do much about it) */
            if (info.link) {
                int ret = symlink(info.link, dest_path);
                (void)ret;  /* Suppress unused result warning */
            }
            #endif
        }
        else if (info.type == ASAR_ENTRY_FILE) {
            if (dir_cache) {
                create_parent_directory_cached(dest_path, dir_cache);
            } else {
                create_parent_directory(dest_path);
            }
            
            if (info.unpacked) {
                char unpacked_path[MAX_PATH_LEN];
                snprintf(unpacked_path, sizeof(unpacked_path), "%s.unpacked%c%s",
                        archive_path, PATH_SEPARATOR, rel_path);

                /* Prevent copying file onto itself */
                if (strcmp(unpacked_path, dest_path) == 0) {
                    asar_entry_info_free(&info);
                    continue;
                }
                
                FILE *src = fopen(unpacked_path, "rb");
                if (src) {
                    FILE *dst = fopen(dest_path, "wb");
                    if (dst) {
                        size_t bytes;
                        while ((bytes = fread(buffer, 1, READ_BUFFER_SIZE, src)) > 0) {
                            fwrite(buffer, 1, bytes, dst);
                        }
                        fclose(dst);
                    }
                    fclose(src);
                }
            }
            else if (info.size > 0) {
                FILE *out = fopen(dest_path, "wb");
                if (out) {
#if !defined(__WINDOWS__)
                    if (archive_map) {
                        /* Fast path: write directly from mmap */
                        size_t file_offset = data_offset + info.offset;
                        /* Check for overflow and bounds */
                        if (file_offset >= data_offset && /* No overflow from addition */
                            file_offset <= (size_t)archive_size && /* Offset within bounds */
                            info.size <= (size_t)archive_size - file_offset) { /* Size within bounds */
                            fwrite((uint8_t*)archive_map + file_offset, 1, info.size, out);
                        }
                    } else
#endif
                    {
                        /* Fallback: standard buffered I/O */
                        long file_offset = (long)(data_offset + info.offset);
                        fseek(archive, file_offset, SEEK_SET);
                        
                        uint64_t remaining = info.size;
                        while (remaining > 0) {
                            size_t to_read = remaining > READ_BUFFER_SIZE ? READ_BUFFER_SIZE : (size_t)remaining;
                            size_t bytes = fread(buffer, 1, to_read, archive);
                            if (bytes == 0) break;
                            fwrite(buffer, 1, bytes, out);
                            remaining -= bytes;
                        }
                    }
                    fclose(out);
                    
                    #ifndef __WINDOWS__
                    if (info.executable) {
                        chmod(dest_path, 0755);
                    }
                    #endif
                }
            } else {
                /* Empty file */
                FILE *out = fopen(dest_path, "wb");
                if (out) fclose(out);
            }
        }
        
        asar_entry_info_free(&info);
    }
    
    dir_cache_free(dir_cache);
    free(buffer);
#if !defined(__WINDOWS__)
    if (archive_map) munmap(archive_map, archive_size);
#endif
    fclose(archive);
    turbo_asar_free_list(files, file_count);
    asar_filesystem_free(fs);
    
    return TURBO_ASAR_OK;
}

turbo_asar_error_t turbo_asar_extract_file(
    const char *archive_path,
    const char *file_path,
    uint8_t **buffer,
    size_t *size
)
{
    if (!archive_path || !file_path || !buffer || !size) {
        return TURBO_ASAR_ERR_NULL_PARAM;
    }
    
    *buffer = NULL;
    *size = 0;

    char *header_json;
    size_t header_size;
    size_t data_offset;
    turbo_asar_error_t err = read_archive_header(archive_path, &header_json, &header_size, &data_offset);
    if (err != TURBO_ASAR_OK) {
        return err;
    }

    cJSON *header = cJSON_Parse(header_json);
    free(header_json);
    if (!header) {
        return TURBO_ASAR_ERR_JSON_PARSE;
    }

    asar_filesystem_t *fs = asar_filesystem_create(archive_path);
    if (!fs) {
        cJSON_Delete(header);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    asar_filesystem_set_header(fs, header, header_size);

    asar_entry_info_t info;
    if (!asar_filesystem_get_entry(fs, file_path, true, &info)) {
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE;
    }
    
    if (info.type != ASAR_ENTRY_FILE) {
        asar_entry_info_free(&info);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_IS_DIRECTORY;
    }

    *buffer = malloc(info.size > 0 ? info.size : 1);
    if (!*buffer) {
        asar_entry_info_free(&info);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    *size = (size_t)info.size;
    
    if (info.size > 0) {
        if (info.unpacked) {
            /* Read from unpacked directory */
            const char *rel_path = file_path;
            while (*rel_path == '/' || *rel_path == '\\') rel_path++;
            
            char unpacked_path[MAX_PATH_LEN];
            snprintf(unpacked_path, sizeof(unpacked_path), "%s.unpacked%c%s",
                    archive_path, PATH_SEPARATOR, rel_path);
            
            FILE *fp = fopen(unpacked_path, "rb");
            if (!fp) {
                free(*buffer);
                *buffer = NULL;
                asar_entry_info_free(&info);
                asar_filesystem_free(fs);
                return TURBO_ASAR_ERR_FILE_NOT_FOUND;
            }
            if (fread(*buffer, 1, info.size, fp) != info.size) {
                free(*buffer);
                *buffer = NULL;
                fclose(fp);
                asar_entry_info_free(&info);
                asar_filesystem_free(fs);
                return TURBO_ASAR_ERR_FILE_READ;
            }
            fclose(fp);
        } else {
            /* Read from archive */
            FILE *fp = fopen(archive_path, "rb");
            if (!fp) {
                free(*buffer);
                *buffer = NULL;
                asar_entry_info_free(&info);
                asar_filesystem_free(fs);
                return TURBO_ASAR_ERR_FILE_NOT_FOUND;
            }
            
            long file_offset = (long)(data_offset + info.offset);
            fseek(fp, file_offset, SEEK_SET);
            if (fread(*buffer, 1, info.size, fp) != info.size) {
                free(*buffer);
                *buffer = NULL;
                fclose(fp);
                asar_entry_info_free(&info);
                asar_filesystem_free(fs);
                return TURBO_ASAR_ERR_FILE_READ;
            }
            fclose(fp);
        }
    }
    
    asar_entry_info_free(&info);
    asar_filesystem_free(fs);
    return TURBO_ASAR_OK;
}

turbo_asar_error_t turbo_asar_list(
    const char *archive_path,
    char ***files,
    size_t *count
)
{
    if (!archive_path || !files || !count) {
        return TURBO_ASAR_ERR_NULL_PARAM;
    }
    
    *files = NULL;
    *count = 0;

    char *header_json;
    size_t header_size;
    size_t data_offset;
    turbo_asar_error_t err = read_archive_header(archive_path, &header_json, &header_size, &data_offset);
    if (err != TURBO_ASAR_OK) {
        return err;
    }

    cJSON *header = cJSON_Parse(header_json);
    free(header_json);
    if (!header) {
        return TURBO_ASAR_ERR_JSON_PARSE;
    }

    asar_filesystem_t *fs = asar_filesystem_create(archive_path);
    if (!fs) {
        cJSON_Delete(header);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    asar_filesystem_set_header(fs, header, header_size);

    if (!asar_filesystem_list_files(fs, files, count)) {
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    
    asar_filesystem_free(fs);
    return TURBO_ASAR_OK;
}

turbo_asar_error_t turbo_asar_get_header(
    const char *archive_path,
    char **header_json
)
{
    if (!archive_path || !header_json) {
        return TURBO_ASAR_ERR_NULL_PARAM;
    }
    
    size_t header_size;
    size_t data_offset;
    return read_archive_header(archive_path, header_json, &header_size, &data_offset);
}

turbo_asar_error_t turbo_asar_stat(
    const char *archive_path,
    const char *file_path,
    turbo_asar_entry_t *entry
)
{
    if (!archive_path || !file_path || !entry) {
        return TURBO_ASAR_ERR_NULL_PARAM;
    }
    
    memset(entry, 0, sizeof(*entry));
    
    /* Read header */
    char *header_json;
    size_t header_size;
    size_t data_offset;
    turbo_asar_error_t err = read_archive_header(archive_path, &header_json, &header_size, &data_offset);
    if (err != TURBO_ASAR_OK) {
        return err;
    }
    
    /* Parse JSON */
    cJSON *header = cJSON_Parse(header_json);
    free(header_json);
    if (!header) {
        return TURBO_ASAR_ERR_JSON_PARSE;
    }
    
    /* Create filesystem from header */
    asar_filesystem_t *fs = asar_filesystem_create(archive_path);
    if (!fs) {
        cJSON_Delete(header);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    asar_filesystem_set_header(fs, header, header_size);
    
    /* Get entry info */
    asar_entry_info_t info;
    if (!asar_filesystem_get_entry(fs, file_path, true, &info)) {
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE;
    }
    
    /* Convert to public struct */
    switch (info.type) {
        case ASAR_ENTRY_FILE:
            entry->type = TURBO_ASAR_ENTRY_FILE;
            break;
        case ASAR_ENTRY_DIRECTORY:
            entry->type = TURBO_ASAR_ENTRY_DIRECTORY;
            break;
        case ASAR_ENTRY_LINK:
            entry->type = TURBO_ASAR_ENTRY_LINK;
            break;
    }
    entry->size = info.size;
    entry->offset = info.offset;
    entry->unpacked = info.unpacked;
    entry->executable = info.executable;
    
    if (info.link) {
        entry->link = strdup(info.link);
    }
    
    /* Copy integrity info if present */
    if (info.integrity_hash) {
        entry->integrity = calloc(1, sizeof(turbo_asar_integrity_t));
        if (entry->integrity) {
            strcpy(entry->integrity->algorithm, "SHA256");
            strncpy(entry->integrity->hash, info.integrity_hash, 64);
            entry->integrity->hash[64] = '\0';
            entry->integrity->block_size = info.integrity_block_size;
            
            if (info.integrity_blocks && info.integrity_block_count > 0) {
                entry->integrity->blocks = malloc(info.integrity_block_count * sizeof(char*));
                if (entry->integrity->blocks) {
                    entry->integrity->block_count = info.integrity_block_count;
                    for (size_t i = 0; i < info.integrity_block_count; i++) {
                        entry->integrity->blocks[i] = info.integrity_blocks[i] ? 
                            strdup(info.integrity_blocks[i]) : NULL;
                    }
                }
            }
        }
    }
    
    asar_entry_info_free(&info);
    asar_filesystem_free(fs);
    return TURBO_ASAR_OK;
}

void turbo_asar_free_list(char **files, size_t count)
{
    if (!files) return;
    for (size_t i = 0; i < count; i++) {
        free(files[i]);
    }
    free(files);
}

void turbo_asar_free_entry(turbo_asar_entry_t *entry)
{
    if (!entry) return;
    
    if (entry->link) {
        free(entry->link);
        entry->link = NULL;
    }
    if (entry->integrity) {
        turbo_asar_free_integrity(entry->integrity);
        free(entry->integrity);
        entry->integrity = NULL;
    }
}

void turbo_asar_free_integrity(turbo_asar_integrity_t *integrity)
{
    if (!integrity) return;
    
    if (integrity->blocks) {
        for (size_t i = 0; i < integrity->block_count; i++) {
            free(integrity->blocks[i]);
        }
        free(integrity->blocks);
        integrity->blocks = NULL;
    }
}
