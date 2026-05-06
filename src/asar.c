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
#include "ta_thread.h"
#include "ta_io.h"
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
#define ta_fseek64(fp, off, whence) _fseeki64((fp), (long long)(off), (whence))
#define ta_ftell64(fp) _ftelli64(fp)
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#define ta_fseek64(fp, off, whence) fseeko((fp), (off_t)(off), (whence))
#define ta_ftell64(fp) ((int64_t)ftello(fp))
#endif

#define BLOCK_SIZE (4 * 1024 * 1024)  /* 4 MB blocks for integrity */
#define MAX_PATH_LEN 4096
#define READ_BUFFER_SIZE (1024 * 1024)  /* 1 MB read buffer */

/* 64-char placeholder used while building the header before real SHA-256
 * hashes are known. Length matches a real hex digest, so the serialized
 * header byte length is invariant w.r.t. real hashes — required for
 * single-pass pack with in-place header patching. */
/* (placeholder no longer needed: pack now hashes BEFORE serializing the header) */

static turbo_asar_error_t mkdir_recursive(const char *path)
{
    char tmp[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;

    if (!path) return TURBO_ASAR_ERR_NULL_PARAM;
    len = strlen(path);
    if (len == 0) return TURBO_ASAR_OK;
    if (len >= MAX_PATH_LEN) {
        return TURBO_ASAR_ERR_PATH_TOO_LONG;
    }

    memcpy(tmp, path, len + 1);

    /* Remove trailing separator (only if not the only character) */
    if (len > 1 && (tmp[len - 1] == '/' || tmp[len - 1] == '\\')) {
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
    return (int64_t)st.st_size;
}

static bool is_executable(const char *path)
{
    #ifdef __WINDOWS__
    (void)path;
    return false;  /* Windows doesn't have exec bit */
    #else
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return (st.st_mode & 0100) != 0;  /* Check owner execute bit */
    #endif
}

/* File entry for crawling */
typedef struct file_entry {
    char *path;
    bool is_dir;
    bool is_link;
    bool unpacked;
    bool executable;
    bool has_integrity;        /* set if real hashes will be computed */
    uint64_t size;             /* file size (files only) */
    uint64_t data_offset;      /* offset within the archive's data section */
    char *symlink_target;      /* readlink target (links only) */
    /* Integrity (allocated only when has_integrity) */
    size_t block_count;
    char *file_hash;           /* SHA256_HEX_SIZE bytes incl. NUL */
    char *block_hashes_buf;    /* block_count * SHA256_HEX_SIZE bytes (contiguous) */
    char **block_hashes_arr;   /* block_count slots, each into block_hashes_buf */
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
        if (!entry->path) {
            free(entry);
            continue;
        }
        entry->is_dir = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        entry->is_link = (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

        if (!head) {
            head = tail = entry;
        } else {
            tail->next = entry;
            tail = entry;
        }

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
        if (!fe->path) {
            free(fe);
            continue;
        }
        fe->is_dir = S_ISDIR(st.st_mode);
        fe->is_link = S_ISLNK(st.st_mode);

        if (!head) {
            head = tail = fe;
        } else {
            tail->next = fe;
            tail = fe;
        }

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
        free(entries->symlink_target);
        free(entries->file_hash);
        free(entries->block_hashes_buf);
        free(entries->block_hashes_arr);
        free(entries);
        entries = next;
    }
}

static char* read_symlink(const char *path)
{
#ifdef __WINDOWS__
    (void)path;
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
    uint64_t *data_offset
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
    *data_offset = (uint64_t)8 + hdr_size;

    free(header_buf);
    fclose(fp);
    return TURBO_ASAR_OK;
}

/* Stream a file: copy from input to output, update file + per-block SHA-256
 * if has_integrity. Block hashes are written into entry->block_hashes_arr[i]
 * (each pointing into entry->block_hashes_buf). */
/* stream_file_to_archive removed: pack path now uses parallel mmap+pwrite. */

/* ----- Parallel SHA-256 pre-pass -----
 *
 * Hashes are computed in worker threads BEFORE the data write phase, so the
 * write phase becomes a pure copy. Buffers (file_hash, block_hashes_arr) are
 * pre-allocated by the main thread during stat/insert, so workers only fill
 * already-owned memory. No shared state between workers except the work
 * queue index. */

#define HASH_WORKER_BUF_SIZE (256 * 1024)
#define HASH_PARALLEL_MIN_FILES 4
#define HASH_PARALLEL_THREAD_CAP 8

typedef struct pack_work {
    file_entry_t **entries;
    size_t count;
    size_t next_idx;
    ta_mutex_t mutex;
} pack_work_t;

static void compute_entry_integrity(file_entry_t *e, uint8_t *buffer)
{
    if (!e->has_integrity) return;

    FILE *fp = fopen(e->path, "rb");
    if (!fp) return;

    sha256_ctx_t fctx, bctx;
    sha256_init(&fctx);
    sha256_init(&bctx);

    size_t block_bytes = 0;
    size_t cur_block = 0;
    size_t n;

    while ((n = fread(buffer, 1, HASH_WORKER_BUF_SIZE, fp)) > 0) {
        sha256_update(&fctx, buffer, n);

        size_t off = 0;
        while (off < n) {
            size_t space = BLOCK_SIZE - block_bytes;
            size_t to_add = n - off;
            if (to_add > space) to_add = space;
            sha256_update(&bctx, buffer + off, to_add);
            block_bytes += to_add;
            off += to_add;

            if (block_bytes >= BLOCK_SIZE) {
                uint8_t d[SHA256_DIGEST_SIZE];
                sha256_final(&bctx, d);
                if (cur_block < e->block_count) {
                    sha256_to_hex(d, e->block_hashes_arr[cur_block]);
                }
                cur_block++;
                block_bytes = 0;
                sha256_init(&bctx);
            }
        }
    }

    if (block_bytes > 0 || cur_block == 0) {
        uint8_t d[SHA256_DIGEST_SIZE];
        sha256_final(&bctx, d);
        if (cur_block < e->block_count) {
            sha256_to_hex(d, e->block_hashes_arr[cur_block]);
        }
    }

    uint8_t df[SHA256_DIGEST_SIZE];
    sha256_final(&fctx, df);
    sha256_to_hex(df, e->file_hash);

    fclose(fp);
}

static void *hash_worker(void *arg)
{
    pack_work_t *w = (pack_work_t *)arg;
    uint8_t *buf = (uint8_t *)malloc(HASH_WORKER_BUF_SIZE);
    if (!buf) return NULL;

    for (;;) {
        ta_mutex_lock(&w->mutex);
        size_t i = w->next_idx;
        if (i < w->count) w->next_idx = i + 1;
        ta_mutex_unlock(&w->mutex);

        if (i >= w->count) break;
        compute_entry_integrity(w->entries[i], buf);
    }

    free(buf);
    return NULL;
}

static int decide_thread_count(int requested, size_t work_items)
{
    if (requested == 1) return 1;
    if (work_items < HASH_PARALLEL_MIN_FILES) return 1;

    int n = requested > 0 ? requested : ta_cpu_count();
    if (n > HASH_PARALLEL_THREAD_CAP) n = HASH_PARALLEL_THREAD_CAP;
    if ((size_t)n > work_items) n = (int)work_items;
    if (n < 1) n = 1;
    return n;
}

static void run_serial_hash(file_entry_t *entries)
{
    uint8_t *buf = (uint8_t *)malloc(HASH_WORKER_BUF_SIZE);
    if (!buf) return;
    for (file_entry_t *e = entries; e; e = e->next) {
        if (e->has_integrity) compute_entry_integrity(e, buf);
    }
    free(buf);
}

static void run_parallel_hash(file_entry_t *entries, int max_threads)
{
    size_t hash_count = 0;
    for (file_entry_t *e = entries; e; e = e->next) {
        if (e->has_integrity) hash_count++;
    }
    if (hash_count == 0) return;

    int n_threads = decide_thread_count(max_threads, hash_count);

    if (n_threads <= 1) {
        run_serial_hash(entries);
        return;
    }

    file_entry_t **arr = (file_entry_t **)malloc(hash_count * sizeof(*arr));
    if (!arr) {
        run_serial_hash(entries);
        return;
    }

    size_t idx = 0;
    for (file_entry_t *e = entries; e; e = e->next) {
        if (e->has_integrity) arr[idx++] = e;
    }

    pack_work_t work;
    work.entries = arr;
    work.count = hash_count;
    work.next_idx = 0;
    ta_mutex_init(&work.mutex);

    /* Spawn n_threads-1 workers; main thread also drains the queue. */
    int to_spawn = n_threads - 1;
    ta_thread_t *threads = NULL;
    int spawned = 0;
    if (to_spawn > 0) {
        threads = (ta_thread_t *)calloc((size_t)to_spawn, sizeof(ta_thread_t));
        if (threads) {
            for (int i = 0; i < to_spawn; i++) {
                if (ta_thread_create(&threads[i], hash_worker, &work) == 0) spawned++;
                else break;
            }
        }
    }

    hash_worker(&work);

    for (int i = 0; i < spawned; i++) {
        ta_thread_join(threads[i]);
    }
    free(threads);
    ta_mutex_destroy(&work.mutex);
    free(arr);
}

/* ----- Parallel data write (mmap source + pwrite to known offset) ----- */

typedef struct {
    file_entry_t **entries;     /* files only, in archive order */
    size_t count;
    size_t next_idx;
    ta_mutex_t mutex;
    ta_fd_t out_fd;
    uint64_t data_section_start; /* byte offset of data section in archive */
    bool ok;                     /* cleared on any failure */
} write_work_t;

static bool write_one_entry(file_entry_t *e, ta_fd_t fd, uint64_t base)
{
    if (e->size == 0) return true;

    ta_mapped_t m;
    if (!ta_map_read(e->path, &m)) return false;
    ta_advise_sequential(&m);

    bool ok = true;
    if (m.size != e->size) {
        /* File changed under us between stat and write. Truncate or pad to
         * declared size to keep offsets valid; treat as soft failure. */
        ok = false;
    } else if (m.size > 0) {
        ok = ta_pwrite_all(fd, m.data, m.size, base + e->data_offset);
    }
    ta_unmap(&m);
    return ok;
}

static void *write_worker(void *arg)
{
    write_work_t *w = (write_work_t *)arg;
    for (;;) {
        ta_mutex_lock(&w->mutex);
        size_t i = w->next_idx;
        if (i < w->count) w->next_idx = i + 1;
        ta_mutex_unlock(&w->mutex);
        if (i >= w->count) break;

        if (!write_one_entry(w->entries[i], w->out_fd, w->data_section_start)) {
            ta_mutex_lock(&w->mutex);
            w->ok = false;
            ta_mutex_unlock(&w->mutex);
        }
    }
    return NULL;
}

static bool run_parallel_write(
    file_entry_t **arr, size_t count,
    ta_fd_t out_fd, uint64_t data_start, int max_threads
)
{
    if (count == 0) return true;

    write_work_t work;
    work.entries = arr;
    work.count = count;
    work.next_idx = 0;
    work.out_fd = out_fd;
    work.data_section_start = data_start;
    work.ok = true;
    ta_mutex_init(&work.mutex);

    int n_threads = decide_thread_count(max_threads, count);
    int to_spawn = n_threads - 1;
    ta_thread_t *threads = NULL;
    int spawned = 0;
    if (to_spawn > 0) {
        threads = (ta_thread_t *)calloc((size_t)to_spawn, sizeof(ta_thread_t));
        if (threads) {
            for (int i = 0; i < to_spawn; i++) {
                if (ta_thread_create(&threads[i], write_worker, &work) == 0) spawned++;
                else break;
            }
        }
    }

    write_worker(&work);

    for (int i = 0; i < spawned; i++) {
        ta_thread_join(threads[i]);
    }
    free(threads);
    bool ok = work.ok;
    ta_mutex_destroy(&work.mutex);
    return ok;
}

/* Compute total bytes that will be written to the data section, given the
 * current pack plan, and assign each file entry's data_offset. */
static uint64_t assign_data_offsets(file_entry_t *entries)
{
    uint64_t off = 0;
    for (file_entry_t *e = entries; e; e = e->next) {
        if (e->is_dir || e->is_link || e->unpacked) continue;
        e->data_offset = off;
        off += e->size;
    }
    return off;
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
    const bool integrity = options->calculate_integrity;

    asar_filesystem_t *fs = asar_filesystem_create(src_dir);
    if (!fs) {
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    file_entry_t *entries = crawl_directory(src_dir, options->exclude_hidden);
    char *unpack_pattern = options->unpack ? normalize_glob_pattern(options->unpack) : NULL;

    /* Phase A: stat + classify every entry (no fs insert yet). Allocate
     * integrity buffers up-front so the parallel hash pass can fill them
     * without locks. */
    for (file_entry_t *entry = entries; entry; entry = entry->next) {
        const char *rel_path = get_relative_path(fs, entry->path);
        const bool should_unpack = unpack_pattern && glob_match(unpack_pattern, rel_path);
        entry->unpacked = should_unpack;

        if (entry->is_link) {
            entry->symlink_target = read_symlink(entry->path);
            continue;
        }
        if (entry->is_dir) {
            continue;
        }

        int64_t fsize = get_file_size(entry->path);
        if (fsize < 0) continue;
        entry->size = (uint64_t)fsize;
        entry->executable = is_executable(entry->path);

        if (integrity && entry->size > 0 && !should_unpack) {
            const size_t bc = (size_t)((entry->size + BLOCK_SIZE - 1) / BLOCK_SIZE);
            entry->file_hash = malloc(SHA256_HEX_SIZE);
            entry->block_hashes_buf = malloc(bc * SHA256_HEX_SIZE);
            entry->block_hashes_arr = malloc(bc * sizeof(char *));
            if (!entry->file_hash || !entry->block_hashes_buf || !entry->block_hashes_arr) {
                free(entry->file_hash); entry->file_hash = NULL;
                free(entry->block_hashes_buf); entry->block_hashes_buf = NULL;
                free(entry->block_hashes_arr); entry->block_hashes_arr = NULL;
                continue;
            }
            for (size_t i = 0; i < bc; i++) {
                entry->block_hashes_arr[i] = entry->block_hashes_buf + i * SHA256_HEX_SIZE;
            }
            entry->block_count = bc;
            entry->has_integrity = true;
        }
    }

    /* Phase B: parallel SHA-256 (file + per-block) on all eligible entries.
     * Workers fill entry->file_hash / block_hashes_arr in place. */
    if (integrity) {
        run_parallel_hash(entries, options->max_threads);
    }

    /* Phase C: assign data_offset per file (matches insert order below) and
     * insert every entry into the filesystem with FINAL hashes. */
    assign_data_offsets(entries);

    for (file_entry_t *entry = entries; entry; entry = entry->next) {
        const char *rel_path = get_relative_path(fs, entry->path);
        const bool should_unpack = entry->unpacked;

        if (entry->is_link) {
            if (entry->symlink_target) {
                asar_filesystem_insert_link(fs, rel_path, entry->symlink_target, should_unpack);
            }
            continue;
        }
        if (entry->is_dir) {
            asar_filesystem_insert_directory(fs, rel_path, should_unpack);
            continue;
        }

        asar_filesystem_insert_file(
            fs, rel_path, entry->size, entry->executable, should_unpack,
            entry->has_integrity ? entry->file_hash : NULL,
            (const char **)entry->block_hashes_arr, entry->block_count, BLOCK_SIZE
        );
    }

    free(unpack_pattern);

    /* Phase D: serialize final header (hashes already real, no patch needed). */
    char *header_json = NULL;
    if (!asar_filesystem_serialize_header(fs, &header_json)) {
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    const size_t header_json_len = strlen(header_json);

    pickle_writer_t header_pickle;
    if (!pickle_writer_init(&header_pickle) ||
        !pickle_write_string(&header_pickle, header_json, header_json_len)) {
        pickle_writer_free(&header_pickle);
        cJSON_free(header_json);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    cJSON_free(header_json);

    size_t header_pickle_size;
    const uint8_t *header_data = pickle_writer_data(&header_pickle, &header_pickle_size);
    if (header_pickle_size > UINT32_MAX) {
        pickle_writer_free(&header_pickle);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_INVALID_HEADER;
    }

    pickle_writer_t size_pickle;
    if (!pickle_writer_init(&size_pickle) ||
        !pickle_write_uint32(&size_pickle, (uint32_t)header_pickle_size)) {
        pickle_writer_free(&size_pickle);
        pickle_writer_free(&header_pickle);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }
    size_t size_pickle_size;
    const uint8_t *size_data = pickle_writer_data(&size_pickle, &size_pickle_size);

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

    /* Phase E: open output, preallocate, write header sequentially. */
    const uint64_t data_total = assign_data_offsets(entries); /* same call, idempotent */
    const uint64_t data_section_start = (uint64_t)size_pickle_size + header_pickle_size;
    const uint64_t archive_total = data_section_start + data_total;

    ta_fd_t out = ta_open_create(dest_path);
    if (out == TA_INVALID_FD) {
        pickle_writer_free(&size_pickle);
        pickle_writer_free(&header_pickle);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_FILE_WRITE;
    }
    ta_preallocate(out, archive_total);

    bool ok = ta_write_all(out, size_data, size_pickle_size) &&
              ta_write_all(out, header_data, header_pickle_size);

    pickle_writer_free(&size_pickle);
    pickle_writer_free(&header_pickle);

    if (!ok) {
        ta_close_fd(out);
        free_file_entries(entries);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_FILE_WRITE;
    }

    /* Phase F: parallel data write. Each file is mmapped and pwritten to its
     * pre-known offset; workers operate on disjoint byte ranges so no locking
     * is needed on the output fd. */
    size_t file_count = 0;
    for (file_entry_t *e = entries; e; e = e->next) {
        if (!e->is_dir && !e->is_link && !e->unpacked) file_count++;
    }

    bool data_ok = true;
    if (file_count > 0) {
        file_entry_t **arr = (file_entry_t **)malloc(file_count * sizeof(*arr));
        if (!arr) {
            ta_close_fd(out);
            free_file_entries(entries);
            asar_filesystem_free(fs);
            return TURBO_ASAR_ERR_OUT_OF_MEMORY;
        }
        size_t idx = 0;
        for (file_entry_t *e = entries; e; e = e->next) {
            if (!e->is_dir && !e->is_link && !e->unpacked) arr[idx++] = e;
        }
        data_ok = run_parallel_write(arr, file_count, out, data_section_start, options->max_threads);
        free(arr);
    }

    ta_close_fd(out);
    free_file_entries(entries);
    asar_filesystem_free(fs);

    return data_ok ? TURBO_ASAR_OK : TURBO_ASAR_ERR_FILE_WRITE;
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
    return calloc(1, sizeof(dir_cache_t));
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
    for (dir_cache_entry_t *entry = cache->buckets[h]; entry; entry = entry->next) {
        if (strcmp(entry->path, path) == 0) return true;
    }
    return false;
}

static void dir_cache_add(dir_cache_t *cache, const char *path) {
    unsigned int h = dir_hash(path);
    dir_cache_entry_t *entry = malloc(sizeof(dir_cache_entry_t));
    if (!entry) return;
    entry->path = strdup(path);
    if (!entry->path) {
        free(entry);
        return;
    }
    entry->next = cache->buckets[h];
    cache->buckets[h] = entry;
}

/* Create a directory, caching the result. Cache also marks ancestors as
 * created so adjacent files that share a parent skip the per-file walk. */
static void create_directory_cached(const char *path, dir_cache_t *cache)
{
    if (!cache || !path || !*path) {
        mkdir_recursive(path);
        return;
    }
    if (dir_cache_contains(cache, path)) return;

    mkdir_recursive(path);
    dir_cache_add(cache, path);

    /* Mark ancestors so subsequent siblings skip mkdir_recursive entirely. */
    char tmp[MAX_PATH_LEN];
    size_t len = strlen(path);
    if (len >= MAX_PATH_LEN) return;
    memcpy(tmp, path, len + 1);

    for (size_t i = len; i > 0; --i) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (*tmp && !dir_cache_contains(cache, tmp)) {
                dir_cache_add(cache, tmp);
            }
            tmp[i] = saved;
        }
    }
}

/* Helper to create parent directory for a file path (modifies path in-place
 * temporarily). */
static void create_parent_directory_cached(char *path, dir_cache_t *cache)
{
    char *last_sep = strrchr(path, '/');
    #ifdef __WINDOWS__
    char *last_sep_win = strrchr(path, '\\');
    if (last_sep_win > last_sep) last_sep = last_sep_win;
    #endif
    if (!last_sep) return;
    char saved = *last_sep;
    *last_sep = '\0';
    create_directory_cached(path, cache);
    *last_sep = saved;
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
    uint64_t data_offset;
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

    char **files;
    size_t file_count;
    if (!asar_filesystem_list_files(fs, &files, &file_count)) {
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    FILE *archive = fopen(archive_path, "rb");
    if (!archive) {
        turbo_asar_free_list(files, file_count);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_FILE_NOT_FOUND;
    }

    if (ta_fseek64(archive, 0, SEEK_END) != 0) {
        fclose(archive);
        turbo_asar_free_list(files, file_count);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_FILE_READ;
    }
    int64_t archive_size = ta_ftell64(archive);
    if (archive_size < 0) {
        fclose(archive);
        turbo_asar_free_list(files, file_count);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_FILE_READ;
    }
    ta_fseek64(archive, 0, SEEK_SET);

#if !defined(__WINDOWS__)
    void *archive_map = NULL;
    int archive_fd = fileno(archive);

    if (archive_size > 0) {
        archive_map = mmap(NULL, (size_t)archive_size, PROT_READ, MAP_PRIVATE, archive_fd, 0);
        if (archive_map != MAP_FAILED) {
            (void)madvise(archive_map, (size_t)archive_size, MADV_SEQUENTIAL);
        } else {
            archive_map = NULL;
        }
    }
#endif

    uint8_t *buffer = malloc(READ_BUFFER_SIZE);
    if (!buffer) {
#if !defined(__WINDOWS__)
        if (archive_map) munmap(archive_map, (size_t)archive_size);
#endif
        fclose(archive);
        turbo_asar_free_list(files, file_count);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    dir_cache_t *dir_cache = dir_cache_create();

    for (size_t i = 0; i < file_count; i++) {
        const char *rel_path = files[i];
        while (*rel_path == '/' || *rel_path == '\\') rel_path++;

        char dest_path[MAX_PATH_LEN];
        snprintf(dest_path, sizeof(dest_path), "%s%c%s", dest_dir, PATH_SEPARATOR, rel_path);

        asar_entry_info_t info;
        #ifdef __WINDOWS__
        bool follow_links = true;
        #else
        bool follow_links = false;
        #endif

        if (!asar_filesystem_get_entry(fs, files[i], follow_links, &info)) {
            continue;
        }

        if (info.type == ASAR_ENTRY_DIRECTORY) {
            create_directory_cached(dest_path, dir_cache);
        }
        else if (info.type == ASAR_ENTRY_LINK) {
            #ifndef __WINDOWS__
            create_parent_directory_cached(dest_path, dir_cache);
            unlink(dest_path);
            if (info.link) {
                int ret = symlink(info.link, dest_path);
                (void)ret;
            }
            #endif
        }
        else if (info.type == ASAR_ENTRY_FILE) {
            create_parent_directory_cached(dest_path, dir_cache);

            if (info.unpacked) {
                char unpacked_path[MAX_PATH_LEN];
                snprintf(unpacked_path, sizeof(unpacked_path), "%s.unpacked%c%s",
                        archive_path, PATH_SEPARATOR, rel_path);

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
                    uint64_t file_offset = data_offset + info.offset;
                    /* Bounds check to guard a malformed header */
                    if (file_offset >= data_offset &&
                        file_offset <= (uint64_t)archive_size &&
                        info.size <= (uint64_t)archive_size - file_offset) {
#if !defined(__WINDOWS__)
                        if (archive_map) {
                            fwrite((uint8_t*)archive_map + file_offset, 1, info.size, out);
                        } else
#endif
                        {
                            ta_fseek64(archive, (int64_t)file_offset, SEEK_SET);
                            uint64_t remaining = info.size;
                            while (remaining > 0) {
                                size_t to_read = remaining > READ_BUFFER_SIZE
                                    ? READ_BUFFER_SIZE : (size_t)remaining;
                                size_t bytes = fread(buffer, 1, to_read, archive);
                                if (bytes == 0) break;
                                fwrite(buffer, 1, bytes, out);
                                remaining -= bytes;
                            }
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
                FILE *out = fopen(dest_path, "wb");
                if (out) fclose(out);
            }
        }

        asar_entry_info_free(&info);
    }

    dir_cache_free(dir_cache);
    free(buffer);
#if !defined(__WINDOWS__)
    if (archive_map) munmap(archive_map, (size_t)archive_size);
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
    uint64_t data_offset;
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

    *size = (size_t)info.size;

    if (info.size == 0) {
        asar_entry_info_free(&info);
        asar_filesystem_free(fs);
        return TURBO_ASAR_OK;
    }

    *buffer = malloc(info.size);
    if (!*buffer) {
        asar_entry_info_free(&info);
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    if (info.unpacked) {
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
        FILE *fp = fopen(archive_path, "rb");
        if (!fp) {
            free(*buffer);
            *buffer = NULL;
            asar_entry_info_free(&info);
            asar_filesystem_free(fs);
            return TURBO_ASAR_ERR_FILE_NOT_FOUND;
        }

        uint64_t file_offset = data_offset + info.offset;
        if (ta_fseek64(fp, (int64_t)file_offset, SEEK_SET) != 0 ||
            fread(*buffer, 1, info.size, fp) != info.size) {
            free(*buffer);
            *buffer = NULL;
            fclose(fp);
            asar_entry_info_free(&info);
            asar_filesystem_free(fs);
            return TURBO_ASAR_ERR_FILE_READ;
        }
        fclose(fp);
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
    uint64_t data_offset;
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
    uint64_t data_offset;
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

    char *header_json;
    size_t header_size;
    uint64_t data_offset;
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

    switch (info.type) {
        case ASAR_ENTRY_FILE:      entry->type = TURBO_ASAR_ENTRY_FILE; break;
        case ASAR_ENTRY_DIRECTORY: entry->type = TURBO_ASAR_ENTRY_DIRECTORY; break;
        case ASAR_ENTRY_LINK:      entry->type = TURBO_ASAR_ENTRY_LINK; break;
    }
    entry->size = info.size;
    entry->offset = info.offset;
    entry->unpacked = info.unpacked;
    entry->executable = info.executable;

    if (info.link) {
        entry->link = strdup(info.link);
    }

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
