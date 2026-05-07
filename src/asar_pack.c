/**
 * @file asar_pack.c
 * @brief ASAR archive packing: directory crawl, parallel SHA-256, parallel write.
 */

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
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#endif

#define BLOCK_SIZE              (4 * 1024 * 1024)
#define MAX_PATH_LEN            4096
#define HASH_WORKER_BUF_SIZE    (256 * 1024)
#define HASH_PARALLEL_MIN_FILES 4
#define HASH_PARALLEL_THREAD_CAP 8

/* ---------- file entry (crawl result) ---------- */

static int64_t get_file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int64_t)st.st_size;
}

static bool is_executable(const char *path)
{
#ifdef __WINDOWS__
    (void)path;
    return false;
#else
    struct stat st;
    if (stat(path, &st) != 0) return false;
    return (st.st_mode & 0100) != 0;
#endif
}

typedef struct file_entry {
    char *path;
    bool is_dir;
    bool is_link;
    bool unpacked;
    bool executable;
    bool has_integrity;
    uint64_t size;
    uint64_t data_offset;
    char *symlink_target;
    size_t block_count;
    char *file_hash;
    char *block_hashes_buf;
    char **block_hashes_arr;
    struct file_entry *next;
} file_entry_t;

static file_entry_t* crawl_directory(const char *dir_path, bool exclude_hidden)
{
    file_entry_t *head = NULL;
    file_entry_t *tail = NULL;

#ifdef __WINDOWS__
    char search_path[MAX_PATH_LEN];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);

    WIN32_FIND_DATAA find_data;
    HANDLE find_handle = FindFirstFileA(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) return NULL;

    do {
        const char *name = find_data.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (exclude_hidden && name[0] == '.') continue;

        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, name);

        file_entry_t *entry = calloc(1, sizeof(file_entry_t));
        if (!entry) continue;

        entry->path = strdup(full_path);
        if (!entry->path) { free(entry); continue; }
        entry->is_dir = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        entry->is_link = (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

        if (!head) { head = tail = entry; }
        else { tail->next = entry; tail = entry; }

        if (entry->is_dir && !entry->is_link) {
            file_entry_t *subdir = crawl_directory(full_path, exclude_hidden);
            if (subdir) { tail->next = subdir; while (tail->next) tail = tail->next; }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
#else
    DIR *dir = opendir(dir_path);
    if (!dir) return NULL;

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        const char *name = de->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (exclude_hidden && name[0] == '.') continue;

        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);

        struct stat st;
        if (lstat(full_path, &st) != 0) continue;

        file_entry_t *fe = calloc(1, sizeof(file_entry_t));
        if (!fe) continue;

        fe->path = strdup(full_path);
        if (!fe->path) { free(fe); continue; }
        fe->is_dir = S_ISDIR(st.st_mode);
        fe->is_link = S_ISLNK(st.st_mode);

        if (!head) { head = tail = fe; }
        else { tail->next = fe; tail = fe; }

        if (fe->is_dir && !fe->is_link) {
            file_entry_t *subdir = crawl_directory(full_path, exclude_hidden);
            if (subdir) { tail->next = subdir; while (tail->next) tail = tail->next; }
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
    return NULL;
#else
    char target[MAX_PATH_LEN];
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len < 0) return NULL;
    target[len] = '\0';
    return strdup(target);
#endif
}

/* ---------- parallel SHA-256 pre-pass ----------
 *
 * Hashes are computed in worker threads BEFORE the data write phase, so the
 * write phase becomes a pure copy.  Buffers (file_hash, block_hashes_arr) are
 * pre-allocated by the main thread during stat/insert, so workers only fill
 * already-owned memory.  No shared state between workers except the work
 * queue index. */

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
                if (cur_block < e->block_count)
                    sha256_to_hex(d, e->block_hashes_arr[cur_block]);
                cur_block++;
                block_bytes = 0;
                sha256_init(&bctx);
            }
        }
    }

    if (block_bytes > 0 || cur_block == 0) {
        uint8_t d[SHA256_DIGEST_SIZE];
        sha256_final(&bctx, d);
        if (cur_block < e->block_count)
            sha256_to_hex(d, e->block_hashes_arr[cur_block]);
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
    if (!arr) { run_serial_hash(entries); return; }

    size_t idx = 0;
    for (file_entry_t *e = entries; e; e = e->next) {
        if (e->has_integrity) arr[idx++] = e;
    }

    pack_work_t work;
    work.entries = arr;
    work.count = hash_count;
    work.next_idx = 0;
    ta_mutex_init(&work.mutex);

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

    for (int i = 0; i < spawned; i++) ta_thread_join(threads[i]);
    free(threads);
    ta_mutex_destroy(&work.mutex);
    free(arr);
}

/* ---------- parallel data write (mmap source + pwrite to known offset) ---------- */

typedef struct {
    file_entry_t **entries;
    size_t count;
    size_t next_idx;
    ta_mutex_t mutex;
    ta_fd_t out_fd;
    uint64_t data_section_start;
    bool ok;
} write_work_t;

static bool write_one_entry(file_entry_t *e, ta_fd_t fd, uint64_t base)
{
    if (e->size == 0) return true;

    ta_mapped_t m;
    if (!ta_map_read(e->path, &m)) return false;
    ta_advise_sequential(&m);

    bool ok = true;
    if (m.size != e->size) {
        /* File changed between stat and write — offsets stay valid; soft failure. */
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

    for (int i = 0; i < spawned; i++) ta_thread_join(threads[i]);
    free(threads);
    bool ok = work.ok;
    ta_mutex_destroy(&work.mutex);
    return ok;
}

/* Assign data_offset to each packed file and return total data section size. */
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

/* ---------- mkdir helper (needed for output directory creation) ---------- */

static turbo_asar_error_t mkdir_pack(const char *path)
{
    char tmp[MAX_PATH_LEN];
    size_t len;
    if (!path) return TURBO_ASAR_ERR_NULL_PARAM;
    len = strlen(path);
    if (len == 0) return TURBO_ASAR_OK;
    if (len >= MAX_PATH_LEN) return TURBO_ASAR_ERR_PATH_TOO_LONG;
    memcpy(tmp, path, len + 1);
    if (len > 1 && (tmp[len - 1] == '/' || tmp[len - 1] == '\\'))
        tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
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
    if (!CreateDirectoryA(tmp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return TURBO_ASAR_ERR_MKDIR_FAILED;
#else
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return TURBO_ASAR_ERR_MKDIR_FAILED;
#endif
    return TURBO_ASAR_OK;
}

/* ---------- turbo_asar_pack ---------- */

turbo_asar_error_t turbo_asar_pack(
    const char *src_dir,
    const char *dest_path,
    const turbo_asar_pack_options_t *options
)
{
    if (!src_dir || !dest_path) return TURBO_ASAR_ERR_NULL_PARAM;

    turbo_asar_pack_options_t default_opts = {0};
    default_opts.calculate_integrity = true;
    if (!options) options = &default_opts;
    const bool integrity = options->calculate_integrity;

    asar_filesystem_t *fs = asar_filesystem_create(src_dir);
    if (!fs) return TURBO_ASAR_ERR_OUT_OF_MEMORY;

    file_entry_t *entries = crawl_directory(src_dir, options->exclude_hidden);
    char *unpack_pattern = options->unpack ? normalize_glob_pattern(options->unpack) : NULL;

    /* Phase A: stat + classify every entry; allocate integrity buffers up-front
     * so the parallel hash pass can fill them without locks. */
    for (file_entry_t *e = entries; e; e = e->next) {
        const char *rel_path = get_relative_path(fs, e->path);
        const bool should_unpack = unpack_pattern && glob_match(unpack_pattern, rel_path);
        e->unpacked = should_unpack;

        if (e->is_link) { e->symlink_target = read_symlink(e->path); continue; }
        if (e->is_dir) continue;

        int64_t fsize = get_file_size(e->path);
        if (fsize < 0) continue;
        e->size = (uint64_t)fsize;
        e->executable = is_executable(e->path);

        if (integrity && e->size > 0 && !should_unpack) {
            const size_t bc = (size_t)((e->size + BLOCK_SIZE - 1) / BLOCK_SIZE);
            e->file_hash        = malloc(SHA256_HEX_SIZE);
            e->block_hashes_buf = malloc(bc * SHA256_HEX_SIZE);
            e->block_hashes_arr = malloc(bc * sizeof(char *));
            if (!e->file_hash || !e->block_hashes_buf || !e->block_hashes_arr) {
                free(e->file_hash);        e->file_hash        = NULL;
                free(e->block_hashes_buf); e->block_hashes_buf = NULL;
                free(e->block_hashes_arr); e->block_hashes_arr = NULL;
                continue;
            }
            for (size_t i = 0; i < bc; i++)
                e->block_hashes_arr[i] = e->block_hashes_buf + i * SHA256_HEX_SIZE;
            e->block_count = bc;
            e->has_integrity = true;
        }
    }

    /* Phase B: parallel SHA-256 (file + per-block) on all eligible entries. */
    if (integrity) run_parallel_hash(entries, options->max_threads);

    /* Phase C: assign data_offset per file (matches insert order below).
     * Compute total data size here to avoid a redundant second pass later. */
    const uint64_t data_total = assign_data_offsets(entries);

    /* Insert every entry into the filesystem with final hashes. */
    for (file_entry_t *e = entries; e; e = e->next) {
        const char *rel_path = get_relative_path(fs, e->path);

        if (e->is_link) {
            if (e->symlink_target)
                asar_filesystem_insert_link(fs, rel_path, e->symlink_target, e->unpacked);
            continue;
        }
        if (e->is_dir) { asar_filesystem_insert_directory(fs, rel_path, e->unpacked); continue; }

        asar_filesystem_insert_file(
            fs, rel_path, e->size, e->executable, e->unpacked,
            e->has_integrity ? e->file_hash : NULL,
            (const char **)e->block_hashes_arr, e->block_count, BLOCK_SIZE
        );
    }

    free(unpack_pattern);

    /* Phase D: serialize header (hashes already real, no patch needed). */
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

    /* Ensure output directory exists. */
    char *dir_copy = strdup(dest_path);
    if (dir_copy) {
        char *last_sep = strrchr(dir_copy, '/');
#ifdef __WINDOWS__
        char *last_sep_win = strrchr(dir_copy, '\\');
        if (last_sep_win > last_sep) last_sep = last_sep_win;
#endif
        if (last_sep) { *last_sep = '\0'; mkdir_pack(dir_copy); }
        free(dir_copy);
    }

    /* Phase E: open output, preallocate, write header sequentially. */
    const uint64_t data_section_start = (uint64_t)size_pickle_size + header_pickle_size;
    const uint64_t archive_total      = data_section_start + data_total;

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

    /* Phase F: parallel data write (each file mmapped, pwritten to its pre-known offset;
     * workers operate on disjoint byte ranges so no locking needed on the output fd). */
    size_t file_count = 0;
    for (file_entry_t *e = entries; e; e = e->next)
        if (!e->is_dir && !e->is_link && !e->unpacked) file_count++;

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
        for (file_entry_t *e = entries; e; e = e->next)
            if (!e->is_dir && !e->is_link && !e->unpacked) arr[idx++] = e;
        data_ok = run_parallel_write(arr, file_count, out, data_section_start, options->max_threads);
        free(arr);
    }

    ta_close_fd(out);
    free_file_entries(entries);
    asar_filesystem_free(fs);

    return data_ok ? TURBO_ASAR_OK : TURBO_ASAR_ERR_FILE_WRITE;
}
