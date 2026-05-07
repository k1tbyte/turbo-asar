/**
 * @file asar.c
 * @brief ASAR archive read operations: extract, list, stat, header.
 *
 * Pack logic lives in asar_pack.c.
 */

/* Feature test macros for mmap/madvise on Linux */
#if !defined(__WINDOWS__)
#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "turbo_asar.h"
#include "pickle.h"
#include "filesystem.h"
#include "cJSON.h"
#include "js_scan.h"

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
#include <fcntl.h>
#define ta_fseek64(fp, off, whence) fseeko((fp), (off_t)(off), (whence))
#define ta_ftell64(fp) ((int64_t)ftello(fp))
#endif

#define MAX_PATH_LEN     4096
#define READ_BUFFER_SIZE (1024 * 1024)

/* ---------- shared utilities ---------- */

static turbo_asar_error_t mkdir_recursive(const char *path)
{
    char tmp[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;

    if (!path) return TURBO_ASAR_ERR_NULL_PARAM;
    len = strlen(path);
    if (len == 0) return TURBO_ASAR_OK;
    if (len >= MAX_PATH_LEN) return TURBO_ASAR_ERR_PATH_TOO_LONG;

    memcpy(tmp, path, len + 1);

    if (len > 1 && (tmp[len - 1] == '/' || tmp[len - 1] == '\\'))
        tmp[len - 1] = '\0';

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
    if (!CreateDirectoryA(tmp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return TURBO_ASAR_ERR_MKDIR_FAILED;
#else
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return TURBO_ASAR_ERR_MKDIR_FAILED;
#endif

    return TURBO_ASAR_OK;
}

/* ---------- public API: version / errors ---------- */

const char* turbo_asar_version(void)
{
    return TURBO_ASAR_VERSION;
}

const char* turbo_asar_strerror(turbo_asar_error_t err)
{
    switch (err) {
        case TURBO_ASAR_OK:                       return "Success";
        case TURBO_ASAR_ERR_NULL_PARAM:           return "Null parameter";
        case TURBO_ASAR_ERR_FILE_NOT_FOUND:       return "File not found";
        case TURBO_ASAR_ERR_FILE_READ:            return "File read error";
        case TURBO_ASAR_ERR_FILE_WRITE:           return "File write error";
        case TURBO_ASAR_ERR_INVALID_ARCHIVE:      return "Invalid archive";
        case TURBO_ASAR_ERR_INVALID_HEADER:       return "Invalid header";
        case TURBO_ASAR_ERR_OUT_OF_MEMORY:        return "Out of memory";
        case TURBO_ASAR_ERR_PATH_TOO_LONG:        return "Path too long";
        case TURBO_ASAR_ERR_MKDIR_FAILED:         return "Failed to create directory";
        case TURBO_ASAR_ERR_JSON_PARSE:           return "JSON parse error";
        case TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE: return "File not found in archive";
        case TURBO_ASAR_ERR_IS_DIRECTORY:         return "Path is a directory";
        case TURBO_ASAR_ERR_SYMLINK_OUTSIDE:      return "Symlink points outside archive";
        default:                                   return "Unknown error";
    }
}

/* ---------- archive header reader ---------- */

static turbo_asar_error_t read_archive_header(
    const char *archive_path,
    char **header_json,
    size_t *header_size,
    uint64_t *data_offset
)
{
    FILE *fp = fopen(archive_path, "rb");
    if (!fp) return TURBO_ASAR_ERR_FILE_NOT_FOUND;

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

    *header_json  = json_str;
    *header_size  = hdr_size;
    *data_offset  = (uint64_t)8 + hdr_size;

    free(header_buf);
    fclose(fp);
    return TURBO_ASAR_OK;
}

/* Navigate `json_root` header to find the entry at `path`.
 * On success fills `info` and returns TURBO_ASAR_OK.
 * Zero heap allocations for regular files and directories. */
static turbo_asar_error_t json_navigate(
    const char *json_root,
    const char *path,
    asar_entry_info_t *info,
    int depth
)
{
    if (depth >= JS_SCAN_NAV_MAX_DEPTH) return TURBO_ASAR_ERR_SYMLINK_OUTSIDE;
    memset(info, 0, sizeof(*info));

    while (*path == '/' || *path == '\\') path++;

    const char *cur = js_obj_get(json_root, "files", 5);
    if (!cur) return TURBO_ASAR_ERR_INVALID_HEADER;

    while (*path) {
        const char *comp_end = path;
        while (*comp_end && *comp_end != '/' && *comp_end != '\\') comp_end++;
        size_t comp_len = (size_t)(comp_end - path);

        const char *node = js_obj_get(cur, path, comp_len);
        if (!node) return TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE;

        path = comp_end;
        while (*path == '/' || *path == '\\') path++;

        if (*path == '\0') {
            /* Leaf node — determine type and fill info. */
            const char *link_v = js_obj_get(node, "link", 4);
            if (link_v && *link_v == '"') {
                char tgt[MAX_PATH_LEN];
                if (!js_read_str(link_v, tgt, sizeof(tgt)))
                    return TURBO_ASAR_ERR_INVALID_HEADER;
                return json_navigate(json_root, tgt, info, depth + 1);
            }

            if (js_obj_get(node, "files", 5)) {
                info->type = ASAR_ENTRY_DIRECTORY;
                const char *u = js_obj_get(node, "unpacked", 8);
                info->unpacked = u && strncmp(u, "true", 4) == 0;
                return TURBO_ASAR_OK;
            }

            info->type = ASAR_ENTRY_FILE;
            const char *sz = js_obj_get(node, "size", 4);
            if (sz && *sz >= '0' && *sz <= '9') info->size = js_u64(sz);
            const char *ov = js_obj_get(node, "offset", 6);
            if (ov && *ov == '"') {
                char ob[24];
                if (js_read_str(ov, ob, sizeof(ob)))
                    info->offset = strtoull(ob, NULL, 10);
            }
            const char *u = js_obj_get(node, "unpacked", 8);
            info->unpacked = u && strncmp(u, "true", 4) == 0;
            const char *xv = js_obj_get(node, "executable", 10);
            info->executable = xv && strncmp(xv, "true", 4) == 0;
            return TURBO_ASAR_OK;
        }

        /* Intermediate path component — descend into "files". */
        const char *link_v = js_obj_get(node, "link", 4);
        if (link_v && *link_v == '"') {
            /* Symlink at intermediate position: append remaining path. */
            char tgt[MAX_PATH_LEN];
            if (!js_read_str(link_v, tgt, sizeof(tgt)))
                return TURBO_ASAR_ERR_INVALID_HEADER;
            size_t tlen = strlen(tgt), rlen = strlen(path);
            if (tlen + 1 + rlen >= MAX_PATH_LEN) return TURBO_ASAR_ERR_PATH_TOO_LONG;
            char full[MAX_PATH_LEN];
            memcpy(full, tgt, tlen);
            full[tlen] = '/';
            memcpy(full + tlen + 1, path, rlen + 1);
            return json_navigate(json_root, full, info, depth + 1);
        }

        const char *files_v = js_obj_get(node, "files", 5);
        if (!files_v) return TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE;
        cur = files_v;
    }

    /* Empty path after stripping separators — root directory. */
    info->type = ASAR_ENTRY_DIRECTORY;
    return TURBO_ASAR_OK;
}

/* ---------- directory cache (used by extract_all) ---------- */

#define DIR_CACHE_SIZE 1024
#define DIR_CACHE_MASK (DIR_CACHE_SIZE - 1)

typedef struct dir_cache_entry {
    char *path;
    struct dir_cache_entry *next;
} dir_cache_entry_t;

typedef struct {
    dir_cache_entry_t *buckets[DIR_CACHE_SIZE];
} dir_cache_t;

static unsigned int dir_hash(const char *str)
{
    unsigned int hash = 5381;
    while (*str) hash = ((hash << 5) + hash) + (unsigned char)*str++;
    return hash & DIR_CACHE_MASK;
}

static dir_cache_t *dir_cache_create(void) { return calloc(1, sizeof(dir_cache_t)); }

static void dir_cache_free(dir_cache_t *cache)
{
    if (!cache) return;
    for (int i = 0; i < DIR_CACHE_SIZE; i++) {
        dir_cache_entry_t *e = cache->buckets[i];
        while (e) { dir_cache_entry_t *nx = e->next; free(e->path); free(e); e = nx; }
    }
    free(cache);
}

static bool dir_cache_contains(dir_cache_t *cache, const char *path)
{
    unsigned int h = dir_hash(path);
    for (dir_cache_entry_t *e = cache->buckets[h]; e; e = e->next)
        if (strcmp(e->path, path) == 0) return true;
    return false;
}

static void dir_cache_add(dir_cache_t *cache, const char *path)
{
    unsigned int h = dir_hash(path);
    dir_cache_entry_t *e = malloc(sizeof(dir_cache_entry_t));
    if (!e) return;
    e->path = strdup(path);
    if (!e->path) { free(e); return; }
    e->next = cache->buckets[h];
    cache->buckets[h] = e;
}

static void create_directory_cached(const char *path, dir_cache_t *cache)
{
    if (!cache || !path || !*path) { mkdir_recursive(path); return; }
    if (dir_cache_contains(cache, path)) return;

    mkdir_recursive(path);
    dir_cache_add(cache, path);

    char tmp[MAX_PATH_LEN];
    size_t len = strlen(path);
    if (len >= MAX_PATH_LEN) return;
    memcpy(tmp, path, len + 1);

    for (size_t i = len; i > 0; --i) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (*tmp && !dir_cache_contains(cache, tmp)) dir_cache_add(cache, tmp);
            tmp[i] = saved;
        }
    }
}

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

/* ---------- turbo_asar_extract_all ---------- */

turbo_asar_error_t turbo_asar_extract_all(
    const char *archive_path,
    const char *dest_dir
)
{
    if (!archive_path || !dest_dir) return TURBO_ASAR_ERR_NULL_PARAM;

    char *header_json;
    size_t header_size;
    uint64_t data_offset;
    turbo_asar_error_t err = read_archive_header(archive_path, &header_json, &header_size, &data_offset);
    if (err != TURBO_ASAR_OK) return err;

    cJSON *header = cJSON_Parse(header_json);
    free(header_json);
    if (!header) return TURBO_ASAR_ERR_JSON_PARSE;

    asar_filesystem_t *fs = asar_filesystem_create(archive_path);
    if (!fs) { cJSON_Delete(header); return TURBO_ASAR_ERR_OUT_OF_MEMORY; }
    asar_filesystem_set_header(fs, header, header_size);

    err = mkdir_recursive(dest_dir);
    if (err != TURBO_ASAR_OK) { asar_filesystem_free(fs); return err; }

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
        if (!asar_filesystem_get_entry(fs, files[i], follow_links, &info)) continue;

        if (info.type == ASAR_ENTRY_DIRECTORY) {
            create_directory_cached(dest_path, dir_cache);
        }
        else if (info.type == ASAR_ENTRY_LINK) {
#ifndef __WINDOWS__
            create_parent_directory_cached(dest_path, dir_cache);
            unlink(dest_path);
            if (info.link) { int r = symlink(info.link, dest_path); (void)r; }
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
                        while ((bytes = fread(buffer, 1, READ_BUFFER_SIZE, src)) > 0)
                            fwrite(buffer, 1, bytes, dst);
                        fclose(dst);
                    }
                    fclose(src);
                }
            }
            else if (info.size > 0) {
                FILE *out = fopen(dest_path, "wb");
                if (out) {
                    uint64_t file_offset = data_offset + info.offset;
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
                    if (info.executable) chmod(dest_path, 0755);
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

/* ---------- turbo_asar_extract_file ----------
 *
 * Uses json_navigate (zero allocations) instead of cJSON_Parse to find the
 * entry, eliminating ~3 000 heap allocations per call on large archives.
 * On POSIX, uses pread for the data read (one syscall, no fseek). */

turbo_asar_error_t turbo_asar_extract_file(
    const char *archive_path,
    const char *file_path,
    uint8_t **buffer,
    size_t *size
)
{
    if (!archive_path || !file_path || !buffer || !size)
        return TURBO_ASAR_ERR_NULL_PARAM;

    *buffer = NULL;
    *size   = 0;

    char *header_json;
    size_t header_size;
    uint64_t data_offset;
    turbo_asar_error_t err = read_archive_header(archive_path, &header_json, &header_size, &data_offset);
    if (err != TURBO_ASAR_OK) return err;

    asar_entry_info_t info;
    err = json_navigate(header_json, file_path, &info, 0);
    free(header_json);

    if (err != TURBO_ASAR_OK) return err;

    if (info.type != ASAR_ENTRY_FILE) {
        asar_entry_info_free(&info);
        return TURBO_ASAR_ERR_IS_DIRECTORY;
    }

    *size = (size_t)info.size;

    if (info.size == 0) {
        asar_entry_info_free(&info);
        return TURBO_ASAR_OK;
    }

    *buffer = malloc(info.size);
    if (!*buffer) {
        asar_entry_info_free(&info);
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
            free(*buffer); *buffer = NULL;
            asar_entry_info_free(&info);
            return TURBO_ASAR_ERR_FILE_NOT_FOUND;
        }
        if (fread(*buffer, 1, info.size, fp) != info.size) {
            free(*buffer); *buffer = NULL;
            fclose(fp);
            asar_entry_info_free(&info);
            return TURBO_ASAR_ERR_FILE_READ;
        }
        fclose(fp);
    } else {
        uint64_t file_offset = data_offset + info.offset;

#if !defined(__WINDOWS__)
        int fd = open(archive_path, O_RDONLY);
        if (fd < 0) {
            free(*buffer); *buffer = NULL;
            asar_entry_info_free(&info);
            return TURBO_ASAR_ERR_FILE_NOT_FOUND;
        }
        ssize_t r = pread(fd, *buffer, info.size, (off_t)file_offset);
        close(fd);
        if (r < 0 || (size_t)r != info.size) {
            free(*buffer); *buffer = NULL;
            asar_entry_info_free(&info);
            return TURBO_ASAR_ERR_FILE_READ;
        }
#else
        FILE *fp = fopen(archive_path, "rb");
        if (!fp) {
            free(*buffer); *buffer = NULL;
            asar_entry_info_free(&info);
            return TURBO_ASAR_ERR_FILE_NOT_FOUND;
        }
        if (ta_fseek64(fp, (int64_t)file_offset, SEEK_SET) != 0 ||
            fread(*buffer, 1, info.size, fp) != info.size) {
            free(*buffer); *buffer = NULL;
            fclose(fp);
            asar_entry_info_free(&info);
            return TURBO_ASAR_ERR_FILE_READ;
        }
        fclose(fp);
#endif
    }

    asar_entry_info_free(&info);
    return TURBO_ASAR_OK;
}

/* ---------- turbo_asar_list ---------- */

turbo_asar_error_t turbo_asar_list(
    const char *archive_path,
    char ***files,
    size_t *count
)
{
    if (!archive_path || !files || !count) return TURBO_ASAR_ERR_NULL_PARAM;

    *files = NULL;
    *count = 0;

    char *header_json;
    size_t header_size;
    uint64_t data_offset;
    turbo_asar_error_t err = read_archive_header(archive_path, &header_json, &header_size, &data_offset);
    if (err != TURBO_ASAR_OK) return err;

    cJSON *header = cJSON_Parse(header_json);
    free(header_json);
    if (!header) return TURBO_ASAR_ERR_JSON_PARSE;

    asar_filesystem_t *fs = asar_filesystem_create(archive_path);
    if (!fs) { cJSON_Delete(header); return TURBO_ASAR_ERR_OUT_OF_MEMORY; }
    asar_filesystem_set_header(fs, header, header_size);

    if (!asar_filesystem_list_files(fs, files, count)) {
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_OUT_OF_MEMORY;
    }

    asar_filesystem_free(fs);
    return TURBO_ASAR_OK;
}

/* ---------- turbo_asar_get_header ---------- */

turbo_asar_error_t turbo_asar_get_header(
    const char *archive_path,
    char **header_json
)
{
    if (!archive_path || !header_json) return TURBO_ASAR_ERR_NULL_PARAM;

    size_t header_size;
    uint64_t data_offset;
    return read_archive_header(archive_path, header_json, &header_size, &data_offset);
}

/* ---------- turbo_asar_stat ---------- */

turbo_asar_error_t turbo_asar_stat(
    const char *archive_path,
    const char *file_path,
    turbo_asar_entry_t *entry
)
{
    if (!archive_path || !file_path || !entry) return TURBO_ASAR_ERR_NULL_PARAM;

    memset(entry, 0, sizeof(*entry));

    char *header_json;
    size_t header_size;
    uint64_t data_offset;
    turbo_asar_error_t err = read_archive_header(archive_path, &header_json, &header_size, &data_offset);
    if (err != TURBO_ASAR_OK) return err;

    cJSON *header = cJSON_Parse(header_json);
    free(header_json);
    if (!header) return TURBO_ASAR_ERR_JSON_PARSE;

    asar_filesystem_t *fs = asar_filesystem_create(archive_path);
    if (!fs) { cJSON_Delete(header); return TURBO_ASAR_ERR_OUT_OF_MEMORY; }
    asar_filesystem_set_header(fs, header, header_size);

    asar_entry_info_t info;
    if (!asar_filesystem_get_entry(fs, file_path, true, &info)) {
        asar_filesystem_free(fs);
        return TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE;
    }

    switch (info.type) {
        case ASAR_ENTRY_FILE:      entry->type = TURBO_ASAR_ENTRY_FILE;      break;
        case ASAR_ENTRY_DIRECTORY: entry->type = TURBO_ASAR_ENTRY_DIRECTORY; break;
        case ASAR_ENTRY_LINK:      entry->type = TURBO_ASAR_ENTRY_LINK;      break;
    }
    entry->size       = info.size;
    entry->offset     = info.offset;
    entry->unpacked   = info.unpacked;
    entry->executable = info.executable;

    if (info.link) entry->link = strdup(info.link);

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
                        entry->integrity->blocks[i] = info.integrity_blocks[i]
                            ? strdup(info.integrity_blocks[i]) : NULL;
                    }
                }
            }
        }
    }

    asar_entry_info_free(&info);
    asar_filesystem_free(fs);
    return TURBO_ASAR_OK;
}

/* ---------- cleanup helpers ---------- */

void turbo_asar_free_list(char **files, size_t count)
{
    if (!files) return;
    for (size_t i = 0; i < count; i++) free(files[i]);
    free(files);
}

void turbo_asar_free_entry(turbo_asar_entry_t *entry)
{
    if (!entry) return;
    if (entry->link)      { free(entry->link);      entry->link      = NULL; }
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
        for (size_t i = 0; i < integrity->block_count; i++) free(integrity->blocks[i]);
        free(integrity->blocks);
        integrity->blocks = NULL;
    }
}
