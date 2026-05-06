/**
 * @file ta_io.h
 * @brief Cross-platform low-level I/O: fd, pwrite, file mmap (internal).
 *
 * POSIX: int fd + pwrite + mmap.
 * Windows: HANDLE + WriteFile(OVERLAPPED) + CreateFileMapping/MapViewOfFile.
 */

#ifndef TURBO_ASAR_TA_IO_H
#define TURBO_ASAR_TA_IO_H

#include "defines.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __WINDOWS__
#  include <windows.h>
typedef HANDLE ta_fd_t;
#  define TA_INVALID_FD INVALID_HANDLE_VALUE
#else
typedef int ta_fd_t;
#  define TA_INVALID_FD (-1)
#endif

typedef struct {
    void    *data;
    size_t   size;
#ifdef __WINDOWS__
    HANDLE   file;
    HANDLE   mapping;
#else
    int      fd;
#endif
} ta_mapped_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Output file: create/truncate for writing. */
ta_fd_t ta_open_create(const char *path);
void    ta_close_fd(ta_fd_t fd);

/* Sequential write. true on success. */
bool    ta_write_all(ta_fd_t fd, const void *buf, size_t n);

/* Positional write at offset. Thread-safe (independent offsets). */
bool    ta_pwrite_all(ta_fd_t fd, const void *buf, size_t n, uint64_t off);

/* Preallocate output to `size` bytes (sparse OK). Best-effort; ignore errors. */
void    ta_preallocate(ta_fd_t fd, uint64_t size);

/* Map a file read-only. On success, fills *m and returns true.
 * Zero-byte files succeed with data=NULL, size=0. */
bool    ta_map_read(const char *path, ta_mapped_t *m);
void    ta_unmap(ta_mapped_t *m);

/* Hint OS that we'll read sequentially (madvise / PrefetchVirtualMemory). */
void    ta_advise_sequential(const ta_mapped_t *m);

#ifdef __cplusplus
}
#endif

#endif /* TURBO_ASAR_TA_IO_H */
