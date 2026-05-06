/**
 * @file ta_io.c
 * @brief Cross-platform low-level I/O implementation.
 */

#if !defined(__WINDOWS__) && !defined(_WIN32)
#  define _FILE_OFFSET_BITS 64
#  define _GNU_SOURCE
#  define _DEFAULT_SOURCE
#endif

#include "ta_io.h"

#include <stdlib.h>
#include <string.h>

#ifdef __WINDOWS__

ta_fd_t ta_open_create(const char *path)
{
    HANDLE h = CreateFileA(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    return h;
}

void ta_close_fd(ta_fd_t fd)
{
    if (fd != TA_INVALID_FD) CloseHandle(fd);
}

bool ta_write_all(ta_fd_t fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        DWORD chunk = n > (1u << 30) ? (1u << 30) : (DWORD)n;
        DWORD written = 0;
        if (!WriteFile(fd, p, chunk, &written, NULL) || written == 0) return false;
        p += written;
        n -= written;
    }
    return true;
}

bool ta_pwrite_all(ta_fd_t fd, const void *buf, size_t n, uint64_t off)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        OVERLAPPED ov = {0};
        ov.Offset = (DWORD)(off & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)(off >> 32);
        DWORD chunk = n > (1u << 30) ? (1u << 30) : (DWORD)n;
        DWORD written = 0;
        if (!WriteFile(fd, p, chunk, &written, &ov) || written == 0) return false;
        p += written;
        n -= written;
        off += written;
    }
    return true;
}

void ta_preallocate(ta_fd_t fd, uint64_t size)
{
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)size;
    if (SetFilePointerEx(fd, li, NULL, FILE_BEGIN)) {
        SetEndOfFile(fd);
    }
    /* Reset to start so subsequent sequential WriteFile() lands at offset 0. */
    LARGE_INTEGER zero = {0};
    SetFilePointerEx(fd, zero, NULL, FILE_BEGIN);
}

bool ta_map_read(const char *path, ta_mapped_t *m)
{
    memset(m, 0, sizeof(*m));
    HANDLE f = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );
    if (f == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(f, &sz)) { CloseHandle(f); return false; }

    m->file = f;
    m->size = (size_t)sz.QuadPart;
    if (sz.QuadPart == 0) {
        m->mapping = NULL;
        m->data = NULL;
        return true;
    }
    if ((uint64_t)sz.QuadPart > (uint64_t)SIZE_MAX) {
        CloseHandle(f);
        return false;
    }

    HANDLE map = CreateFileMappingA(f, NULL, PAGE_READONLY, sz.HighPart, sz.LowPart, NULL);
    if (!map) { CloseHandle(f); return false; }
    void *data = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!data) { CloseHandle(map); CloseHandle(f); return false; }

    m->mapping = map;
    m->data = data;
    return true;
}

void ta_unmap(ta_mapped_t *m)
{
    if (!m) return;
    if (m->data) UnmapViewOfFile(m->data);
    if (m->mapping) CloseHandle(m->mapping);
    if (m->file && m->file != INVALID_HANDLE_VALUE) CloseHandle(m->file);
    memset(m, 0, sizeof(*m));
}

void ta_advise_sequential(const ta_mapped_t *m)
{
    if (!m || !m->data || m->size == 0) return;
    /* PrefetchVirtualMemory requires Win8+. Best-effort, ignore failure. */
    typedef BOOL (WINAPI *PFN_PVM)(HANDLE, ULONG_PTR, PWIN32_MEMORY_RANGE_ENTRY, ULONG);
    static PFN_PVM pfn = NULL;
    static int resolved = 0;
    if (!resolved) {
        HMODULE k = GetModuleHandleA("kernel32.dll");
        if (k) pfn = (PFN_PVM)(void(*)(void))GetProcAddress(k, "PrefetchVirtualMemory");
        resolved = 1;
    }
    if (pfn) {
        WIN32_MEMORY_RANGE_ENTRY r = { m->data, m->size };
        pfn(GetCurrentProcess(), 1, &r, 0);
    }
}

#else  /* POSIX */

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

ta_fd_t ta_open_create(const char *path)
{
    return open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
}

void ta_close_fd(ta_fd_t fd)
{
    if (fd >= 0) close(fd);
}

bool ta_write_all(ta_fd_t fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return false;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return true;
}

bool ta_pwrite_all(ta_fd_t fd, const void *buf, size_t n, uint64_t off)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = pwrite(fd, p, n, (off_t)off);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return false;
        }
        p += (size_t)w;
        n -= (size_t)w;
        off += (uint64_t)w;
    }
    return true;
}

void ta_preallocate(ta_fd_t fd, uint64_t size)
{
#if defined(__linux__) && defined(_GNU_SOURCE)
    (void)fallocate(fd, 0, 0, (off_t)size);
#else
    (void)ftruncate(fd, (off_t)size);
#endif
}

bool ta_map_read(const char *path, ta_mapped_t *m)
{
    memset(m, 0, sizeof(*m));
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return false; }

    m->fd = fd;
    m->size = (size_t)st.st_size;
    if (st.st_size == 0) {
        m->data = NULL;
        return true;
    }
    if ((uint64_t)st.st_size > (uint64_t)SIZE_MAX) {
        close(fd);
        return false;
    }

    void *data = mmap(NULL, m->size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) { close(fd); return false; }

    m->data = data;
    return true;
}

void ta_unmap(ta_mapped_t *m)
{
    if (!m) return;
    if (m->data) munmap(m->data, m->size);
    if (m->fd > 0) close(m->fd);
    memset(m, 0, sizeof(*m));
}

void ta_advise_sequential(const ta_mapped_t *m)
{
    if (!m || !m->data || m->size == 0) return;
#if defined(MADV_SEQUENTIAL)
    (void)madvise(m->data, m->size, MADV_SEQUENTIAL);
#endif
#if defined(POSIX_MADV_WILLNEED)
    (void)posix_madvise(m->data, m->size, POSIX_MADV_WILLNEED);
#endif
}

#endif
