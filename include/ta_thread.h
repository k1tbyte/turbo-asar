/**
 * @file ta_thread.h
 * @brief Minimal cross-platform threading primitives (internal).
 *
 * pthread on POSIX, Win32 on Windows. Header-only for POSIX glue,
 * implementation in ta_thread.c.
 */

#ifndef TURBO_ASAR_TA_THREAD_H
#define TURBO_ASAR_TA_THREAD_H

#include "defines.h"
#include <stddef.h>

#ifdef __WINDOWS__
#  include <windows.h>
typedef HANDLE           ta_thread_t;
typedef CRITICAL_SECTION ta_mutex_t;
#else
#  include <pthread.h>
typedef pthread_t        ta_thread_t;
typedef pthread_mutex_t  ta_mutex_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(*ta_thread_fn)(void *arg);

/* Returns 0 on success, non-zero on failure. */
int  ta_thread_create(ta_thread_t *thread, ta_thread_fn fn, void *arg);
void ta_thread_join(ta_thread_t thread);

void ta_mutex_init(ta_mutex_t *m);
void ta_mutex_destroy(ta_mutex_t *m);
void ta_mutex_lock(ta_mutex_t *m);
void ta_mutex_unlock(ta_mutex_t *m);

/* Logical CPU count, clamped to >= 1. */
int  ta_cpu_count(void);

#ifdef __cplusplus
}
#endif

#endif /* TURBO_ASAR_TA_THREAD_H */
