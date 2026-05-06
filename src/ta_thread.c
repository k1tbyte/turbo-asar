/**
 * @file ta_thread.c
 * @brief Cross-platform threading primitives implementation.
 */

#include "ta_thread.h"

#include <stdlib.h>
#include <stdint.h>

#ifdef __WINDOWS__

#include <process.h>

typedef struct {
    ta_thread_fn fn;
    void *arg;
} ta_win_trampoline_t;

static unsigned __stdcall ta_win_thread_entry(void *p)
{
    ta_win_trampoline_t *t = (ta_win_trampoline_t *)p;
    ta_thread_fn fn = t->fn;
    void *arg = t->arg;
    free(t);
    (void)fn(arg);
    return 0;
}

int ta_thread_create(ta_thread_t *thread, ta_thread_fn fn, void *arg)
{
    ta_win_trampoline_t *t = (ta_win_trampoline_t *)malloc(sizeof(*t));
    if (!t) return -1;
    t->fn = fn;
    t->arg = arg;

    uintptr_t h = _beginthreadex(NULL, 0, ta_win_thread_entry, t, 0, NULL);
    if (h == 0) {
        free(t);
        return -1;
    }
    *thread = (HANDLE)h;
    return 0;
}

void ta_thread_join(ta_thread_t thread)
{
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
}

void ta_mutex_init(ta_mutex_t *m)    { InitializeCriticalSection(m); }
void ta_mutex_destroy(ta_mutex_t *m) { DeleteCriticalSection(m); }
void ta_mutex_lock(ta_mutex_t *m)    { EnterCriticalSection(m); }
void ta_mutex_unlock(ta_mutex_t *m)  { LeaveCriticalSection(m); }

int ta_cpu_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int n = (int)si.dwNumberOfProcessors;
    return n < 1 ? 1 : n;
}

#else  /* POSIX */

#include <unistd.h>

int ta_thread_create(ta_thread_t *thread, ta_thread_fn fn, void *arg)
{
    return pthread_create(thread, NULL, fn, arg);
}

void ta_thread_join(ta_thread_t thread)
{
    pthread_join(thread, NULL);
}

void ta_mutex_init(ta_mutex_t *m)    { pthread_mutex_init(m, NULL); }
void ta_mutex_destroy(ta_mutex_t *m) { pthread_mutex_destroy(m); }
void ta_mutex_lock(ta_mutex_t *m)    { pthread_mutex_lock(m); }
void ta_mutex_unlock(ta_mutex_t *m)  { pthread_mutex_unlock(m); }

int ta_cpu_count(void)
{
#if defined(_SC_NPROCESSORS_ONLN)
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    return (int)n;
#else
    return 1;
#endif
}

#endif
