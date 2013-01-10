#ifndef MONGOOSE_THREAD_H
#define MONGOOSE_THREAD_H

#if defined(_WIN32) || defined(_WIN32_WCE)
#include <windows.h>
typedef HANDLE mg_thread_mutex_t;
typedef struct {HANDLE signal, broadcast;} mg_thread_cond_t;
typedef DWORD mg_thread_t;
typedef void mg_thread_mutexattr_t;
typedef void mg_thread_condattr_t;
#else
#include <pthread.h>
typedef pthread_mutex_t mg_thread_mutex_t;
typedef pthread_cond_t mg_thread_cond_t;
typedef pthread_t mg_thread_t;
typedef pthread_mutexattr_t mg_thread_mutexattr_t;
typedef pthread_condattr_t mg_thread_condattr_t;
#endif

// Convenience function -- create detached thread.
// Return: 0 on success, non-0 on error.
typedef void * (*mg_thread_func_t)(void *);

mg_thread_t mg_thread_self(void);
int mg_start_thread(mg_thread_func_t func, void *param);
int mg_thread_mutex_init(mg_thread_mutex_t *mutex, const mg_thread_mutexattr_t *attr);
int mg_thread_mutex_destroy(mg_thread_mutex_t *mutex);
int mg_thread_mutex_lock(mg_thread_mutex_t *mutex);
int mg_thread_mutex_unlock(mg_thread_mutex_t *mutex);
int mg_thread_cond_init(mg_thread_cond_t *cv, const mg_thread_condattr_t *attr);
int mg_thread_cond_wait(mg_thread_cond_t *cv, mg_thread_mutex_t *mutex);
int mg_thread_cond_signal(mg_thread_cond_t *cv);
int mg_thread_cond_broadcast(mg_thread_cond_t *cv);
int mg_thread_cond_destroy(mg_thread_cond_t *cv);

#endif //MONGOOSE_THREAD_H
