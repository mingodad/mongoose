#include "mongoose_thread.h"

mg_thread_t mg_thread_self(void)
{
#ifdef _WIN32
    return GetCurrentThreadId();
#else
    return pthread_self();
#endif // _WIN32
}

int mg_start_thread(mg_thread_func_t func, void *param) {
#if defined(_WIN32) && !defined(__SYMBIAN32__)
  return _beginthread((void (__cdecl *)(void *)) func, 0, param) == -1L ? -1 : 0;
#else
  pthread_t thread_id;
  pthread_attr_t attr;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  // TODO(lsm): figure out why mongoose dies on Linux if next line is enabled
  // (void) pthread_attr_setstacksize(&attr, sizeof(struct mg_connection) * 5);

  return pthread_create(&thread_id, &attr, func, param);
#endif
}

int mg_thread_mutex_init(mg_thread_mutex_t *mutex, const mg_thread_mutexattr_t *attr)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    attr = NULL;
    *mutex = CreateMutex(NULL, FALSE, NULL);
    return *mutex == NULL ? -1 : 0;
#else
    return pthread_mutex_init(mutex, attr);
#endif
}

int mg_thread_mutex_destroy(mg_thread_mutex_t *mutex)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    return CloseHandle(*mutex) == 0 ? -1 : 0;
#else
    return pthread_mutex_destroy(mutex);
#endif
}

int mg_thread_mutex_lock(mg_thread_mutex_t *mutex)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0? 0 : -1;
#else
    return pthread_mutex_lock(mutex);
#endif
}

int mg_thread_mutex_unlock(mg_thread_mutex_t *mutex)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    return ReleaseMutex(*mutex) == 0 ? -1 : 0;
#else
    return pthread_mutex_unlock(mutex);
#endif
}

int mg_thread_cond_init(mg_thread_cond_t *cv, const mg_thread_condattr_t *attr)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    attr = NULL;
    cv->signal = CreateEvent(NULL, FALSE, FALSE, NULL);
    cv->broadcast = CreateEvent(NULL, TRUE, FALSE, NULL);
    return cv->signal != NULL && cv->broadcast != NULL ? 0 : -1;
#else
    return pthread_cond_init((pthread_cond_t*)cv, attr);
#endif
}

int mg_thread_cond_wait(mg_thread_cond_t *cv, mg_thread_mutex_t *mutex)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    HANDLE handles[] = {cv->signal, cv->broadcast};
    ReleaseMutex(*mutex);
    WaitForMultipleObjects(2, handles, FALSE, INFINITE);
    return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0? 0 : -1;
#else
    return pthread_cond_wait((pthread_cond_t*)cv, mutex);
#endif
}

int mg_thread_cond_signal(mg_thread_cond_t *cv)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    return SetEvent(cv->signal) == 0 ? -1 : 0;
#else
    return pthread_cond_signal((pthread_cond_t*)cv);
#endif
}

int mg_thread_cond_broadcast(mg_thread_cond_t *cv)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    // Implementation with PulseEvent() has race condition, see
    // http://www.cs.wustl.edu/~schmidt/win32-cv-1.html
    return PulseEvent(cv->broadcast) == 0 ? -1 : 0;
#else
    return pthread_cond_broadcast((pthread_cond_t*)cv);
#endif
}

int mg_thread_cond_destroy(mg_thread_cond_t *cv)
{
#if defined(_WIN32) && !defined(__SYMBIAN32__)
    return CloseHandle(cv->signal) && CloseHandle(cv->broadcast) ? 0 : -1;
#else
    return pthread_cond_destroy((pthread_cond_t*)cv);
#endif
}
