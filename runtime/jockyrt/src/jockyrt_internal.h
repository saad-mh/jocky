/* Internal helpers shared between jockyrt translation units. Not installed. */
#ifndef JOCKYRT_INTERNAL_H
#define JOCKYRT_INTERNAL_H

#include <stdint.h>

#if defined(_MSC_VER)
#  define JKF_TLS __declspec(thread)
#else
#  define JKF_TLS _Thread_local
#endif

/* Record the OS error to report through jkf_last_os_error(). Call this right
 * before returning JKF_E_OS. */
void jkf__set_os_error(uint32_t err);

/* --- handle table (src/handle.c) --------------------------------------
 *
 * A small-int token stands in for a Win32 HANDLE so no pointer crosses the
 * ABI. Single-threaded use is assumed (a scan is sequential). */

/* Registers `os_handle` and returns a token >= 1, or JKF_E_NOMEM. */
int jkf__handle_alloc(void *os_handle);

/* The HANDLE behind `token`, or NULL if the token is unknown. */
void *jkf__handle_get(int token);

/* Drops `token` (does NOT close the underlying HANDLE). Returns JKF_OK or
 * JKF_E_BADHANDLE. */
int jkf__handle_release(int token);

#endif /* JOCKYRT_INTERNAL_H */
