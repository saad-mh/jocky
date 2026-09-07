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

#endif /* JOCKYRT_INTERNAL_H */
