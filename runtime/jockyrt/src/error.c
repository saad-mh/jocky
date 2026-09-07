#include "jockyrt.h"

#include "jockyrt_internal.h"

static JKF_TLS uint32_t g_last_os_error = 0;

void jkf__set_os_error(uint32_t err) { g_last_os_error = err; }

uint32_t jkf_last_os_error(void) { return g_last_os_error; }

uint32_t jkf_abi_version(void) { return JKF_ABI_VERSION; }
