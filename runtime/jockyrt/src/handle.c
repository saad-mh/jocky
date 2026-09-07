#include "jockyrt.h"

#include "jockyrt_internal.h"

#include <stddef.h>

/* A fixed table is plenty: a forensic run opens one target at a time, maybe a
 * handful with snapshots. Slot 0 is never handed out so a token is always
 * truthy. */
enum { JKF_HANDLE_SLOTS = 64 };

static void *g_handles[JKF_HANDLE_SLOTS];

int jkf__handle_alloc(void *os_handle) {
    for (int i = 1; i < JKF_HANDLE_SLOTS; ++i) {
        if (g_handles[i] == NULL) {
            g_handles[i] = os_handle;
            return i;
        }
    }
    return JKF_E_NOMEM;
}

void *jkf__handle_get(int token) {
    if (token <= 0 || token >= JKF_HANDLE_SLOTS) return NULL;
    return g_handles[token];
}

int jkf__handle_release(int token) {
    if (token <= 0 || token >= JKF_HANDLE_SLOTS || g_handles[token] == NULL)
        return JKF_E_BADHANDLE;
    g_handles[token] = NULL;
    return JKF_OK;
}
