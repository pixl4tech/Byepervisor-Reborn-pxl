#include "notify.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Same kernel notification API as the byepv-pxl payload (see util.c
 * notifyf / sdk samples/notify). M4: full JSON payload + icon. */

typedef struct notify_request {
    uint32_t size;
    uint32_t version;
    uint32_t type;
    uint32_t param;
    char     message[1024];
} notify_request_t;

extern int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

int pxl_notify(const char *fmt, ...)
{
    notify_request_t req;
    va_list ap;

    memset(&req, 0, sizeof(req));
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);

    return sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}
