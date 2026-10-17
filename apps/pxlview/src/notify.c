#include "notify.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Same kernel notification struct the byepv-pxl payload uses on hardware
 * (root include/util.h: char useless1[45] + char message[3075], passed to
 * sceKernelSendNotificationRequest with sizeof as the size). pxlview's key
 * line is the only thing that goes to a system notification. */

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

extern int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

int pxl_notify(const char *fmt, ...)
{
    notify_request_t req;
    va_list ap;

    bzero(&req, sizeof(req));
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);

    return sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}
