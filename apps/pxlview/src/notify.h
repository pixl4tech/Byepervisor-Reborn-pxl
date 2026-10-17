/* pxlview notification helper — the ONE key line goes to a system
 * notification; everything else lives in the on-screen window. */
#ifndef PXL_NOTIFY_H
#define PXL_NOTIFY_H

/* Fire a system notification with a single key summary line. */
int pxl_notify(const char *fmt, ...);

#endif /* PXL_NOTIFY_H */
