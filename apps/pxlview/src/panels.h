/* pxlview panel content generators.
 *
 * Each panel appends formatted, human-readable lines into a shared text
 * buffer. All kernel reads happen here (one-shot at startup); the UI only
 * scrolls the finished text.
 */
#ifndef PXL_PANELS_H
#define PXL_PANELS_H

#include <stddef.h>

typedef struct pxl_ctx {
    char  *buf;
    size_t len;
    size_t cap;
} pxl_ctx_t;

/* append helper (returns 0 on success, -1 on OOM) */
int pxl_append(pxl_ctx_t *ctx, const char *fmt, ...);

int panel_ktext(pxl_ctx_t *ctx);    /* P1: first 64 bytes of kernel .text */
int panel_hv(pxl_ctx_t *ctx);       /* P2: HV memory hex + strings */
int panel_procs(pxl_ctx_t *ctx);    /* P3: allproc walk */
int panel_nor(pxl_ctx_t *ctx);      /* P4: /mnt/nor0 directory tree */
int panel_identity(pxl_ctx_t *ctx); /* P5: fw / soc / model / bases */

int panels_collect_all(pxl_ctx_t *ctx);

#endif /* PXL_PANELS_H */
