/* pxlview panel content generators.
 *
 * Each panel appends formatted, human-readable lines into a shared text
 * buffer. All kernel reads happen here (one-shot at startup); the UI only
 * scrolls the finished text.
 */
#ifndef PXL_PANELS_H
#define PXL_PANELS_H

#include <stddef.h>
#include <stdint.h>

typedef struct pxl_ctx {
    char  *buf;
    size_t len;
    size_t cap;
} pxl_ctx_t;

/* Key-line summary, filled by panels_collect_all() for the notification. */
typedef struct pxl_summary {
    int      ktext_ok;      /* P1: .text read succeeded */
    uint64_t ktext_base;    /* P1: KERNEL_ADDRESS_TEXT_BASE */
    int      hv_ok;         /* P2: HV window read succeeded */
    int      procs_count;   /* P3: live processes found */
    int      nor_ok;        /* P4: /mnt/nor0 listed */
    int      nor_entries;   /* P4: entries listed */
    uint32_t fw_version;    /* P5: kernel_get_fw_version() */
} pxl_summary_t;

/* append helper (returns 0 on success, -1 on OOM) */
int pxl_append(pxl_ctx_t *ctx, const char *fmt, ...);

int panel_ktext(pxl_ctx_t *ctx, pxl_summary_t *sum);  /* P1: kernel .text */
int panel_hv(pxl_ctx_t *ctx, pxl_summary_t *sum);     /* P2: HV hex + strings */
int panel_procs(pxl_ctx_t *ctx, pxl_summary_t *sum);  /* P3: process list */
int panel_nor(pxl_ctx_t *ctx, pxl_summary_t *sum);    /* P4: /mnt/nor0 tree */
int panel_identity(pxl_ctx_t *ctx, pxl_summary_t *sum); /* P5: fw/soc/bases */

/* Collect all panels. 0 = ok (individual panel failures are reported
 * inside the text, not as an error). */
int panels_collect_all(pxl_ctx_t *ctx, pxl_summary_t *sum);

#endif /* PXL_PANELS_H */
