#include "panels.h"
#include "kmem.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ps5/kernel.h>

int pxl_append(pxl_ctx_t *ctx, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0)
        return -1;

    if (ctx->len + (size_t)need + 1 > ctx->cap) {
        size_t ncap = ctx->cap ? ctx->cap * 2 : 8192;
        while (ncap < ctx->len + (size_t)need + 1)
            ncap *= 2;
        char *nbuf = realloc(ctx->buf, ncap);
        if (!nbuf)
            return -1;
        ctx->buf = nbuf;
        ctx->cap = ncap;
    }

    va_start(ap, fmt);
    int n = vsnprintf(ctx->buf + ctx->len, (size_t)need + 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        return -1;
    ctx->len += (size_t)n;
    return 0;
}

int panel_ktext(pxl_ctx_t *ctx)
{
    uint8_t buf[64];
    char fmt[512];

    if (pxl_append(ctx, "== P1: kernel .text, first 64 bytes (xotext) ==\n"))
        return -1;
    if (kmem_read((uint64_t)KERNEL_ADDRESS_TEXT_BASE, buf, sizeof(buf)) != 0) {
        pxl_append(ctx, "  [read failed]\n");
        return 0;
    }
    kmem_hexdump_fmt(buf, sizeof(buf), fmt, sizeof(fmt));
    return pxl_append(ctx, "%s\n", fmt);
}

int panel_hv(pxl_ctx_t *ctx)      { (void)ctx; return 0; } /* M3 */
int panel_procs(pxl_ctx_t *ctx)   { (void)ctx; return 0; } /* M3 */
int panel_nor(pxl_ctx_t *ctx)     { (void)ctx; return 0; } /* M3 */
int panel_identity(pxl_ctx_t *ctx){ (void)ctx; return 0; } /* M3 */

int panels_collect_all(pxl_ctx_t *ctx)
{
    if (panel_ktext(ctx))    return -1;
    if (panel_hv(ctx))       return -1;
    if (panel_procs(ctx))    return -1;
    if (panel_nor(ctx))      return -1;
    if (panel_identity(ctx)) return -1;
    return 0;
}
