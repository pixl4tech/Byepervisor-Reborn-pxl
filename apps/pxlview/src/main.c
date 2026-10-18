/* pxlview — kernel/HV inspector payload (read-only).
 *
 * Lifecycle:
 *   init  -> verify kernel access, raise system authid (saved/restored),
 *            collect panels (one-shot; L3 re-collects)
 *   loop  -> SDL events, scroll, render-on-dirty, quit on input/timeout
 *   quit  -> notification with the key line, clean exit
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "version.h"
#include "kmem.h"
#include "panels.h"
#include "console_ui.h"
#include "notify.h"

/* Clean exit on SIGTERM (so the VideoOut session is released via
 * SDL_Quit instead of leaking in the driver when the app manager
 * kills the process). */
static volatile sig_atomic_t g_sigterm = 0;
static void on_sigterm(int s) { (void)s; g_sigterm = 1; }

static void finish(int code)
{
    kmem_restore_authid();
    ui_fini();
    printf("[pxlview] done\n");
    exit(code);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    printf("[pxlview] starting v%s\n", PXL_VERSION);

    if (kmem_init() != 0) {
        printf("[pxlview] kernel access FAILED\n");
        pxl_notify("pxlview v%s: kernel access FAILED", PXL_VERSION);
        finish(1);
    }
    printf("[pxlview] kernel access ok\n");

    /* System authid for VideoOut buffer registration (M1) and /mnt/nor0
     * (P4). Restored on exit; see kmem.h for the read-only caveat. */
    if (kmem_set_system_authid() != 0)
        printf("[pxlview] warning: system authid set failed\n");

    /* Mount-jail escape so /mnt/nor0 (P4) is visible from the WebKit
     * namespace. One-shot, not restored. */
    if (kmem_set_root_vnode() != 0)
        printf("[pxlview] warning: root-vnode escape failed\n");

    pxl_ctx_t ctx = {0};
    pxl_summary_t sum;
    if (panels_collect_all(&ctx, &sum) != 0) {
        printf("[pxlview] panel collection FAILED\n");
        pxl_notify("pxlview v%s: panel collection FAILED", PXL_VERSION);
        free(ctx.buf);
        finish(1);
    }
    printf("[pxlview] collected %zu bytes of panel text "
           "(procs=%d nor=%d hv=%d)\n",
           ctx.len, sum.procs_count, sum.nor_ok, sum.hv_ok);

    if (ui_init() != 0) {
        printf("[pxlview] display FAILED\n");
        pxl_notify("pxlview v%s: display FAILED (see host log)", PXL_VERSION);
        free(ctx.buf);
        finish(1);
    }

    char title[128];
    snprintf(title, sizeof(title),
             "pxlview v%s - PS5 kernel/HV inspector (read-only)", PXL_VERSION);
    ui_set_title(title);
    ui_set_text(ctx.buf, ctx.len);

    int quit = 0;
    int dirty = 1;
    signal(SIGTERM, on_sigterm);
    while (!quit) {
        if (g_sigterm) {
            printf("[pxlview] SIGTERM — clean exit\n");
            quit = 1;
        }
        int recollect = 0;
        ui_handle_input(&quit, &recollect, &dirty);
        if (recollect && !quit) {
            pxl_ctx_t nctx = {0};
            if (panels_collect_all(&nctx, &sum) == 0) {
                free(ctx.buf);
                ctx = nctx;
                ui_set_text(ctx.buf, ctx.len);
            } else {
                /* keep the previous content on OOM */
                free(nctx.buf);
            }
            printf("[pxlview] re-collected %zu bytes\n", ctx.len);
            dirty = 1;
        }
        if (dirty)
            ui_render(&dirty);
    }

    char keyline[160];
    snprintf(keyline, sizeof(keyline),
             "pxlview v%s: .text=%s 0x%llx, %d procs, NOR %s, HV %s, "
             "fw 0x%08x",
             PXL_VERSION,
             sum.ktext_ok ? "ok" : "FAIL",
             (unsigned long long)sum.ktext_base,
             sum.procs_count,
             sum.nor_ok ? "ok" : "FAIL",
             sum.hv_ok ? "ok" : "FAIL",
             (unsigned)sum.fw_version);
    pxl_notify("%s", keyline);
    printf("[pxlview] %s\n", keyline);

    free(ctx.buf);
    finish(0);
}
