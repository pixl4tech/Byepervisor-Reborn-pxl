/* pxlview — kernel/HV inspector payload (read-only).
 *
 * Lifecycle:
 *   init  -> verify kernel access, collect panels (one-shot)
 *   loop  -> SDL events, render-on-dirty, quit on input/timeout
 *   quit  -> notification with the key line, clean exit
 */
#include <stdio.h>
#include <stdlib.h>

#include "kmem.h"
#include "panels.h"
#include "console_ui.h"
#include "notify.h"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    printf("[pxlview] starting v0.1.0\n");

    if (kmem_init() != 0) {
        printf("[pxlview] kernel access unavailable\n");
        pxl_notify("pxlview: kernel access FAILED");
        return 1;
    }
    printf("[pxlview] kernel access ok\n");

    pxl_ctx_t ctx = {0};
    if (panels_collect_all(&ctx) != 0) {
        printf("[pxlview] panel collection failed\n");
        free(ctx.buf);
        return 1;
    }
    printf("[pxlview] collected %zu bytes of panel text\n", ctx.len);

    if (ui_init() != 0) {
        free(ctx.buf);
        return 1;
    }
    ui_set_text(ctx.buf, ctx.len);

    int quit = 0;
    int dirty = 1;
    while (!quit) {
        ui_handle_input(&quit);
        if (dirty)
            ui_render(&dirty);
    }

    pxl_notify("pxlview: .text read ok, %zu bytes collected (M1)", ctx.len);
    ui_fini();
    free(ctx.buf);

    printf("[pxlview] done\n");
    return 0;
}
