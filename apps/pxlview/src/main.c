/* pxlview — kernel/HV inspector payload (read-only).
 *
 * Lifecycle:
 *   init  -> verify kernel access, collect panels (one-shot)
 *   loop  -> SDL events, scroll, render-on-dirty
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

    printf("[pxlview] starting (stub M0)\n");

    if (kmem_init() != 0) {
        printf("[pxlview] kernel access unavailable\n");
        return 1;
    }

    pxl_ctx_t ctx = {0};
    if (panels_collect_all(&ctx) != 0) {
        printf("[pxlview] panel collection failed\n");
        free(ctx.buf);
        return 1;
    }
    printf("[pxlview] collected %zu bytes of panel text\n", ctx.len);
    free(ctx.buf);

    /* M1+: ui_init() / ui_set_text() / event loop / ui_fini() */

    printf("[pxlview] done (stub)\n");
    return 0;
}
