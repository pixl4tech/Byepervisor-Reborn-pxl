#include "console_ui.h"

/* M0 stubs — no SDL calls yet (M1 brings the window + blitter). */

int  ui_init(void)                { return 0; }
void ui_set_text(const char *t, size_t n) { (void)t; (void)n; }
void ui_render(int *dirty)        { if (dirty) *dirty = 0; }
int  ui_handle_input(int *quit)   { (void)quit; return 0; }
void ui_fini(void)                { }
