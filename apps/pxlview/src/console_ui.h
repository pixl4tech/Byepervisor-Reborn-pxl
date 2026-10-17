/* pxlview on-screen terminal console (SDL2, CPU surface rendering).
 *
 * M0: stubs. M1: SDL window + single line. M2: scroller + pad input.
 */
#ifndef PXL_CONSOLE_UI_H
#define PXL_CONSOLE_UI_H

#include <stddef.h>

int  ui_init(void);                          /* SDL video, current mode */
void ui_set_text(const char *text, size_t len);
void ui_render(int *dirty);                  /* blit viewport, present */
int  ui_handle_input(int *quit);             /* pump events; 1 = quit */
void ui_fini(void);

#endif /* PXL_CONSOLE_UI_H */
