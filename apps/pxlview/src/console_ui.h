/* pxlview on-screen terminal console (SDL2, CPU surface rendering).
 *
 * M1: SDL window + static text.
 * M2: line viewport + scrolling + pad/remote input + status bar.
 */
#ifndef PXL_CONSOLE_UI_H
#define PXL_CONSOLE_UI_H

#include <stddef.h>

int  ui_init(void);                          /* SDL video+joystick, current mode */
void ui_set_title(const char *title);        /* header bar text */
void ui_set_text(const char *text, size_t len);
void ui_render(int *dirty);                  /* blit viewport, present */
/* Pump SDL events. Sets *quit (Start/R3/Quit), *recollect (L3),
 * *dirty (viewport changed). */
int  ui_handle_input(int *quit, int *recollect, int *dirty);
void ui_fini(void);

#endif /* PXL_CONSOLE_UI_H */
