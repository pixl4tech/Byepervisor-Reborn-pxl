/* pxlview on-screen terminal console (SDL2, CPU surface rendering).
 *
 * M1: fullscreen window + static text (no scrolling yet).
 * Display path: window surface (ABGR8888) -> PS5_Tilemap_Blit ->
 * sceVideoOutSubmitFlip (implemented inside the SDL PS5 video driver,
 * see third_party/SDL2/src/video/ps5/SDL_ps5video.c).
 */
#include "console_ui.h"
#include "font_5x7.h"

#include <SDL.h>
#include <string.h>
#include <stdio.h>

#define SCALE        4            /* 5x7 -> 20x28 px per cell at 4K */
#define MARGIN_X     64           /* px */
#define MARGIN_Y     48           /* px */
#define HEADER_H     72           /* px, title bar height */

#define COL_BG       0xFF000000u  /* black  (ABGR8888) */
#define COL_HEADER   0xFF101018u  /* near-black blue */
#define COL_TEXT     0xFFFFFFFFu  /* white  */
#define COL_DIM      0xFF888899u  /* dim gray */

static SDL_Window  *win;
static SDL_Surface *surface;
static const char  *g_text;
static size_t       g_text_len;
static int          g_inited;

/* draw one character at cell (col, row) with the 5x7 font at SCALE */
static void draw_char(SDL_Surface *s, int px, int py, unsigned char c)
{
    const uint8_t *g = font_5x7[c & 0xFF];
    for (int y = 0; y < FONT_H; y++) {
        uint8_t bits = g[y];
        for (int x = 0; x < FONT_W; x++) {
            if (!(bits & (1u << x)))
                continue;
            SDL_Rect r = { px + x * SCALE, py + y * SCALE, SCALE, SCALE };
            SDL_FillRect(s, &r, COL_TEXT);
        }
    }
}

static void draw_string(SDL_Surface *s, int px, int py,
                        const char *str, Uint32 color)
{
    (void)color; /* M1: single text color; dim colors arrive with M2 */
    for (const char *p = str; *p; p++)
        draw_char(s, px, py, (unsigned char)*p), px += FONT_W * SCALE;
}

int ui_init(void)
{
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        printf("[pxlview-ui] SDL_Init: %s\n", SDL_GetError());
        return -1;
    }

    /* Fullscreen; the PS5 driver reports the current mode (3840x2160). */
    win = SDL_CreateWindow("pxlview", SDL_WINDOWPOS_CENTERED,
                           SDL_WINDOWPOS_CENTERED, 1920, 1080,
                           SDL_WINDOW_FULLSCREEN);
    if (!win) {
        printf("[pxlview-ui] SDL_CreateWindow: %s\n", SDL_GetError());
        SDL_Quit();
        return -1;
    }

    surface = SDL_GetWindowSurface(win);
    if (!surface) {
        printf("[pxlview-ui] SDL_GetWindowSurface: %s\n", SDL_GetError());
        SDL_Quit();
        return -1;
    }
    printf("[pxlview-ui] window %dx%d fmt=0x%x\n",
           surface->w, surface->h, (unsigned)surface->format->format);

    g_inited = 1;
    return 0;
}

void ui_set_text(const char *text, size_t len)
{
    g_text = text;
    g_text_len = len;
}

void ui_render(int *dirty)
{
    if (!g_inited)
        return;

    /* background */
    SDL_FillRect(surface, NULL, COL_BG);

    /* header bar */
    SDL_Rect hdr = { 0, 0, surface->w, HEADER_H };
    SDL_FillRect(surface, &hdr, COL_HEADER);
    draw_string(surface, MARGIN_X, (HEADER_H - FONT_H * SCALE) / 2,
                "pxlview v0.1.0  -  PS5 kernel/HV inspector (read-only)",
                COL_TEXT);

    /* body: all lines, top to bottom (no scrolling in M1) */
    int py = MARGIN_Y + HEADER_H;
    const char *p = g_text ? g_text : "";
    size_t remaining = g_text_len;
    while (remaining > 0 && py < surface->h - FONT_H * SCALE) {
        const char *eol = memchr(p, '\n', remaining);
        size_t linelen = eol ? (size_t)(eol - p) : remaining;
        if (linelen > 160)
            linelen = 160;
        draw_string(surface, MARGIN_X, py, p, COL_TEXT);
        if (eol) { p = eol + 1; remaining -= linelen + 1; }
        else break;
        py += FONT_H * SCALE + 8;
    }

    if (SDL_UpdateWindowSurface(win) != 0)
        printf("[pxlview-ui] update: %s\n", SDL_GetError());

    if (dirty)
        *dirty = 0;
}

int ui_handle_input(int *quit)
{
    /* M1: quit on SDL_QUIT or after 30 s (console test without a pad). */
    static int frames = 0;
    SDL_Event e;
    while (SDL_PollEvent(&e)) {
        if (e.type == SDL_QUIT) {
            *quit = 1;
            return 0;
        }
    }
    if (++frames > 30 * 60)   /* 30 s at 60 fps */
        *quit = 1;
    SDL_Delay(16);            /* ~60 fps tick */
    return 0;
}

void ui_fini(void)
{
    if (!g_inited)
        return;
    SDL_Quit();
    g_inited = 0;
}
