/* pxlview on-screen terminal console (SDL2, CPU surface rendering).
 *
 * M2: line viewport + scrolling + pad input + status bar.
 * Display path: window surface (ABGR8888) -> PS5_Tilemap_Blit ->
 * sceVideoOutSubmitFlip (implemented inside the SDL PS5 video driver,
 * see third_party/SDL2/src/video/ps5/SDL_ps5video.c).
 *
 * Pad button map (SDL_ps5joystick.c btn_map):
 *   b6=Options(Start) b7=L3 b8=R3 b9=L1 b10=R1 b11=Up b12=Down
 */
#include "console_ui.h"
#include "font_5x7.h"

#include <SDL.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SCALE        4            /* 5x7 -> 20x28 px per cell at 4K */
#define MARGIN_X     64           /* px */
#define MARGIN_Y     48           /* px */
#define HEADER_H     72           /* px, title bar height */
#define STATUS_H     48           /* px, bottom status bar height */
#define LINE_H       (FONT_H * SCALE + 8)
#define MAX_LINE     160          /* chars per line (render cap) */
#define MAX_LINES    4096
#define GUARD_TIMEOUT_SECS 900    /* 15 min last-resort exit (no input) */

#define COL_BG       0xFF000000u  /* black  (ABGR8888) */
#define COL_HEADER   0xFF101018u  /* near-black blue */
#define COL_STATUS   0xFF101018u
#define COL_TEXT     0xFFFFFFFFu  /* white  */
#define COL_DIM      0xFF888899u  /* dim gray */

static SDL_Window  *win;
static SDL_Surface *surface;
static int          g_inited;

static const char  *g_title = "pxlview";
static const char  *g_text;
static size_t       g_text_len;
static const char  *g_lines[MAX_LINES];
static size_t       g_lines_len[MAX_LINES];
static int          g_nlines;
static int          g_scroll;     /* top visible line index */
static int          g_vlines;     /* visible lines (set at render time) */

/* draw one character at cell (col, row) with the 5x7 font at SCALE */
static void draw_char(SDL_Surface *s, int px, int py, unsigned char c,
                      Uint32 color)
{
    const uint8_t *g = font_5x7[c & 0xFF];
    for (int y = 0; y < FONT_H; y++) {
        uint8_t bits = g[y];
        for (int x = 0; x < FONT_W; x++) {
            if (!(bits & (1u << x)))
                continue;
            SDL_Rect r = { px + x * SCALE, py + y * SCALE, SCALE, SCALE };
            SDL_FillRect(s, &r, color);
        }
    }
}

static void draw_string(SDL_Surface *s, int px, int py,
                        const char *str, size_t len, Uint32 color)
{
    for (size_t i = 0; i < len; i++) {
        draw_char(s, px, py, (unsigned char)str[i], color);
        px += FONT_W * SCALE;
    }
}

void ui_set_title(const char *title)
{
    if (title)
        g_title = title;
}

void ui_set_text(const char *text, size_t len)
{
    g_text = text;
    g_text_len = len;
    g_nlines = 0;
    g_scroll = 0;

    const char *p = text ? text : "";
    size_t remaining = len;
    while (remaining > 0 && g_nlines < MAX_LINES) {
        const char *eol = memchr(p, '\n', remaining);
        size_t linelen = eol ? (size_t)(eol - p) : remaining;
        g_lines[g_nlines] = p;
        g_lines_len[g_nlines] = linelen;
        g_nlines++;
        if (eol) { p = eol + 1; remaining -= linelen + 1; }
        else break;
    }
}

int ui_init(void)
{
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_JOYSTICK) != 0) {
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

    /* Open joysticks so SDL posts raw button events (DualSense via the
     * PS5 joystick driver). */
    int nj = SDL_NumJoysticks();
    for (int i = 0; i < nj; i++) {
        SDL_Joystick *js = SDL_JoystickOpen(i);
        printf("[pxlview-ui] joystick %d: %s\n", i,
               js ? SDL_JoystickName(js) : "open failed");
    }

    g_inited = 1;
    return 0;
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
                g_title, strlen(g_title), COL_TEXT);

    /* body: viewport over the line array */
    int body_top = MARGIN_Y + HEADER_H;
    int body_bot = surface->h - STATUS_H;
    g_vlines = (body_bot - body_top) / LINE_H;
    if (g_vlines < 1)
        g_vlines = 1;
    if (g_scroll < 0)
        g_scroll = 0;
    if (g_scroll > g_nlines)
        g_scroll = g_nlines;
    if (g_scroll + g_vlines > g_nlines)
        g_scroll = g_nlines - g_vlines;
    if (g_scroll < 0)
        g_scroll = 0;

    for (int i = 0; i < g_vlines; i++) {
        int idx = g_scroll + i;
        if (idx >= g_nlines)
            break;
        size_t ll = g_lines_len[idx];
        if (ll > (size_t)MAX_LINE)
            ll = MAX_LINE;
        draw_string(surface, MARGIN_X, body_top + i * LINE_H,
                    g_lines[idx], ll, COL_TEXT);
    }

    /* status bar */
    SDL_Rect st = { 0, surface->h - STATUS_H, surface->w, STATUS_H };
    SDL_FillRect(surface, &st, COL_STATUS);
    char status[160];
    snprintf(status, sizeof(status),
             " L %d/%d  |  ^v:scroll  L1/R1:page  L3:re-collect  "
             "Start/R3:quit",
             g_nlines ? g_scroll + 1 : 0, g_nlines);
    draw_string(surface, MARGIN_X,
                (surface->h - STATUS_H + STATUS_H - FONT_H * SCALE) / 2,
                status, strlen(status), COL_DIM);

    if (SDL_UpdateWindowSurface(win) != 0)
        printf("[pxlview-ui] update: %s\n", SDL_GetError());

    if (dirty)
        *dirty = 0;
}

int ui_handle_input(int *quit, int *recollect, int *dirty)
{
    /* M2: pad/remote input. Guard timeout as a last-resort exit. */
    static int frames = 0;
    SDL_Event e;

    while (SDL_PollEvent(&e)) {
        switch (e.type) {
        case SDL_QUIT:
            *quit = 1;
            return 0;

        case SDL_JOYBUTTONDOWN:
            switch (e.jbutton.button) {
            case 11:                       /* dpad up */
                if (g_scroll > 0) { g_scroll--; *dirty = 1; }
                break;
            case 12:                       /* dpad down */
                if (g_scroll < g_nlines) { g_scroll++; *dirty = 1; }
                break;
            case 9:                        /* L1: page up */
                g_scroll -= g_vlines;
                if (g_scroll < 0) g_scroll = 0;
                *dirty = 1;
                break;
            case 10:                       /* R1: page down */
                g_scroll += g_vlines;
                *dirty = 1;
                break;
            case 7:                        /* L3: re-collect panels */
                *recollect = 1;
                break;
            case 8:                        /* R3 */
            case 6:                        /* Options (Start) */
            case 1:                        /* Circle (back) */
                *quit = 1;
                return 0;
            default:
                break;
            }
            break;

        case SDL_KEYDOWN:
            /* CEC remote / keyboard fallback (SDL_ps5remote maps pad
             * d-pad + back/ok to scancodes). */
            switch (e.key.keysym.scancode) {
            case SDL_SCANCODE_UP:
                if (g_scroll > 0) { g_scroll--; *dirty = 1; }
                break;
            case SDL_SCANCODE_DOWN:
                if (g_scroll < g_nlines) { g_scroll++; *dirty = 1; }
                break;
            case SDL_SCANCODE_ESCAPE:
            case SDL_SCANCODE_RETURN:
                *quit = 1;
                return 0;
            default:
                break;
            }
            break;

        default:
            break;
        }
    }

    if (++frames > GUARD_TIMEOUT_SECS * 60)   /* ~60 fps tick */
        *quit = 1;
    SDL_Delay(16);
    return 0;
}

void ui_fini(void)
{
    if (!g_inited)
        return;
    SDL_Quit();
    g_inited = 0;
}
