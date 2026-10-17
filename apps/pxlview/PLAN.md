# pxlview — implementation plan

**Status:** approved plan (v1, 2026-10-17)
**Target:** PS5 11.60 regular (0x840f80), payload delivery via elfldr (TCP 9021)

## 1. Goal

A standalone helper ELF (`pxlview.elf`) that runs on the console and shows an
**on-screen, scrollable text window** (a real UI, not a toast notification)
with kernel/hypervisor data that is **impossible to read without the HV
exploit**:

| # | Panel | Why it needs the exploit |
|---|-------|--------------------------|
| P1 | First 64 bytes of kernel `.text` (hex + ascii) | `.text` is **xotext** (execute-only): normal reads fault; needs physical/IOMMU copy |
| P2 | HV (hvcore) memory: 64-byte hex dump + ASCII strings | HV is not mapped into any VA space; only reachable by **physical address** |
| P3 | Kernel process list (pid, name, uid, authid) | Built by walking `allproc` **in kernel memory** |
| P4 | NOR flash firmware directory structure (`/mnt/nor0`) | Root-only firmware partition; needs **system authid** |
| P5 | Console identity: firmware version, soc id, model, `.text` base | `kernel_get_fw_version()`, kenv, kernel symbols |

Key facts (verified):

- The payload runs as a **userspace process** (inside the exploited
  WebKit/browser process) with an **IOMMU kernel-copy primitive** provided by
  the SDK C runtime: `kernel_copyin()/kernel_copyout()` from
  `<ps5/kernel.h>`. The main byepv-pxl payload already uses exactly this
  (`util.c: kread/kwrite`).
- The SDK exposes absolute kernel addresses: `KERNEL_ADDRESS_TEXT_BASE`,
  `KERNEL_ADDRESS_ALLPROC`, plus proc/ucred field offsets and
  `kernel_set_ucred_authid()` (the main payload uses authid
  `0x4800000000000007` = system).
- **pxlview is strictly read-only**: no `kernel_copyin` writes, no patches.
  It can run on a stock (pre-bypass) console and cannot brick a running
  bypass.

Only the **key result** goes to a system notification
(`sceKernelSendNotificationRequest`, same API as byepv-pxl): one line like
`pxlview: .text=0x57C6BBE8, 14 procs, NOR ok, HV ok`.

## 2. On-screen UI approach — analysis

Requirement: a visible window on the TV, scrollable, with full text;
notifications only for the key line.

Options considered:

| Option | Verdict |
|--------|---------|
| **A. SDL2 (ps5-payload-dev port), CPU surface rendering** | ✅ **Chosen.** Actively maintained (pushed 2026-09). PS5 video driver: ABGR8888 window surface → `PS5_Tilemap_Blit` → `sceVideoOutSubmitFlip` (double-buffered, 3840×2160@60). Gamepad input built in (`SDL_ps5remote.c`). Proven on console by scene games (FBNeo, LakeSnes, yquake2 ports). CPU blit path needs **no GL** — ideal for a text console. |
| B. OpenUI (Sony framework) | ❌ Not shipped in ps5-payload-sdk v0.44; heavier C++ integration; no payload examples in the SDK. |
| C. Software OpenGL via SDK (`libSceGLSlimVSH.so`, OSMesa) | ⚠️ Emerging (headers + lib present, no SDK sample). Unnecessary — the SDL CPU-surface path already reaches the screen. Keep as future upgrade for prettier rendering. |
| D. Web UI (`ps5-payload-dev/websrv`) | ❌ UI lands on the PC browser, not on the console. |
| E. Raw framebuffer (find FB PA, write pixels) | ⚠️ Works (same tilemap/VideoOut path) but is exactly what the SDL driver already wraps; only as fallback if the SDL port misbehaves on 11.60. |

**Decision: Option A — SDL2, window-surface (CPU) rendering, no GL.**

Rendering model:

- One fullscreen `SDL_Window` (current mode 3840×2160, ABGR8888).
- Text drawn with an **embedded 8×16 bitmap font** (public-domain VGA font),
  scaled ×4 (32×64 px per glyph at 4K) → no freetype, no SDL_ttf, zero font
  dependencies, crisp monospace terminal look.
- Scrolling = viewport offset over a static text buffer (all panel content is
  collected **once at startup**, UI only scrolls).
- Input: DualSense via SDL events —
  `▲/▼` scroll 1 line, `L1/R1` page, `R3/Start` quit, `L3` re-collect.

## 3. Dependencies

| Dependency | Source | Integration |
|------------|--------|-------------|
| ps5-payload-sdk **v0.44** | already in `sdk/ps5-payload-sdk` | toolchain (`prospero.mk`), `<ps5/kernel.h>`, `libkernel.so`, `libSceVideoOut.so`, `libScePad.so`, `libSceNotification*.so` |
| **SDL2** (PS5 port) | `https://github.com/ps5-payload-dev/SDL` (zlib license — GPL-3.0 compatible) | git submodule at `apps/pxlview/third_party/SDL2`, built **static** (`libSDL2.a`) with the same prospero toolchain |
| Bitmap font | public-domain 8×16 VGA font, generated as `font_8x16.h` (C array) | vendored in `src/` |
| LLVM 18.1.8 | `sdk/llvm18` (bootstrap) | same as main build |
| Gamepad | `libScePad.so` (SDK) via SDL's PS5 remote driver | dynamic (SDK default) |

No pacbrew install on the console is needed: SDL2 is statically linked, all
`libSce*` are dynamic system libraries resolved by the SDK linker script.

SDL2 build flags (mirroring the port's tested `build-scripts/ps5-payload-sdk.sh`):
`-DCMAKE_BUILD_TYPE=Release -DSDL_OPENGL=YES -DSDL_LOADSO=YES`
(OpenGL flag kept for parity with the tested config; our code path never
creates a GL context).

## 4. Architecture

```
┌────────────────────────────────────────────────────────────┐
│ main.c — lifecycle + event loop                            │
│                                                            │
│  init:  kmem_init() → panels_collect() → ui_init()        │
│  loop:  SDL_PollEvents → input (scroll/page/quit)         │
│         → ui_render(viewport) → SDL_UpdateWindowSurface   │
│  quit:  notify(key line) → ui_fini() → exit(0)            │
└──────────┬─────────────────────────────┬───────────────────┘
           │                             │
┌──────────▼──────────┐      ┌───────────▼──────────────────┐
│ panels.c            │      │ console_ui.c                 │
│  P1 ktext 64B hex   │      │  text buffer (ring of lines) │
│  P2 HV hex + strings│ ───► │  viewport + scroll offset    │
│  P3 allproc list    │      │  8x16 font ×4 blitter        │
│  P4 /mnt/nor0 tree  │      │  header/status bar           │
│  P5 console identity│      └──────────────────────────────┘
└──────────┬──────────┘
           │
┌──────────▼──────────────────────────────┐
│ kmem.c — thin kernel access layer       │
│  kread()/kread64()  ← kernel_copyout()  │
│  hexdump_fmt()      (hex+ascii, 16B/row)│
│  proc_walk()        (allproc → lines)   │
│  strings_extract()  (HV ASCII strings)  │
└─────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────┐
│ notify.c — sceKernelSendNotificationRequest (key line only)│
└─────────────────────────────────────────┘
```

Data flow:

1. **Boot (one-shot):** verify kernel access (read `.text[0]`), then collect
   all panels into a single static text buffer. IOMMU copies are traps, so
   all kernel reads happen here, off the render path. Budget: P1 4 reads,
   P2 ~16 reads (1 KB window + strings), P3 ~2×N procs (~40 reads for 20
   procs), P4 userspace `opendir`/`readdir` (no kernel reads; system authid),
   P5 a handful. Total < 100 ms.
2. **UI loop:** pure CPU blitting of the viewport; 60 fps not required —
   render only on scroll/refresh (dirty-flag), ~16 ms per full 4K frame is
   fine for text.
3. **Exit:** read-only guarantee → nothing to restore; `SDL_Quit()` + `exit`.

Threading: **single-threaded** (main thread owns SDL + input + render).
No threads → no locking, no HV-hook interaction.

Safety invariants (enforced + CI-grepped):

- **no `kernel_copyin`/`kernel_set*` calls** (read-only),
- no `mmap`/`mprotect` of kernel ranges,
- every kernel read bounded (max 16 KB total per panel),
- UI must not block > 500 ms per frame (panel collection is the only slow
  phase, shown behind a "collecting..." screen).

## 5. Source layout

```
apps/pxlview/
├── PLAN.md                  # this document
├── README.md                # usage (after M4)
├── Makefile                 # app build (see §6)
├── src/
│   ├── main.c               # init, event loop, quit (~250 LOC)
│   ├── kmem.c / kmem.h      # kernel read layer, hexdump, proc walk (~300)
│   ├── panels.c / panels.h  # P1..P5 content generators (~350)
│   ├── console_ui.c / .h    # terminal renderer + scroller (~350)
│   ├── font_8x16.h          # embedded VGA 8x16 font (generated, ~1 KB glyphs)
│   └── notify.c / notify.h  # notification helper (~60)
├── third_party/
│   └── SDL2/                # git submodule (ps5-payload-dev/SDL)
└── build/                   # artifacts (gitignored)
    └── pxlview-v0.1.0.elf, pxlview-latest.elf
```

Panel interface:

```c
/* panels.h */
typedef struct pxl_ctx {
    char *buf;      /* collected text (owned) */
    size_t len, cap;
} pxl_ctx_t;

/* each returns 0 or -1; append formatted lines into ctx */
int panel_ktext(pxl_ctx_t *ctx);   /* P1 */
int panel_hv(pxl_ctx_t *ctx);      /* P2 */
int panel_procs(pxl_ctx_t *ctx);   /* P3 */
int panel_nor(pxl_ctx_t *ctx);     /* P4 */
int panel_identity(pxl_ctx_t *ctx);/* P5 */
int panels_collect_all(pxl_ctx_t *ctx);
```

UI interface:

```c
/* console_ui.h */
int  ui_init(int w, int h);                 /* SDL window, 4K current mode */
void ui_set_text(const char *text, size_t len);
void ui_render(int *dirty);                 /* blit viewport, present */
int  ui_handle_input(int *quit);            /* pump SDL events */
void ui_fini(void);
```

## 6. Build process

### 6.1 Submodule

```sh
git submodule add https://github.com/ps5-payload-dev/SDL.git \
    apps/pxlview/third_party/SDL2
```

### 6.2 `apps/pxlview/Makefile` (sketch)

```make
PS5_PAYLOAD_SDK ?= ../../sdk/ps5-payload-sdk
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
VERSION ?= 0.1.0
BUILD := build
ELF   := $(BUILD)/pxlview-v$(VERSION).elf
SDL2  := third_party/SDL2
SDL_A := $(SDL2)/build-ps5/libSDL2.a

CFLAGS += -O2 -Wall -Werror -Isrc
# pxlview has no inline-asm single-stepping; -O2 is safe (unlike byepv)

all: $(ELF)

$(SDL_A):                        # one-time static SDL2 build (cmake)
	cmake -DCMAKE_BUILD_TYPE=Release -DSDL_OPENGL=YES -DSDL_LOADSO=YES \
	        -B $(SDL2)/build-ps5 -S $(SDL2)
	$(MAKE) -C $(SDL2)/build-ps5

$(ELF): src/main.c src/kmem.c src/panels.c src/console_ui.c src/notify.c $(SDL_A)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(SDL_A) -lSDL2
	ln -sf pxlview-v$(VERSION).elf $(BUILD)/pxlview-latest.elf

clean:
	rm -rf $(BUILD)
```

Notes:

- **Static SDL2** → single self-contained ELF (~2–4 MB), no console-side
  installs, works with plain `nc`/`ps5_run.py`.
- **`-O2`** is fine here (no HV hook, no inline-asm resume path) — unlike the
  byepv-pxl payload where `-O0` is mandatory.
- `libSceVideoOut.so` / `libScePad.so` are pulled dynamically by the SDK
  linker script (same as byepv-pxl pulls `libkernel`).

### 6.3 Integration with the root Makefile

```make
pxlview:
	$(MAKE) -C apps/pxlview
```

`make all-apps` builds byepv-pxl (all variants) + pxlview.

### 6.4 CI

- `ci.yml`: add a `pxlview` build step after the main build (submodule
  checkout: `submodules: recursive`).
- New test in `tests/test_builds.py`: pxlview ELF exists, valid x86-64 ELF,
  size < 8 MB.
- **Read-only invariant test** (static): `grep` the pxlview sources for
  `kernel_copyin|kernel_set` → must be absent (same style as the 11.60 audit).
- CI build of SDL2 adds ~2–4 min; cache the `build-ps5` dir on `main`
  pushes keyed on the submodule SHA (nice-to-have, not blocking).

## 7. Run / deployment

```sh
# live run with host log stream (recommended first time)
python3 scripts/ps5_run.py --elf apps/pxlview/build/pxlview-latest.elf

# bare upload (UI is on the TV; host optional)
nc -q0 10.10.10.2 9021 < apps/pxlview/build/pxlview-latest.elf
```

`ps5_run.py` integration: the payload prints the same `elog`-style markers
(`[pxlview] ...`, terminal marker `pxlview: done`) so the existing
success/drop logic works unchanged; stdout stays the log channel.

Expected console UX:

1. Screen flips to a full-black terminal window, header bar:
   `pxlview v0.1.0 — PS5 11.60 kernel/HV inspector (read-only)`.
2. Panels P1..P5 rendered top-to-bottom; scroll with the pad.
3. One system notification with the key summary line.
4. `Start` → screen returns to the system UI; process exits.

## 8. Testing

| Layer | Test |
|-------|------|
| Host/CI | build + ELF sanity (readelf), read-only grep audit, size limit |
| Host | font renderer unit test (host-compiled, renders a known string to an offscreen buffer, compares pixels) |
| Console M1 | black screen + one text line appears (proves VideoOut/tilemap path) |
| Console M2 | scrolling + pad input + clean quit |
| Console M3 | panel content checks vs known values (`.text` base `0x57C6BBE8...` first byte `E8`, proc list contains `vsh`/`webkit`, NOR listing contains firmware files) |
| Console M4 | exit returns to system UI, no crash on repeated runs, runs on pre-bypass console (fresh boot, no byepv run) |

Checklist file: `apps/pxlview/LIVE_CHECKLIST.md` (created at M3).

## 9. Risks & mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| SDL2 PS5 port issue on 11.60 (mode/flip) | low-medium | M1 isolates the display path first; fallback = raw `libSceVideoOut` + tilemap driver (same 3 calls SDL uses) |
| 4K frame cost for CPU text blit | low | render-on-dirty only; 32 MB/buffer is trivial on 16 GB RAM |
| IOMMU copy of HV PA fails (not in IOMMU map) | low | same primitive byepv already uses for HV reads; guard each panel with error text in the UI |
| Static SDL2 bloat / link issues (C++ parts) | low | port ships a static-lib build via cmake; link `libc++` (SDK has `libc++.a`) |
| Font licensing | none | VGA 8×16 font is public domain |
| Gamepad not visible to payload | low | scene games (FBNeo) use libScePad from payloads; SDL driver present |

## 10. Milestones

| M | Deliverable | Exit criterion |
|---|-------------|----------------|
| M0 | plan + skeleton + submodule + Makefile (this commit) | `make -C apps/pxlview` builds a stub ELF (no UI) |
| M1 | display path | text line on the TV |
| M2 | terminal console + scroll + pad | scroll/quit work |
| M3 | all 5 panels | content verified on console |
| M4 | notification + markers + docs + CI | full run clean, repeated runs OK |
| M5 | hardware sign-off, `v0.1.0` of the app | checklist green |

## 11. References

- SDK kernel helpers: `sdk/ps5-payload-sdk/target/include/ps5/kernel.h`
- Main payload kernel access: `util.c` (`kread/kwrite` = `kernel_copyout/in`)
- SDL PS5 video driver: `third_party/SDL2/src/video/ps5/SDL_ps5video.c`
  (`PS5_UpdateWindowFramebuffer` → `PS5_Tilemap_Blit` → `sceVideoOutSubmitFlip`)
- SDL PS5 build script: `third_party/SDL2/build-scripts/ps5-payload-sdk.sh`
- Prebuilt SDL2/SDL2_ttf packages (reference only):
  `github.com/ps5-payload-dev/pacbrew-repo`
- Notification API: `sdk/.../samples/notify/main.c` (`sceNotificationSend`
  JSON) and byepv-pxl `util.c:notifyf`
