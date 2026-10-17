# pxlview live test checklist (on hardware)

Prerequisites: PS5 11.60 regular, static IP 10.10.10.2, MacBook
10.10.10.1, elfldr listening on TCP 9021 (relapse chain).

## M1 — display path

```sh
make -C apps/pxlview
python3 scripts/ps5_run.py --elf apps/pxlview/build/pxlview-latest.elf
```

| # | Expected | Where |
|---|----------|-------|
| 1 | `[pxlview] starting v0.1.0` + `kernel access ok` | terminal |
| 2 | `[pxlview-ui] window 3840x2160 fmt=0x...` | terminal |
| 3 | **black fullscreen terminal on the TV** with header bar + P1 hexdump | TV |
| 4 | exit (pad Start or 15-min guard) → system notification key line | PS5 UI |
| 5 | `verdict=SUCCESS reconnects=0` (pxlview markers) | terminal `[report]` |

If `SDL_Init` fails, run the diagnostic:

```sh
make -C apps/pxlview diag
python3 scripts/ps5_run.py --elf apps/pxlview/build/pxlview-diag.elf
```

Read `[diag]` sections 1–3 (authid, VideoOut matrix, p_comm).

## M2 — scroll + pad

| # | Expected |
|---|----------|
| 1 | ▲/▼ scroll 1 line, status bar `L x/y` updates |
| 2 | L1/R1 page up/down |
| 3 | L3 re-collects (new `[pxlview] re-collected N bytes` line) |
| 4 | Start/R3/Circle → clean exit back to system UI |
| 5 | no exit on its own while interacting (guard timeout 15 min) |

## M3 — panel content

| # | Expected |
|---|----------|
| 1 | P1: `.text` first byte `E8` (11.60), 64B hex+ascii present |
| 2 | P2: HV PA `0x62800000` read ok, hex + strings (or `[read failed]`) |
| 3 | P3: process list contains `vsh` and a WebKit process, uid/authid plausible |
| 4 | P4: `/mnt/nor0` lists firmware files with sizes (needs system authid) |
| 5 | P5: fw `0x1160...`, soc `0x840f80`, `.text`/data/allproc bases |
| 6 | p_comm: if P3 names show `-`, run diag, set `PXL_PROC_P_COMM`, rebuild |

## M4/M5 — robustness

| # | Expected |
|---|----------|
| 1 | repeated runs (3+) — no crash, screen always returns to VSH |
| 2 | run on a **pre-bypass** console (fresh boot, no byepv run) — works |
| 3 | no new files on USB, no kernel writes (audit: `make test`) |
| 4 | exit leaves authid restored (diag section 1 shows restore ok) |
| 5 | 4K and 1080p console modes both render |
