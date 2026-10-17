# pxlview

Read-only PS5 kernel/HV inspector with an **on-screen scrollable UI**
(SDL2, CPU-surface rendering, no GL). Shows data that is impossible to
read without the HV exploit:

| # | Panel | Why it needs the exploit |
|---|-------|--------------------------|
| P1 | First 64 bytes of kernel `.text` (hex + ascii) | `.text` is **xotext** (execute-only) |
| P2 | HV (hvcore) memory: 64-byte hex dump + ASCII strings | HV is only reachable by **physical address** |
| P3 | Kernel process list (pid, name, uid, authid) | Built by reading procs **in kernel memory** |
| P4 | NOR flash firmware directory (`/mnt/nor0`) | Root-only partition; needs **system authid** |
| P5 | Console identity: fw version, soc id, kernel bases | `kernel_get_fw_version()`, kernel symbols |

**Strictly read-only**: no kernel memory writes. It can run on a stock
(pre-bypass) console and cannot brick a running bypass. The one
deliberate exception: the process **ucred authid** is raised to system
at start and **restored on exit** (needed for VideoOut buffer
registration and `/mnt/nor0`). See `PLAN.md`.

## Build

```sh
export PS5_PAYLOAD_SDK=$PWD/sdk/ps5-payload-sdk
export LLVM_CONFIG=$PWD/sdk/llvm18/llvm@18/18.1.8/bin/llvm-config
make -C apps/pxlview        # -> apps/pxlview/build/pxlview-v0.1.0.elf
make -C apps/pxlview diag   # -> apps/pxlview/build/pxlview-diag.elf (dev tool)
```

First build compiles static SDL2 (a few minutes). The SDL2 submodule is
patched automatically (`patches/sdl2-ps5-videout-open.patch`).

## Run

Requires the relapse chain running on the console (elfldr on TCP 9021).

```sh
# live run with host log stream (recommended)
python3 scripts/ps5_run.py --elf apps/pxlview/build/pxlview-latest.elf

# bare upload (UI is on the TV; host optional)
nc -q0 10.10.10.2 9021 < apps/pxlview/build/pxlview-latest.elf
```

## On-screen UX

1. Fullscreen black terminal, header `pxlview v0.1.0 - PS5
   kernel/HV inspector (read-only)`.
2. Panels P1..P5 rendered top-to-bottom; bottom status bar shows
   position and key hints.
3. One system notification with the key summary line on exit.

**Controls (DualSense):**

| Button | Action |
|--------|--------|
| ▲ / ▼ | scroll 1 line |
| L1 / R1 | page up / down |
| L3 | re-collect panels |
| Start / R3 / Circle | quit (returns to system UI) |

The TV remote / keyboard also works (▲/▼ scroll, Back/Enter quit).
Last-resort exit: 15 minutes without input.

## Tests

```sh
make test            # includes pxlview build + read-only audit + font test
```

On-hardware runs: `LIVE_CHECKLIST.md`.

## Dev tool

`src/diag.c` (`make diag`) — single-run hardware diagnostic:

1. **authid probe** — current/system authid set+restore;
2. **VideoOut matrix** — `sceKernelAllocateMainDirectMemory` /
   `sceVideoOutOpen` / `sceVideoOutRegisterBuffers2` with varying
   memsize/display id, errno at every step;
3. **p_comm finder** — printable strings inside the payload's own
   `struct proc` with offsets (used to set `PXL_PROC_P_COMM` in
   `src/panels.c`).
