# Architecture (11.60 regular)

Byepervisor-pxl defeats the PS5 11.60 hypervisor protection by:

1. disabling **xotext** (kernel `.text` becomes writable), and
2. striking all **16 hypervisor VMCB structures** (nested-control fields)
   during a rest-mode → resume cycle.

Validated on hardware: strike 16/16, `.text` read/write canary passed,
hook fully restored afterwards.

## Exploit chain (per run)

```
relapse (kernel exploit)          -> elfldr listens on TCP 9021
elfldr                            -> loads byepv-pxl ELF, dup2(socket -> stdio)
byepv-pxl (user-mode payload):
  1. detect firmware/model        (11.60, soc 0x840f80, HV loader PA 0x62800000)
  2. forensics                    (gate / IST6 / cave residue of prior runs)
  3. self-heal                    (clean up a stale armed hook, if any)
  4. early exit if results exist  ("Hypervisor is already compromised")
  5. disable xotext               (page-table RW on kernel .text)
  6. arm hardened hook            (see below)
  7. wait for rest mode + resume  (heartbeat every 30 s awake time)
  8. on resume: #DB at startup_mp -> production handler -> AP payload
     -> 16/16 VMCB strike -> cleanup (gate + IST6 restored) -> SUCCESS
```

## The hardened resume hook (`h1160.c`)

The vector-1 (#DB) IDT gate is **global**: any of the 16 cores can take it
first. A hook that prepares only one stack is therefore unsafe (a foreign
core entering the shared path hangs the console — see the failure ledger in
the porting toolkit docs).

Design: one **isolated IST6 entry path per core**.

- TSS row 0 (the selected core, pinned to scheduler CPU 15): **arm chain**,
  then the **production resume handler**;
- TSS rows 1..15: **register-neutral passthrough** (`pop rsp; iretq`) —
  any vector that lands on a foreign core is delivered as if the gate were
  stock;
- the global gate is switched IST4 → IST6 as the **last** write, and
  restored as the **first** handler mutation;
- every original IST6 value is saved and restored with a readback.

### TSS layout (11.60)

```
row stride: 0x68
  +0x04  RSP0
  +0x24  IST1      KH_TSS_IST(k) = 0x24 + (k-1)*8
  +0x48  IST4      <- stock #DB gate uses this
  +0x64  IST6      <- hook target
  +0x6C  IST7      (aliases next row's RSP0; unused by the kernel)
```

Pre-arm validation per row: canonical high-half RSP0, non-zero IST4
handler, pairwise-distinct RSP0/IST4 (proves the stride). IST6 must be free
of **real** owners: values inside the per-core kernel handler code region
(±2 MiB of that core's IST4 handler) or inside the data cave are refused;
stale per-core data (observed on long-running sessions: counters, packed
values) is tolerated because the original is saved and restored exactly.
On a fresh boot all 16 IST6 slots are zero (the validated state).

### Cave geometry (`include/h1160.h`)

```
+0x0440  oracle block      (entry/mode/done marks, CHAIN mark)
+0x0600  state word        (H1160_STATE_ARMED)
+0x0680  preparation mark
+0x1000  arm block (0x400) (ROP @0x50, ctx @0x100, cont @0x200)
+0x1400  15 passthrough stacks (0x100 each, CPUs 1..15)
+0x2400  production handler (0x400)
+0x2800  AP payload staging source (0x800)
+0x3000  recovery save area (state, gate lo/hi, ist[16])
+0x3400  AP result stash (error, self_count, targets, written, verified, ...)
```

## The AP payload (`break_hv_payload/break_hv.c`)

Runs in kernel context from a direct-map page during resume:

1. scans physical memory for the 16 VMCB structures (ASID match, profile
   checks on IOPM base);
2. rewrites `VMCB_NESTED_CTRL` + `VMCB_CLEAN` on all 16 (the strike);
3. writes the result stash (16/16 targets/written/verified, error code).

The outer payload then verifies the stash, restores the hook, and reports.

## Build variants

| | debug | release | standalone |
|---|---|---|---|
| USB log file | yes | no | no |
| stdout/TCP stream | blocking | blocking | **non-blocking** |
| host listener required | yes (for logs) | optional | **no** |
| verdict channel | stream + on-screen notify | stream + on-screen notify | on-screen notify |

See [build.md](build.md).
