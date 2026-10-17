# Live test checklist (on hardware)

Prerequisites: PS5 11.60 regular, static IP 10.10.10.2, MacBook 10.10.10.1,
elfldr listening on TCP 9021 (relapse chain), USB stick in the console
(debug runs).

## 1. debug variant (scripted) — the reference run

```sh
make
caffeinate -i python3 scripts/ps5_run.py --no-setup
```

| # | Expected | Where |
|---|---|---|
| 1 | link check OK, port 9021 open | terminal `[link]`/`[wait]` |
| 2 | ELF uploaded (sha printed) | terminal `[send]` |
| 3 | banner `Byepervisor-pxl v0.1.0 (debug)` | terminal + console (silent) |
| 4 | forensics lines (gate ist, IST6, cave) | terminal |
| 5 | `hook armed, enter sleep and resume!` | terminal **and** console notification |
| 6 | put console to rest mode | `[net] console silent` in terminal |
| 7 | wake the console | `[net] console awake again` |
| 8 | success notification on the console screen | PS5 UI |
| 9 | `verdict=SUCCESS reconnects=0` + log saved | terminal `[report]` |
| 10 | `byepv960_*.log` on the USB stick, non-empty | USB |

Re-run immediately after success → `Hypervisor is already compromised` +
`.text` dump + `verdict=SUCCESS` (idempotency).

## 2. release variant (manual)

```sh
make release
nc -q0 10.10.10.2 9021 < build/release/byepv-pxl-v0.1.0.elf
```

| # | Expected |
|---|---|
| 1 | run completes (arm → rest → wake → success notification) |
| 2 | **no** new `byepv960_*.log` file appears on the USB stick |
| 3 | first stdout line: `[elog] release build: no USB log file, stdout stream only` (if a host is listening) |

## 3. standalone variant (manual, no host)

```sh
make standalone
nc -q0 10.10.10.2 9021 < build/standalone/byepv-pxl-v0.1.0.elf
```

| # | Expected |
|---|---|
| 1 | upload can be done from any host; disconnect afterwards |
| 2 | payload runs to completion with **no listener at all** (no hang on stdout) |
| 3 | all verdicts visible as on-screen notifications only |
| 4 | arm → rest → wake → success notification |

## Pass criteria

- all three variants complete the cycle without a console crash;
- after every run the hook is restored (next debug run forensics shows
  `gate ... ist=4`, IST6 slots zero, state 0);
- the HV stays broken across runs (`already compromised` path).

## Results (v0.1.0, 2026-10-17, PS5 11.60 regular 0x840f80)

| Variant | Run | Result |
|---|---|---|
| debug | scripted `ps5_run.py` (fresh exploit: arm → rest → wake) | PASS — success notification, `verdict=SUCCESS reconnects=0`, USB log written |
| debug | scripted re-run (idempotency) | PASS — `Hypervisor is already compromised`, `.text` dump, `verdict=SUCCESS` |
| release | scripted `ps5_run.py --elf build/release/...` | PASS — `no USB log file` banner, `already compromised`, `verdict=SUCCESS`, no USB log created |
| standalone | scripted `ps5_run.py --elf build/standalone/...` | PASS — `no USB log file` banner, `already compromised`, `verdict=SUCCESS`, no USB log created |

All three variants hardware-validated. Hook state restored after every run;
HV stays compromised across runs (idempotent re-entry).
