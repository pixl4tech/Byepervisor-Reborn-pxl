# Testing

## Automatic tests (local + CI)

```sh
make test          # = python3 -m unittest discover -s tests -v
```

| Suite | Covers |
|---|---|
| `tests/test_builds.py` | builds all 3 variants; ELF magic / 64-bit / x86-64; version + variant strings embedded; USB-log code compiled in **only** for debug; `byepv-pxl-latest.elf` symlink; generated `include/version.h`. Skipped when `sdk/` is not installed. |
| `tests/test_ps5_run.py` | `ps5_run.stream()` verdict logic against `tests/mock_elfldr.py`: SUCCESS, ARM_FAIL, EOF-without-marker (no infinite resend), drop → reconnect + resend → success, quiet gap (rest mode) → success. |
| `tests/mock_elfldr.py` | mock elfldr: accepts the ELF upload, honours `SHUT_WR`, streams parameterized scenarios (success / arffail / arffail_noclose / quiet / drop). |

Static audit (regression marker for the 11.60 offsets/gadgets):

```sh
python3 scripts/audit_11_60.py
```

## Live test checklist

`tests/live_test_checklist.md` describes the on-hardware runs:

1. **debug** — via `scripts/ps5_run.py` (full stream + `verdict=SUCCESS`);
2. **release** — manual upload, no USB files created, run completes with
   on-screen notifications;
3. **standalone** — manual upload, no Mac needed after upload, run
   completes with on-screen notifications.

## What a good live run looks like (debug)

```
[send]   elf=.../byepv-pxl-latest.elf size=... sha256=...
[stream] [+] Byepervisor-pxl v0.1.0 (debug)
[stream] [h1160] forensics: gate ... ist=4
[stream] [+] 11.60 hook armed, enter sleep and resume!
[net]    console silent ... rest mode assumed
[net]    console awake again
[stream] [NOTIFY] ... 11.60 - SUCCESS ...
[verdict] SUCCESS marker seen in stream
[verdict] payload finished (log file closed)
[report] verdict=SUCCESS reconnects=0
```
