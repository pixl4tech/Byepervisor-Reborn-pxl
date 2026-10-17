# Byepervisor-Reborn-pxl

HV-bypass exploit for **PS5 firmware 11.60 (regular model)** with a
Macbook-driven network launcher, live log streaming, and standalone
builds. Validated on hardware: **16/16 hypervisor VMCB strike**, xotext
defeated (kernel `.text` read/write), hook fully restored afterwards.

This is a `pxl` re-implementation of
[PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn),
ported and hardened against the validated 11.60 production port from
[gzimbric/ps5-hv-bypass-porting](https://github.com/gzimbric/ps5-hv-bypass-porting)
(see [Credits](#credits--links)).

## What it does

Per run (after the relapse kernel exploit brings up `elfldr` on TCP 9021):

1. loads a user-mode payload on the console;
2. the payload disables **xotext** (kernel `.text` becomes writable);
3. installs a **hardened resume hook**: 16 isolated per-core IST6 entry
   paths around the global #DB IDT gate (CPU 0 gets the production
   handler, CPUs 1–15 get a register-neutral passthrough);
4. on **rest mode → resume**, the hook fires at the `startup_mp` call
   site, an AP payload strikes all **16 hypervisor VMCB structures**
   (nested-control fields), and the hook is restored;
5. result: the hypervisor is compromised — kernel `.text` is readable and
   writable from a normal payload.

See [docs/architecture.md](docs/architecture.md) for the full design
(TSS/IST6 layout, cave geometry, VMCB scan).

## Build variants

| Variant | USB log | stdout/TCP stream | Host listener needed |
|---|---|---|---|
| `debug` (default) | ✅ | blocking | yes (for logs) |
| `release` | ❌ | blocking | optional |
| `standalone` | ❌ | **non-blocking** | **no** — verdicts via on-screen notifications |

```sh
scripts/bootstrap_sdk.sh                 # one-time: SDK + LLVM into sdk/
export PS5_PAYLOAD_SDK=$PWD/sdk/ps5-payload-sdk
export LLVM_CONFIG=$PWD/sdk/llvm18/llvm@18/18.1.8/bin/llvm-config
make all-variants                        # build/debug|release|standalone/byepv-pxl-v<ver>.elf
```

Versioning: `VERSION ?= 0.1.0` in the Makefile — compiled into the payload
banner and artifact names; git tags `v*` drive GitHub releases.

## Quick start (network run with live logs)

```sh
cd Byepervisor-Reborn-pxl
make                                     # if the ELF is stale
caffeinate -i python3 scripts/ps5_run.py --no-setup
```

The script checks the ethernet link, waits for elfldr on `10.10.10.2:9021`,
uploads the ELF, and streams the payload log live into the terminal and
into `ps5-run-logs/mac_*.log`. When you see
`hook armed, enter sleep and resume!` — **put the PS5 into rest mode, then
wake it**. The success notification appears on the console and the verdict
(`SUCCESS`) in the terminal.

Details: [docs/network-run.md](docs/network-run.md),
[docs/standalone-run.md](docs/standalone-run.md),
[docs/build.md](docs/build.md), [docs/testing.md](docs/testing.md).

## Scripts

| Script | Purpose |
|---|---|
| `scripts/ps5_run.py` | network launcher: link check → elfldr wait → ELF upload → live log stream → rest-mode tolerant reconnect → verdict. Flags: `--probe`, `--no-setup`, `--stall`, `--timeout`, `--elf`, … |
| `scripts/audit_11_60.py` | static audit of the 11.60 offsets/gadget table (regression marker) |
| `scripts/bootstrap_sdk.sh` | installs `sdk/ps5-payload-sdk` + LLVM 18 into `sdk/` (idempotent) |

## Tests

```sh
make test        # python unit tests: build verification + ps5_run verdict logic (mock elfldr)
```

On-hardware runs follow [`tests/live_test_checklist.md`](tests/live_test_checklist.md):
debug via the script; release/standalone via manual upload.

## Repository layout

```
Makefile                 VERSION + VARIANT build system
main.c h1160.c khook.c kdlsym.c elog.c paging.c util.c   payload sources
include/                 payload headers (+ generated version.h)
break_hv_payload/        AP payload (VMCB strike), flat-linked
scripts/                 ps5_run.py, audit_11_60.py, bootstrap_sdk.sh
tests/                   unit tests, mock elfldr, live checklist
build/                   build artifacts (gitignored)
docs/                    English documentation
analysis/                research notes (local only, gitignored)
sdk/                     toolchain (gitignored, bootstrap_sdk.sh)
tools/ps5-hv-bypass-porting/   reference porting toolkit (gitignored, see below)
```

## Reference porting toolkit

The validated 11.60 production port and its analysis toolkit are **not**
committed. To fetch:

```sh
git clone https://github.com/gzimbric/ps5-hv-bypass-porting.git \
    tools/ps5-hv-bypass-porting
```

## CI / releases

- `.github/workflows/ci.yml` — on push: bootstrap SDK, build all variants,
  run tests, upload artifacts.
- `.github/workflows/release.yml` — on tag `v*`: GitHub Release with the
  three ELFs, the launcher script, and `SHA256SUMS`.

## Credits & links

Thanks to the authors of the projects this implementation is built on:

- **[PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn)**
  (John Törnblom and contributors) — the base Byepervisor implementation
  this repo re-implements.
- **[gzimbric/ps5-hv-bypass-porting](https://github.com/gzimbric/ps5-hv-bypass-porting)**
  and **[gzimbric/Byepervisor-Reborn](https://github.com/gzimbric/Byepervisor-Reborn)**
  (commit `340ed30`) — the validated 11.60 production port, the porting
  toolkit, and the multicore debug-hook design this implementation follows.
- **[ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk)**
  (v0.44; John Törnblom / community) — the PS5 payload SDK and prospero
  toolchain wrappers.
- **Homebrew `llvm@18`** (18.1.8) — the clang/lld toolchain used for the
  cross-build.
- **relapse** kernel exploit chain and **elfldr** (TCP 9021) — payload
  delivery on the console.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
