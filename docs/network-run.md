# Network run & live log (MacBook ⇄ PS5 over Ethernet)

`scripts/ps5_run.py` drives the full cycle: link check → wait for elfldr →
send the ELF → **live payload log stream in the terminal** → verdict.
Session logs are written to `ps5-run-logs/` in the repository.

## Topology

```
MacBook 10.10.10.1 (en7) === ethernet cable === PS5 10.10.10.2 (static)
```

- PS5: Settings → Network → PS5 Ethernet → Manual → `10.10.10.2 / 255.255.255.0`.
- MacBook: the script checks/assigns `10.10.10.1` on an active en interface
  (needs sudo); `--no-setup` checks only.

## How it works

1. The kernel exploit chain (relapse) is already running on the PS5 and
   **elfldr listens on TCP 9021**.
2. elfldr protocol: raw ELF bytes over TCP + `SHUT_WR`
   (first 4 bytes = ELF magic). Equivalent to
   `nc -q0 10.10.10.2 9021 < byepv-pxl.elf`.
3. elfldr `dup2()`s the same socket to the payload's stdin/stdout/stderr —
   **the same socket carries the payload's live stdout back**.
   `elog()` writes every line to stdout (unbuffered) and, in the debug
   variant, to a USB log file, so lines arrive in real time.
4. The script scans the stream for markers:
   - `Byepervisor-pxl v` → payload started;
   - `Byepervisor Reborn 11.60 - SUCCESS` / `hypervisor is defeated` /
     `Hypervisor is already compromised` → SUCCESS;
   - `hook arm failed` → ARM_FAIL;
   - `log file closed` → payload finished cleanly (terminal marker);
   - `[NOTIFY] [ERROR]` → error.

## Rest mode: how the listener survives console sleep

During rest mode the console CPUs are stopped: no ping replies, no TCP
data, frozen TCP stack. The script:

- **ping watchdog** (background thread) tracks `AWAKE → SILENT → AWAKE`
  transitions and logs them (`[net]` lines);
- stream silence beyond `--stall` seconds → `[stream] ... rest mode
  assumed` marker;
- if the socket dies (EOF/RST — the NIC may power down): the script waits
  for the console to wake, then **reconnects and re-sends the ELF**. The
  payload is idempotent: a fresh instance reads the cave state and
  continues (armed → keeps waiting; results present → proof and exit;
  stale armed hook → self-heal cleanup).
- the terminal marker (`elog: log file closed`) means a clean exit — no
  resend loop.

During sleep no lines are lost in practice: the payload is frozen, its
USB log (debug variant) keeps accumulating, and the stream resumes after
wake. If the TCP socket dies around resume, the final stdout lines may be
stuck in the console's send buffer; the on-screen notification and the
cave result blocks are the authoritative success proof.

## Usage

```sh
cd Byepervisor-Reborn-pxl
make                                  # if the ELF is stale
caffeinate -i python3 scripts/ps5_run.py --no-setup
```

Expected flow:

```
[send]   elf=.../build/debug/byepv-pxl-latest.elf size=... sha256=...
[stream] [+] Byepervisor-pxl v0.1.0 (debug)
...
[+] 11.60 hook armed, enter sleep and resume!      <- put the console to sleep
[net]   console silent ... rest mode assumed
[net]   console awake again
[verdict] SUCCESS marker seen in stream
[verdict] payload finished (log file closed)
[report] verdict=SUCCESS reconnects=0 ...
```

After step 2: **put the PS5 into rest mode, then wake it.** The success
notification appears on the console screen and the verdict in the
terminal.

## Flags

```
--probe            link/port check only (no ELF sent)
--no-setup         do not assign the Mac IP (check only)
--stall N          stream silence (s) after which rest mode is assumed
--timeout N        overall timeout (s, default 1800)
--sleep-max N      max seconds to wait for the console to wake
--max-reconnects N
--elf PATH         custom ELF (default: build/debug/byepv-pxl-latest.elf)
--ps5-ip / --elf-port / --log-dir
```

## Logs

- `ps5-run-logs/mac_<ts>.log` — Mac session: phases, `[net]`/`[stream]`/
  `[reconnect]` events + the full payload stream.
- `byepv960_<ts>.log` on the USB stick — console-side elog file (same lines
  + header: build/fw/soc/clock).
- Every payload start streams the **previous** USB log into the stream
  (`[elog] previous run log: ...`), so the Mac session automatically
  carries the console log of the prior (possibly crashed) run.

## Exit codes

`0` success · `1` exploit failed/inconclusive · `2` infrastructure/timeout ·
`130` Ctrl-C
