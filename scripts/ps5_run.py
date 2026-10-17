#!/usr/bin/env python3
"""
ps5_run.py — one-command Byepervisor-Reborn run over Ethernet (MacBook <-> PS5).

Topology
  MacBook (10.10.10.1) === ethernet cable === PS5 (10.10.10.2, static IP)

Protocol (ps5-payload-dev/elfldr)
  * The kernel exploit chain (relapse) must already be running on the PS5 and
    elfldr must be listening on TCP 9021.
  * Upload = raw ELF bytes over TCP, then half-close (SHUT_WR). The first 4
    bytes of the ELF (0x7f 'E' 'L' 'F') are elfldr's ELF magic, so a plain
    file dump is the complete protocol (same as `nc -q0 $PS5 9021 < x.elf`).
  * elfldr dup2()s that same socket to the payload's stdin/stdout/stderr, so
    after the upload the socket carries the payload's LIVE printf stream.
    That stream is the log channel for this script.

Rest mode
  The exploit puts the console into rest mode in the middle of the run.
  While the console sleeps: no ping replies, no TCP data (CPU suspended,
  TCP stack frozen). The NIC link may or may not survive; if the socket
  dies, the script waits for the console to wake (ping) and RE-SENDS the
  ELF. The payload is idempotent: a re-sent instance reads the cave state
  and continues (armed -> keep waiting / results survived -> prove & exit).

Log
  <log-dir>/mac_<YYYYmmdd_HHMMSS>.log — phase events + full payload stream.
  (The console-side elog file on the USB SSD contains the same payload
  lines; keep both, they are complementary artifacts.)

Exit codes
  0 success   1 exploit failure   2 infra/timeout   130 Ctrl-C

Usage
  python3 scripts/ps5_run.py                 # full run
  python3 scripts/ps5_run.py --probe         # link + port check only
  python3 scripts/ps5_run.py --no-setup      # don't touch the Mac IP
"""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ELF = REPO_ROOT / "build" / "debug" / "byepv-pxl-latest.elf"
DEFAULT_LOG_DIR = REPO_ROOT / "ps5-run-logs"

# Stream markers (exact substrings of the payload's log lines).
MARK_START_1160 = "Byepervisor-pxl v"
MARK_SUCCESS_1160 = "Byepervisor Reborn 11.60 - SUCCESS"
MARK_SUCCESS_LEGACY = "hypervisor is defeated"
MARK_SUCCESS_ALREADY = "Hypervisor is already compromised"
MARK_ARM_FAIL = "hook arm failed"
MARK_ERROR = "[NOTIFY] [ERROR]"
MARK_DONE = "log file closed"          # elog_finish

# pxlview (read-only inspector app) stream markers: the app has no rest
# mode cycle, so a clean run ends with "[pxlview] done" + EOF and must NOT
# be re-sent (that looped the launcher during M1 debugging).
PXL_START = "[pxlview] starting"
PXL_DONE = "[pxlview] done"
PXL_FAIL = "FAILED"


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


class Session:
    """Dual writer: terminal + file. Control lines are timestamped,
    payload stream is written verbatim."""

    def __init__(self, path: Path):
        self.path = path
        self.fh = path.open("w", encoding="utf-8", buffering=1)
        self.lock = threading.Lock()
        self.bytes_received = 0
        self.lines_received = 0

    def _w(self, s: str) -> None:
        with self.lock:
            print(s, flush=True)
            self.fh.write(s + "\n")

    def emit(self, tag: str, msg: str) -> None:
        self._w(f"[{ts()}] [{tag}] {msg}")

    def raw(self, text: str) -> None:
        if not text:
            return
        with self.lock:
            sys.stdout.write(text)
            sys.stdout.flush()
            self.fh.write(text)
            self.bytes_received += len(text.encode("utf-8", "replace"))
            self.lines_received += text.count("\n")

    def close(self) -> None:
        with self.lock:
            try:
                self.fh.close()
            except Exception:
                pass


def ping_once(ip: str, timeout: float = 2.0) -> bool:
    """True if the host answered one ICMP echo."""
    try:
        p = subprocess.run(
            ["ping", "-c", "1", "-t", str(max(1, int(timeout))), ip],
            capture_output=True, text=True, timeout=timeout + 3,
        )
        return "bytes from" in p.stdout
    except Exception:
        return False


class NetWatchdog(threading.Thread):
    """Background ping probe; reports AWAKE/SILENT state transitions.
    SILENT during the armed phase == console in rest mode (expected)."""

    def __init__(self, session: Session, ip: str, interval: float = 2.0):
        super().__init__(daemon=True)
        self.session = session
        self.ip = ip
        self.interval = interval
        self.state = "UNKNOWN"
        self._lock = threading.Lock()

    def get_state(self) -> str:
        with self._lock:
            return self.state

    def run(self) -> None:
        silent_streak = 0
        while True:
            t0 = time.time()
            alive = ping_once(self.ip, 1.5)
            silent_streak = 0 if alive else silent_streak + 1
            if alive:
                state = "AWAKE"
            elif silent_streak >= 2:
                state = "SILENT"
            else:
                state = "DEGRADED"
            with self._lock:
                old, self.state = self.state, state
            if state != old:
                if state == "SILENT":
                    self.session.emit(
                        "net", f"console silent (no ping reply) — "
                               f"rest mode assumed (was {old})")
                elif state == "AWAKE":
                    self.session.emit("net", f"console awake again (was {old})")
            time.sleep(max(0.1, self.interval - (time.time() - t0)))


def find_eth_interfaces() -> list[dict]:
    """Active en* interfaces from `ifconfig -a` (line-based parsing: blocks
    are separated by a single newline, not a blank line)."""
    out = subprocess.run(
        ["ifconfig", "-a"], capture_output=True, text=True).stdout
    blocks = []
    cur = None
    for line in out.splitlines():
        m = re.match(r"^([A-Za-z0-9]+):", line)
        if m:
            cur = {"name": m.group(1), "text": line}
            blocks.append(cur)
        elif cur is not None:
            cur["text"] += "\n" + line
    ifaces = []
    for b in blocks:
        if not re.match(r"^en\d+$", b["name"]):
            continue
        if "status: active" not in b["text"]:
            continue
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", b["text"])
        ifaces.append({"name": b["name"], "inet": m.group(1) if m else None})
    return ifaces


def ensure_mac_ip(session: Session, mac_ip: str, do_setup: bool) -> None:
    ifaces = find_eth_interfaces()
    active = [i["name"] for i in ifaces]
    session.emit("link", f"active Ethernet interfaces: {active or 'none'}")
    for i in ifaces:
        if i["inet"] == mac_ip:
            session.emit("link", f"{i['name']} already has {mac_ip}")
            return
    if not do_setup:
        session.emit("link", f"WARNING: no interface has {mac_ip} "
                             "(use --setup to assign it)")
        return
    cand = next((i for i in ifaces if i["inet"] is None), None)
    if not cand:
        session.emit("link", f"WARNING: no candidate interface to assign "
                             f"{mac_ip} to")
        return
    session.emit("link", f"assigning {mac_ip} to {cand['name']} (sudo)")
    r = subprocess.run(
        ["sudo", "ifconfig", cand["name"], mac_ip, "netmask", "255.255.255.0"])
    if r.returncode == 0:
        session.emit("link", f"{cand['name']} = {mac_ip}")
    else:
        session.emit("link", f"WARNING: ifconfig failed (rc={r.returncode}); "
                             f"set the IP manually")


def wait_for_elfldr(session: Session, ip: str, port: int,
                    timeout: float) -> bool:
    session.emit("wait",
                 f"waiting for elfldr on {ip}:{port} "
                 f"(run the kernel exploit chain and send elfldr first)")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((ip, port), timeout=3)
            s.close()
            session.emit("wait", f"elfldr port {port} is open")
            return True
        except OSError:
            time.sleep(3)
    session.emit("wait", f"elfldr port {port} did not open in {timeout:.0f}s")
    return False


def send_elf(session: Session, ip: str, port: int, elf: Path) -> socket.socket:
    data = elf.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    session.emit("send", f"elf={elf} size={len(data)} sha256={sha}")
    sock = socket.create_connection((ip, port), timeout=10)
    sock.settimeout(1.0)
    sock.sendall(data)
    sock.shutdown(socket.SHUT_WR)
    session.emit("send",
                 "ELF uploaded; the socket now carries the payload's "
                 "live stdout")
    return sock


def stream(session: Session, args, sock: socket.socket,
           watchdog: NetWatchdog) -> tuple[str, int]:
    """Read the payload stream until a verdict is reached.

    Survives rest mode:
      * silence          -> marked as a gap (expected while sleeping)
      * socket EOF/reset -> if the console is (or becomes) awake again,
                            reconnect and re-send the ELF
    Returns (verdict, reconnects).
    """
    verdict = None
    reconnects = 0
    start = time.time()
    last_data = time.time()
    gap_warned = False
    tail = b""
    pxlv = "pxlview" in args.elf.name

    success_seen = arm_fail_seen = done_seen = error_seen = False
    start_seen = False

    def scan(chunk: bytes) -> None:
        nonlocal tail, success_seen, arm_fail_seen, done_seen, error_seen, \
            start_seen
        tail = (tail + chunk)[-8192:]
        t = tail.decode("utf-8", "replace")
        if pxlv:
            if not start_seen and PXL_START in t:
                start_seen = True
                session.emit("stream", "pxlview started (banner seen)")
            if not done_seen and PXL_DONE in t:
                done_seen = True
                session.emit("verdict", "pxlview finished (done marker)")
            if not error_seen and PXL_FAIL in t:
                error_seen = True
            return
        if not start_seen and MARK_START_1160 in t:
            start_seen = True
            session.emit("stream", "payload started (banner seen)")
        if not success_seen and (MARK_SUCCESS_1160 in t
                                 or MARK_SUCCESS_LEGACY in t
                                 or MARK_SUCCESS_ALREADY in t):
            success_seen = True
            session.emit("verdict", "SUCCESS marker seen in stream")
        if not arm_fail_seen and MARK_ARM_FAIL in t:
            arm_fail_seen = True
            session.emit("verdict", "ARM-FAIL marker seen in stream")
        if not done_seen and MARK_DONE in t:
            done_seen = True
            session.emit("verdict", "payload finished (log file closed)")
        if not error_seen and MARK_ERROR in t:
            error_seen = True

    def lose_connection(reason: str) -> bool:
        """Handle a dead socket. Returns True if the stream continues."""
        nonlocal sock, reconnects, last_data, gap_warned
        session.emit("stream", f"connection lost ({reason}); "
                               f"net state: {watchdog.get_state()}")
        # If the console is asleep, wait for it to wake first.
        deadline = time.time() + args.sleep_max
        while (watchdog.get_state() != "AWAKE"
               and time.time() - start < args.timeout
               and time.time() < deadline):
            time.sleep(2)
        for attempt in range(1, args.max_reconnects + 1):
            try:
                sock = send_elf(session, args.ps5_ip, args.elf_port, args.elf)
                reconnects += 1
                session.emit("reconnect",
                             f"reconnected, ELF re-sent (attempt {attempt}); "
                             f"new payload instance sees cave state and "
                             f"continues")
                last_data = time.time()
                gap_warned = False
                return True
            except OSError as e:
                session.emit("reconnect",
                             f"attempt {attempt} failed: {e}; retry in 5s")
                time.sleep(5)
        return False

    while verdict is None:
        if time.time() - start > args.timeout:
            session.emit("verdict", f"overall timeout ({args.timeout:.0f}s)")
            verdict = "TIMEOUT"
            break
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            silent = time.time() - last_data
            if silent > args.stall and not gap_warned:
                session.emit(
                    "stream",
                    f"no payload output for {silent:.0f}s "
                    f"(net: {watchdog.get_state()}); console is likely in "
                    f"rest mode — waiting")
                gap_warned = True
            continue
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            if not lose_connection(str(e)):
                verdict = "STREAM_LOST"
                break
            continue

        if not chunk:  # EOF
            session.emit("stream", "loader closed the connection (EOF)")
            if pxlv:
                # pxlview is one-shot: done marker == clean exit. No
                # rest-mode cycle, so no idempotent re-send semantics.
                if done_seen:
                    verdict = "FAIL" if error_seen else "SUCCESS"
                elif error_seen:
                    verdict = "FAIL"
                else:
                    # No terminal marker at all: treat as a transient drop
                    if not lose_connection("EOF without terminal marker"):
                        verdict = "STREAM_LOST"
                    continue
            elif success_seen:
                verdict = "SUCCESS"
            elif arm_fail_seen:
                # Terminal failure path reached (e.g. arm refused). In
                # serial-only log mode the payload exits WITHOUT a
                # 'log file closed' line, so the terminal marker is the
                # goodbye. Reconnecting here would replay the same
                # failure in an infinite loop — stop instead.
                session.emit("stream",
                             "EOF with terminal marker: payload exited, "
                             "no reconnect")
                verdict = "ARM_FAIL"
            elif done_seen:
                verdict = "FAIL" if error_seen else "INCONCLUSIVE"
            else:
                # No terminal marker at all: treat as a transient drop
                # (NIC reset around resume, console about to sleep, ...).
                # Reconnect and re-send the ELF — the payload is
                # idempotent and a fresh instance continues from the
                # cave state.
                if not lose_connection("EOF without terminal marker"):
                    verdict = "STREAM_LOST"
                continue
            break

        last_data = time.time()
        gap_warned = False
        session.raw(chunk.decode("utf-8", "replace"))
        scan(chunk)
        if pxlv and done_seen:
            verdict = "FAIL" if error_seen else "SUCCESS"
            break
        if success_seen and done_seen:
            verdict = "SUCCESS"
            break
        if arm_fail_seen and done_seen:
            verdict = "ARM_FAIL"
            break

    return verdict, reconnects


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    ap.add_argument("--ps5-ip", default="10.10.10.2")
    ap.add_argument("--mac-ip", default="10.10.10.1")
    ap.add_argument("--elf-port", type=int, default=9021)
    ap.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    ap.add_argument("--timeout", type=float, default=1800.0,
                    help="overall run timeout, seconds (default 1800)")
    ap.add_argument("--stall", type=float, default=25.0,
                    help="silence threshold before a gap warning, seconds")
    ap.add_argument("--sleep-max", type=float, default=900.0,
                    help="max seconds to wait for the console to wake")
    ap.add_argument("--max-reconnects", type=int, default=8)
    ap.add_argument("--wait-elf-timeout", type=float, default=600.0)
    ap.add_argument("--probe", action="store_true",
                    help="link + elfldr port check only; no ELF is sent")
    ap.add_argument("--no-setup", action="store_true",
                    help="never assign the Mac IP (no sudo)")
    args = ap.parse_args()

    args.log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session = Session(args.log_dir / f"mac_{stamp}.log")
    watchdog = NetWatchdog(session, args.ps5_ip)

    session.emit("run", f"Byepervisor-Reborn network run")
    session.emit("run",
                 f"mac_ip={args.mac_ip} ps5_ip={args.ps5_ip} "
                 f"elf_port={args.elf_port} elf={args.elf}")
    session.emit("run", f"log file: {session.path}")
    if not args.elf.exists():
        session.emit("run",
                     f"WARNING: {args.elf} not found — build it first "
                     f"(`make` with PS5_PAYLOAD_SDK set)")

    watchdog.start()

    # Phase 0: link
    ensure_mac_ip(session, args.mac_ip, do_setup=not args.no_setup)
    if ping_once(args.ps5_ip, 2.0):
        session.emit("link", f"PS5 {args.ps5_ip} answers ping")
    else:
        session.emit("link",
                     f"PS5 {args.ps5_ip} does not answer ping "
                     f"(powered off? asleep? wrong IP?)")

    if args.probe:
        open_now = False
        try:
            s = socket.create_connection((args.ps5_ip, args.elf_port), 3)
            s.close()
            open_now = True
        except OSError:
            pass
        session.emit("probe",
                     f"elfldr port {args.elf_port} "
                     f"{'OPEN' if open_now else 'closed'}")
        session.emit("probe", "probe done (no ELF sent)")
        session.close()
        return 0

    # Phase 1: wait for elfldr
    if not wait_for_elfldr(session, args.ps5_ip, args.elf_port,
                           args.wait_elf_timeout):
        session.emit("report", "verdict=WAIT_TIMEOUT")
        session.close()
        return 2

    # Phase 2+3: send ELF, stream the payload
    verdict = "INCONCLUSIVE"
    reconnects = 0
    try:
        sock = send_elf(session, args.ps5_ip, args.elf_port, args.elf)
        verdict, reconnects = stream(session, args, sock, watchdog)
    except KeyboardInterrupt:
        session.emit("run", "interrupted by user (Ctrl-C)")
        verdict = "USER_INTERRUPT"

    # Phase 4: report
    session.emit(
        "report",
        f"verdict={verdict} reconnects={reconnects} "
        f"payload_bytes={session.bytes_received} "
        f"payload_lines={session.lines_received} "
        f"net_state={watchdog.get_state()}")
    session.emit("report", f"log saved: {session.path}")
    session.close()

    return {"SUCCESS": 0, "ARM_FAIL": 1, "FAIL": 1,
            "INCONCLUSIVE": 1, "TIMEOUT": 2, "STREAM_LOST": 2,
            "USER_INTERRUPT": 130}.get(verdict, 2)


if __name__ == "__main__":
    raise SystemExit(main())
