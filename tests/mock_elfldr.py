#!/usr/bin/env python3
"""Mock elfldr for local testing of ps5_run.py (thread per connection).

Usage: mock_elfldr.py <mode> [port]
Modes: success | arffail | arffail_noclose | quiet | drop
       | pxlview | pxlview_fail
"""
import socket, sys, time, threading

mode = sys.argv[1] if len(sys.argv) > 1 else "success"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 9021
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(5)
state = {"n": 0}
lock = threading.Lock()

BANNER = "[+] Byepervisor-pxl v0.1.0 (debug)\n"

def drain_upload(conn):
    got = 0
    try:
        while True:
            d = conn.recv(65536)
            if not d:
                break
            got += len(d)
    except OSError:
        pass
    return got

def stream(conn, lines, pause_after=None, pause=1.5):
    try:
        for i, (delay, line) in enumerate(lines):
            time.sleep(delay)
            conn.sendall(line.encode())
            if pause_after is not None and i == pause_after:
                time.sleep(pause)
    except OSError:
        pass

HDR = [
    (0.2, "[elog] run log: /mnt/usb0/byepv960_mock.log\n"),
    (0.0, BANNER),
    (0.0, "[+] Detected firmware: 11.60\n"),
    (0.0, "[+] Regular model detected, HV loader PA = 0x62800000\n"),
    (0.0, "[+] Disabling xotext + enabling write on kernel .text...\n"),
    (0.0, "[+] Installing 11.60 hardened hook...\n"),
]
MID = [
    (0.0, "[+] 11.60 hook armed, enter sleep and resume!\n"),
]
POST_RESUME = [
    (1.0, "[11.60] armed, waiting for resume/strike... 30s\n"),
    (0.5, "[+] Strike finished, uninstalling hook\n"),
    (0.0, "[11.60] chain=434841494e2d3031 entered=454e544552454431 mode=31454b4952545356 done=444f4e452d415031\n"),
    (0.0, "[NOTIFY] Byepervisor Reborn 11.60 - SUCCESS. Kernel .text first 8 bytes\n48 8b 1d c3 35 00 00\n"),
    (0.0, "elog: log file closed (/mnt/usb0/byepv960_mock.log)\n"),
]
ARFAIL = [
    (0.0, "[h1160] verify_tss REFUSE: -1 (-1=bad RSP0/IST4, -2=IST6 owned, -3=row alias)\n"),
    (0.0, "[!] 11.60 hook arm failed: -3\n"),
    (0.0, "[NOTIFY] [ERROR] Byepervisor Reborn\n11.60 hook arm failed :(\n"),
    (0.0, "elog: log file closed (/mnt/usb0_mock.log)\n"),
]
PXLVIEW_OK = [
    (0.2, "[pxlview] starting v0.1.0\n"),
    (0.0, "[pxlview] kernel access ok\n"),
    (0.0, "[pxlview] collected 1234 bytes of panel text (procs=20 nor=1 hv=1)\n"),
    (0.0, "[pxlview-ui] window 3840x2160 fmt=0x1620rgb\n"),
    (3.0, "[pxlview] pxlview v0.1.0: .text=ok 0x57c6bbe8, 20 procs, NOR ok, HV ok, fw 0x11600000\n"),
    (0.0, "[pxlview] done\n"),
]
PXLVIEW_FAIL = [
    (0.2, "[pxlview] starting v0.1.0\n"),
    (0.0, "[pxlview] kernel access FAILED\n"),
    (0.0, "[pxlview] done\n"),
]

def handle(conn):
    up = drain_upload(conn)
    if up == 0:
        print("[mock] probe (0 bytes), ignored", flush=True)
        conn.close()
        return
    with lock:
        state["n"] += 1
        n = state["n"]
    print(f"[mock] conn#{n} upload={up} bytes", flush=True)
    if mode == "success":
        if n == 1:
            stream(conn, HDR + MID, pause_after=len(HDR + MID) - 1, pause=2.0)
            stream(conn, POST_RESUME)
        else:
            stream(conn, POST_RESUME)
    elif mode == "armfail":
        stream(conn, HDR + ARFAIL)
    elif mode == "armfail_noclose":
        # serial-only log mode: payload exits WITHOUT 'log file closed'
        stream(conn, HDR + ARFAIL[:-1])
    elif mode == "quiet":
        # socket stays open; 8s of silence simulates rest mode
        stream(conn, HDR + MID)
        time.sleep(8)
        stream(conn, POST_RESUME)
    elif mode == "drop":
        if n == 1:
            stream(conn, HDR[:3])
            conn.close()
            time.sleep(2.5)
        else:
            stream(conn, HDR[3:] + MID)
            stream(conn, POST_RESUME)
    elif mode == "pxlview":
        stream(conn, PXLVIEW_OK)
    elif mode == "pxlview_fail":
        # kernel access FAILED is the terminal marker; done marker follows
        stream(conn, PXLVIEW_FAIL)
    conn.close()

print(f"[mock] listening on 127.0.0.1:{port} mode={mode}", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
