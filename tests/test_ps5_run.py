"""Unit tests for scripts/ps5_run.py stream/verdict logic.

Each test spawns tests/mock_elfldr.py on a free localhost port and drives
ps5_run.stream() against it, asserting the resulting verdict and the
reconnect count.
"""
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import ps5_run  # noqa: E402

MOCK = REPO_ROOT / "tests" / "mock_elfldr.py"
FAKE_ELF = REPO_ROOT / "tests" / "fake.elf"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_args(port: int, max_reconnects: int = 3) -> SimpleNamespace:
    return SimpleNamespace(
        timeout=90.0,
        sleep_max=10.0,
        max_reconnects=max_reconnects,
        stall=5.0,
        ps5_ip="127.0.0.1",
        elf_port=port,
        elf=FAKE_ELF,
    )


class MockElfldr:
    def __init__(self, mode: str):
        self.port = free_port()
        self.proc = subprocess.Popen(
            [sys.executable, str(MOCK), mode, str(self.port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def wait_ready(self) -> None:
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", self.port), 0.3)
                s.close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("mock elfldr did not start")

    def __enter__(self):
        self.wait_ready()
        return self

    def __exit__(self, *a):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class TestStreamVerdicts(unittest.TestCase):
    def _run(self, mode: str, max_reconnects: int = 3
             ) -> tuple[str, int]:
        with MockElfldr(mode) as mock:
            # small fake ELF payload for the upload
            FAKE_ELF.write_bytes(b"\x7fELF" + b"\x00" * 1024)
            session = ps5_run.Session(
                Path(tempfile.mktemp(prefix="ps5run_test_")))
            watchdog = ps5_run.NetWatchdog(session, "127.0.0.1",
                                           interval=0.5)
            watchdog.start()
            try:
                sock = socket.create_connection(
                    ("127.0.0.1", mock.port), timeout=10)
                sock.sendall(FAKE_ELF.read_bytes())
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(1.0)
                verdict, reconnects = ps5_run.stream(
                    session, make_args(mock.port, max_reconnects),
                    sock, watchdog)
            finally:
                # watchdog is a daemon thread; it dies with the process
                try:
                    sock.close()
                except (NameError, OSError):
                    pass
                session.close()
        return verdict, reconnects

    def test_success(self):
        verdict, reconnects = self._run("success")
        self.assertEqual(verdict, "SUCCESS")
        self.assertEqual(reconnects, 0)

    def test_arm_fail(self):
        verdict, reconnects = self._run("armfail")
        self.assertEqual(verdict, "ARM_FAIL")
        self.assertEqual(reconnects, 0)

    def test_arm_fail_noclose_no_resend_loop(self):
        # EOF without terminal marker + terminal failure already seen:
        # must stop (no infinite resend).
        verdict, reconnects = self._run("armfail_noclose",
                                        max_reconnects=2)
        self.assertIn(verdict, ("ARM_FAIL", "STREAM_LOST"))
        self.assertLessEqual(reconnects, 2)

    def test_drop_reconnects_and_succeeds(self):
        verdict, reconnects = self._run("drop")
        self.assertEqual(verdict, "SUCCESS")
        self.assertEqual(reconnects, 1)

    def test_quiet_gap_then_success(self):
        verdict, reconnects = self._run("quiet")
        self.assertEqual(verdict, "SUCCESS")
        self.assertEqual(reconnects, 0)


if __name__ == "__main__":
    unittest.main()
