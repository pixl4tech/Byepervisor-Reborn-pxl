"""Build verification tests for the three payload variants.

Skipped when the SDK toolchain (sdk/) is not installed - run
scripts/bootstrap_sdk.sh first. CI installs it before running this suite.
"""
import os
import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def sdk_env() -> dict | None:
    sdk = REPO_ROOT / "sdk" / "ps5-payload-sdk"
    llvm = REPO_ROOT / "sdk" / "llvm18" / "llvm@18" / "18.1.8"
    if not (sdk / "toolchain" / "prospero.mk").exists():
        return None
    if not (llvm / "bin" / "clang").exists():
        return None
    env = dict(os.environ)
    env["PS5_PAYLOAD_SDK"] = str(sdk)
    env["LLVM_CONFIG"] = str(llvm / "bin" / "llvm-config")
    return env


VERSION = "0.1.0"
VARIANTS = ("debug", "release", "standalone")


@unittest.skipIf(sdk_env() is None,
                 "SDK toolchain not installed (scripts/bootstrap_sdk.sh)")
class TestBuilds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = sdk_env()
        env.setdefault("VERSION", VERSION)
        r = subprocess.run(["make", "all-variants", f"VERSION={VERSION}"],
                           cwd=REPO_ROOT, env=env,
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise RuntimeError(f"make all-variants failed:\n{r.stdout}\n"
                               f"{r.stderr}")

    def elf(self, variant: str) -> Path:
        return (REPO_ROOT / "build" / variant
                / f"byepv-pxl-v{VERSION}.elf")

    def test_all_variants_built(self):
        for v in VARIANTS:
            p = self.elf(v)
            self.assertTrue(p.exists(), f"missing build: {p}")
            self.assertGreater(p.stat().st_size, 100_000,
                               f"{v}: implausibly small ELF")

    def test_elf_validity(self):
        for v in VARIANTS:
            data = self.elf(v).read_bytes()
            self.assertEqual(data[:4], b"\x7fELF", f"{v}: bad magic")
            self.assertEqual(data[4], 2, f"{v}: not 64-bit")
            self.assertEqual(data[18], 62, f"{v}: not x86-64 (EM_X86_64)")
            self.assertIn(VERSION.encode(), data,
                          f"{v}: version string missing")
            self.assertIn(v.encode(), data, f"{v}: variant string missing")

    def test_latest_symlink(self):
        latest = REPO_ROOT / "build" / "debug" / "byepv-pxl-latest.elf"
        self.assertTrue(latest.is_symlink())
        self.assertTrue(latest.exists())  # resolves

    def test_usb_log_strings_per_variant(self):
        debug = self.elf("debug").read_bytes()
        release = self.elf("release").read_bytes()
        standalone = self.elf("standalone").read_bytes()
        # debug: USB storage lookup + previous-log streaming compiled in
        self.assertIn(b"/mnt/usb0", debug)
        self.assertIn(b"previous run log", debug)
        # release / standalone: no USB file, no previous-log streaming
        for name, data in (("release", release), ("standalone", standalone)):
            self.assertNotIn(b"/mnt/usb0", data,
                             f"{name}: USB path compiled in")
            self.assertNotIn(b"previous run log", data,
                             f"{name}: previous-log code compiled in")
            self.assertIn(b"no USB log file", data,
                          f"{name}: no-usb banner missing")

    def test_version_header_generated(self):
        vh = (REPO_ROOT / "include" / "version.h").read_text()
        self.assertIn(f'PXEL_VERSION "{VERSION}"', vh)


class TestPxlviewAudit(unittest.TestCase):
    """pxlview source invariants (no SDK needed)."""

    SRC = REPO_ROOT / "apps" / "pxlview" / "src"

    def test_sources_present(self):
        for name in ("main.c", "kmem.c", "panels.c", "console_ui.c",
                     "notify.c"):
            self.assertTrue((self.SRC / name).exists(), f"missing {name}")
        self.assertTrue((REPO_ROOT / "apps" / "pxlview" / "PLAN.md").exists())

    def test_readonly_kernel_access(self):
        """pxlview must never write kernel memory."""
        banned = ("kernel_copyin", "kernel_setlong", "kernel_setint",
                  "kernel_setshort", "kernel_setchar")
        for p in self.SRC.glob("*.c"):
            text = p.read_text()
            for bad in banned:
                self.assertNotIn(bad, text,
                                 f"{p.name}: kernel write call: {bad}")


@unittest.skipIf(sdk_env() is None,
                 "SDK toolchain not installed (scripts/bootstrap_sdk.sh)")
class TestPxlviewBuild(unittest.TestCase):
    """pxlview ELF build (static SDL2 from the submodule)."""

    def test_pxlview_elf_built(self):
        env = sdk_env()
        r = subprocess.run(["make"], cwd=REPO_ROOT / "apps" / "pxlview",
                           env=env, capture_output=True, text=True,
                           timeout=1800)
        self.assertEqual(r.returncode, 0,
                         f"pxlview build failed:\n{r.stdout}\n{r.stderr}")
        elf = (REPO_ROOT / "apps" / "pxlview" / "build"
               / f"pxlview-v{VERSION}.elf")
        self.assertTrue(elf.exists())
        data = elf.read_bytes()
        self.assertEqual(data[:4], b"\x7fELF")
        self.assertEqual(data[18], 62, "not x86-64")
        self.assertLess(elf.stat().st_size, 8 * 1024 * 1024,
                        "pxlview ELF implausibly large")


if __name__ == "__main__":
    unittest.main()
