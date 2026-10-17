"""Host unit test for the pxlview 5x7 bitmap font renderer.

Compiles a tiny C program (host compiler) that blits the 'A' glyph at
4x scale into a 24x28 buffer and prints it, then verifies the pixel
layout against the known font bytes (font_5x7[0x41] =
{0x7C, 0x12, 0x11, 0x12, 0x7C}).

Skipped when no host C compiler is available.
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FONT_H = REPO_ROOT / "apps" / "pxlview" / "src" / "font_5x7.h"

C_SRC = r"""
#include <stdio.h>
#include "font_5x7.h"
int main(void) {
    int buf[28][24];
    for (int y = 0; y < 28; y++)
        for (int x = 0; x < 24; x++)
            buf[y][x] = 0;
    const uint8_t *g = font_5x7['A'];
    for (int y = 0; y < FONT_H; y++)
        for (int x = 0; x < FONT_W; x++)
            if (g[y] & (1u << x))
                for (int dy = 0; dy < 4; dy++)
                    for (int dx = 0; dx < 4; dx++)
                        buf[y * 4 + dy][x * 4 + dx] = 1;
    for (int y = 0; y < 28; y++) {
        for (int x = 0; x < 24; x++)
            putchar(buf[y][x] ? '1' : '0');
        putchar('\n');
    }
    return 0;
}
"""


def cc_available() -> str | None:
    for c in ("clang", "gcc", "cc"):
        if shutil.which(c):
            return c
    return None


@unittest.skipIf(cc_available() is None, "no host C compiler")
class TestFontRender(unittest.TestCase):
    def _render(self) -> list[str]:
        cc = cc_available()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "render.c"
            out = Path(td) / "render"
            src.write_text(C_SRC)
            r = subprocess.run(
                [cc, "-I", str(FONT_H.parent), str(src), "-o", str(out)],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            r = subprocess.run([str(out)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
        return r.stdout.strip().split("\n")

    def test_glyph_a_shape(self):
        rows = self._render()
        self.assertEqual(len(rows), 28)
        for row in rows:
            self.assertEqual(len(row), 24)

        def on(cols: range, row: int) -> None:
            self.assertEqual(rows[row][cols.start:cols.stop],
                             "1" * (cols.stop - cols.start),
                             f"rows {row}..{row+3} cols {cols.start}..{cols.stop}")

        def off(cols: range, row: int) -> None:
            self.assertEqual(rows[row][cols.start:cols.stop],
                             "0" * (cols.stop - cols.start),
                             f"rows {row}..{row+3} cols {cols.start}..{cols.stop}")

        # y=0 (0x7C, 5-bit 0b11100): x=2..4 on -> cols 8..19
        off(range(0, 8), 0)
        on(range(8, 20), 0)
        off(range(20, 24), 0)
        # y=2 (0x11 = 0b00101): x=0,4 on -> cols 0..3, 16..19
        on(range(0, 4), 8)
        off(range(4, 16), 8)
        on(range(16, 20), 8)
        off(range(20, 24), 8)
        # glyph ends after 7 rows: last row empty
        self.assertEqual(rows[27], "0" * 24)

    def test_font_table_size(self):
        # 256 glyphs x 5 bytes
        text = FONT_H.read_text()
        self.assertIn("font_5x7[256][5]", text)


if __name__ == "__main__":
    unittest.main()
