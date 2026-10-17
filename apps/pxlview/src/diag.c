/* pxlview display diagnostic v5 —
 * scan the VideoOut.sprx module region for main-memory PAs
 * (candidate scanout buffer physical addresses)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <ps5/kernel.h>

#define CHUNK 0x1000ULL

int main(void)
{
    uint64_t base = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
    /* module region around the VideoOut strings (text+0x10dbf4e / 0x11b4e08) */
    uint64_t start = base + 0x1000000;
    uint64_t end   = base + 0x1800000;

    printf("[diag5] scanning %#llx..%#llx for main-mem PAs\n",
           (unsigned long long)start, (unsigned long long)end);

    uint8_t buf[CHUNK + 16];
    int hits = 0;
    for (uint64_t off = start; off < end && hits < 40; off += CHUNK) {
        if (kernel_copyout((intptr_t)off, buf, CHUNK) != 0)
            continue;
        for (uint64_t i = 0; i + 8 <= CHUNK && hits < 40; i += 8) {
            uint64_t v;
            memcpy(&v, buf + i, 8);
            /* PS5 main DRAM physical addresses: 0x800000000..0x880000000,
             * 256KB aligned for direct-memory buffers */
            if (v >= 0x800000000ULL && v < 0x880000000ULL &&
                (v & 0x1FFFF) == 0) {
                uint8_t ctx[48];
                kernel_copyout((intptr_t)(off + i - 16), ctx, 48);
                printf("[diag5] pa=%#llx @ %#llx  ctx:",
                       (unsigned long long)v, (unsigned long long)(off + i));
                for (int j = 0; j < 48; j++)
                    printf(" %02x", ctx[j]);
                putchar('\n');
                hits++;
                i += 8;
            }
        }
    }
    printf("[diag5] %d hits, done\n", hits);
    return 0;
}
