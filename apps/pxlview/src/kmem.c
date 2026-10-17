#include "kmem.h"
#include <stdio.h>
#include <string.h>

#include <ps5/kernel.h>

int kmem_init(void)
{
    uint64_t v = 0;
    if (kernel_copyout(KERNEL_ADDRESS_TEXT_BASE, &v, sizeof(v)) != 0)
        return -1;
    return 0;
}

int kmem_read(uint64_t kaddr, void *dst, size_t len)
{
    if (len == 0 || len > 4096)
        return -1;
    return kernel_copyout((intptr_t)kaddr, dst, len);
}

size_t kmem_hexdump_fmt(const void *data, size_t len, char *out, size_t out_sz)
{
    const uint8_t *d = data;
    size_t off = 0;
    for (size_t i = 0; i < len && off + 50 < out_sz; i += 16) {
        char *line = out + off;
        int n = snprintf(line, out_sz - off, "  %04zX  ", i);
        off += (size_t)n;
        size_t chunk = len - i < 16 ? len - i : 16;
        for (size_t j = 0; j < 16 && off + 3 < out_sz; j++) {
            if (j < chunk)
                off += (size_t)snprintf(out + off, out_sz - off, "%02X ", d[i + j]);
            else
                off += (size_t)snprintf(out + off, out_sz - off, "   ");
            if (j == 7 && off + 1 < out_sz) { out[off++] = '|'; }
        }
        if (off + 1 < out_sz) out[off++] = ' ';
        for (size_t j = 0; j < chunk && off + 2 < out_sz; j++) {
            uint8_t c = d[i + j];
            out[off++] = (c >= 0x20 && c < 0x7F) ? c : '.';
        }
        if (off + 2 < out_sz) { out[off++] = '\n'; }
    }
    out[off] = '\0';
    return off;
}
