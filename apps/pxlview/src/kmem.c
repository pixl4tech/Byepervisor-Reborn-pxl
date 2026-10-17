#include "kmem.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>

/* System authid — same value the byepv-pxl payload uses (root main.c:
 * "We need system ucred to pin to core 0"). */
#define PXL_AUTHID_SYSTEM  0x4800000000000007ULL

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

size_t kmem_strings_extract(const void *data, size_t len,
                            char *out, size_t out_sz)
{
    const uint8_t *d = data;
    size_t off = 0;
    size_t i = 0;

    while (i < len && off + 8 < out_sz) {
        /* start of a printable run? */
        if (d[i] < 0x20 || d[i] >= 0x7F) { i++; continue; }
        size_t start = i;
        while (i < len && d[i] >= 0x20 && d[i] < 0x7F)
            i++;
        size_t run = i - start;
        if (run < 4)
            continue;
        if (run > 48)
            run = 48;
        for (size_t j = 0; j < run && off + 1 < out_sz; j++)
            out[off++] = (char)d[start + j];
        if (off + 2 < out_sz) { out[off++] = '\n'; }
    }
    out[off] = '\0';
    return off;
}

static uint64_t g_saved_authid;
static int g_authid_set;

int kmem_set_system_authid(void)
{
    if (g_authid_set)
        return 0;
    g_saved_authid = kernel_get_ucred_authid(getpid());
    if (kernel_set_ucred_authid(getpid(), PXL_AUTHID_SYSTEM) != 0)
        return -1;
    g_authid_set = 1;
    return 0;
}

void kmem_restore_authid(void)
{
    if (!g_authid_set)
        return;
    kernel_set_ucred_authid(getpid(), g_saved_authid);
    g_authid_set = 0;
}
