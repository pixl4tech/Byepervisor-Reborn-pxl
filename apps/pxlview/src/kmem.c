#include "kmem.h"
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
    /* M3: hex + ascii, 16 bytes per row (same layout as byepv kHexDump) */
    (void)data; (void)len; (void)out; (void)out_sz;
    return 0;
}
