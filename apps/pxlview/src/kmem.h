/* pxlview kernel access layer — READ-ONLY.
 *
 * Backed by the SDK C-runtime IOMMU copy-out (see kmem.c). The CI audit
 * greps pxlview sources for kernel write calls (copy-in / set-long and
 * friends) and must find none: pxlview never writes kernel memory.
 */
#ifndef PXL_KMEM_H
#define PXL_KMEM_H

#include <stdint.h>
#include <stddef.h>

/* Verify the kernel-copy primitive works (reads .text[0]). 0 = ok. */
int kmem_init(void);

/* Bounded kernel read (len <= 4096). 0 = ok, -1 = fault. */
int kmem_read(uint64_t kaddr, void *dst, size_t len);

/* Format len bytes as hex+ascii lines (16 bytes/row) into out (out_sz).
 * Returns number of characters written (excluding NUL). */
size_t kmem_hexdump_fmt(const void *data, size_t len, char *out, size_t out_sz);

#endif /* PXL_KMEM_H */
