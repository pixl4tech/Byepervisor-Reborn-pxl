/* pxlview kernel access layer — READ-ONLY (kernel memory).
 *
 * Backed by the SDK C-runtime IOMMU copy-out (see kmem.c). The CI audit
 * greps pxlview sources for kernel write calls (copy-in / set-long and
 * friends) and must find none: pxlview never writes kernel memory.
 *
 * One deliberate exception, documented in PLAN.md: the *process ucred*
 * authid is raised to system (0x4800000000000007) and restored on exit.
 * That is a credential change of our own process (needed for
 * sceVideoOutRegisterBuffers2 and /mnt/nor0 access), not a kernel memory
 * write, and it is reverted before exit.
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

/* Extract printable ASCII strings (min length 4) from a buffer, one per
 * line, NUL-terminated into out. Returns number of characters written. */
size_t kmem_strings_extract(const void *data, size_t len,
                            char *out, size_t out_sz);

/* Save the current ucred authid and switch to system (same value the
 * byepv-pxl payload uses, main.c: kernel_set_ucred_authid). 0 = ok. */
int kmem_set_system_authid(void);

/* Restore the authid saved by kmem_set_system_authid(). No-op if not set. */
void kmem_restore_authid(void);

/* Mount-jail escape: set our proc rootdir to the kernel root vnode so
 * paths from the VSH namespace (e.g. /mnt/nor0) become visible. The
 * WebKit payload namespace does not mount /mnt/nor0. 0 = ok. One-shot,
 * not restored (the process dies with the payload). */
int kmem_set_root_vnode(void);

#endif /* PXL_KMEM_H */
