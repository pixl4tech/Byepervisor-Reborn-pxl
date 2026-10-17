#include "panels.h"
#include "kmem.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>

#include <ps5/kernel.h>

/* HV loader physical address, 11.60 regular (same constant as the
 * byepv-pxl payload: root main.c HV_LOADER_PA_REGULAR). */
#define PXL_HV_LOADER_PA_REGULAR  0x062800000ULL
#define PXL_HV_WINDOW             1024          /* bytes read for P2 */

/* struct proc p_comm offset on 11.60. Located on hardware 2026-10-18
 * (pxlview-diag section 3): own proc +0x5dc = "payload.elf" (the ELF
 * basename elfldr execs). Sanity-checked at runtime (printable, NUL
 * within 16B). */
#define PXL_PROC_P_COMM           0x5dc
#define PXL_PROC_SCAN_MAX         256
#define PXL_PROC_LIST_MAX         48

/* struct proc p_pid is uint32 on PS5 (pid_t). */
static int proc_name_at(uint64_t proc, char *out, size_t out_sz)
{
    uint8_t raw[16];

    if (PXL_PROC_P_COMM == 0)
        return -1;
    if (kmem_read(proc + PXL_PROC_P_COMM, raw, sizeof(raw)) != 0)
        return -1;
    for (size_t i = 0; i < 16; i++) {
        if (raw[i] == 0)
            break;
        if (raw[i] < 0x20 || raw[i] >= 0x7F)
            return -1;
    }
    if (raw[15] != 0)   /* must fit in MAXCOMLEN */
        return -1;
    snprintf(out, out_sz, "%s", (const char *)raw);
    return 0;
}

int pxl_append(pxl_ctx_t *ctx, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0)
        return -1;

    if (ctx->len + (size_t)need + 1 > ctx->cap) {
        size_t ncap = ctx->cap ? ctx->cap * 2 : 8192;
        while (ncap < ctx->len + (size_t)need + 1)
            ncap *= 2;
        char *nbuf = realloc(ctx->buf, ncap);
        if (!nbuf)
            return -1;
        ctx->buf = nbuf;
        ctx->cap = ncap;
    }

    va_start(ap, fmt);
    int n = vsnprintf(ctx->buf + ctx->len, (size_t)need + 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        return -1;
    ctx->len += (size_t)n;
    return 0;
}

int panel_ktext(pxl_ctx_t *ctx, pxl_summary_t *sum)
{
    uint8_t buf[64];
    char fmt[512];

    if (pxl_append(ctx, "== P1: kernel .text, first 64 bytes (xotext) ==\n"))
        return -1;
    if (kmem_read((uint64_t)KERNEL_ADDRESS_TEXT_BASE, buf, sizeof(buf)) != 0) {
        pxl_append(ctx, "  [read failed]\n");
        return 0;
    }
    kmem_hexdump_fmt(buf, sizeof(buf), fmt, sizeof(fmt));
    pxl_append(ctx, "%s\n", fmt);
    if (sum) {
        sum->ktext_ok = 1;
        sum->ktext_base = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
    }
    return 0;
}

int panel_hv(pxl_ctx_t *ctx, pxl_summary_t *sum)
{
    uint8_t win[PXL_HV_WINDOW];
    char fmt[600];
    char str[1024];

    if (pxl_append(ctx,
        "== P2: HV memory (hvcore), PA 0x%llx (physical only) ==\n",
        (unsigned long long)PXL_HV_LOADER_PA_REGULAR))
        return -1;
    if (kmem_read(PXL_HV_LOADER_PA_REGULAR, win, sizeof(win)) != 0) {
        pxl_append(ctx, "  [read failed - HV PA not mapped in IOMMU?]\n");
        return 0;
    }
    if (sum)
        sum->hv_ok = 1;
    pxl_append(ctx, "first 64 bytes:\n");
    kmem_hexdump_fmt(win, 64, fmt, sizeof(fmt));
    pxl_append(ctx, "%s\n", fmt);
    pxl_append(ctx, "ASCII strings in first %d bytes:\n", PXL_HV_WINDOW);
    kmem_strings_extract(win, sizeof(win), str, sizeof(str));
    if (str[0])
        pxl_append(ctx, "%s\n", str);
    else
        pxl_append(ctx, "  (none)\n");
    return 0;
}

int panel_procs(pxl_ctx_t *ctx, pxl_summary_t *sum)
{
    int count = 0;

    if (pxl_append(ctx, "== P3: kernel process list (allproc) ==\n"))
        return -1;
    pxl_append(ctx, "  %-8s %-18s %-8s %s\n", "pid", "name", "uid", "authid");
    for (int pid = 0; pid < PXL_PROC_SCAN_MAX && count < PXL_PROC_LIST_MAX;
         pid++) {
        intptr_t proc = kernel_get_proc((pid_t)pid);
        if (proc == 0)
            continue;

        uint32_t real_pid = 0;
        kmem_read((uint64_t)(proc + KERNEL_OFFSET_PROC_P_PID),
                  &real_pid, sizeof(real_pid));

        char name[17] = "-";
        if (proc_name_at((uint64_t)proc, name, sizeof(name)) != 0)
            name[0] = '-', name[1] = '\0';

        uid_t uid = kernel_get_ucred_uid((pid_t)pid);
        uint64_t authid = kernel_get_ucred_authid((pid_t)pid);

        pxl_append(ctx, "  %-8u %-18s %-8u 0x%016llx\n",
                   (unsigned)real_pid, name, (unsigned)uid,
                   (unsigned long long)authid);
        count++;
    }
    pxl_append(ctx, "  (%d processes listed, scan cap %d)\n",
               count, PXL_PROC_SCAN_MAX);
    if (sum)
        sum->procs_count = count;
    return 0;
}

int panel_nor(pxl_ctx_t *ctx, pxl_summary_t *sum)
{
    /* /mnt/nor0 is the NOR firmware partition in the VSH namespace. The
     * WebKit payload namespace does not mount it (rootdir is already the
     * kernel root; ucred prison 0 does not help - PS5 per-app mount
     * trees). /mnt/rnps (ufs.ver/ufs.env/ufs.rev/apps) is the system
     * partition visible here. */
    static const char *const paths[] = {
        "/mnt/nor0", "/mnt/rnps", "/mnt/pfs", "/mnt/rnps2",
    };
    struct dirent *e;
    DIR *d;
    int entries = 0;
    int listed = 0;

    for (size_t i = 0; i < 4 && !listed; i++) {
        d = opendir(paths[i]);
        if (!d)
            continue;
        listed = 1;
        if (pxl_append(ctx, "== P4: firmware directory (%s) ==\n", paths[i]))
            break;
        while ((e = readdir(d)) != NULL && entries < 48) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", paths[i], e->d_name);

            struct stat st;
            if (stat(path, &st) == 0) {
                if (S_ISDIR(st.st_mode))
                    pxl_append(ctx, "  %-32s <dir>\n", e->d_name);
                else
                    pxl_append(ctx, "  %-32s %12llu bytes\n", e->d_name,
                               (unsigned long long)st.st_size);
            } else {
                pxl_append(ctx, "  %-32s (stat failed)\n", e->d_name);
            }
            entries++;
        }
        closedir(d);
    }

    if (!listed) {
        pxl_append(ctx, "== P4: firmware directory ==\n"
                        "  [none of /mnt/nor0|pfs|rnps|rnps2 visible]\n");
        return 0;
    }
    pxl_append(ctx, "  (%d entries)\n", entries);
    if (sum) {
        sum->nor_ok = 1;
        sum->nor_entries = entries;
    }
    return 0;
}

int panel_identity(pxl_ctx_t *ctx, pxl_summary_t *sum)
{
    uint32_t fw = kernel_get_fw_version();
    int soc = 0;

    /* Same extern the byepv-pxl payload uses (include/util.h). */
    extern int sceKernelGetMainSocId(void);
    soc = sceKernelGetMainSocId();

    pxl_append(ctx, "== P5: console identity ==\n");
    pxl_append(ctx, "  fw version   : 0x%08x (%u.%02u)\n",
               (unsigned)fw, (unsigned)(fw >> 8), (unsigned)(fw & 0xff));
    pxl_append(ctx, "  soc id       : 0x%08x\n", (unsigned)soc);
    pxl_append(ctx, "  .text base   : 0x%llx\n",
               (unsigned long long)(uint64_t)KERNEL_ADDRESS_TEXT_BASE);
    pxl_append(ctx, "  data base    : 0x%llx\n",
               (unsigned long long)(uint64_t)KERNEL_ADDRESS_DATA_BASE);
    pxl_append(ctx, "  allproc      : 0x%llx\n",
               (unsigned long long)(uint64_t)KERNEL_ADDRESS_ALLPROC);
    if (sum)
        sum->fw_version = fw;
    return 0;
}

int panels_collect_all(pxl_ctx_t *ctx, pxl_summary_t *sum)
{
    if (sum)
        memset(sum, 0, sizeof(*sum));

    if (panel_ktext(ctx, sum))    return -1;
    if (panel_hv(ctx, sum))       return -1;
    if (panel_procs(ctx, sum))    return -1;
    if (panel_nor(ctx, sum))      return -1;
    if (panel_identity(ctx, sum)) return -1;
    return 0;
}
