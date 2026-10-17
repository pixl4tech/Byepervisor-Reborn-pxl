/* pxlview hardware diagnostic (single ELF, all checks in one run).
 *
 *  1. authid probe   — current ucred authid, then system authid set
 *                       (M1 hypothesis H1: VideoOut EACCES needs system)
 *  2. VideoOut matrix — sceKernelAllocateMainDirectMemory /
 *                       sceVideoOutOpen / sceVideoOutRegisterBuffers2 with
 *                       varying memsize and display id, errno printed at
 *                       every step (M1 hypothesis H2)
 *  3. p_comm finder  — printable strings inside our own struct proc with
 *                       their offsets (M3: PXL_PROC_P_COMM)
 *
 * Build: make diag -> build/pxlview-diag.elf
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define PXL_AUTHID_SYSTEM  0x4800000000000007ULL

/* --- VideoOut prototypes (same as SDL2 src/video/ps5/SDL_ps5video.h) --- */
typedef struct { void *data; uint64_t junk0[3]; } DiagVideoBuf;
typedef struct { uint8_t junk0[80]; } DiagVideoAttr;

int sceKernelAllocateMainDirectMemory(size_t, size_t, int, intptr_t *);
int sceKernelMapDirectMemory(void **, size_t, int, int, intptr_t, size_t);
int sceKernelReleaseDirectMemory(intptr_t, size_t);
int sceVideoOutOpen(int, int, int, const void *);
void sceVideoOutClose(int);
void sceVideoOutSetBufferAttribute2(DiagVideoAttr *, uint64_t, uint32_t,
                                    uint32_t, uint32_t, uint64_t, uint32_t,
                                    uint64_t);
int sceVideoOutRegisterBuffers2(int, int, int, DiagVideoBuf *, int,
                                DiagVideoAttr *, int, void *);

static void sec(const char *t)
{
    printf("\n[diag] ===== %s =====\n", t);
}

static void diag_authid(void)
{
    sec("1. authid probe");
    pid_t me = getpid();
    uint64_t before = kernel_get_ucred_authid(me);
    printf("[diag] pid=%d authid before = 0x%016llx\n", (int)me,
           (unsigned long long)before);
    int rc = kernel_set_ucred_authid(me, PXL_AUTHID_SYSTEM);
    printf("[diag] set system authid rc=%d\n", rc);
    uint64_t after = kernel_get_ucred_authid(me);
    printf("[diag] authid after    = 0x%016llx\n",
           (unsigned long long)after);
    kernel_set_ucred_authid(me, before);
    printf("[diag] authid restored = 0x%016llx\n",
           (unsigned long long)kernel_get_ucred_authid(me));
}

static void try_videoout(size_t memsize, int display_id)
{
    intptr_t pa = 0;
    void *va = 0;
    DiagVideoBuf vbuf[2];
    DiagVideoAttr vattr;
    int rc;

    memset(vbuf, 0, sizeof(vbuf));
    memset(&vattr, 0, sizeof(vattr));

    rc = sceKernelAllocateMainDirectMemory(memsize, 0x20000, 3, &pa);
    printf("[diag] alloc(%s, disp=%d): rc=%d (%s) pa=0x%llx\n",
           (memsize == 0x1000000) ? "16M" :
           (memsize == 0x2000000) ? "32M" : "64M",
           display_id, rc, rc ? strerror(errno) : "ok",
           (unsigned long long)pa);
    if (rc)
        return;

    rc = sceKernelMapDirectMemory(&va, memsize, 0x33, 0, pa, 0x20000);
    printf("[diag]   map: rc=%d (%s) va=%p\n", rc,
           rc ? strerror(errno) : "ok", va);
    if (rc) {
        sceKernelReleaseDirectMemory(pa, memsize);
        return;
    }

    vbuf[0].data = va;
    vbuf[1].data = va + (memsize / 2);

    int h = sceVideoOutOpen(0xff, display_id, 0, NULL);
    printf("[diag]   videoout_open(0xff,%d): h=%d (%s)\n", display_id, h,
           h < 0 ? strerror(errno) : "ok");
    if (h < 0) {
        sceKernelReleaseDirectMemory(pa, memsize);
        return;
    }

    sceVideoOutSetBufferAttribute2(&vattr, 0x8000000022000000ULL, 0,
                                   1920, 1080, 0, 0, 0);
    rc = sceVideoOutRegisterBuffers2(h, 0, 0, vbuf, 2, &vattr, 0, NULL);
    printf("[diag]   register_buffers2: rc=%d (%s)\n", rc,
           rc ? strerror(errno) : "ok");

    sceVideoOutClose(h);
    sceKernelReleaseDirectMemory(pa, memsize);
}

static void diag_videoout(void)
{
    sec("2. VideoOut matrix (after system authid set)");
    kernel_set_ucred_authid(getpid(), PXL_AUTHID_SYSTEM);
    errno = 0;
    try_videoout(0x1000000, 1);
    errno = 0;
    try_videoout(0x1000000, 0);
    errno = 0;
    try_videoout(0x2000000, 1);
    errno = 0;
    try_videoout(0x4000000, 1);
}

static void diag_pcomm(void)
{
    sec("3. p_comm candidates in own struct proc");
    intptr_t proc = kernel_get_proc(getpid());
    printf("[diag] own proc = 0x%llx\n", (unsigned long long)proc);
    if (proc == 0)
        return;

    uint8_t raw[1024];
    if (kernel_copyout(proc, raw, sizeof(raw)) != 0) {
        printf("[diag] proc read failed\n");
        return;
    }

    size_t i = 0;
    while (i < sizeof(raw)) {
        if (raw[i] < 0x20 || raw[i] >= 0x7F) { i++; continue; }
        size_t start = i;
        while (i < sizeof(raw) && raw[i] >= 0x20 && raw[i] < 0x7F)
            i++;
        size_t run = i - start;
        if (run >= 6 && run <= 32)
            printf("[diag]   off=+0x%03zx len=%zu \"%s\"\n",
                   start, run, (const char *)raw + start);
    }
}

int main(void)
{
    printf("[diag] pxlview diagnostic starting\n");
    diag_authid();
    diag_videoout();
    diag_pcomm();
    printf("[diag] all done\n");
    return 0;
}
