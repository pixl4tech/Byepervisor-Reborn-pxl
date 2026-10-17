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
 *  4. fs probe       — what the WebKit payload can see: /, /mnt, /dev,
 *                       /mnt/nor0 (P4)
 *
 * Build: make diag -> build/pxlview-diag.elf
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/event.h>
#include <dirent.h>

#include <ps5/kernel.h>

#define PXL_AUTHID_SYSTEM  0x4800000000000007ULL

/* --- VideoOut prototypes (same as SDL2 src/video/ps5/SDL_ps5video.h) --- */
typedef struct { void *data; uint64_t junk0[3]; } DiagVideoBuf;
typedef struct { uint8_t junk0[80]; } DiagVideoAttr;

int sceKernelAllocateMainDirectMemory(size_t, size_t, int, intptr_t *);
int sceKernelMapDirectMemory(void **, size_t, int, int, intptr_t, size_t);
int sceKernelReleaseDirectMemory(intptr_t, size_t);
int sceKernelCreateEqueue(struct kevent **, const char *);
int sceKernelDeleteEqueue(struct kevent *);
int sceKernelWaitEqueue(struct kevent *, struct kevent *, int, int *, uint *);
int sceVideoOutOpen(int, int, int, const void *);
void sceVideoOutClose(int);
void sceVideoOutSetBufferAttribute2(DiagVideoAttr *, uint64_t, uint32_t,
                                    uint32_t, uint32_t, uint64_t, uint32_t,
                                    uint64_t);
int sceVideoOutRegisterBuffers2(int, int, int, DiagVideoBuf *, int,
                                DiagVideoAttr *, int, void *);
int sceVideoOutAddFlipEvent(struct kevent *, int, void *);
int sceVideoOutSetFlipRate(int, int);
int sceVideoOutSubmitFlip(int, int, uint32_t, int64_t);
int sceVideoOutSetFlipMaster(int);

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

    uint8_t raw[4096];
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
        if (run >= 4 && run <= 32)
            printf("[diag]   off=+0x%03zx len=%zu \"%s\"\n",
                   start, run, (const char *)raw + start);
    }
}

static void probe_path(const char *p)
{
    struct stat st;
    if (stat(p, &st) == 0) {
        printf("[diag]   %-16s ok  %s\n", p,
               S_ISDIR(st.st_mode) ? "<dir>" : "<file>");
        if (S_ISDIR(st.st_mode)) {
            DIR *d = opendir(p);
            if (d) {
                int n = 0;
                struct dirent *e;
                while ((e = readdir(d)) != NULL && n < 12) {
                    printf("[diag]       %s\n", e->d_name);
                    n++;
                }
                closedir(d);
            } else {
                printf("[diag]       opendir FAILED (%s)\n",
                       strerror(errno));
            }
        }
    } else {
        printf("[diag]   %-16s stat failed (%s)\n", p, strerror(errno));
    }
}

static void diag_fs(void)
{
    sec("4. fs probe (what the WebKit payload can see)");
    probe_path("/");
    probe_path("/mnt");
    probe_path("/mnt/nor0");
    probe_path("/mnt/pfs");
    probe_path("/mnt/rnps");
    probe_path("/mnt/rnps2");
    probe_path("/mnt/ext0");
    probe_path("/dev");
}

static void diag_rootdir(void)
{
    sec("4b. mount-jail escape test (rootdir -> kernel root vnode)");
    intptr_t root = kernel_get_root_vnode();
    printf("[diag]   kernel root vnode = 0x%llx\n", (unsigned long long)root);
    intptr_t cur = kernel_get_proc_rootdir(getpid());
    printf("[diag]   our proc rootdir  = 0x%llx\n", (unsigned long long)cur);
    int rc = kernel_set_proc_rootdir(getpid(), root);
    printf("[diag]   set_proc_rootdir  rc=%d\n", rc);
    struct stat st;
    rc = stat("/mnt/nor0", &st);
    printf("[diag]   /mnt/nor0 after   %s\n", rc ? "stat FAILED" : "VISIBLE");
    if (!rc) {
        DIR *d = opendir("/mnt/nor0");
        if (d) {
            int n = 0;
            struct dirent *e;
            while ((e = readdir(d)) != NULL && n < 12) {
                printf("[diag]     %s\n", e->d_name);
                n++;
            }
            closedir(d);
        }
    }
}

static void probe_nor0(void)
{
    struct stat st;
    if (stat("/mnt/nor0", &st) == 0) {
        printf("[diag]   /mnt/nor0 VISIBLE");
        DIR *d = opendir("/mnt/nor0");
        if (d) {
            int n = 0;
            struct dirent *e;
            printf(":");
            while ((e = readdir(d)) != NULL && n < 12) {
                printf(" %s", e->d_name);
                n++;
            }
            closedir(d);
        }
        printf("\n");
    } else {
        printf("[diag]   /mnt/nor0 still not visible (%s)\n", strerror(errno));
    }
}

static void diag_prison(void)
{
    sec("4c. prison test (ucred prison -> 0 = root namespace)");
    intptr_t p = kernel_get_ucred_prison(getpid());
    printf("[diag]   our ucred prison = 0x%llx\n", (unsigned long long)p);
    int rc = kernel_set_ucred_prison(getpid(), 0);
    printf("[diag]   set_ucred_prison(0) rc=%d\n", rc);
    probe_nor0();
    kernel_set_ucred_prison(getpid(), p);   /* restore */
}

/* Solid-color test pattern on display 1 for ~10 s: if the TV turns the
 * pattern color, display 1 IS the TV output. */
static void diag_videotest(uint32_t pattern, const char *name, int frames)
{
    sec(name);
    intptr_t pa = 0;
    void *va = 0;
    DiagVideoBuf vbuf[2];
    DiagVideoAttr vattr;
    struct kevent *eq = 0;
    struct kevent evt;
    int h, rc, junk;
    const size_t memsize = 0x2000000;

    memset(vbuf, 0, sizeof(vbuf));
    memset(&vattr, 0, sizeof(vattr));

    rc = sceKernelAllocateMainDirectMemory(memsize, 0x20000, 3, &pa);
    if (rc) { printf("[diag]   alloc: %s\n", strerror(errno)); return; }
    rc = sceKernelMapDirectMemory(&va, memsize, 0x33, 0, pa, 0x20000);
    if (rc) { printf("[diag]   map: %s\n", strerror(errno)); return; }

    vbuf[0].data = va;
    vbuf[1].data = va + (memsize / 2);
    /* fill both buffers with the pattern (ABGR8888 u32 LE) */
    uint32_t *px = (uint32_t *)va;
    for (size_t i = 0; i < memsize / 2 / 4; i++)
        px[i] = pattern;

    h = sceVideoOutOpen(0xff, 1, 0, NULL);
    printf("[diag]   open(0xff,1): h=%d (%s)\n", h,
           h < 0 ? strerror(errno) : "ok");
    if (h < 0) return;

    sceVideoOutSetBufferAttribute2(&vattr, 0x8000000022000000ULL, 0,
                                   1920, 1080, 0, 0, 0);
    rc = sceVideoOutRegisterBuffers2(h, 0, 0, vbuf, 2, &vattr, 0, NULL);
    printf("[diag]   register: rc=%d (%s)\n", rc,
           rc ? strerror(errno) : "ok");
    if (rc) { sceVideoOutClose(h); return; }

    int fm = sceVideoOutSetFlipMaster(h);
    printf("[diag]   set_flip_master: rc=%d (%s)\n", fm,
           fm ? strerror(errno) : "ok");

    rc = sceKernelCreateEqueue(&eq, "diag flip");
    if (rc) { printf("[diag]   equeue: %s\n", strerror(errno)); return; }
    sceVideoOutAddFlipEvent(eq, h, 0);
    sceVideoOutSetFlipRate(h, 0);

    for (int f = 0; f < frames; f++) {
        rc = sceVideoOutSubmitFlip(h, 0, 1, f);
        if (rc) {
            printf("[diag]   flip %d: %s\n", f, strerror(errno));
            break;
        }
        sceKernelWaitEqueue(eq, &evt, 1, &junk, 0);
        /* ~30 fps */
        struct timespec ts = { 0, 33000000 };
        nanosleep(&ts, 0);
    }
    printf("[diag]   %d flips done\n", frames);

    sceVideoOutClose(h);
    sceKernelDeleteEqueue(eq);
    sceKernelReleaseDirectMemory(pa, memsize);
}

int main(void)
{
    /* pxlview-style markers: the launcher auto-detects pxlview from the
     * ELF name (pxlview-diag.elf) and stops on the done marker instead of
     * re-sending in a loop. */
    printf("[pxlview] starting v0.1.0-diag\n");
    printf("[diag] pxlview diagnostic starting\n");
    diag_authid();
    diag_videoout();
    diag_pcomm();
    diag_fs();
    diag_rootdir();
    diag_prison();
    /* WATCH THE TV: solid green for ~10 s, then white for ~5 s */
    diag_videotest(0xFF00FF00u, "5. video test: GREEN pattern on display 1 (10s) - watch the TV!", 300);
    diag_videotest(0xFFFFFFFFu, "6. video test: WHITE pattern on display 1 (5s) - watch the TV!", 150);
    printf("[diag] all done\n");
    printf("[pxlview] done\n");
    return 0;
}
