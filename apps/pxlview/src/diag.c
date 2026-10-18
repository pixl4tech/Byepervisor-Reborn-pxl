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
#include <signal.h>
#include <unistd.h>
#include "kmem.h"
#include "pt.h"

#include <sys/wait.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/uio.h>
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
int sceVideoOutClearFlipMaster(void);

/* Sys* family (VSH's display path) + Webcore status: prototypes are
 * guesses (no public header); SysV ABI makes extra args harmless. */
extern int sceVideoOutSysOpenInternal(int, int, int, int);
extern int sceVideoOutSysGetFlipStatus(int, int, int, int);
extern int sceVideoOutSysGetCurrentOutputMode(int, int, int, int);
extern int sceVideoOutGetStatusForWebcore(int, int, int, int);

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

/* Solid-color test pattern on a VideoOut session for ~frames/30 s:
 * if the monitor/TV turns the pattern color, that session drives the
 * visible output. */
static void diag_videotest(int p2, int p3, uint32_t pattern,
                           const char *name, int frames)
{
    sec(name);
    intptr_t pa0 = 0, pa1 = 0;
    void *va0 = 0, *va1 = 0;
    DiagVideoBuf vbuf[2];
    DiagVideoAttr vattr;
    struct kevent *eq = 0;
    struct kevent evt;
    int h, rc, junk;
    /* Two 16M allocations (2 buffers required): the buffers need not be
     * contiguous, and a single 32M block is not always allocatable. */
    const size_t half = 0x1000000;

    memset(vbuf, 0, sizeof(vbuf));
    memset(&vattr, 0, sizeof(vattr));

    rc = sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa0);
    if (rc) { printf("[diag]   alloc16M#1: %s\n", strerror(errno)); return; }
    rc = sceKernelMapDirectMemory(&va0, half, 0x33, 0, pa0, 0x20000);
    if (rc) { printf("[diag]   map#1: %s\n", strerror(errno)); return; }
    rc = sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa1);
    if (rc) { printf("[diag]   alloc16M#2: %s\n", strerror(errno)); return; }
    rc = sceKernelMapDirectMemory(&va1, half, 0x33, 0, pa1, 0x20000);
    if (rc) { printf("[diag]   map#2: %s\n", strerror(errno)); return; }

    vbuf[0].data = va0;
    vbuf[1].data = va1;
    /* fill both buffers with the pattern (ABGR8888 u32 LE) */
    uint32_t *px = (uint32_t *)va0;
    for (size_t i = 0; i < half / 4; i++)
        px[i] = pattern;
    px = (uint32_t *)va1;
    for (size_t i = 0; i < half / 4; i++)
        px[i] = pattern;

    h = sceVideoOutOpen(0xff, p2, p3, NULL);
    printf("[diag]   open(0xff,%d,%d): h=%d (%s)\n", p2, p3, h,
           h < 0 ? strerror(errno) : "ok");
    if (h < 0) return;

    sceVideoOutSetBufferAttribute2(&vattr, 0x8000000022000000ULL, 0,
                                   1920, 1080, 0, 0, 0);
    rc = sceVideoOutRegisterBuffers2(h, 0, 0, vbuf, 2, &vattr, 0, NULL);
    printf("[diag]   register(2 buf): rc=%d (%s)\n", rc,
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
    sceKernelReleaseDirectMemory(pa0, half);
    sceKernelReleaseDirectMemory(pa1, half);
}

/* The VSH owns the display 0 session (monitor). Try sceVideoOutOpen
 * parameter combinations to find one that opens a (second) handle to
 * the same visible output. */
static void diag_open_matrix(void)
{
    sec("2b. open matrix: sceVideoOutOpen(0xff, p2, p3) while VSH holds display");
    for (int p2 = 0; p2 <= 3; p2++) {
        for (int p3 = 0; p3 <= 3; p3++) {
            errno = 0;
            int h = sceVideoOutOpen(0xff, p2, p3, NULL);
            if (h >= 0) {
                printf("[diag]   open(0xff,%d,%d): h=%d OK!\n", p2, p3, h);
                int fm = sceVideoOutSetFlipMaster(h);
                printf("[diag]     set_flip_master: rc=%d (%s)\n", fm,
                       fm ? strerror(errno) : "ok");
                sceVideoOutClose(h);
            } else {
                printf("[diag]   open(0xff,%d,%d): %s\n", p2, p3,
                       strerror(errno));
            }
        }
    }
}

/* FLIP MASTER TAKEOVER: the physical output shows only the flip
 * master's session (VSH is the master). Clear it, become master on a
 * (0,0) session, flip green for ~10 s. If the monitor turns green,
 * that is the visible output and the takeover works. */
/* Read a kernel 64-bit word. */
static int kread64(uint64_t a, uint64_t *v)
{
    return kernel_copyout((intptr_t)a, v, sizeof(*v)) == 0;
}

static void diag_flip_master(void)
{
    sec("8. FLIP MASTER TAKEOVER on session (0,0) - watch the monitor!");
    intptr_t pa0 = 0, pa1 = 0;
    void *va0 = 0, *va1 = 0;
    DiagVideoBuf vbuf[2];
    DiagVideoAttr vattr;
    struct kevent *eq = 0;
    struct kevent evt;
    int h, rc, junk;
    const size_t half = 0x1000000;

    memset(vbuf, 0, sizeof(vbuf));
    memset(&vattr, 0, sizeof(vattr));

    h = sceVideoOutOpen(0xff, 0, 0, NULL);
    printf("[diag]   open(0xff,0,0): h=%d (%s)\n", h,
           h < 0 ? strerror(errno) : "ok");
    if (h < 0) return;

    rc = sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa0);
    if (rc) { printf("[diag]   alloc#1: %s\n", strerror(errno)); return; }
    rc = sceKernelMapDirectMemory(&va0, half, 0x33, 0, pa0, 0x20000);
    if (rc) { printf("[diag]   map#1: %s\n", strerror(errno)); return; }
    rc = sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa1);
    if (rc) { printf("[diag]   alloc#2: %s\n", strerror(errno)); return; }
    rc = sceKernelMapDirectMemory(&va1, half, 0x33, 0, pa1, 0x20000);
    if (rc) { printf("[diag]   map#2: %s\n", strerror(errno)); return; }

    vbuf[0].data = va0;
    vbuf[1].data = va1;
    uint32_t green = 0xFF00FF00u;
    uint32_t *px = (uint32_t *)va0;
    for (size_t i = 0; i < half / 4; i++)
        px[i] = green;
    px = (uint32_t *)va1;
    for (size_t i = 0; i < half / 4; i++)
        px[i] = green;

    sceVideoOutSetBufferAttribute2(&vattr, 0x8000000022000000ULL, 0,
                                   1920, 1080, 0, 0, 0);
    rc = sceVideoOutRegisterBuffers2(h, 0, 0, vbuf, 2, &vattr, 0, NULL);
    printf("[diag]   register: rc=%d (%s)\n", rc,
           rc ? strerror(errno) : "ok");
    if (rc) return;

    rc = sceVideoOutClearFlipMaster();
    printf("[diag]   clear_flip_master: rc=%d (%s)\n", rc,
           rc ? strerror(errno) : "ok");
    rc = sceVideoOutSetFlipMaster(h);
    printf("[diag]   set_flip_master(handle): rc=%d (%s)\n", rc,
           rc ? strerror(errno) : "ok");
    /* New hypothesis: the argument is a PID (ESRCH = "no such
     * process"). Set the master to our own process's session. */
    rc = sceVideoOutSetFlipMaster(getpid());
    printf("[diag]   set_flip_master(pid=%d): rc=%d (%s)\n", (int)getpid(),
           rc, rc ? strerror(errno) : "ok");
    printf("[diag]   handle=0x%x (not dereferenced: not mapped here)\n", h);

    /* New idea: the argument may be the session's file descriptor.
     * Find our fd via kernel_get_proc_file and retry. */
    {
        uint64_t file = 0, fdata = 0;
        int fd = -1;
        for (int i = 0; i < 128; i++) {
            intptr_t f = kernel_get_proc_file(getpid(), i);
            if (f == 0)
                continue;
            uint64_t fop = 0, fdt = 0;
            if (!kread64((uint64_t)f + 0x0, &fop) ||
                !kread64((uint64_t)f + 0x30, &fdt))
                continue;
            if (fop < 0xffffffff98000000ULL || fop >= 0xffffffff9b000000ULL)
                continue;
            if (fdt < 0xffffb60000000000ULL || fdt >= 0xffffb70000000000ULL)
                continue;
            file = (uint64_t)f;
            fdata = fdt;
            fd = i;
        }
        printf("[diag]   our vout fd=%d file=0x%llx fdata=0x%llx\n", fd,
               (unsigned long long)file, (unsigned long long)fdata);
        if (fd >= 0) {
            int r = sceVideoOutSetFlipMaster(fd);
            printf("[diag]   set_flip_master(fd=%d): rc=%d (%s)\n", fd, r,
                   r ? strerror(errno) : "ok");
        }
    }

    rc = sceKernelCreateEqueue(&eq, "diag flip");
    if (rc) { printf("[diag]   equeue: %s\n", strerror(errno)); return; }
    sceVideoOutAddFlipEvent(eq, h, 0);
    sceVideoOutSetFlipRate(h, 0);

    for (int f = 0; f < 300; f++) {
        rc = sceVideoOutSubmitFlip(h, 0, 1, f);
        if (rc) {
            printf("[diag]   flip %d: %s\n", f, strerror(errno));
            break;
        }
        sceKernelWaitEqueue(eq, &evt, 1, &junk, 0);
        struct timespec ts = { 0, 33000000 };
        nanosleep(&ts, 0);
    }
    printf("[diag]   flips done\n");

    sceVideoOutClose(h);
    sceKernelDeleteEqueue(eq);
    sceKernelReleaseDirectMemory(pa0, half);
    sceKernelReleaseDirectMemory(pa1, half);
}

/* Probe the Sys* (system) VideoOut API family: VSH likely drives the
 * monitor through these, not the plain sceVideoOutOpen sessions. */
static void diag_sysapi(void)
{
    sec("9. Sys* API probe (VSH display path)");
    extern int sceVideoOutSysGetBus(void);

    int bus = sceVideoOutSysGetBus();
    printf("[diag]   SysGetBus: r=%d (0x%x)\n", bus, bus);

    for (int id = 0; id <= 2; id++) {
        int h = sceVideoOutSysOpenInternal(id, 0, 0, 0);
        printf("[diag]   SysOpenInternal(%d,0,0,0): h=%d (%s)\n", id, h,
               h < 0 ? "err" : "OK");
        if (h >= 0) {
            int fs = sceVideoOutSysGetFlipStatus(h, 0, 0, 0);
            printf("[diag]     SysGetFlipStatus: r=%d\n", fs);
            int om = sceVideoOutSysGetCurrentOutputMode(h, 0, 0, 0);
            printf("[diag]     SysGetCurrentOutputMode: r=%d\n", om);
            extern void sceVideoOutSysClose(int);
            sceVideoOutSysClose(h);
        }
    }

    int st = sceVideoOutGetStatusForWebcore(0, 0, 0, 0);
    printf("[diag]   GetStatusForWebcore(0,0,0,0): r=%d (0x%x)\n", st, st);
}

/* Full process list: identify VSH and any other display owners. */
static void diag_proc_list(void)
{
    sec("10. process list");
    for (int pid = 0; pid < 256; pid++) {
        intptr_t proc = kernel_get_proc((pid_t)pid);
        if (proc == 0)
            continue;
        char raw[16];
        if (kernel_copyout((uint64_t)(proc + 0x5dc), raw, sizeof(raw)) != 0)
            continue;
        raw[15] = 0;
        int ok = 1;
        for (int i = 0; raw[i]; i++)
            if (raw[i] < 0x20 || raw[i] > 0x7e)
                ok = 0;
        if (!ok)
            continue;
        printf("[diag]   pid=%d %s\n", pid, raw);
    }
}

/* Dump a driver session struct (f_data) as 16 lines of 8 words. */
static void dump_sess(const char *tag, uint64_t fdata)
{
    if (fdata < 0xffff000000000000ULL)
        return;
    uint8_t buf[256];
    if (kernel_copyout((intptr_t)fdata, buf, sizeof(buf)) != 0)
        return;
    printf("[diag]   %s fdata=0x%llx:\n", tag, (unsigned long long)fdata);
    for (int i = 0; i < 32; i++) {
        uint64_t w;
        memcpy(&w, buf + i * 8, 8);
        printf("[diag]     +0x%02x: 0x%016llx\n", i * 8,
               (unsigned long long)w);
    }
}

/* Find the fd of a freshly opened VideoOut session in our process:
 * scan fds via kernel_get_proc_file, match the videoout fileops with
 * a unique (non-shared) f_data. */
static int find_our_vout_fd(uint64_t *out_file, uint64_t *out_fdata)
{
    for (int fd = 0; fd < 128; fd++) {
        intptr_t file = kernel_get_proc_file(getpid(), fd);
        if (file == 0)
            continue;
        uint64_t fop = 0, fdata = 0;
        if (!kread64((uint64_t)file + 0x0, &fop) ||
            !kread64((uint64_t)file + 0x30, &fdata))
            continue;
        /* per-instance session: text fileops + heap f_data */
        if (fop < 0xffffffff98000000ULL || fop >= 0xffffffff9b000000ULL)
            continue;
        if (fdata < 0xffffb60000000000ULL || fdata >= 0xffffb70000000000ULL)
            continue;
        *out_file = (uint64_t)file;
        *out_fdata = fdata;
        return 0;
    }
    return -1;
}

/* Return the first vout session fdata NOT in the before[] list.
 * Used to identify the session of a just-opened handle. */
static int find_new_vout_fd(const uint64_t *before, int nbefore,
                            uint64_t *out_file, uint64_t *out_fdata)
{
    for (int fd = 0; fd < 128; fd++) {
        intptr_t file = kernel_get_proc_file(getpid(), fd);
        if (file == 0)
            continue;
        uint64_t fop = 0, fdata = 0;
        if (!kread64((uint64_t)file + 0x0, &fop) ||
            !kread64((uint64_t)file + 0x30, &fdata))
            continue;
        if (fop < 0xffffffff98000000ULL || fop >= 0xffffffff9b000000ULL)
            continue;
        if (fdata < 0xffffb60000000000ULL || fdata >= 0xffffb70000000000ULL)
            continue;
        int known = 0;
        for (int b = 0; b < nbefore; b++)
            if (before[b] == fdata)
                known = 1;
        if (known)
            continue;
        *out_file = (uint64_t)file;
        *out_fdata = fdata;
        return 0;
    }
    return -1;
}

/* Snapshot all our current vout session fdata values. */
static int snapshot_vout_fds(uint64_t *vals, int maxv)
{
    int n = 0;
    for (int fd = 0; fd < 128 && n < maxv; fd++) {
        intptr_t file = kernel_get_proc_file(getpid(), fd);
        if (file == 0)
            continue;
        uint64_t fop = 0, fdata = 0;
        if (!kread64((uint64_t)file + 0x0, &fop) ||
            !kread64((uint64_t)file + 0x30, &fdata))
            continue;
        if (fop < 0xffffffff98000000ULL || fop >= 0xffffffff9b000000ULL)
            continue;
        if (fdata < 0xffffb60000000000ULL || fdata >= 0xffffb70000000000ULL)
            continue;
        vals[n++] = fdata;
    }
    return n;
}

/* Close all our vout session fds (the driver caches sessions; a fresh
 * open may hand back an old fdata). */
static int close_all_vout_fds(void)
{
    int n = 0;
    for (int fd = 0; fd < 128; fd++) {
        intptr_t file = kernel_get_proc_file(getpid(), fd);
        if (file == 0)
            continue;
        uint64_t fop = 0, fdata = 0;
        if (!kread64((uint64_t)file + 0x0, &fop) ||
            !kread64((uint64_t)file + 0x30, &fdata))
            continue;
        if (fop < 0xffffffff98000000ULL || fop >= 0xffffffff9b000000ULL)
            continue;
        if (fdata < 0xffffb60000000000ULL || fdata >= 0xffffb70000000000ULL)
            continue;
        if (close(fd) == 0)
            n++;
    }
    return n;
}


/* Kernel spelunking: find the VideoOut sessions in our process and in
 * the VSH video processes, dump full structs. Read-only. */
static uint64_t g_vsh_sessions[16];
static int g_nvsh_sessions = 0;

static uint64_t diag_vsh_videoout(void)
{
    static const int vsh_pids[] = { 78, 59, 94 };

    sec("11. VideoOut session hunt v2 (kernel_get_proc_file)");
    int nhits = 0;
    struct { int pid; uint64_t fdata; } vout_hits[64];

    /* Open our session, find its file+fd. */
    int h = sceVideoOutOpen(0xff, 0, 0, NULL);
    printf("[diag]   our session: h=0x%x (%s)\n", h,
           h < 0 ? strerror(errno) : "ok");

    uint64_t our_file = 0, our_fdata = 0;
    /* Debug: dump every file the kernel reports for our pid. */
    for (int fd = 0; fd < 128; fd++) {
        intptr_t file = kernel_get_proc_file(getpid(), fd);
        if (file == 0)
            continue;
        uint64_t fop = 0, fdata = 0;
        kread64((uint64_t)file + 0x0, &fop);
        kread64((uint64_t)file + 0x30, &fdata);
        printf("[diag]   our fd%d file=0x%llx fop=0x%llx fdata=0x%llx\n",
               fd, (unsigned long long)file, (unsigned long long)fop,
               (unsigned long long)fdata);
    }
    if (find_our_vout_fd(&our_file, &our_fdata) == 0) {
        printf("[diag]   OUR session file=0x%llx fdata=0x%llx\n",
               (unsigned long long)our_file,
               (unsigned long long)our_fdata);
        dump_sess("ours", our_fdata);
        uint64_t true_start = our_fdata - 0x28;
        dump_sess("ours-0x28", true_start);
    } else {
        printf("[diag]   our vout fd not found\n");
    }

    for (size_t pi = 0; pi < sizeof(vsh_pids) / sizeof(int); pi++) {
        int pid = vsh_pids[pi];
        for (int fd = 0; fd < 128; fd++) {
            intptr_t file = kernel_get_proc_file((pid_t)pid, fd);
            if (file == 0)
                continue;
            uint64_t fop = 0, fdata = 0;
            if (!kread64((uint64_t)file + 0x0, &fop) ||
                !kread64((uint64_t)file + 0x30, &fdata))
                continue;
            if (fop < 0xffffffff98000000ULL || fop >= 0xffffffff9b000000ULL)
                continue;
            if (fdata < 0xffffb60000000000ULL || fdata >= 0xffffb70000000000ULL)
                continue;
            vout_hits[nhits].pid = pid;
            vout_hits[nhits].fdata = fdata;
            nhits++;
        }
    }

    /* Dump each unique session (cap 8) and hunt for direct-memory
     * physical addresses in the nested structs. */
    int dumped = 0;
    for (int i = 0; i < nhits && dumped < 8; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++)
            if (vout_hits[i].fdata == vout_hits[j].fdata)
                dup = 1;
        if (dup)
            continue;
        dumped++;
        printf("[diag]   VSH session pid=%d fdata=0x%llx\n",
               vout_hits[i].pid,
               (unsigned long long)vout_hits[i].fdata);
        dump_sess("vsh", vout_hits[i].fdata);
        /* The shared entry[2] object (common to all 5 entries) is the
         * output pipe. Dump it and look for a back-pointer to this
         * session (the field to steal). */
        uint8_t sbuf0[256];
        if (kernel_copyout((intptr_t)vout_hits[i].fdata, sbuf0,
                           sizeof(sbuf0)) == 0) {
            uint64_t eptr = 0, shared = 0;
            memcpy(&eptr, sbuf0 + 0x40, 8); /* entry0 object */
            if (eptr >= 0xffffb60000000000ULL &&
                eptr < 0xffffb70000000000ULL &&
                kread64(eptr + 0x10, &shared) &&
                shared >= 0xffffb60000000000ULL &&
                shared < 0xffffb70000000000ULL) {
                uint8_t ob[256];
                printf("[diag]     pipe obj @0x%llx:\n",
                       (unsigned long long)shared);
                if (kernel_copyout((intptr_t)shared, ob, sizeof(ob)) == 0) {
                    for (int x = 0; x < 32; x++) {
                        uint64_t q;
                        memcpy(&q, ob + x * 8, 8);
                        printf("[diag]       +0x%02x: 0x%016llx%s\n",
                               x * 8, (unsigned long long)q,
                               q == vout_hits[i].fdata ? "  <== SESSION"
                                                       : "");
                    }
                }
            }
        }
        /* Dump the 5 entry structs (0x30-byte slots at +0x40..+0xf0):
         * the first pointer of each slot is the entry object. */
        uint8_t sbuf[256];
        if (kernel_copyout((intptr_t)vout_hits[i].fdata, sbuf,
                           sizeof(sbuf)) == 0) {
            for (int e = 0; e < 5; e++) {
                uint64_t ep;
                memcpy(&ep, sbuf + (0x40 + e * 0x30), 8);
                if (ep < 0xffffb60000000000ULL ||
                    ep >= 0xffffb70000000000ULL)
                    continue;
                uint8_t eb[128];
                if (kernel_copyout((intptr_t)ep, eb, sizeof(eb)) != 0)
                    continue;
                printf("[diag]     entry%d @0x%llx:", e,
                       (unsigned long long)ep);
                for (int x = 0; x < 16; x++) {
                    uint64_t q;
                    memcpy(&q, eb + x * 8, 8);
                    printf(" %016llx", (unsigned long long)q);
                }
                printf("\n");
                /* One level deeper: chase the first 4 pointers, look
                 * for direct-memory PAs (0x100000000..0x300000000) or
                 * canonical user VAs (0x20000000..0x80000000). */
                for (int x = 0; x < 4; x++) {
                    uint64_t q;
                    memcpy(&q, eb + x * 8, 8);
                    if (q < 0xffffb60000000000ULL ||
                        q >= 0xffffb70000000000ULL)
                        continue;
                    uint8_t db[256];
                    if (kernel_copyout((intptr_t)q, db, sizeof(db)) != 0)
                        continue;
                    for (int y = 0; y < 32; y++) {
                        uint64_t r;
                        memcpy(&r, db + y * 8, 8);
                        if ((r >= 0x100000000ULL && r < 0x300000000ULL) ||
                            (r >= 0x20000000ULL && r < 0x80000000ULL)) {
                            printf("[diag]       entry%d[%d]+0x%02x: "
                                   "PA/VA 0x%llx\n", e, x, y * 8,
                                   (unsigned long long)r);
                        }
                    }
                }
            }
        }
        uint8_t buf[256];
        if (kernel_copyout((intptr_t)vout_hits[i].fdata, buf,
                           sizeof(buf)) != 0)
            continue;
        for (int w = 0; w < 32; w++) {
            uint64_t p;
            memcpy(&p, buf + w * 8, 8);
            if (p < 0xffffb60000000000ULL ||
                p >= 0xffffb70000000000ULL)
                continue;
            uint8_t nb[128];
            if (kernel_copyout((intptr_t)p, nb, sizeof(nb)) != 0)
                continue;
            for (int x = 0; x < 16; x++) {
                uint64_t q;
                memcpy(&q, nb + x * 8, 8);
                if (q >= 0x100000000ULL && q < 0x400000000ULL) {
                    printf("[diag]     PHYS cand: sess+0x%02x -> "
                           "+0x%02x = 0x%llx\n", w * 8, x * 8,
                           (unsigned long long)q);
                }
            }
        }
    }

    if (h > 0)
        sceVideoOutClose(h);
    /* Collect unique sessions for the link hunt. */
    g_nvsh_sessions = 0;
    for (int i = 0; i < nhits && g_nvsh_sessions < 16; i++) {
        int dup = 0;
        for (int j = 0; j < g_nvsh_sessions; j++)
            if (vout_hits[i].fdata == g_vsh_sessions[j])
                dup = 1;
        if (!dup)
            g_vsh_sessions[g_nvsh_sessions++] = vout_hits[i].fdata;
    }
    return nhits ? (uint64_t)vout_hits[0].fdata : 0;
}

/* Find the VideoOut kernel module and dump the SetFlipMaster
 * function bytes for offline disassembly. */
static void diag_dynlib(void)
{
    sec("12. kernel dynlib probe (VideoOut driver)");
    const char *names[] = {
        "libSceVideoOut.sprx", "libSceVideoOut", "libSceVideoOut.so",
        "SceVideoOut.sprx", NULL,
    };
    for (int i = 0; names[i]; i++) {
        uint32_t h = 0;
        int rc = kernel_dynlib_handle(getpid(), names[i], &h);
        printf("[diag]   dynlib %-16s rc=%d h=0x%x\n", names[i], rc, h);
        if (rc)
            continue;
        intptr_t mapbase = kernel_dynlib_mapbase_addr(getpid(), h);
        intptr_t entry = kernel_dynlib_entry_addr(getpid(), h);
        printf("[diag]     mapbase=0x%llx entry=0x%llx\n",
               (unsigned long long)mapbase,
               (unsigned long long)entry);
        const char *syms[] = {
            "sceVideoOutSetFlipMaster", "sceVideoOutClearFlipMaster",
            "sceVideoOutOpen", "sceVideoOutSubmitFlip", NULL,
        };
        for (int j = 0; syms[j]; j++) {
            intptr_t f = kernel_dynlib_dlsym(getpid(), h, syms[j]);
            printf("[diag]     dlsym %-28s = 0x%llx\n", syms[j],
                   (unsigned long long)f);
            if (f == 0)
                continue;
            uint8_t code[128];
            int rc = kernel_copyout(f, code, sizeof(code));
            if (rc != 0) {
                /* copyout may not reach sprx VAs; try byte reads. */
                for (int b = 0; b < 128; b++)
                    code[b] = kernel_getchar(f + b);
                rc = 0;
            }
            if (rc == 0) {
                printf("[diag]     code %s:", syms[j]);
                for (int b = 0; b < 128; b++)
                    printf(" %02x", code[b]);
                printf("\n");
            }
        }
    }
}

/* EXPERIMENT: our session's entry objects look "unassigned" while
 * VSH's entry0 carries type 0x1_00040001 (main output). Write that
 * type into our entry0, flip green 10 s, restore. Watch the monitor. */
static void diag_entry_takeover(void)
{
    sec("13. ENTRY TYPE TAKEOVER experiment - watch the monitor!");
    intptr_t pa0 = 0, pa1 = 0;
    void *va0 = 0, *va1 = 0;
    DiagVideoBuf vbuf[2];
    DiagVideoAttr vattr;
    struct kevent *eq = 0;
    struct kevent evt;
    int h, rc, junk;
    const size_t half = 0x1000000;
    int nclosed = close_all_vout_fds();
    uint64_t vout_before[16];
    int nvout = snapshot_vout_fds(vout_before, 16);
    printf("[diag]   closed %d stale vout fds; %d remain\n", nclosed, nvout);

    h = sceVideoOutOpen(0xff, 0, 0, NULL);
    printf("[diag]   open(0,0): h=0x%x (%s)\n", h, h < 0 ? strerror(errno) : "ok");
    if (h < 0) return;

    memset(vbuf, 0, sizeof(vbuf));
    memset(&vattr, 0, sizeof(vattr));
    rc = sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa0);
    if (rc) { printf("[diag]   alloc#1: %s\n", strerror(errno)); return; }
    rc = sceKernelMapDirectMemory(&va0, half, 0x33, 0, pa0, 0x20000);
    if (rc) return;
    rc = sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa1);
    if (rc) { printf("[diag]   alloc#2: %s\n", strerror(errno)); return; }
    rc = sceKernelMapDirectMemory(&va1, half, 0x33, 0, pa1, 0x20000);
    if (rc) return;
    vbuf[0].data = va0;
    vbuf[1].data = va1;
    uint32_t *px = (uint32_t *)va0;
    for (size_t i = 0; i < half / 4; i++)
        px[i] = 0xFF00FF00u;
    px = (uint32_t *)va1;
    for (size_t i = 0; i < half / 4; i++)
        px[i] = 0xFF00FF00u;

    sceVideoOutSetBufferAttribute2(&vattr, 0x8000000022000000ULL, 0,
                                   1920, 1080, 0, 0, 0);
    rc = sceVideoOutRegisterBuffers2(h, 0, 0, vbuf, 2, &vattr, 0, NULL);
    printf("[diag]   register: rc=%d (%s)\n", rc, rc ? strerror(errno) : "ok");
    if (rc) return;

    /* Find our session + entry0 (the NEW fd, not a stale one). */
    uint64_t file = 0, fdata = 0;
    for (int fd = 0; fd < 128; fd++) {
        intptr_t f = kernel_get_proc_file(getpid(), fd);
        if (f == 0)
            continue;
        uint64_t fop = 0, fd2 = 0;
        kread64((uint64_t)f + 0x0, &fop);
        kread64((uint64_t)f + 0x30, &fd2);
        printf("[diag]   post-open fd%d file=0x%llx fop=0x%llx fdata=0x%llx\n",
               fd, (unsigned long long)f, (unsigned long long)fop,
               (unsigned long long)fd2);
    }
    if (find_new_vout_fd(vout_before, nvout, &file, &fdata) != 0) {
        printf("[diag]   our session not found\n");
        return;
    }
    printf("[diag]   our session fdata=0x%llx\n", (unsigned long long)fdata);
    uint64_t eptr = 0;
    if (!kread64(fdata + 0x40, &eptr))
        return;
    printf("[diag]   our entry0=0x%llx\n", (unsigned long long)eptr);
    uint8_t eb[128];
    if (kernel_copyout((intptr_t)eptr, eb, sizeof(eb)) != 0)
        return;
    printf("[diag]   entry0 before:");
    for (int x = 0; x < 16; x++) {
        uint64_t q;
        memcpy(&q, eb + x * 8, 8);
        printf(" %016llx", (unsigned long long)q);
    }
    printf("\n");

    uint64_t old = 0;
    kread64(eptr + 0x20, &old);
    printf("[diag]   entry0+0x20 old=0x%llx; writing VSH type 0x1_00040001\n",
           (unsigned long long)old);
    fflush(stdout);

    rc = sceKernelCreateEqueue(&eq, "diag flip");
    if (rc) { printf("[diag]   equeue: %s\n", strerror(errno)); return; }
    sceVideoOutAddFlipEvent(eq, h, 0);
    sceVideoOutSetFlipRate(h, 0);

    int wr = kernel_setlong((intptr_t)(eptr + 0x20), 0x0000000100040001ULL);
    printf("[diag]   write rc=%d; flipping 10 s - WATCH THE MONITOR\n", wr);
    fflush(stdout);

    for (int f = 0; f < 300; f++) {
        rc = sceVideoOutSubmitFlip(h, 0, 1, f);
        if (rc) {
            printf("[diag]   flip %d: %s\n", f, strerror(errno));
            break;
        }
        sceKernelWaitEqueue(eq, &evt, 1, &junk, 0);
        struct timespec ts = { 0, 33000000 };
        nanosleep(&ts, 0);
    }
    printf("[diag]   flips done; restoring entry0+0x20\n");
    fflush(stdout);
    kernel_setlong((intptr_t)(eptr + 0x20), old);

    sceVideoOutClose(h);
    sceKernelDeleteEqueue(eq);
    sceKernelReleaseDirectMemory(pa0, half);
    sceKernelReleaseDirectMemory(pa1, half);
}

/* Scan the videoout driver's memory for a pointer to the VSH session.
 * The kernel driver keeps global state (active session) in the sprx
 * data segment. Find it, then we can swap it for our session. */
static void diag_sprx_hunt(uint64_t vsh_session)
{
    sec("14. SPRX data hunt (VSH session pointer)");
    if (!vsh_session) return;
    /* libSceVideoOut.sprx mapbase from the dynlib probe; scan 2 MB. */
    uint64_t base = 0x838e94000ULL;
    int found = 0;
    for (uint64_t off = 0; off < 0x200000 && found < 8; off += 8) {
        uint64_t v = 0;
        if (kernel_copyout((intptr_t)(base + off), &v, 8) != 0)
            continue;
        if (v == vsh_session) {
            printf("[diag]   VSH session ptr at sprx+0x%llx (0x%llx)\n",
                   (unsigned long long)off,
                   (unsigned long long)(base + off));
            found++;
        }
    }
    if (!found)
        printf("[diag]   no VSH session pointer in sprx+0..0x200000\n");
}

/* Dump a wide range around the VSH session and mark any word that
 * matches a known session fdata (reveals the driver's session list
 * links: next/prev offsets). */
static void diag_sess_links(uint64_t main_sess, const uint64_t *others,
                            int nothers)
{
    sec("15. session list-link hunt");
    if (!main_sess) return;
    uint8_t w[0x400];
    if (kernel_copyout((intptr_t)(main_sess - 0x200), w, sizeof(w)) != 0) {
        printf("[diag]   wide dump failed\n");
        return;
    }
    for (int off = -0x200; off < 0x200; off += 8) {
        uint64_t v;
        memcpy(&v, w + (size_t)(off + 0x200), 8);
        for (int o = 0; o < nothers; o++) {
            if (v == others[o]) {
                printf("[diag]   main_sess+0x%x (0x%llx) == other session "
                       "0x%llx  <== LIST LINK\n",
                       off, (unsigned long long)(main_sess + off),
                       (unsigned long long)v);
            }
        }
    }
}

/* LIST HIJACK: insert our session right after the VSH main session
 * in the driver's session list (+0x8 = next). Flip 10 s, restore. */
static void diag_list_hijack(uint64_t main_sess)
{
    sec("16. SESSION LIST HIJACK - watch the monitor!");
    if (!main_sess) return;

    int nclosed = close_all_vout_fds();
    uint64_t vout_before[16];
    int nvout = snapshot_vout_fds(vout_before, 16);
    printf("[diag]   closed %d stale vout fds; %d remain\n", nclosed, nvout);

    int h = sceVideoOutOpen(0xff, 0, 0, NULL);
    printf("[diag]   open: h=0x%x (%s)\n", h, h < 0 ? strerror(errno) : "ok");
    if (h < 0) return;

    uint64_t our_file = 0, our = 0;
    if (find_new_vout_fd(vout_before, nvout, &our_file, &our) != 0) {
        printf("[diag]   our session not found\n");
        sceVideoOutClose(h);
        return;
    }
    printf("[diag]   our sess=0x%llx main sess=0x%llx\n",
           (unsigned long long)our, (unsigned long long)main_sess);

    /* Green 2x16M buffers. */
    intptr_t pa0 = 0, pa1 = 0;
    void *va0 = 0, *va1 = 0;
    DiagVideoBuf vbuf[2];
    DiagVideoAttr vattr;
    struct kevent *eq = 0;
    struct kevent evt;
    int rc, junk;
    const size_t half = 0x1000000;
    if (sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa0) ||
        sceKernelMapDirectMemory(&va0, half, 0x33, 0, pa0, 0x20000) ||
        sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa1) ||
        sceKernelMapDirectMemory(&va1, half, 0x33, 0, pa1, 0x20000)) {
        printf("[diag]   alloc/map failed\n");
        sceVideoOutClose(h);
        return;
    }
    vbuf[0].data = va0;
    vbuf[1].data = va1;
    uint32_t *px = (uint32_t *)va0;
    for (size_t i = 0; i < half / 4; i++) px[i] = 0xFF00FF00u;
    px = (uint32_t *)va1;
    for (size_t i = 0; i < half / 4; i++) px[i] = 0xFF00FF00u;
    sceVideoOutSetBufferAttribute2(&vattr, 0x8000000022000000ULL, 0,
                                   1920, 1080, 0, 0, 0);
    rc = sceVideoOutRegisterBuffers2(h, 0, 0, vbuf, 2, &vattr, 0, NULL);
    printf("[diag]   register: rc=%d (%s)\n", rc, rc ? strerror(errno) : "ok");
    if (rc) {
        sceVideoOutClose(h);
        sceKernelReleaseDirectMemory(pa0, half);
        sceKernelReleaseDirectMemory(pa1, half);
        return;
    }

    uint64_t main_next = 0, our_next = 0;
    if (!kread64(main_sess + 0x8, &main_next) ||
        !kread64(our + 0x8, &our_next)) {
        printf("[diag]   read next-links failed\n");
        return;
    }
    printf("[diag]   main.next=0x%llx our.next=0x%llx\n",
           (unsigned long long)main_next, (unsigned long long)our_next);

    int w1 = kernel_setlong((intptr_t)(our + 0x8), main_next);
    int w2 = kernel_setlong((intptr_t)(main_sess + 0x8), our);
    printf("[diag]   spliced: w1=%d w2=%d; flipping 10 s\n", w1, w2);
    fflush(stdout);

    rc = sceKernelCreateEqueue(&eq, "hijack");
    if (!rc) {
        sceVideoOutAddFlipEvent(eq, h, 0);
        sceVideoOutSetFlipRate(h, 0);
        for (int f = 0; f < 300; f++) {
            rc = sceVideoOutSubmitFlip(h, 0, 1, f);
            if (rc) break;
            sceKernelWaitEqueue(eq, &evt, 1, &junk, 0);
            struct timespec ts = { 0, 33000000 };
            nanosleep(&ts, 0);
        }
        printf("[diag]   flips done\n");
        fflush(stdout);
    }

    kernel_setlong((intptr_t)(main_sess + 0x8), main_next);
    kernel_setlong((intptr_t)(our + 0x8), our_next);
    printf("[diag]   list restored\n");

    sceVideoOutClose(h);
    sceKernelDeleteEqueue(eq);
    sceKernelReleaseDirectMemory(pa0, half);
    sceKernelReleaseDirectMemory(pa1, half);
}

/* The visible display is the DEAD pid-78 session's last frame.
 * Dump its full struct tree (3 levels) to find the scanout buffer,
 * then write a green pattern straight into it. */
static void diag_dead_session(void)
{
    sec("17. DEAD SESSION buffer hunt (pid 78)");
    const uint64_t dead = 0xffffb60202bd23e0ULL; /* last seen fdata */

    uint8_t hdr[64];
    if (kernel_copyout((intptr_t)dead, hdr, sizeof(hdr)) != 0) {
        printf("[diag]   dead session fdata unreadable (freed?)\n");
        return;
    }
    printf("[diag]   dead session alive: ");
    for (int x = 0; x < 8; x++) {
        uint64_t q;
        memcpy(&q, hdr + x * 8, 8);
        printf("%016llx ", (unsigned long long)q);
    }
    printf("\n");

    /* Walk the tree: session -> entries -> entry objects -> sub-objs.
     * Print every pointer-ish word so we can spot the buffer. */
    uint64_t seen[128];
    int nseen = 0;
    seen[nseen++] = dead;
    for (int level = 0; level < 3 && nseen < 128; level++) {
        int start = (level == 0) ? 1 : nseen - 1;
        for (int s = start; s < nseen; s++) {
            uint8_t b[256];
            if (kernel_copyout((intptr_t)seen[s], b, sizeof(b)) != 0)
                continue;
            for (int x = 0; x < 32; x++) {
                uint64_t q;
                memcpy(&q, b + x * 8, 8);
                if (q < 0xffffb60000000000ULL ||
                    q >= 0xffffb70000000000ULL)
                    continue;
                int dup = 0;
                for (int j = 0; j < nseen; j++)
                    if (seen[j] == q) dup = 1;
                if (dup) continue;
                if (nseen < 128) {
                    seen[nseen++] = q;
                    printf("[diag]   L%d: 0x%llx at 0x%llx+0x%02x\n",
                           level, (unsigned long long)q,
                           (unsigned long long)seen[s], x * 8);
                }
            }
        }
    }
    /* Focused dump: entry0[0] object - the buffer descriptor. */
    uint64_t e00 = 0;
    uint8_t s1[0x100];
    if (kernel_copyout((intptr_t)dead, s1, sizeof(s1)) == 0) {
        memcpy(&e00, s1 + 0x40, 8); /* entry0 */
        uint8_t e1[0x100];
        if (kernel_copyout((intptr_t)e00, e1, sizeof(e1)) == 0) {
            memcpy(&e00, e1, 8); /* entry0[0] */
        }
    }
    /* PA scan: direct-memory physical addresses in 0x200000000..0x300000000
     * across every object in the tree. */
    int npa = 0;
    for (int s = 0; s < nseen && npa < 16; s++) {
        uint8_t b[256];
        if (kernel_copyout((intptr_t)seen[s], b, sizeof(b)) != 0)
            continue;
        for (int x = 0; x < 32 && npa < 16; x++) {
            uint64_t q;
            memcpy(&q, b + x * 8, 8);
            if (q >= 0x200000000ULL && q < 0x300000000ULL) {
                printf("[diag]   PA 0x%llx at 0x%llx+0x%02x\n",
                       (unsigned long long)q,
                       (unsigned long long)seen[s], x * 8);
                npa++;
            }
        }
    }
    if (!npa)
        printf("[diag]   no PAs in 0x2_0000_0000..0x3_0000_0000 in tree\n");

    /* Last candidate: e00+0xa8 object (e00 computed above). */
    {
        uint64_t e0a8 = 0;
        if (kread64(e00 + 0xa8, &e0a8) &&
            e0a8 >= 0xffffb60000000000ULL &&
            e0a8 < 0xffffb70000000000ULL) {
            uint8_t lb[256];
            printf("[diag]   e00=0x%llx e00+0xa8=0x%llx:\n",
                   (unsigned long long)e00, (unsigned long long)e0a8);
            if (kernel_copyout((intptr_t)e0a8, lb, sizeof(lb)) == 0) {
                for (int x = 0; x < 32; x++) {
                    uint64_t q;
                    memcpy(&q, lb + x * 8, 8);
                    printf("[diag]   la+0x%02x: 0x%016llx\n", x * 8,
                           (unsigned long long)q);
                }
            }
        }
    }
}

/* LAUNCH PROBE: verify preconditions for the FAKE-app launch path
 * (E3b): /system_ex, NPXS40106 eboot, user id, running app id. */
static void diag_launch_probe(void)
{
    sec("18. LAUNCH PROBE (FAKE app preconditions)");
    struct stat st;
    const char *paths[] = {
        "/system_ex",
        "/system_ex/app",
        "/system_ex/app/NPXS40106",
        "/system_ex/app/NPXS40106/eboot.bin",
        "/system/vsh/app/NPXS40112/eboot.bin",
        "/system_ex/app/FAKE00000",
        NULL,
    };
    for (int i = 0; paths[i]; i++) {
        if (stat(paths[i], &st) == 0)
            printf("[diag]   %s: OK size=%lld\n", paths[i],
                   (long long)st.st_size);
        else
            printf("[diag]   %s: %s\n", paths[i], strerror(errno));
    }

    /* user + app ids */
    extern int sceUserServiceInitialize(void *);
    extern int sceUserServiceGetForegroundUser(uint32_t *);
    extern int sceSystemServiceGetAppIdOfRunningBigApp(void);
    sceUserServiceInitialize(0);
    uint32_t uid = 0;
    int ur = sceUserServiceGetForegroundUser(&uid);
    printf("[diag]   foreground user: rc=%d uid=0x%x\n", ur, uid);
    int app_id = sceSystemServiceGetAppIdOfRunningBigApp();
    printf("[diag]   running bigapp id: 0x%x\n", app_id);

    /* remount /system_ex rw test */
    struct iovec iov[] = {
        { (void *)"from", 4 }, { (void *)"/dev/ssd0.system_ex", 19 },
        { (void *)"fspath", 6 }, { (void *)"/system_ex", 10 },
        { (void *)"fstype", 6 }, { (void *)"exfatfs", 7 },
        { (void *)"large", 5 }, { (void *)"yes", 3 },
        { (void *)"timezone", 8 }, { (void *)"static", 6 },
        { (void *)"async", 5 }, { (void *)0, 0 },
        { (void *)"ignoreacl", 9 }, { (void *)0, 0 },
    };
    int mr = nmount(iov, 14, MNT_UPDATE);
    printf("[diag]   nmount MNT_UPDATE /system_ex: rc=%d (%s)\n", mr,
           mr ? strerror(errno) : "ok");

    /* SPLAT check: /system_ex has MNT_SPLAT (0x40) — it belongs to the
     * system mount world, not ours. Try MNT_UPDATE on mounts that are
     * NOT splatted (native to our world): /system_data, /system_tmp. */
    struct iovec sdiov[] = {
        { (void *)"from", 4 }, { (void *)"/dev/ssd0.system_data", 20 },
        { (void *)"fspath", 6 }, { (void *)"/system_data", 12 },
        { (void *)"fstype", 6 }, { (void *)"ufs", 3 },
    };
    int mrd = nmount(sdiov, 6, MNT_UPDATE);
    printf("[diag]   nmount MNT_UPDATE /system_data (ufs): rc=%d (%s)\n",
           mrd, mrd ? strerror(errno) : "ok");
    struct iovec tmiov[] = {
        { (void *)"fspath", 6 }, { (void *)"/system_tmp", 11 },
    };
    int mrt = nmount(tmiov, 2, MNT_UPDATE);
    printf("[diag]   nmount MNT_UPDATE /system_tmp (tmpfs): rc=%d (%s)\n",
           mrt, mrt ? strerror(errno) : "ok");

    /* What device backs /system_ex? */
    const char *devs[] = {
        "/dev/ssd0.system_ex", "/dev/mblk0.system_ex",
        "/dev/geo0", "/dev/ssd0", NULL,
    };
    for (int i = 0; devs[i]; i++) {
        if (stat(devs[i], &st) == 0)
            printf("[diag]   %s: exists\n", devs[i]);
        else
            printf("[diag]   %s: no\n", devs[i]);
    }
    /* /proc/mounts via raw read */
    int mfd = open("/proc/mounts", O_RDONLY);
    if (mfd >= 0) {
        char mbuf[4096];
        ssize_t n = read(mfd, mbuf, sizeof(mbuf) - 1);
        close(mfd);
        if (n > 0) {
            mbuf[n] = 0;
            for (char *ln = strtok(mbuf, "\n"); ln;
                 ln = strtok(0, "\n")) {
                if (strstr(ln, "system"))
                    printf("[diag]   mounts: %s\n", ln);
            }
        } else {
            printf("[diag]   /proc/mounts: empty (n=%zd)\n", n);
        }
    } else {
        printf("[diag]   /proc/mounts: open failed (%s)\n", strerror(errno));
    }

    /* Mount table via getmntinfo */
    struct statfs *mfs = 0;
    int nm = getmntinfo(&mfs, 0);
    printf("[diag]   getmntinfo: %d mounts\n", nm);
    for (int i = 0; i < nm && mfs; i++) {
        if (strstr(mfs[i].f_mntonname, "system") ||
            strstr(mfs[i].f_mntonname, "hdd") ||
            strstr(mfs[i].f_mntonname, "nor") ||
            strstr(mfs[i].f_mntonname, "lv0") ||
            strstr(mfs[i].f_mntonname, "dev0"))
            printf("[diag]   MNT: %s type=%s flags=0x%x\n",
                   mfs[i].f_mntonname, mfs[i].f_fstypename,
                   (unsigned)mfs[i].f_flags);
    }

    /* Minimal MNT_UPDATE: fspath only */
    struct iovec miniov[] = {
        { (void *)"fspath", 6 }, { (void *)"/system_ex", 10 },
    };
    int m2 = nmount(miniov, 2, MNT_UPDATE);
    printf("[diag]   nmount minimal MNT_UPDATE: rc=%d (%s)\n", m2,
           m2 ? strerror(errno) : "ok");

    /* Option-set matrix: find which option breaks exfat MNT_UPDATE. */
    struct iovec v_from[2] = {
        { (void *)"from", 4 }, { (void *)"/dev/ssd0.system_ex", 19 } };
    struct iovec v_fs[2] = {
        { (void *)"fspath", 6 }, { (void *)"/system_ex", 10 } };
    struct iovec v_ft[2] = {
        { (void *)"fstype", 6 }, { (void *)"exfatfs", 7 } };
    struct iovec v_lg[2] = {
        { (void *)"large", 5 }, { (void *)"yes", 3 } };
    struct iovec v_tz[2] = {
        { (void *)"timezone", 8 }, { (void *)"static", 6 } };
    struct iovec v_ac[2] = {
        { (void *)"async", 5 }, { 0, 0 } };
    struct iovec v_ia[2] = {
        { (void *)"ignoreacl", 9 }, { 0, 0 } };
    const char *names[8] = {
        "from+fspath",
        "+fstype",
        "+large",
        "+timezone",
        "+async",
        "+ignoreacl",
        "ALL",
        "from+fspath+fstype(retry rw check)",
    };
    for (int s = 0; s < 8; s++) {
        struct iovec buf[14];
        int n = 0;
        switch (s) {
        case 0: memcpy(buf, v_from, 16); memcpy(buf + 2, v_fs, 16); n = 4; break;
        case 1: memcpy(buf, v_from, 16); memcpy(buf + 2, v_fs, 16);
               memcpy(buf + 4, v_ft, 16); n = 6; break;
        case 2: memcpy(buf, v_from, 16); memcpy(buf + 2, v_fs, 16);
               memcpy(buf + 4, v_ft, 16); memcpy(buf + 6, v_lg, 16); n = 8; break;
        case 3: memcpy(buf, v_from, 16); memcpy(buf + 2, v_fs, 16);
               memcpy(buf + 4, v_ft, 16); memcpy(buf + 6, v_lg, 16);
               memcpy(buf + 8, v_tz, 16); n = 10; break;
        case 4: memcpy(buf, v_from, 16); memcpy(buf + 2, v_fs, 16);
               memcpy(buf + 4, v_ft, 16); memcpy(buf + 6, v_lg, 16);
               memcpy(buf + 8, v_tz, 16); memcpy(buf + 10, v_ac, 16); n = 12; break;
        case 5: memcpy(buf, v_from, 16); memcpy(buf + 2, v_fs, 16);
               memcpy(buf + 4, v_ft, 16); memcpy(buf + 6, v_lg, 16);
               memcpy(buf + 8, v_tz, 16); memcpy(buf + 10, v_ac, 16);
               memcpy(buf + 12, v_ia, 16); n = 14; break;
        case 6: memcpy(buf, v_from, 16); memcpy(buf + 2, v_fs, 16);
               memcpy(buf + 4, v_ft, 16); memcpy(buf + 6, v_lg, 16);
               memcpy(buf + 8, v_tz, 16); memcpy(buf + 10, v_ac, 16);
               memcpy(buf + 12, v_ia, 16); n = 14; break;
        case 7: memcpy(buf, v_from, 16); memcpy(buf + 2, v_fs, 16);
               memcpy(buf + 4, v_ft, 16); n = 6; break;
        }
        int r = nmount(buf, n, MNT_UPDATE);
        printf("[diag]   nmount[%d] %-28s n=%d: rc=%d (%s)\n", s,
               names[s], n, r, r ? strerror(errno) : "ok");
        if (r == 0) {
            int fd2 = open("/system_ex/.pxlview_writetest2", O_CREAT | O_WRONLY, 0644);
            printf("[diag]   writable after set %d: %s\n", s,
                   fd2 >= 0 ? "YES" : "NO");
            if (fd2 >= 0) { close(fd2); unlink("/system_ex/.pxlview_writetest2"); }
            break;
        }
    }

    /* Enumerate /system_ex/app and read param.json of video-app
     * candidates (launchable foreground apps with video-out). */
    DIR *ad = opendir("/system_ex/app");
    if (ad) {
        struct dirent *de;
        while ((de = readdir(ad)) != 0) {
            if (de->d_name[0] == '.')
                continue;
            char pj[256];
            snprintf(pj, sizeof(pj), "/system_ex/app/%s/sce_sys/param.json",
                     de->d_name);
            FILE *pf = fopen(pj, "r");
            if (!pf)
                continue;
            char pbuf[1024];
            size_t pn = fread(pbuf, 1, sizeof(pbuf) - 1, pf);
            fclose(pf);
            pbuf[pn] = 0;
            /* extract attribute3 value */
            const char *a3 = strstr(pbuf, "\"attribute3\"");
            const char *cat = strstr(pbuf, "\"applicationCategoryType\"");
            printf("[diag]   APP %s: attr3=%.*s cat=%.*s\n", de->d_name,
                   a3 ? 12 : 0, a3 ? a3 + 14 : "",
                   cat ? 12 : 0, cat ? cat + 26 : "");
        }
        closedir(ad);
    } else {
        printf("[diag]   /system_ex/app: opendir failed (%s)\n", strerror(errno));
    }

    /* Find and print the system boot script mount commands. */
    DIR *bd = opendir("/system_ex/boot");
    if (bd) {
        struct dirent *de;
        while ((de = readdir(bd)) != 0) {
            if (de->d_name[0] == '.')
                continue;
            char bp[256];
            snprintf(bp, sizeof(bp), "/system_ex/boot/%s", de->d_name);
            printf("[diag]   /system_ex/boot/%s\n", de->d_name);
            FILE *bf = fopen(bp, "r");
            if (bf) {
                char bl[256];
                int bn = 0;
                while (fgets(bl, sizeof(bl), bf) && bn < 60) {
                    if (strstr(bl, "mount") || strstr(bl, "system") ||
                        strstr(bl, "ssd0") || strstr(bl, "exfat") ||
                        strstr(bl, "ufs"))
                        printf("[diag]     |%s", bl);
                    bn++;
                }
                fclose(bf);
            }
        }
        closedir(bd);
    } else {
        printf("[diag]   /system_ex/boot: %s\n", strerror(errno));
    }
    DIR *bd2 = opendir("/system/boot");
    if (bd2) {
        struct dirent *de;
        while ((de = readdir(bd2)) != 0) {
            if (de->d_name[0] == '.')
                continue;
            printf("[diag]   /system/boot/%s\n", de->d_name);
        }
        closedir(bd2);
    }

    /* /data (homebrew storage) + /dev device enumeration. */
    const char *dw[] = { "/data", "/data/homebrew", NULL };
    for (int i = 0; dw[i]; i++) {
        if (stat(dw[i], &st) == 0)
            printf("[diag]   %s: OK\n", dw[i]);
        else
            printf("[diag]   %s: %s\n", dw[i], strerror(errno));
    }
    int dfd = open("/data/.pxlview_writetest", O_CREAT | O_WRONLY, 0644);
    printf("[diag]   /data writable: %s\n", dfd >= 0 ? "YES" : "NO");
    if (dfd >= 0) {
        close(dfd);
        unlink("/data/.pxlview_writetest");
    }
    DIR *dd = opendir("/dev");
    if (dd) {
        struct dirent *de;
        int cnt = 0;
        while ((de = readdir(dd)) != 0 && cnt < 200) {
            if (de->d_name[0] == '.')
                continue;
            if (strstr(de->d_name, "ufs") || strstr(de->d_name, "geo") ||
                strstr(de->d_name, "ssd") || strstr(de->d_name, "mblk")) {
                printf("[diag]   /dev/%s\n", de->d_name);
                cnt++;
            }
        }
        closedir(dd);
    }

    /* Mount /dev/ssd0.user (the /dev_hdd0 device) rw at /tmp/hdd0 and
     * create the FAKE00000 app there (homebrew PKG layout). */
    rmdir("/tmp/hdd0");
    mkdir("/tmp/hdd0", 0755);
    struct iovec um[] = {
        { (void *)"from", 4 }, { (void *)"/dev/ssd0.user", 14 },
        { (void *)"fspath", 6 }, { (void *)"/tmp/hdd0", 8 },
        { (void *)"fstype", 6 }, { (void *)"ufs", 3 },
    };
    int ur2 = nmount(um, 6, 0);
    printf("[diag]   mount /dev/ssd0.user -> /tmp/hdd0: rc=%d (%s)\n", ur2,
           ur2 ? strerror(errno) : "ok");

    /* Old mount(2) syscall + plain tmpfs (no device). */
    rmdir("/tmp/pxl_t");
    mkdir("/tmp/pxl_t", 0755);
    int om1 = mount("/tmp/pxl_t", "tmpfs", 0, 0);
    printf("[diag]   mount(2) tmpfs -> /tmp/pxl_t: rc=%d (%s)\n", om1,
           om1 ? strerror(errno) : "ok");
    rmdir("/tmp/pxl_h");
    mkdir("/tmp/pxl_h", 0755);
    int om2 = mount("/tmp/pxl_h", "ufs", 0, "/dev/ssd0.user");
    printf("[diag]   mount(2) ufs ssd0.user -> /tmp/pxl_h: rc=%d (%s)\n",
           om2, om2 ? strerror(errno) : "ok");
    if (ur2 == 0) {
        /* See what's in user storage. */
        DIR *hd = opendir("/tmp/hdd0");
        if (hd) {
            struct dirent *de;
            while ((de = readdir(hd)) != 0) {
                if (de->d_name[0] == '.')
                    continue;
                printf("[diag]   /tmp/hdd0/%s\n", de->d_name);
            }
            closedir(hd);
        }
        DIR *ha = opendir("/tmp/hdd0/app");
        if (ha) {
            struct dirent *de;
            while ((de = readdir(ha)) != 0) {
                if (de->d_name[0] == '.')
                    continue;
                printf("[diag]   /tmp/hdd0/app/%s\n", de->d_name);
            }
            closedir(ha);
        } else {
            printf("[diag]   /tmp/hdd0/app: %s\n", strerror(errno));
        }
    }

    /* /dev_hdd0 (user storage) checks — homebrew apps live here. */
    const char *hdd[] = { "/dev_hdd0", "/dev_hdd0/app", "/dev_hdd0/data", NULL };
    for (int i = 0; hdd[i]; i++) {
        if (stat(hdd[i], &st) == 0)
            printf("[diag]   %s: OK\n", hdd[i]);
        else
            printf("[diag]   %s: %s\n", hdd[i], strerror(errno));
    }
    int hfd = open("/dev_hdd0/.pxlview_writetest", O_CREAT | O_WRONLY, 0644);
    printf("[diag]   /dev_hdd0 writable: %s\n",
           hfd >= 0 ? "YES" : "NO");
    if (hfd >= 0) {
        close(hfd);
        unlink("/dev_hdd0/.pxlview_writetest");
    }

    /* Fresh rw mount of the same device at a new mountpoint. */
#ifndef MNT_UNMOUNT
#define MNT_UNMOUNT 0x0008
#endif
    mkdir("/tmp/pxl_ex", 0755);
    struct iovec fm[] = {
        { (void *)"from", 4 }, { (void *)"/dev/ssd0.system_ex", 19 },
        { (void *)"fspath", 6 }, { (void *)"/tmp/pxl_ex", 10 },
        { (void *)"fstype", 6 }, { (void *)"exfatfs", 7 },
        { (void *)"large", 5 }, { (void *)"yes", 3 },
    };
    int fr = nmount(fm, 8, 0);
    printf("[diag]   fresh mount /tmp/pxl_ex: rc=%d (%s)\n", fr,
           fr ? strerror(errno) : "ok");
    if (fr == 0) {
        int fd3 = open("/tmp/pxl_ex/.pxlview_writetest3", O_CREAT | O_WRONLY,
                        0644);
        printf("[diag]   fresh mount writable: %s\n",
               fd3 >= 0 ? "YES" : "NO");
        if (fd3 >= 0)
            close(fd3);
        struct iovec um[] = {
            { (void *)"fspath", 6 }, { (void *)"/tmp/pxl_ex", 10 },
        };
        nmount(um, 2, MNT_UNMOUNT);
        rmdir("/tmp/pxl_ex");
    }
    /* write test */
    int fd = open("/system_ex/.pxlview_writetest", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        printf("[diag]   /system_ex writable: YES\n");
        close(fd);
        unlink("/system_ex/.pxlview_writetest");
    } else {
        printf("[diag]   /system_ex writable: NO (%s)\n", strerror(errno));
    }
}

/* Remote nmount MNT_UPDATE /system_ex from SceSysCore.elf (pid in the
 * system mount world). Our own process cannot update any mount
 * (EINVAL on everything), but a VSH process in world 0 should be able
 * to. Uses the pt_syscall trampoline (NID HoLVWNanBBc). */
static void diag_remote_mount(void)
{
    sec("20. REMOUNT via SceSysCore (remote nmount)");
    #include <sys/ptrace.h>

    /* Find SceSysCore.elf by comm. */
    pid_t target = -1;
    /* Use the kernel proc walk: scan pids 1..128. */
    pid_t target1 = -1;
    for (int p = 1; p < 128; p++) {
        intptr_t proc = kernel_get_proc(p);
        if (!proc)
            continue;
        char comm[16] = {0};
        if (kernel_copyout(proc + 0x5dc, comm, 15) == 0) {
            if (!strcmp(comm, "SceSysCore.elf")) {
                target = p;
                break;
            }
            if (!strcmp(comm, "mini-syscore.el"))
                target1 = p;
        }
    }
    printf("[diag]   SceSysCore.elf pid: %d, mini-syscore pid: %d\n",
           target, target1);
    if (target1 > 0) {
        printf("[diag]   trying mini-syscore (pid 1, world 0?) first\n");
        if (pt_attach(target1) == 0) {
            intptr_t p1 = pt_mmap(target1, 0, 0x4000, 3, 0x1002, -1, 0);
            printf("[diag]   p1 pt_mmap: 0x%lx\n", (unsigned long)p1);
            if (p1 != -1) {
                struct iovec iov1[] = {
                    { (void *)"from", 4 }, { (void *)"/dev/ssd0.system_ex", 19 },
                    { (void *)"fspath", 6 }, { (void *)"/system_ex", 10 },
                    { (void *)"fstype", 6 }, { (void *)"exfatfs", 7 },
                    { (void *)"large", 5 }, { (void *)"yes", 3 },
                    { (void *)"timezone", 8 }, { (void *)"static", 6 },
                    { (void *)"async", 5 }, { (void *)0, 0 },
                    { (void *)"ignoreacl", 9 }, { (void *)0, 0 },
                };
                pt_copyin(target1, iov1, p1, sizeof(iov1));
                long r1 = pt_syscall(target1, 378, p1, 14, MNT_UPDATE);
                printf("[diag]   p1 remote nmount: rc=%ld (%s)\n", r1,
                       r1 ? strerror((int)r1) : "ok");
                pt_copyin(target1, "/system_ex", p1 + 0x100, 11);
                long s1 = pt_syscall(target1, 137, p1 + 0x100, p1 + 0x200);
                printf("[diag]   p1 statfs /system_ex: rc=%ld\n", s1);
                if (s1 == 0) {
                    struct statfs sf1;
                    pt_copyout(target1, p1 + 0x200, &sf1, sizeof(sf1));
                    printf("[diag]   p1 sees /system_ex flags=0x%llx\n",
                           (unsigned long long)sf1.f_flags);
                }
                pt_copyin(target1, "/dev_hdd0", p1 + 0x100, 10);
                long s2 = pt_syscall(target1, 137, p1 + 0x100, p1 + 0x200);
                printf("[diag]   p1 statfs /dev_hdd0: rc=%ld\n", s2);
                if (s2 == 0) {
                    struct statfs sf2;
                    pt_copyout(target1, p1 + 0x200, &sf2, sizeof(sf2));
                    printf("[diag]   p1 sees /dev_hdd0 flags=0x%llx type=%s\n",
                           (unsigned long long)sf2.f_flags,
                           sf2.f_fstypename);
                }
                pt_munmap(target1, p1, 0x4000);
                pt_detach(target1, 0);
            } else {
                pt_detach(target1, 0);
            }
        } else {
            printf("[diag]   p1 pt_attach failed: %s\n", strerror(errno));
        }
    }
    if (target < 0)
        return;

    if (pt_attach(target)) {
        printf("[diag]   pt_attach: %s\n", strerror(errno));
        return;
    }
    printf("[diag]   attached\n");
    fflush(stdout);

    /* Build the iovec in the target's memory (hbldr's exact set). */
    intptr_t page = pt_mmap(target, 0, 0x4000, 3, 0x1002, -1, 0); /*ANON|PRIVATE*/
    printf("[diag]   pt_mmap: 0x%lx\n", (unsigned long)page);
    if (page == -1) {
        pt_detach(target, 0);
        return;
    }
    /* Probe PT_IO with small sizes. */
    long rv = pt_getlong(target, page);
    printf("[diag]   pt_getlong(page) = 0x%lx\n", (unsigned long)rv);
    if (pt_setlong(target, page, 0xdeadbeef))
        printf("[diag]   pt_setlong (PT_IO): %s\n", strerror(errno));
    else {
        rv = pt_getlong(target, page);
        printf("[diag]   readback: 0x%lx\n", (unsigned long)rv);
    }
    /* Try PT_POKEDATA word-write instead (with ptrace authid). */
    uint64_t saved_auth = kernel_get_ucred_authid(0);
    uint8_t saved_caps[16];
    kernel_get_ucred_caps(0, saved_caps);
    uint8_t full[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    kernel_set_ucred_authid(0, 0x4800000000010003);
    kernel_set_ucred_caps(0, full);
    errno = 0;
    int pw = syscall(SYS_ptrace, 2 /*PT_POKEDATA*/, target, (void *)page, 0xdeadbeefL);
    printf("[diag]   PT_POKEDATA: rc=%d (%s)\n", pw, pw ? strerror(errno) : "ok");
    if (pw == 0) {
        rv = pt_getlong(target, page);
        printf("[diag]   pokedata readback: 0x%lx\n", (unsigned long)rv);
    }
    /* Write to target's stack area (known RW) as a control. */
    struct reg tr;
    if (pt_getregs(target, &tr) == 0) {
        intptr_t sp = tr.r_rsp & ~0xffL;
        int ps = pt_setlong(target, sp, 0x123456789abcdefL);
        printf("[diag]   pt_setlong(stack-0x100): rc=%d (%s)\n", ps,
               ps ? strerror(errno) : "ok");
    }
    kernel_set_ucred_caps(0, saved_caps);
    kernel_set_ucred_authid(0, saved_auth);
    struct iovec iov[] = {
        { (void *)"from", 4 }, { (void *)"/dev/ssd0.system_ex", 19 },
        { (void *)"fspath", 6 }, { (void *)"/system_ex", 10 },
        { (void *)"fstype", 6 }, { (void *)"exfatfs", 7 },
        { (void *)"large", 5 }, { (void *)"yes", 3 },
        { (void *)"timezone", 8 }, { (void *)"static", 6 },
        { (void *)"async", 5 }, { (void *)0, 0 },
        { (void *)"ignoreacl", 9 }, { (void *)0, 0 },
    };
    if (pt_copyin(target, iov, page, sizeof(iov))) {
        printf("[diag]   pt_copyin iov: %s; trying kernel_proc_copyin\n",
               strerror(errno));
        if (kernel_proc_copyin(target, iov, page, sizeof(iov))) {
            printf("[diag]   kernel_proc_copyin: %s\n", strerror(errno));
            pt_munmap(target, page, 0x4000);
            pt_detach(target, 0);
            return;
        }
    }

    long rc = pt_syscall(target, 378 /*SYS_nmount*/, page, 14, MNT_UPDATE);
    printf("[diag]   remote nmount MNT_UPDATE: rc=%ld (%s)\n", rc,
           rc ? strerror((int)rc) : "ok");
    fflush(stdout);

    /* Remote statfs: what flags does /system_ex have in the target's
     * mount world? */
    pt_copyin(target, "/system_ex", page + 0x100, 11);
    long sfc = pt_syscall(target, 137 /*SYS_statfs*/, page + 0x100,
                          page + 0x200);
    printf("[diag]   remote statfs: rc=%ld\n", sfc);
    if (sfc == 0) {
        struct statfs sfs;
        pt_copyout(target, page + 0x200, &sfs, sizeof(sfs));
        printf("[diag]   target sees /system_ex flags=0x%llx type=%s\n",
               (unsigned long long)sfs.f_flags, sfs.f_fstypename);
    }
    /* Also: does the target see /dev_hdd0? */
    pt_copyin(target, "/dev_hdd0", page + 0x100, 10);
    long sfc2 = pt_syscall(target, 137, page + 0x100, page + 0x200);
    printf("[diag]   target statfs /dev_hdd0: rc=%ld\n", sfc2);
    if (sfc2 == 0) {
        struct statfs sfs2;
        pt_copyout(target, page + 0x200, &sfs2, sizeof(sfs2));
        printf("[diag]   target sees /dev_hdd0 flags=0x%llx type=%s\n",
               (unsigned long long)sfs2.f_flags, sfs2.f_fstypename);
    }

    /* Can the TARGET itself write to /system_ex? (remote open O_CREAT) */
    pt_copyin(target, "/system_ex/.pxlview_rw", page + 0x100, 20);
    long ofc = pt_syscall(target, 13 /*SYS_open*/, page + 0x100,
                          0x141 /*O_CREAT|O_WRONLY*/, 0644);
    printf("[diag]   target open /system_ex/.pxlview_rw O_CREAT: fd=%ld\n",
           ofc);
    if (ofc > 0) {
        pt_syscall(target, 6 /*SYS_close*/, ofc);
        pt_copyin(target, "/system_ex/.pxlview_rw", page + 0x100, 20);
        long uf = pt_syscall(target, 37 /*SYS_unlink*/, page + 0x100);
        printf("[diag]   target unlink: rc=%ld\n", uf);
    }

    /* Can WE write to /system_ex now? */
    int fd = open("/system_ex/.pxlview_rw", O_CREAT | O_WRONLY, 0644);
    printf("[diag]   /system_ex writable from us now: %s\n",
           fd >= 0 ? "YES" : "NO");
    if (fd >= 0) {
        close(fd);
        unlink("/system_ex/.pxlview_rw");
    }

    pt_munmap(target, page, 0x4000);
    pt_detach(target, 0);
    printf("[diag]   detached\n");
    fflush(stdout);
}

/* E6: full app hijack — launch NPXS40140 (Disc Player) through the
 * system, catch the forked+exec'd process with kqueue/ptrace, break at
 * eboot's main() call site, and load the pxlview ELF into it. pxlview
 * then runs in the context of a formally launched app, which should
 * have the primary VideoOut route. */
#include "elfldr_hw.h"
#include "pxlview_elf_blob.h"

typedef struct app_launch_ctx_e6 {
    uint32_t structsize;
    uint32_t user_id;
    uint32_t app_opt;
    uint64_t crash_report;
    uint32_t check_flag;
} app_launch_ctx_e6_t;

extern int sceSystemServiceLaunchApp(const char *, char **, void *);

static void *e6_launch_thread(void *arg)
{
    (void)arg;
    extern int sceUserServiceGetForegroundUser(uint32_t *);
    app_launch_ctx_e6_t ctx = {0};
    sceUserServiceGetForegroundUser(&ctx.user_id);
    char *argv[] = { (char *)"NPXS40140", 0 };
    sceSystemServiceLaunchApp("NPXS40140", argv, &ctx);
    return 0;
}

static void diag_app_hijack(void)
{
    sec("21. APP HIJACK: launch NPXS40140 + load pxlview");

    /* Find SceSysCore.elf. */
    pid_t syscore = -1;
    for (int p = 1; p < 128; p++) {
        intptr_t proc = kernel_get_proc(p);
        if (!proc)
            continue;
        char comm[16] = {0};
        if (kernel_copyout(proc + 0x5dc, comm, 15) == 0 &&
            !strcmp(comm, "SceSysCore.elf")) {
            syscore = p;
            break;
        }
    }
    printf("[diag]   SceSysCore.elf pid: %d\n", syscore);
    if (syscore < 0)
        return;

    /* Clean-exit any leftover pxlview-in-app from a previous run
     * (SIGTERM -> SDL_Quit -> VideoOut session released). */
    for (int p = 1; p < 128; p++) {
        intptr_t proc = kernel_get_proc(p);
        if (!proc)
            continue;
        char comm[16] = {0};
        if (kernel_copyout(proc + 0x5dc, comm, 15) == 0 &&
            !strcmp(comm, "SceDiscPlayer")) {
            kill(p, SIGTERM);
            printf("[diag]   SIGTERM to leftover SceDiscPlayer pid %d\n", p);
        }
    }
    sleep(1);

    /* Kill any already-running bigapp (LNC says "already running" and
     * no fork happens, so the kqueue below would stall). hbldr does
     * the same. */
    extern int sceSystemServiceGetAppIdOfRunningBigApp(void);
    extern int sceSystemServiceKillApp(int, int, int, int);
    int bigapp = sceSystemServiceGetAppIdOfRunningBigApp();
    printf("[diag]   running bigapp: 0x%x\n", bigapp);
    if (bigapp > 0) {
        if (sceSystemServiceKillApp(bigapp, -1, 0, 0))
            printf("[diag]   KillApp: %s\n", strerror(errno));
        else {
            sleep(3);
            printf("[diag]   bigapp 0x%x kill requested\n", bigapp);
        }
    }
    fflush(stdout);

    /* kqueue tracking of SceSysCore forks. */
    int kq = kqueue();
    struct kevent evt = {0};
    EV_SET(&evt, syscore, EVFILT_PROC,
           EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_FORK | NOTE_EXEC | NOTE_TRACK, 0, 0);
    if (kevent(kq, &evt, 1, 0, 0, 0) < 0) {
        printf("[diag]   kevent: %s\n", strerror(errno));
        close(kq);
        return;
    }

    /* Launch the app in a thread. */
    pthread_t trd;
    pthread_create(&trd, 0, e6_launch_thread, 0);
    pthread_detach(trd);

    /* Wait for the fork event (with 30s timeout). */
    struct timespec ktimeout = { 30, 0 };
    int nkev = kevent(kq, 0, 0, &evt, 1, &ktimeout);
    close(kq);
    if (nkev <= 0) {
        printf("[diag]   no fork event (nkev=%d, %s)\n", nkev,
               nkev < 0 ? strerror(errno) : "timeout");
        return;
    }
    if (!(evt.fflags & NOTE_CHILD)) {
        printf("[diag]   no NOTE_CHILD in event (fflags=0x%x)\n", evt.fflags);
        return;
    }
    pid_t child = evt.ident;
    printf("[diag]   fork child: %d\n", child);
    fflush(stdout);

    if (pt_attach(child)) {
        printf("[diag]   pt_attach(%d): %s\n", child, strerror(errno));
        return;
    }
    if (pt_follow_exec(child) < 0) {
        printf("[diag]   pt_follow_exec: %s\n", strerror(errno));
        pt_detach(child, SIGKILL);
        return;
    }
    if (pt_continue(child, SIGCONT) < 0) {
        pt_detach(child, SIGKILL);
        return;
    }
    if (pt_await_exec(child)) {
        printf("[diag]   pt_await_exec: %s\n", strerror(errno));
        pt_detach(child, SIGKILL);
        return;
    }
    printf("[diag]   exec'd eboot, pid %d\n", child);
    fflush(stdout);

    /* Let the kernel assign process parameters. */
    if (pt_syscall(child, 599))
        printf("[diag]   sys 599: %s\n", strerror(errno));
    elfldr_set_heap_size(child, -1);
    elfldr_raise_privileges(child);

    /* Breakpoint at eboot's main() call site. */
    intptr_t brk = kernel_dynlib_entry_addr(child, 0);
    if (!brk) {
        printf("[diag]   kernel_dynlib_entry_addr failed\n");
        pt_detach(child, SIGKILL);
        return;
    }
    brk += 58;
    uint8_t int3 = 0xcc;
    uint8_t orig = 0;
    kernel_mprotect(child, brk, 0x4000, 7);
    pt_copyout(child, brk, &orig, 1);
    pt_copyin(child, &int3, brk, 1);
    pt_continue(child, SIGCONT);
    if (waitpid(child, 0, 0) < 0) {
        printf("[diag]   waitpid at brk: %s\n", strerror(errno));
        pt_detach(child, SIGKILL);
        return;
    }
    pt_copyin(child, &orig, brk, 1);
    printf("[diag]   stopped at eboot main (brk=0x%lx)\n", (unsigned long)brk);
    fflush(stdout);

    /* Give the app process OUR stdout/stderr so pxlview's logs reach
     * the console. */
    if (elfldr_set_stdio(child, STDOUT_FILENO))
        printf("[diag]   set_stdio: %s\n", strerror(errno));
    else
        printf("[diag]   stdio redirected to console\n");

    /* Load pxlview into the app process. */
    if (elfldr_exec(child, (uint8_t *)build_pxlview_embed_elf)) {
        printf("[diag]   elfldr_exec FAILED\n");
        pt_detach(child, SIGKILL);
        return;
    }
    printf("[diag]   pxlview loaded into app process %d — GO!\n", child);
    fflush(stdout);

    /* Watch the process for 20s: alive? what state? Then SIGTERM for a
     * clean pxlview exit (releases the VideoOut session). */
    for (int i = 1; i <= 20; i++) {
        sleep(1);
        intptr_t proc = kernel_get_proc(child);
        if (!proc) {
            printf("[diag]   t+%d: process %d GONE\n", i, child);
            break;
        }
        /* proc state: p_stat at +0x330 (11.60); comm at +0x5dc */
        uint32_t pstat = 0;
        kernel_copyout(proc + 0x330, &pstat, 4);
        char comm[16] = {0};
        kernel_copyout(proc + 0x5dc, comm, 15);
        printf("[diag]   t+%d: pid %d alive state=0x%x comm=%s\n",
               i, child, pstat, comm);
        fflush(stdout);
    }
    kill(child, SIGTERM);
    printf("[diag]   SIGTERM sent to %d (clean pxlview exit)\n", child);
    sleep(3);
    if (kernel_get_proc(child)) {
        kill(child, SIGKILL);
        printf("[diag]   SIGKILL fallback\n");
    }
}

/* E5: launch a real video app (Disc Player 2) through the system
 * app-launch path and watch the monitor. The formal launch should
 * perform the VSH->app display handoff. */
typedef struct app_launch_ctx {
    uint32_t structsize;
    uint32_t user_id;
    uint32_t app_opt;
    uint64_t crash_report;
    uint32_t check_flag;
} app_launch_ctx_t;

extern int sceSystemServiceLaunchApp(const char *, char **, void *);

struct launch_arg {
    const char *tid;
    char **argv;
    void *ctx;
    int *rc;
};

static void *launch_thread(void *arg)
{
    struct launch_arg *la = arg;
    *la->rc = sceSystemServiceLaunchApp(la->tid, la->argv, la->ctx);
    return 0;
}

static void diag_launch_test(void) __attribute__((unused));

static void diag_launch_test(void)
{
    sec("19. LAUNCH TEST: sceSystemServiceLaunchApp(NPXS40140)");
    extern int sceUserServiceInitialize(void *);
    extern int sceUserServiceGetForegroundUser(uint32_t *);

    sceUserServiceInitialize(0);
    uint32_t uid = 0;
    if (sceUserServiceGetForegroundUser(&uid)) {
        printf("[diag]   no foreground user\n");
        return;
    }
    printf("[diag]   user 0x%x; launching NPXS40140 in thread...\n", uid);
    fflush(stdout);

    /* Try switching to the system mount world (FreeBSD 413 =
     * mount_world). If it works, /dev_hdd0 becomes visible and
     * LaunchApp can write. */
    long mw = syscall(413, 0);
    printf("[diag]   mount_world(0): rc=%ld (%s)\n", mw,
           mw < 0 ? strerror(errno) : "ok");
    struct stat wst;
    if (stat("/dev_hdd0", &wst) == 0)
        printf("[diag]   /dev_hdd0 NOW VISIBLE after mount_world\n");
    else
        printf("[diag]   /dev_hdd0 still: %s\n", strerror(errno));
    int wfd = open("/system_ex/.pxlview_mwtest", O_CREAT | O_WRONLY, 0644);
    printf("[diag]   /system_ex writable after mount_world: %s\n",
           wfd >= 0 ? "YES" : "NO");
    if (wfd >= 0) {
        close(wfd);
        unlink("/system_ex/.pxlview_mwtest");
    }
    fflush(stdout);

    app_launch_ctx_t ctx = {0}; /* all zeros, like hbldr */
    ctx.user_id = uid;
    char *argv[] = { (char *)"NPXS40140", 0 };
    static int lr;
    lr = -999;
    struct launch_arg la = { "NPXS40140", argv, &ctx, &lr };

    pthread_t trd;
    pthread_create(&trd, 0, launch_thread, &la);

    /* Give the app time to start; user watches the monitor. */
    for (int i = 0; i < 10; i++) {
        sleep(1);
        printf("[diag]   t+%d s\n", i + 1);
        fflush(stdout);
    }

    pthread_join(trd, 0);
    printf("[diag]   LaunchApp rc=%d (%s)\n", lr, lr ? strerror(errno) : "ok");
    fflush(stdout);
}

int main(void)
{
    /* pxlview-style markers: the launcher auto-detects pxlview from the
     * ELF name (pxlview-diag.elf) and stops on the done marker instead of
     * re-sending in a loop. */
    printf("[pxlview] starting v0.1.0-diag\n");

    /* EARLY experiment: kill VSH's video core (SceVideoCore2K, pid 78)
     * and watch what happens to the display. Then keep going. */
    if (1 /* getenv("PXL_KILLVSH") */) {
        int pid78 = 78;
        int kr = kill(pid78, 9);
        printf("[diag] KILLVSH: kill(78,9) = %d (%s)\n", kr, kr ? strerror(errno) : "ok");
        fflush(stdout);
        for (int i = 0; i < 10; i++) {
            sleep(1);
            printf("[diag]   t+%d s alive\n", i + 1);
            fflush(stdout);
        }
        /* try to open + flip after the kill */
        intptr_t pa0 = 0, pa1 = 0;
        void *va0 = 0, *va1 = 0;
        DiagVideoBuf vbuf[2];
        DiagVideoAttr vattr;
        struct kevent *eq = 0;
        struct kevent evt;
        int h, rc, junk;
        const size_t half = 0x1000000;
        h = sceVideoOutOpen(0xff, 0, 0, NULL);
        printf("[diag]   post-kill open(0,0): h=0x%x (%s)\n", h,
               h < 0 ? strerror(errno) : "ok");
        if (h >= 0) {
            memset(vbuf, 0, sizeof(vbuf));
            memset(&vattr, 0, sizeof(vattr));
            sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa0);
            sceKernelMapDirectMemory(&va0, half, 0x33, 0, pa0, 0x20000);
            sceKernelAllocateMainDirectMemory(half, 0x20000, 3, &pa1);
            sceKernelMapDirectMemory(&va1, half, 0x33, 0, pa1, 0x20000);
            vbuf[0].data = va0;
            vbuf[1].data = va1;
            uint32_t *px = (uint32_t *)va0;
            for (size_t i = 0; i < half / 4; i++) px[i] = 0xFF00FF00u;
            px = (uint32_t *)va1;
            for (size_t i = 0; i < half / 4; i++) px[i] = 0xFF00FF00u;
            sceVideoOutSetBufferAttribute2(&vattr, 0x8000000022000000ULL, 0,
                                           1920, 1080, 0, 0, 0);
            rc = sceVideoOutRegisterBuffers2(h, 0, 0, vbuf, 2, &vattr, 0, NULL);
            printf("[diag]   post-kill register: rc=%d (%s)\n", rc,
                   rc ? strerror(errno) : "ok");
            if (!rc) {
                sceKernelCreateEqueue(&eq, "postkill");
                sceVideoOutAddFlipEvent(eq, h, 0);
                sceVideoOutSetFlipRate(h, 0);
                for (int f = 0; f < 600; f++) {
                    rc = sceVideoOutSubmitFlip(h, 0, 1, f);
                    if (rc) break;
                    sceKernelWaitEqueue(eq, &evt, 1, &junk, 0);
                    struct timespec ts = { 0, 33000000 };
                    nanosleep(&ts, 0);
                }
                printf("[diag]   post-kill flips done\n");
                fflush(stdout);
            }
            sceVideoOutClose(h);
        }
        printf("[diag] KILLVSH done\n");
    }
    printf("[diag] pxlview diagnostic starting\n");
    /* Sys* probe + process list first (cheap, no video resources). */
    diag_sysapi();
    diag_proc_list();
    diag_dynlib();
    diag_entry_takeover();
    uint64_t vsh_sess = diag_vsh_videoout();
    diag_sprx_hunt(vsh_sess);
    diag_sess_links(vsh_sess, g_vsh_sessions, g_nvsh_sessions);
    diag_list_hijack(vsh_sess);
    diag_dead_session();
    diag_launch_probe();
    diag_remote_mount();
    diag_flip_master();

    /* VIDEO TESTS (direct-memory pool is freshest now): */
    diag_videotest(2, 0, 0xFF00FF00u,
                   "5. video test: GREEN on session (2,0) (10s) - watch the monitor!",
                   300);
    diag_videotest(2, 0, 0xFFFFFFFFu,
                   "6. video test: WHITE on session (2,0) (5s) - watch the monitor!",
                   150);
    diag_videotest(1, 0, 0xFFFF0000u,
                   "7. video test: BLUE on session (1,0) (5s) - control",
                   150);

    diag_authid();
    diag_videoout();
    diag_open_matrix();
    diag_pcomm();
    diag_fs();
    diag_rootdir();
    diag_prison();

    /* APP HIJACK LAST: it launches a real app and loads pxlview into it;
     * nothing after it may steal the display. */
    diag_app_hijack();

    printf("[diag] all done\n");
    printf("[pxlview] done\n");
    return 0;
}
