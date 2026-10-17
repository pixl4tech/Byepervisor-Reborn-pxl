#ifndef OFFSETS_11_60_H
#define OFFSETS_11_60_H

/* Firmware 11.60 (regular PS5). All values are ktext-relative unless noted.
 * kdata - ktext = 0xD30000.
 *
 * Provenance: hardware-validated production port (regular console, 2026-10-13,
 * strike result 16/16, kernel text SHA-256 0e3439b5...60d5). See
 * tools/ps5-hv-bypass-porting/firmwares/11.60.json for per-value evidence.
 *
 * HV_HEAP_BASE / HV_PCPUS are deliberately zero: on 11.60 the hypervisor
 * heap/pcpu globals read as zero during the startup AP window, so the AP
 * payload locates the live VMCBs structurally (see break_hv.c, 11.60 mode).
 */
uint64_t g_sym_map_1160[] = {
  0x3B351B4,  // KERNEL_SYM_DMPML4I
  0x3B351B8,  // KERNEL_SYM_DMPDPI
  0x3B33D6C,  // KERNEL_SYM_PML4PML4I
  0x34F590,   // KERNEL_SYM_SYS_GETUID
  0x535A50,   // KERNEL_SYM_PRINTF
  0x42FB40,   // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK
  0xC885D0,   // KERNEL_SYM_HV_MP_STARTUP_CALL
  0x3110B8,   // KERNEL_SYM_MP_STARTUP_INIT_VECTOR
  0x3B34F18,  // KERNEL_SYM_PMAP_STORE
  0x2D02000,  // KERNEL_SYM_DATA_CAVE
  0x3BA0300,  // KERNEL_SYM_IDT_ARRAY
  0x3BA2FE0,  // KERNEL_SYM_COMMON_TSS
  0,          // HV_SYM_HEAP_BASE  (not used: runtime VMCB discovery)
  0,          // HV_SYM_PCPUS      (not used: runtime VMCB discovery)
};

uint64_t g_gadget_map_1160[] = {
  0x2A0EDE,   // PIVOT_ADD_RSP28_RET  add rsp,0x28; rep ret
  0x2AC22D,   // IRETQ
  0x338D2A,   // POP_RAX
  0x339712,   // POP_RCX
  0x289E0A,   // POP_RDI
  0x8AAFB5,   // POP_RSI
  0x3476DB,   // POP_RDX
  0,          // POP_R8 - absent from 11.60 kernel .text
  0x33974D,   // POP_RSP
  0,          // STORE_RCX_R8 - unused by the portable store sequence
  0x3CC4AF,   // STORE_RDI8_RCX
  0,          // OR_RCX_EAX - unreachable for the one-shot resume hook
  0xA7BD86,   // SET_DR7
  0x8A2725,   // ST_RCX_RDX
  0x3620BF,   // ST_RCX_RAX
  0x958504,   // MOV_RAX_RSI
  0xC5E5DA,   // MOV_RAX_RDI
  0x304367,   // REP_MOVSB
  0x462C1A,   // CLD
  0x338D2B,   // RET_TRAMP
  0x2A5778,   // DBREG_RESUME
};

#endif // OFFSETS_11_60_H
