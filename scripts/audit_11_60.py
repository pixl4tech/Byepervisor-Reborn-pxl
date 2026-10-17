#!/usr/bin/env python3
"""Static audit for the 11.60 hardened port.

Checks:
  1. AP payload fits the 0x800 staging area.
  2. The outer ELF embeds exactly one copy of the AP image.
  3. The AP binary contains no SVM/MSR/CR/DR opcodes: it must only do
     guarded data writes to the VMCB page range.
  4. Exactly one call site each of the guarded vmcb_write64/vmcb_write32.
  5. The hardened hook invariants are present in h1160.c:
     16 isolated IST6 paths, gate published last, stock gate restored as the
     first handler mutation, DR7 cleared before staging, all IST slots
     restored independently.
"""
import argparse
import subprocess
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--ap-bin", default="break_hv_payload/break_hv.bin")
ap.add_argument("--ap-elf", default="break_hv_payload/break_hv.o")
ap.add_argument("--outer-elf", default="build/debug/byepv-pxl-latest.elf")
ap.add_argument("--objdump",
                default="sdk/llvm18/llvm@18/18.1.8/bin/llvm-objdump")
args = ap.parse_args()

ap_bin = Path(args.ap_bin).read_bytes()
outer = Path(args.outer_elf).read_bytes()

# 1. staging area budget
assert len(ap_bin) <= 0x800, \
    f"AP payload too large for hardened staging: 0x{len(ap_bin):x}"

# 2. single embedded image
assert outer.count(ap_bin) == 1, "outer ELF must contain exactly one AP image"

# 3. forbidden opcodes in the AP binary
for opcode in (
    b"\x0f\x01\xd9",  # vmmcall
    b"\x0f\x01\xda",  # vmload
    b"\x0f\x01\xdb",  # vmsave
    b"\x0f\x01\xd8",  # vmrun
    b"\x0f\x01\xd1",  # vmmcall (alt encoding not used, kept for symmetry)
    b"\x0f\x22",      # mov to control register
    b"\x0f\x23",      # mov to debug register
    b"\x0f\x30",      # wrmsr
    b"\x0f\x32",      # rdmsr
):
    assert opcode not in ap_bin, f"forbidden AP opcode: {opcode.hex()}"

# 4. guarded write call sites
disassembly = subprocess.check_output(
    [args.objdump, "-d", "--x86-asm-syntax=intel", args.ap_elf], text=True
).splitlines()
write64_calls = sum("call" in line and "<vmcb_write64" in line
                    for line in disassembly)
write32_calls = sum("call" in line and "<vmcb_write32" in line
                    for line in disassembly)
assert write64_calls == 1, \
    f"expected one guarded write64 call site, got {write64_calls}"
assert write32_calls == 1, \
    f"expected one guarded write32 call site, got {write32_calls}"

# 5. hardened hook invariants
main_source = Path("main.c").read_text()
hook_source = Path("h1160.c").read_text()
header_source = Path("include/h1160.h").read_text()

for marker in ("h1160_arm(cave", "h1160_cleanup(cave)"):
    assert marker in main_source, f"missing 11.60 orchestration call: {marker}"

required_hook = (
    "16 isolated IST6 paths verified",
    "gate goes up only now",
    "h1160_build_passthrough",
    "KERNEL_GADGET_MOV_RAX_RDI",
    "KERNEL_GADGET_SET_DR7",
    "h1160_restore_ists",
    "H1160_CHAIN_MARK",
)
for marker in required_hook:
    assert marker in hook_source, f"missing hardened hook invariant: {marker}"

# ordering: stock gate restored first, DR7 cleared second, staging third
restore_pos = hook_source.index(
    "h1160_store(h, &off, H1160_BLOCK, db_gate, saved_gate_lo)",
    hook_source.index("h1160_build_handler"),
)
clear_pos = hook_source.index("KERNEL_GADGET_SET_DR7", restore_pos)
stage_pos = hook_source.index("KERNEL_GADGET_REP_MOVSB", clear_pos)
assert restore_pos < clear_pos < stage_pos, \
    "handler order must be: gate restore, DR7 clear, payload staging"

assert "#define H1160_STASH_OFF      0x3400ULL" in header_source
assert "#define H1160_STAGE_SIZE     0x800ULL" in header_source

print(
    f"11.60 hardened audit passed: AP size=0x{len(ap_bin):x}, embedded once, "
    "forbidden-opcode scan clean, guarded writes=1+1, per-core hook "
    "invariants present"
)
