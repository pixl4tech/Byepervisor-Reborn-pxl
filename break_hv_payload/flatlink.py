#!/usr/bin/env python3
"""Minimal flat ELF64 linker for the break_hv AP payload.

Used only when a GNU/LLVM linker is not available (e.g. stock macOS, whose
ld64 does not accept -T linker scripts). Layout follows link.ld:

    .text  : entry.o(.text) then break_hv.o(.text)
    .rodata: all .rodata
    .data  : all .data

Relocations handled: R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_64, R_X86_64_32.
"""
import struct
import sys

SHT_RELA = 4
SHT_SYMTAB = 2

# x86-64 relocation types
R_X86_64_64 = 1
R_X86_64_PC32 = 2
R_X86_64_PLT32 = 4
R_X86_64_32 = 10


def load_elf(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x7fELF", f"{path}: not an ELF"
    assert data[4] == 2, f"{path}: not 64-bit"

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_addralign, sh_entsize) = \
            struct.unpack_from("<IIQQQQIIQQ", data, off)
        sections.append({
            "name_off": sh_name, "type": sh_type, "offset": sh_offset,
            "size": sh_size, "link": sh_link, "info": sh_info,
            "entsize": sh_entsize,
        })

    shstr = sections[e_shstrndx]
    strtab = data[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for s in sections:
        end = strtab.index(b"\0", s["name_off"])
        s["name"] = strtab[s["name_off"]:end].decode()

    # symbols (with section name, not index)
    symbols = []
    for i, s in enumerate(sections):
        if s["type"] != SHT_SYMTAB:
            continue
        st_sec = sections[s["link"]]
        st = data[st_sec["offset"]:st_sec["offset"] + st_sec["size"]]
        n = s["size"] // s["entsize"]
        for j in range(n):
            so = s["offset"] + j * s["entsize"]
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", data, so)
            end = st.index(b"\0", st_name)
            shndx_name = sections[st_shndx]["name"] if st_shndx < len(sections) else ""
            symbols.append({
                "name": st[st_name:end].decode(),
                "section": shndx_name,
                "value": st_value,
            })
        break

    relocations = []
    for s in sections:
        if s["type"] != SHT_RELA:
            continue
        # the rela section targets sections[s['info']]
        target = sections[s["info"]]["name"] if s["info"] < len(sections) else ""
        n = s["size"] // 24
        for i in range(n):
            ro = s["offset"] + i * 24
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, ro)
            relocations.append({
                "section": target,
                "offset": r_offset,
                "type": r_info & 0xffffffff,
                "sym": symbols[r_info >> 32],
                "addend": r_addend,
            })

    return {
        "sections": {s["name"]: data[s["offset"]:s["offset"] + s["size"]]
                     for s in sections if s["size"]},
        "symbols": symbols,
        "relocations": relocations,
    }


def main():
    out = sys.argv[1]
    objs = [load_elf(p) for p in sys.argv[2:]]

    # layout: .text (object order), then .rodata, then .data
    layout = []   # [offset, bytes, (obj_idx, sect_name)]
    cur = 0
    for sect in (".text", ".rodata", ".data"):
        for oi, o in enumerate(objs):
            if o["sections"].get(sect):
                layout.append([cur, o["sections"][sect], (oi, sect)])
                cur += len(o["sections"][sect])

    out_data = bytearray(cur)
    for offset, blob, (oi, sect) in layout:
        out_data[offset:offset + len(blob)] = blob

    # symbol addresses: section base + symbol value
    sect_base = {(oi, sect): off for off, _, (oi, sect) in layout}
    sym_addr = {}
    for oi, o in enumerate(objs):
        for s in o["symbols"]:
            if s["name"] and (oi, s["section"]) in sect_base:
                size = len(o["sections"][s["section"]])
                if s["value"] <= size:
                    sym_addr.setdefault(s["name"], sect_base[(oi, s["section"])] + s["value"])

    # apply relocations
    for offset, blob, (oi, sect) in layout:
        for r in objs[oi]["relocations"]:
            if r["section"] != sect:
                continue
            name = r["sym"]["name"] if r["sym"] else ""
            if name not in sym_addr:
                raise SystemExit(f"unresolved symbol: {name!r}")
            target = sym_addr[name]
            loc = offset + r["offset"]
            if r["type"] in (R_X86_64_PC32, R_X86_64_PLT32):
                # ELF: value = S + A - P, where P is the field offset.
                # The assembler bakes the instruction-length compensation
                # into A (e.g. -4 for a 5-byte call).
                struct.pack_into("<i", out_data, loc,
                                 target + r["addend"] - loc)
            elif r["type"] == R_X86_64_64:
                struct.pack_into("<Q", out_data, loc, target + r["addend"])
            elif r["type"] == R_X86_64_32:
                struct.pack_into("<I", out_data, loc, target + r["addend"])
            else:
                raise SystemExit(f"unsupported relocation type {r['type']}")

    with open(out, "wb") as f:
        f.write(bytes(out_data))
    print(f"flatlink: {out} = 0x{len(out_data):x} bytes")


if __name__ == "__main__":
    main()
