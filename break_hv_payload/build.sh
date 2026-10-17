#!/bin/sh
set -e
cd "$(dirname "$0")"

# Host-side x86-64 tools for the flat HV payload. Kept separate from the
# PS5 SDK's target CC/LD/OBJCOPY variables inherited through the outer Makefile.
CC=${HV_CC:-gcc}
LD=${HV_LD:-ld}
OBJCOPY=${HV_OBJCOPY:-objcopy}

# The flat payload needs a GNU-style linker and objcopy. On macOS look for
# binutils/lld in the usual prefixes (they may come from different
# packages); on Linux they are in PATH. Apple's ld64 rejects -nostdlib, so
# detect a usable linker and fall back to the Python flat linker otherwise.
USE_FLATLINK=0
if [ -z "${HV_LD:-}" ]; then
  for prefix in /opt/homebrew/opt/binutils/bin /usr/local/opt/binutils/bin; do
    [ -x "$prefix/ld" ] && LD="$prefix/ld"
  done
  if command -v ld.lld >/dev/null 2>&1 && [ "$LD" = "ld" ]; then
    LD=ld.lld
  fi
fi
if [ -z "${HV_OBJCOPY:-}" ]; then
  for prefix in /opt/homebrew/opt/binutils/bin /usr/local/opt/binutils/bin; do
    [ -x "$prefix/objcopy" ] && OBJCOPY="$prefix/objcopy"
  done
fi
if ! "$LD" -nostdlib -V >/dev/null 2>&1; then
  USE_FLATLINK=1
fi

# On arm64 hosts (macOS) the default cc/clang target is arm64; the payload
# must be x86-64, so pin the target explicitly.
if [ "$(uname -m)" = "arm64" ]; then
  TARGET_FLAGS="--target=x86_64"
else
  TARGET_FLAGS="-m64"
fi

CFLAGS="-O2 -ffreestanding -nostdlib -fno-pic -fno-plt \
  -fno-stack-protector -fno-stack-clash-protection \
  -fomit-frame-pointer -fno-asynchronous-unwind-tables \
  -fcf-protection=none -fno-jump-tables -mgeneral-regs-only \
  -mno-red-zone -Wall -Wextra"

"$CC" $TARGET_FLAGS $CFLAGS -c break_hv.c -o break_hv.o
"$CC" $TARGET_FLAGS -c entry.S -o entry.o

if [ "$USE_FLATLINK" = "1" ]; then
  # flatlink.py emits the raw binary directly (no objcopy needed)
  python3 flatlink.py break_hv.bin entry.o break_hv.o
else
  "$LD" -nostdlib -no-pie -T link.ld entry.o break_hv.o -o break_hv.elf
  "$OBJCOPY" -O binary break_hv.elf break_hv.bin
fi
xxd -i -n break_hv break_hv.bin > break_hv.h
