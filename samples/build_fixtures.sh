#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build the stripped regression fixtures deglyph's function-recovery tests load.
#
# Each target is independent and best-effort: a missing toolchain skips that one
# fixture (the matching test is skipif-absent) instead of failing the build, so
# the script is useful on a dev box (native Mach-O + fat here) and in CI (ELF via
# gcc, PE via mingw-w64). Nothing produced here is committed; CI rebuilds it.
#
# Fixtures (written next to this script):
#   fixture_macho_x64     thin Mach-O, x86_64, stripped
#   fixture_macho_arm64   thin Mach-O, arm64, stripped
#   fixture_macho_fat     fat Mach-O (x86_64 + arm64), stripped
#   fixture_elf_x64       ELF, x86_64, stripped
#   fixture_elf_arm64     ELF, AArch64, stripped
#   fixture_pe_x64.exe    PE, x86_64, stripped
#
# All are built from fixture_src.c (a libc-free, self-contained variant of
# demo.c: the same crc16 / encode_frame / send_frame / set_volume shapes, so the
# detectors and discovery have real functions to recover, with no printf so it
# links freestanding without a sysroot).

set -u
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/fixture_src.c"
built=0
skipped=0

have() { command -v "$1" >/dev/null 2>&1; }

note() { printf '  %s\n' "$*"; }

build() {
  # build <label> <output> <cc> <args...>
  local label="$1" out="$2"; shift 2
  if "$@" -o "$here/$out" "$src" 2>/dev/null; then
    strip "$here/$out" 2>/dev/null || true
    note "built   $label -> $out"
    built=$((built + 1))
  else
    note "skipped $label (toolchain or link unavailable)"
    skipped=$((skipped + 1))
    rm -f "$here/$out"
  fi
}

if [ ! -f "$src" ]; then
  echo "error: $src not found" >&2
  exit 1
fi

echo "deglyph fixtures -> $here"

# --- Mach-O (native host: macOS) ------------------------------------------
# -nostdlib drops the C runtime so the _start entry is the only code; -lSystem
# is still required (macOS rejects a dynamic main executable that does not link
# libSystem.dylib); -fno-stack-protector avoids __stack_chk_* refs the dropped
# runtime would otherwise supply. The Mach-O symbol table prefixes C names with
# an underscore, so the C `_start` is the linker symbol `__start` (hence -e
# __start). strip then removes the symbol table -> a stripped fixture.
if have clang && [ "$(uname)" = "Darwin" ]; then
  build "Mach-O x86_64" fixture_macho_x64 \
    clang -arch x86_64 -O1 -nostdlib -fno-stack-protector -lSystem -e __start
  build "Mach-O arm64" fixture_macho_arm64 \
    clang -arch arm64 -O1 -nostdlib -fno-stack-protector -lSystem -e __start
  if [ -f "$here/fixture_macho_x64" ] && [ -f "$here/fixture_macho_arm64" ] && have lipo; then
    if lipo -create "$here/fixture_macho_x64" "$here/fixture_macho_arm64" \
        -output "$here/fixture_macho_fat" 2>/dev/null; then
      note "built   Mach-O fat -> fixture_macho_fat"
      built=$((built + 1))
    fi
  fi
fi

# --- ELF (native gcc on Linux, or a cross gcc anywhere) -------------------
# ELF / PE toolchains do not prefix symbols, so the entry is plain `_start`.
if have gcc && [ "$(uname)" = "Linux" ]; then
  build "ELF x86_64" fixture_elf_x64 \
    gcc -O1 -nostdlib -fno-stack-protector -e _start -static
fi
if have aarch64-linux-gnu-gcc; then
  build "ELF arm64" fixture_elf_arm64 \
    aarch64-linux-gnu-gcc -O1 -nostdlib -fno-stack-protector -e _start -static
fi

# --- PE (mingw-w64) -------------------------------------------------------
if have x86_64-w64-mingw32-gcc; then
  build "PE x86_64" fixture_pe_x64.exe \
    x86_64-w64-mingw32-gcc -O1 -nostdlib -fno-stack-protector -e _start
fi

echo "fixtures: $built built, $skipped skipped"
exit 0
