# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Authoritative function starts from a binary's unwind metadata.

The OS uses unwind tables to walk the stack at runtime, so every start they list
is a real function boundary, not a heuristic guess. `unwind_starts(image)` reads
the table for the loaded format and returns `(va, source)` pairs:

  - Mach-O: LF_FUNCTION_STARTS (`__LINKEDIT`), via LIEF `function_starts`.
  - PE:     the exception table (`.pdata`), via LIEF `exception_functions`
            (x64 / ARM64; 32-bit x86 PE uses SEH and exposes none).
  - ELF:    `.eh_frame` / symbol-derived starts, via LIEF's synthesized list.

For a fat Mach-O, `image._lief` is already the chosen slice, so its table is the
right one. Each source is wrapped so a malformed table yields `[]` rather than
aborting discovery. Addresses are normalized to VAs (an RVA below the image base
is promoted), and only those landing in a known section are kept.
"""

from __future__ import annotations

from ..core.image import Image


def _norm(image: Image, addr: int) -> int | None:
    """Normalize a reported address to a VA inside a mapped section, or None."""
    if addr <= 0:
        return None
    if image.base and addr < image.base and image.section_at(addr + image.base):
        addr += image.base
    return addr if image.section_at(addr) else None


def _macho_starts(b, image: Image) -> list[int]:
    fs = getattr(b, "function_starts", None)
    if fs is None:
        return []
    return list(getattr(fs, "functions", []) or [])


def _pe_starts(b, image: Image) -> list[int]:
    out: list[int] = []
    for f in getattr(b, "exception_functions", []) or []:
        addr = int(getattr(f, "address", 0) or 0)
        if addr:
            out.append(addr)
    return out


def _elf_starts(b, image: Image) -> list[int]:
    out: list[int] = []
    for f in getattr(b, "functions", []) or []:
        addr = int(getattr(f, "address", 0) or 0)
        if addr:
            out.append(addr)
    return out


_SOURCES = {
    "MachO": ("function-starts table", _macho_starts),
    "PE": ("exception table (.pdata)", _pe_starts),
    "ELF": ("eh_frame / symbols", _elf_starts),
}


def unwind_starts(image: Image) -> list[tuple[int, str]]:
    """Authoritative `(va, source)` function starts from the unwind metadata.

    Returns `[]` for a format without a readable table (e.g. 32-bit x86 PE). The
    list is de-duplicated and section-filtered; callers feed it into discovery as
    confirmed starts with the source string as evidence.
    """
    b = image._lief
    if b is None:
        return []
    entry = _SOURCES.get(image.fmt)
    if entry is None:
        return []
    label, fn = entry
    try:
        raw = fn(b, image)
    except Exception:
        return []
    seen: set[int] = set()
    out: list[tuple[int, str]] = []
    for addr in raw:
        try:
            va = _norm(image, int(addr))
        except Exception:
            continue
        if va is None or va in seen:
            continue
        seen.add(va)
        out.append((va, label))
    out.sort(key=lambda t: t[0])
    return out
