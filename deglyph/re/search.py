# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Image-wide search: byte patterns (with `??` wildcards), ASCII/UTF-16 strings,
and immediate constants referenced in code. Results carry both file offset and
virtual address so the TUI can jump to them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.disasm import Disassembler
from ..core.image import Image


@dataclass(slots=True)
class Hit:
    va: int
    off: int
    # bytes | string | imm
    kind: str
    # matched text / decoded value
    detail: str
    section: str = ""


def _raw(image: Image) -> bytes:
    with open(image.path, "rb") as fh:
        return fh.read()


def _off_to_va(image: Image, off: int) -> int | None:
    for s in image.sections:
        if s.raw_off <= off < s.raw_off + s.raw_size:
            return s.va + (off - s.raw_off)
    return None


def _section_name(image: Image, va: int | None) -> str:
    sec = image.section_at(va) if va else None
    return sec.name if sec else ""


def _parse_pattern(pat: str) -> re.Pattern:
    """Turn 'DE ?? BE' or 'deadbe' into a compiled regex over raw bytes."""
    pat = pat.strip()
    toks = (
        pat.split() if " " in pat else [pat[i : i + 2] for i in range(0, len(pat), 2)]
    )
    rx = b""
    for t in toks:
        if t in ("??", "?", "**", "*"):
            rx += b"."
        else:
            rx += re.escape(bytes([int(t, 16)]))
    return re.compile(rx, re.DOTALL)


def find_bytes(image: Image, pattern: str, limit: int = 500) -> list[Hit]:
    data = _raw(image)
    rx = _parse_pattern(pattern)
    out: list[Hit] = []
    for m in rx.finditer(data):
        off = m.start()
        va = _off_to_va(image, off)
        sec = _section_name(image, va)
        out.append(Hit(va or 0, off, "bytes", m.group().hex(" "), sec))
        if len(out) >= limit:
            break
    return out


def find_string(
    image: Image, needle: str, *, min_len: int = 4, limit: int = 500
) -> list[Hit]:
    """Find ASCII and UTF-16LE occurrences of `needle` (case-sensitive)."""
    data = _raw(image)
    out: list[Hit] = []
    nb = needle.encode("latin-1", "ignore")
    for enc, label in ((nb, "ascii"), (needle.encode("utf-16-le", "ignore"), "utf16")):
        if len(enc) < 1:
            continue
        start = 0
        while True:
            i = data.find(enc, start)
            if i < 0:
                break
            va = _off_to_va(image, i)
            sec = _section_name(image, va)
            out.append(Hit(va or 0, i, f"str/{label}", needle, sec))
            start = i + 1
            if len(out) >= limit:
                return out
    return out


def find_immediate(image: Image, value: int, *, limit: int = 500) -> list[Hit]:
    """Scan executable sections for instructions that reference `value`.

    Catches CRC polynomials, magic constants, opcodes loaded into registers,
    and data references (`lea rcx, [rip+offset]` / `mov rax, [abs_va]`). For a
    memory operand, the actual target VA is resolved before comparing:
    rip-relative operands carry a displacement, not the absolute address.
    """
    dis = Disassembler(image)
    out: list[Hit] = []
    mask = 0xFFFFFFFFFFFFFFFF
    for s in image.sections:
        if "X" not in s.flags.upper():
            continue
        for ins in dis.at(s.va, s.size):
            if ins.addr >= s.end:
                break
            next_pc = ins.addr + ins.size
            for op in ins.operands():
                target: int | None = None
                kind = ""
                if op.is_imm and op.imm is not None:
                    target, kind = op.imm & mask, "imm"
                elif op.is_mem:
                    base = (op.mem_base or "").lower()
                    if base in ("rip", "pc"):
                        target, kind = (next_pc + op.mem_disp) & mask, "ref/rip"
                    elif op.mem_base is None and op.mem_index is None and op.mem_disp:
                        target, kind = op.mem_disp & mask, "ref/abs"
                if target == value:
                    out.append(Hit(ins.addr, 0, kind, ins.text, s.name))
                    break
            if len(out) >= limit:
                return out
    return out
