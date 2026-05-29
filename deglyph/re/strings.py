# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Value extraction: image-wide strings and the data a function references.

`extract_strings` is the `strings(1)` equivalent (ASCII + UTF-16LE, with virtual
address and section). `referenced_data` resolves the strings, tables, and pointer
constants a function points at -- x86 rip-relative / absolute operands and pointer
immediates -- decoding each as a string or a short hex preview.

Public: StringLit, DataRef, string_runs, extract_strings, referenced_data.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from capstone import x86

from ..core.disasm import Disassembler
from ..core.image import Arch, Image

_ASCII_RUN = re.compile(rb"[\x20-\x7e]+")


@dataclass(slots=True)
class StringLit:
    va: int
    off: int
    section: str
    # ascii | utf16
    encoding: str
    text: str


@dataclass(slots=True)
class DataRef:
    # the instruction that references the data
    addr: int
    # the data address
    target: int
    section: str
    # str | data
    kind: str
    # decoded string, or a hex preview for non-string data
    text: str


def string_runs(data: bytes, *, min_len: int = 4) -> Iterator[tuple[int, str, str]]:
    """Yield (offset, encoding, text) for printable ASCII and UTF-16LE runs."""
    for m in _ASCII_RUN.finditer(data):
        if m.end() - m.start() >= min_len:
            yield m.start(), "ascii", m.group().decode("ascii")
    # UTF-16LE: an ASCII byte followed by NUL, repeated.
    i, n = 0, len(data)
    while i + 1 < n:
        if 0x20 <= data[i] <= 0x7E and data[i + 1] == 0:
            start = i
            chars = []
            while i + 1 < n and 0x20 <= data[i] <= 0x7E and data[i + 1] == 0:
                chars.append(chr(data[i]))
                i += 2
            if len(chars) >= min_len:
                yield start, "utf16", "".join(chars)
        else:
            i += 1


def _off_to_va(image: Image, off: int) -> int | None:
    for s in image.sections:
        if s.raw_size and s.raw_off <= off < s.raw_off + s.raw_size:
            return s.va + (off - s.raw_off)
    return None


def extract_strings(
    image: Image, *, min_len: int = 4, limit: int = 4000
) -> list[StringLit]:
    """Every printable string in the image, with its address and section."""
    with open(image.path, "rb") as fh:
        data = fh.read()
    out: list[StringLit] = []
    for off, enc, text in string_runs(data, min_len=min_len):
        va = _off_to_va(image, off)
        sec = image.section_at(va) if va is not None else None
        out.append(StringLit(va or 0, off, sec.name if sec else "", enc, text))
        if len(out) >= limit:
            break
    return out


def _printable_prefix(raw: bytes) -> str:
    out = []
    for b in raw:
        if 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            break
    return "".join(out)


def _describe(
    image: Image, addr: int, target: int, section: str, *, string_only: bool
) -> DataRef | None:
    raw = image.read_va(target, 64)
    if not raw:
        return None
    s = _printable_prefix(raw)
    if len(s) >= 4:
        text = s if len(s) <= 48 else s[:45] + "..."
        return DataRef(addr, target, section, "str", text)
    if string_only:
        return None
    return DataRef(addr, target, section, "data", raw[:16].hex(" "))


def referenced_data(image: Image, va: int, *, max_insns: int = 1500) -> list[DataRef]:
    """Strings, tables, and pointer constants referenced by the function at `va`.

    x86 only (rip-relative / absolute memory operands and pointer immediates);
    returns [] on other architectures, like the other operand-level detectors.
    """
    if image.arch not in (Arch.X86, Arch.X64):
        return []
    dis = Disassembler(image)
    out: list[DataRef] = []
    seen: set[int] = set()
    for ins in dis.func(va, max_insns=max_insns):
        cs = ins._cs
        if cs is None:
            continue
        try:
            ops = cs.operands
        except Exception:
            continue
        for op in ops:
            target, string_only = None, False
            if op.type == x86.X86_OP_MEM:
                mem = op.mem
                if mem.base == x86.X86_REG_RIP:
                    target = ins.addr + ins.size + mem.disp
                elif mem.base == 0 and mem.index == 0 and mem.disp:
                    target = mem.disp & 0xFFFFFFFFFFFFFFFF
            elif op.type == x86.X86_OP_IMM:
                # A bare immediate is only a "reference" if it points at a string;
                # plain numeric constants would be too noisy here.
                target, string_only = op.imm & 0xFFFFFFFFFFFFFFFF, True
            if target is None or target in seen:
                continue
            sec = image.section_at(target)
            # data sections only; code targets are jumps/calls
            if sec is None or "X" in sec.flags.upper():
                continue
            ref = _describe(image, ins.addr, target, sec.name, string_only=string_only)
            if ref is not None:
                out.append(ref)
                seen.add(target)
    return out
