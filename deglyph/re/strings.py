# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Value extraction: image-wide strings and the data a function references.

`extract_strings` is the `strings(1)` equivalent (ASCII + UTF-8 + UTF-16LE, with
virtual address, section, and a category). `referenced_data` resolves the strings,
tables, and pointer constants a function points at (arch-neutral via the operand
walker), decoding each as a string, a pointer table, or a short hex preview.

Public: StringLit, DataRef, string_runs, extract_strings, referenced_data.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from ..core.image import Arch, Image
from .cfg import function_insns

_ASCII_RUN = re.compile(rb"[\x20-\x7e]+")
# A printable UTF-8 run: ASCII printables plus well-formed 2/3/4-byte sequences.
_UTF8_RUN = re.compile(
    rb"(?:[\x20-\x7e]"
    rb"|[\xc2-\xdf][\x80-\xbf]"
    rb"|\xe0[\xa0-\xbf][\x80-\xbf]"
    rb"|[\xe1-\xec][\x80-\xbf]{2}"
    rb"|\xed[\x80-\x9f][\x80-\xbf]"
    rb"|[\xee-\xef][\x80-\xbf]{2}"
    rb"|\xf0[\x90-\xbf][\x80-\xbf]{2}"
    rb"|[\xf1-\xf3][\x80-\xbf]{3}"
    rb"|\xf4[\x80-\x8f][\x80-\xbf]{2})+"
)

# A run that is exactly a section name (e.g. `.text`) or a COFF aux name (`/19`)
# is container metadata, not a program string literal.
_SECTION_NAME = re.compile(r"^\.[A-Za-z][\w.$]*$|^/\d+$")


@dataclass(slots=True)
class StringLit:
    va: int
    off: int
    section: str
    # ascii | utf-8 | utf-16le
    encoding: str
    text: str
    # literal | section-name | symbol  (literal is a real program string)
    category: str = "literal"


@dataclass(slots=True)
class DataRef:
    # the instruction that references the data
    addr: int
    # the data address
    target: int
    section: str
    # str | table | data
    kind: str
    # decoded string, table summary, or a hex preview for non-string data
    text: str


def string_runs(data: bytes, *, min_len: int = 4) -> Iterator[tuple[int, str, str]]:
    """Yield (offset, encoding, text) for printable ASCII / UTF-8 / UTF-16LE runs.

    Encodings are labeled `ascii`, `utf-8`, `utf-16le`. A run is `utf-8` only when
    it carries at least one multibyte sequence; a pure-ASCII run stays `ascii`
    (so the common case is not relabeled). UTF-16LE is detected separately as the
    `ascii-byte, NUL` repetition the other two regexes cannot match.
    """
    for m in _UTF8_RUN.finditer(data):
        raw = m.group()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) < min_len:
            continue
        # multibyte present -> utf-8, else plain ascii
        enc = "ascii" if len(raw) == len(text) else "utf-8"
        yield m.start(), enc, text
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
                yield start, "utf-16le", "".join(chars)
        else:
            i += 1


def _off_to_va(image: Image, off: int) -> int | None:
    for s in image.sections:
        if s.raw_size and s.raw_off <= off < s.raw_off + s.raw_size:
            return s.va + (off - s.raw_off)
    return None


def _categorize(text: str, symbols: set[str]) -> str:
    """Classify a run as a real literal, a section name, or a known symbol."""
    if _SECTION_NAME.match(text):
        return "section-name"
    if text in symbols:
        return "symbol"
    return "literal"


def extract_strings(
    image: Image,
    *,
    min_len: int = 4,
    limit: int = 4000,
    section: str | None = None,
    raw: bool = False,
) -> list[StringLit]:
    """Program string literals in the image, with address, section, and category.

    By default this returns only **mapped** runs that look like real literals:
    a run that does not fall inside a mapped section (a file-header / COFF
    string-table artifact that would otherwise show as VA 0) is dropped, and
    runs that are section names or known symbols are categorized and excluded
    from the default view. Pass `raw=True` for the unfiltered `strings(1)` dump
    (every run, VA 0 included, every category). `section` filters to one section;
    `min_len` is the minimum run length.
    """
    with open(image.path, "rb") as fh:
        data = fh.read()
    symbols = {f.name for f in image.funcs if f.name}
    out: list[StringLit] = []
    for off, enc, text in string_runs(data, min_len=min_len):
        va = _off_to_va(image, off)
        sec = image.section_at(va) if va is not None else None
        sec_name = sec.name if sec else ""
        category = _categorize(text, symbols)
        lit = StringLit(va or 0, off, sec_name, enc, text, category)
        if not raw:
            # mapped, real-literal default: drop unmapped runs and metadata
            if va is None or sec is None:
                continue
            if category != "literal":
                continue
            if section is not None and sec_name != section:
                continue
        elif section is not None and sec_name != section:
            continue
        out.append(lit)
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


def _word_size(image: Image) -> int:
    """Pointer width in bytes for the image's architecture (8 for 64-bit)."""
    return 8 if image.arch.bits == 64 else 4


def _looks_like_pointer_table(
    image: Image, target: int, *, min_entries: int = 3
) -> int:
    """Count leading word-sized values at `target` that point into a section.

    Returns the number of consecutive pointer-shaped entries (0 if fewer than
    `min_entries`), the signal that `target` is a pointer array / jump table
    rather than a scalar. Bounded so a huge data region cannot stall the walk.
    """
    wsize = _word_size(image)
    count = 0
    for i in range(64):
        raw = image.read_va(target + i * wsize, wsize)
        if len(raw) < wsize:
            break
        ptr = int.from_bytes(raw, "little")
        if image.section_at(ptr) is None:
            break
        count += 1
    return count if count >= min_entries else 0


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
    entries = _looks_like_pointer_table(image, target)
    if entries:
        return DataRef(addr, target, section, "table", f"{entries} pointers")
    return DataRef(addr, target, section, "data", raw[:16].hex(" "))


def referenced_data(image: Image, va: int, *, max_insns: int = 1500) -> list[DataRef]:
    """Strings, tables, and pointer constants referenced by the function at `va`.

    Arch-neutral via the operand walker: x86 RIP-relative / absolute memory
    operands, AArch64 `adrp`/`ldr`-literal and other PC-relative refs, and bare
    pointer immediates. A memory reference is reported whether it lands on a
    string, a pointer table, or other data; a bare immediate only when it points
    at a string.
    """
    if image.arch == Arch.UNKNOWN:
        return []
    out: list[DataRef] = []
    seen: set[int] = set()
    for ins in function_insns(image, va, max_insns=max_insns):
        next_pc = ins.addr + ins.size
        for op in ins.operands():
            target, string_only = None, False
            if op.is_mem:
                base = (op.mem_base or "").lower()
                if base in ("rip", "pc"):
                    target = (next_pc + op.mem_disp) & 0xFFFFFFFFFFFFFFFF
                elif op.mem_base is None and op.mem_index is None and op.mem_disp:
                    target = op.mem_disp & 0xFFFFFFFFFFFFFFFF
            elif op.is_imm and op.imm:
                # adrp / ldr-literal resolve a PC-relative address into the IMM;
                # a bare numeric immediate is only a "reference" if it points at
                # a string (else too noisy).
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
