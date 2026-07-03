# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Go function-name recovery from the pclntab.

A Go binary keeps a complete function table (the pclntab) even when it carries
no symbol table, so a "stripped" Go program still names every function it
contains. `go_functions` locates the pclntab (a named section, or a magic-byte
scan of the read-only data), parses its header, and returns each function's
entry address and name. `add_go_functions` registers those as named `Func`s,
and `apply_go_symbols` does both in one call for headless use.

Four header layouts are handled by magic: go1.2 (0xfffffffb), go1.16
(0xfffffffa), go1.18 (0xfffffff0), and go1.20 (0xfffffff1). Anything the parser
cannot validate (a bad magic, an out-of-range offset, a non-printable name)
yields no entry rather than a wrong one; recovery is all-or-nothing per name.
Little-endian only, which the magic-byte gate enforces.

Public: `GoFunc`, `go_functions`, `add_go_functions`, `apply_go_symbols`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from ..core.image import Func, Image

log = logging.getLogger(__name__)

# pcHeader magic (little-endian) -> a short version label. The magic sits at the
# start of the pclntab and is followed by two zero pad bytes.
_MAGICS = {
    0xFFFFFFFB: "go1.2",
    0xFFFFFFFA: "go1.16",
    0xFFFFFFF0: "go1.18",
    0xFFFFFFF1: "go1.20",
}
# Little-endian magic byte prefixes to scan for, each followed by `00 00`.
_MAGIC_SCAN = [(bytes([m & 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00]), m) for m in _MAGICS]
# Sections that carry the pclntab across the three container formats.
_PCLNTAB_SECTIONS = (".gopclntab", "__gopclntab", ".go.pclntab")
# Sections to scan for the magic when no dedicated pclntab section exists.
_SCAN_SECTIONS = (".rdata", ".rodata", "__rodata", "__const", ".data.rel.ro")
# A sane ceiling so a corrupt nfunc cannot drive an unbounded loop.
_MAX_FUNCS = 1_000_000
_MAX_NAME = 1024


@dataclass(slots=True)
class GoFunc:
    va: int
    name: str


def _u32(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        raise IndexError
    return int.from_bytes(buf[off : off + 4], "little")


def _i32(buf: bytes, off: int) -> int:
    v = _u32(buf, off)
    return v - (1 << 32) if v >> 31 else v


def _ptr(buf: bytes, off: int, psize: int) -> int:
    if off < 0 or off + psize > len(buf):
        raise IndexError
    return int.from_bytes(buf[off : off + psize], "little")


def _cstring(buf: bytes, off: int) -> str | None:
    """A printable NUL-terminated name at `off`, or None if implausible."""
    if off < 0 or off >= len(buf):
        return None
    end = buf.find(b"\x00", off, off + _MAX_NAME)
    if end < 0:
        return None
    raw = buf[off:end]
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Go names are printable and contain no control characters or spaces.
    if any(ch < "\x20" or ch == "\x7f" for ch in text):
        return None
    return text


def _find_pcheader(image: Image) -> tuple[int, bytes, int] | None:
    """Locate the pclntab: return (header_va, bytes_from_header, magic) or None.

    A dedicated section is trusted directly; otherwise the read-only data
    sections are scanned for a magic byte pattern with a valid header shape.
    """
    for name in _PCLNTAB_SECTIONS:
        for sec in image.sections:
            if sec.name == name and sec.size:
                buf = image.read_va(sec.va, sec.size)
                hit = _validate_header(buf, 0)
                if hit is not None:
                    return sec.va, buf, hit
    for sec in image.sections:
        if sec.name not in _SCAN_SECTIONS or not sec.size:
            continue
        buf = image.read_va(sec.va, sec.size)
        for prefix, magic in _MAGIC_SCAN:
            start = 0
            while True:
                pos = buf.find(prefix, start)
                if pos < 0:
                    break
                if _validate_header(buf, pos) is not None:
                    return sec.va + pos, buf[pos:], magic
                start = pos + 1
    return None


def _validate_header(buf: bytes, off: int) -> int | None:
    """The magic at `off` when the surrounding bytes form a valid header, else None."""
    try:
        magic = _u32(buf, off)
    except IndexError:
        return None
    if magic not in _MAGICS or off + 8 > len(buf):
        return None
    if buf[off + 4] != 0 or buf[off + 5] != 0:
        return None
    pcquantum, ptrsize = buf[off + 6], buf[off + 7]
    if pcquantum not in (1, 2, 4) or ptrsize not in (4, 8):
        return None
    return magic


def go_functions(image: Image) -> list[GoFunc]:
    """Recover named Go functions from the pclntab, or [] when there is none.

    Read-only: safe to call on a worker thread. Entries whose name or address
    cannot be validated are skipped, so the result carries only confident names.
    """
    found = _find_pcheader(image)
    if found is None:
        return []
    _hdr_va, buf, magic = found
    ptrsize = buf[7]
    try:
        if magic == 0xFFFFFFFB:
            return _parse_go12(buf, ptrsize)
        if magic == 0xFFFFFFFA:
            return _parse_go116(buf, ptrsize)
        return _parse_go118(buf, ptrsize)
    except (IndexError, ValueError) as e:
        log.debug("go pclntab parse aborted: %s", e)
        return []


def _collect(
    nfunc: int,
    entry_of: Callable[[int], int],
    name_of: Callable[[int], str | None],
) -> list[GoFunc]:
    """Walk `nfunc` functab entries, resolving each to a (va, name) pair.

    `entry_of(i)` gives the entry VA of function `i`; `name_of(i)` gives its
    name (or None). A per-entry failure is skipped, never fatal.
    """
    out: list[GoFunc] = []
    seen: set[int] = set()
    for i in range(nfunc):
        try:
            va = entry_of(i)
            if va <= 0 or va in seen:
                continue
            name = name_of(i)
        except (IndexError, ValueError):
            continue
        if not name:
            continue
        seen.add(va)
        out.append(GoFunc(va=va, name=name))
    return out


def _parse_go118(buf: bytes, psize: int) -> list[GoFunc]:
    """go1.18 / go1.20: uint32 functab, entry PCs offset from textStart."""
    nfunc = _ptr(buf, 8, psize)
    if not 0 < nfunc <= _MAX_FUNCS:
        return []
    text_start = _ptr(buf, 8 + 2 * psize, psize)
    funcname_off = _ptr(buf, 8 + 3 * psize, psize)
    functab_off = _ptr(buf, 8 + 7 * psize, psize)

    def entry_of(i: int) -> int:
        return text_start + _u32(buf, functab_off + i * 8)

    def name_of(i: int) -> str | None:
        funcoff = _u32(buf, functab_off + i * 8 + 4)
        name_idx = _i32(buf, funcoff + 4)
        return _cstring(buf, funcname_off + name_idx)

    return _collect(nfunc, entry_of, name_of)


def _parse_go116(buf: bytes, psize: int) -> list[GoFunc]:
    """go1.16: ptr-wide functab, absolute entry PCs, funcname index table."""
    nfunc = _ptr(buf, 8, psize)
    if not 0 < nfunc <= _MAX_FUNCS:
        return []
    funcname_off = _ptr(buf, 8 + 2 * psize, psize)
    functab_off = _ptr(buf, 8 + 6 * psize, psize)
    stride = 2 * psize

    def entry_of(i: int) -> int:
        return _ptr(buf, functab_off + i * stride, psize)

    def name_of(i: int) -> str | None:
        funcoff = _ptr(buf, functab_off + i * stride + psize, psize)
        name_idx = _i32(buf, funcoff + psize)
        return _cstring(buf, funcname_off + name_idx)

    return _collect(nfunc, entry_of, name_of)


def _parse_go12(buf: bytes, psize: int) -> list[GoFunc]:
    """go1.2 through go1.15: ptr-wide functab, name is a direct pclntab offset."""
    nfunc = _ptr(buf, 8, psize)
    if not 0 < nfunc <= _MAX_FUNCS:
        return []
    functab_off = 8 + psize
    stride = 2 * psize

    def entry_of(i: int) -> int:
        return _ptr(buf, functab_off + i * stride, psize)

    def name_of(i: int) -> str | None:
        funcoff = _ptr(buf, functab_off + i * stride + psize, psize)
        name_ptr = _i32(buf, funcoff + psize)
        return _cstring(buf, name_ptr)

    return _collect(nfunc, entry_of, name_of)


def add_go_functions(image: Image, gofuncs: list[GoFunc]) -> int:
    """Register recovered Go names as `Func`s not already present. Returns count.

    A name lands only at an address in an executable section that no existing
    function claims, so a container symbol always wins over a recovered name.
    Go code always sits in the text section (executable on every format), so an
    entry that resolves into a non-executable section is a corrupt table and is
    dropped, matching the CFG's jump-table gate.
    """
    added = 0
    for gf in gofuncs:
        if image.func_at(gf.va) is not None:
            continue
        sec = image.section_at(gf.va)
        if sec is None or "X" not in sec.flags.upper():
            continue
        image.funcs.append(
            Func(
                name=gf.name,
                va=gf.va,
                kind="symbol",
                confidence="confirmed",
                evidence=("go pclntab",),
            )
        )
        added += 1
    if added:
        image.reindex()
    return added


def apply_go_symbols(image: Image) -> int:
    """Recover and register Go function names in one synchronous pass."""
    return add_go_functions(image, go_functions(image))
