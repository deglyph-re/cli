# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Container abstraction over LIEF.

`Image` gives a uniform view of a PE / ELF / Mach-O binary: image base, sections,
and a flat list of `Func` entries (exports, symbols, entrypoint) keyed by virtual
address. Format and architecture are auto-detected but can be overridden by the
caller (the TUI exposes this as "choose binary format").
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import lief

log = logging.getLogger(__name__)


class Arch(str, Enum):
    """Disassembler-relevant architecture, independent of container format."""

    # 32-bit
    X86 = "x86"
    # 64-bit
    X64 = "x86-64"
    # 32-bit ARM
    ARM = "arm"
    # AArch64
    ARM64 = "arm64"
    UNKNOWN = "unknown"

    @property
    def bits(self) -> int:
        return {Arch.X86: 32, Arch.X64: 64, Arch.ARM: 32, Arch.ARM64: 64}.get(self, 0)


@dataclass(slots=True)
class Section:
    name: str
    # virtual address (image base already applied)
    va: int
    # virtual size
    size: int
    # file offset of raw data
    raw_off: int
    raw_size: int
    flags: str = ""

    @property
    def end(self) -> int:
        return self.va + self.size

    def contains(self, va: int) -> bool:
        return self.va <= va < self.end


@dataclass(slots=True)
class Func:
    """A named address of interest: export, imported thunk, symbol, or entrypoint."""

    name: str
    va: int
    # export | symbol | entry | import
    kind: str = "func"
    ordinal: int | None = None
    demangled: str | None = None
    # 0 = unknown (computed lazily)
    size: int = 0

    @property
    def display(self) -> str:
        return self.demangled or self.name


@dataclass
class Image:
    path: str
    # "PE" | "ELF" | "MachO"
    fmt: str
    arch: Arch
    base: int
    sections: list[Section] = field(default_factory=list)
    funcs: list[Func] = field(default_factory=list)
    _lief: object = None
    _by_va: dict[int, Func] = field(default_factory=dict, repr=False)

    # -- lookups -----------------------------------------------------------
    def section_at(self, va: int) -> Section | None:
        for s in self.sections:
            if s.contains(va):
                return s
        return None

    @property
    def text(self) -> Section | None:
        """Best-guess executable section (.text / __text / first exec section)."""
        for cand in (".text", "__text", "CODE", "code"):
            for s in self.sections:
                if s.name == cand:
                    return s
        for s in self.sections:
            if "X" in s.flags.upper():
                return s
        return self.sections[0] if self.sections else None

    def read_va(self, va: int, n: int) -> bytes:
        """Read `n` bytes of mapped data starting at virtual address `va`."""
        s = self.section_at(va)
        if not s:
            return b""
        off = va - s.va
        data = self._section_raw(s)
        return data[off : off + n]

    def func_at(self, va: int) -> Func | None:
        return self._by_va.get(va)

    def nearest_func(self, va: int) -> Func | None:
        """The named function whose address is the greatest <= va (symbolization)."""
        best = None
        for f in self.funcs:
            if f.va <= va and (best is None or f.va > best.va):
                best = f
        return best

    # -- internals ---------------------------------------------------------
    _raw_cache: dict[str, bytes] = field(default_factory=dict, repr=False)

    def _section_raw(self, s: Section) -> bytes:
        if s.name not in self._raw_cache:
            with open(self.path, "rb") as fh:
                fh.seek(s.raw_off)
                self._raw_cache[s.name] = fh.read(s.raw_size)
        return self._raw_cache[s.name]

    def reindex(self) -> None:
        self.funcs.sort(key=lambda f: f.va)
        self._by_va = {f.va: f for f in self.funcs}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
_MACHINE_TO_ARCH = {
    # PE machine
    0x14C: Arch.X86,
    0x8664: Arch.X64,
    0x1C0: Arch.ARM,
    0xAA64: Arch.ARM64,
}


def _detect_arch(b) -> Arch:
    fmt = str(b.format)
    try:
        if "PE" in fmt:
            m = int(b.header.machine.value)
            return _MACHINE_TO_ARCH.get(m, Arch.UNKNOWN)
        if "ELF" in fmt:
            mach = str(b.header.machine_type)
            if "x86_64" in mach or "X86_64" in mach:
                return Arch.X64
            if "i386" in mach or "I386" in mach or "386" in mach:
                return Arch.X86
            if "AARCH64" in mach or "aarch64" in mach:
                return Arch.ARM64
            if "ARM" in mach:
                return Arch.ARM
        if "MachO" in fmt or "MACHO" in fmt:
            cpu = str(b.header.cpu_type)
            if "x86_64" in cpu or "X86_64" in cpu:
                return Arch.X64
            if "x86" in cpu or "X86" in cpu:
                return Arch.X86
            if "ARM64" in cpu or "arm64" in cpu:
                return Arch.ARM64
            if "ARM" in cpu:
                return Arch.ARM
    except Exception:
        pass
    return Arch.UNKNOWN


def _flags(s) -> str:
    out = ""
    try:
        ch = s.characteristics
        # PE: 0x20000000 exec, 0x40000000 read, 0x80000000 write
        if ch & 0x20000000:
            out += "X"
        if ch & 0x40000000:
            out += "R"
        if ch & 0x80000000:
            out += "W"
    except Exception:
        # ELF / Mach-O: rely on name heuristic, mark text exec
        if s.name in (".text", "__text", "CODE"):
            out = "RX"
    return out or "?"


def _build_sections(b: Any, base: int) -> list[Section]:
    """Section list with PE RVAs promoted to VAs; bad entries are skipped."""
    out: list[Section] = []
    for s in b.sections:
        try:
            va = int(s.virtual_address)
            if va and base and va < base:
                # LIEF gives RVA for PE
                va += base
            out.append(
                Section(
                    name=(s.name or "").rstrip("\x00") or "<unnamed>",
                    va=va,
                    size=int(getattr(s, "virtual_size", 0) or s.size),
                    raw_off=int(s.offset),
                    raw_size=int(s.size),
                    flags=_flags(s),
                )
            )
        except Exception as e:
            log.debug("skipped section %r: %s", getattr(s, "name", "?"), e)
            continue
    return out


def _symbol_va(sym, img: Image) -> int | None:
    """Virtual address of a symbol, or None if it cannot be placed.

    PE COFF symbols carry a section-relative `value` plus a 1-based `section_idx`;
    resolve those against the section's VA. ELF / Mach-O symbol values are already
    addresses (an RVA below the base is promoted).
    """
    val = int(getattr(sym, "value", 0) or 0)
    idx = getattr(sym, "section_idx", None)
    if isinstance(idx, int) and 1 <= idx <= len(img.sections):
        # PE COFF: section base + offset
        return img.sections[idx - 1].va + val
    if val == 0:
        return None
    if img.base and val < img.base and img.section_at(val + img.base):
        val += img.base
    return val


def load_image(path: str, *, fmt: str | None = None, arch: Arch | None = None) -> Image:
    """Parse `path` with LIEF and build a uniform `Image`.

    `fmt` / `arch` override auto-detection (used by the TUI's format picker).
    Raises ValueError if the file cannot be parsed as a known object format.
    """
    if not os.path.isfile(path):
        raise ValueError(f"not a file: {path}")

    # LIEF's parse() return is a format union with incomplete stubs; the loader
    # below is defensively wrapped, so treat the binary as untyped.
    b: Any = lief.parse(path)
    if b is None:
        raise ValueError(f"LIEF could not parse {path!r} as a known binary format")

    # FORMATS.PE -> PE
    detected_fmt = str(b.format).split(".")[-1]
    use_fmt = fmt or detected_fmt
    use_arch = arch or _detect_arch(b)

    try:
        base = int(b.imagebase)
    except Exception:
        base = 0

    img = Image(path=path, fmt=use_fmt, arch=use_arch, base=base, _lief=b)
    img.sections = _build_sections(b, base)

    # Exported functions
    seen: set[int] = set()
    for f in b.exported_functions:
        try:
            va = int(f.address)
            if base and va < base:
                va += base
            name = f.name or f"export_{va:x}"
            img.funcs.append(
                Func(name=name, va=va, kind="export", demangled=_demangle(name))
            )
            seen.add(va)
        except Exception as e:
            log.debug("skipped export %r: %s", getattr(f, "name", "?"), e)
            continue

    # Imported functions (thunks) — useful for the demo's import view
    try:
        for f in b.imported_functions:
            va = int(getattr(f, "address", 0) or 0)
            name = f.name or ""
            if name:
                img.funcs.append(Func(name=name, va=va, kind="import"))
    except Exception:
        pass

    # Generic symbols (named functions in ELF/Mach-O symtabs, and PE COFF symbol
    # tables from mingw/debug builds).
    try:
        for sym in getattr(b, "symbols", []):
            name = getattr(sym, "name", "") or ""
            if not name:
                continue
            sva = _symbol_va(sym, img)
            if sva is None or sva in seen or not img.section_at(sva):
                continue
            img.funcs.append(
                Func(name=name, va=sva, kind="symbol", demangled=_demangle(name))
            )
            seen.add(sva)
    except Exception:
        pass

    # Entrypoint
    try:
        ep = int(b.entrypoint)
        if ep and ep not in seen and img.section_at(ep):
            img.funcs.append(Func(name="entry", va=ep, kind="entry"))
    except Exception:
        pass

    img.reindex()
    log.info(
        "loaded %s: %s/%s base=%#x, %d sections, %d functions",
        os.path.basename(path),
        img.fmt,
        img.arch.value,
        img.base,
        len(img.sections),
        len(img.funcs),
    )
    return img


def _demangle(name: str) -> str | None:
    """Best-effort symbol demangling (MSVC / Itanium) when tooling is present."""
    if not name or not (name.startswith("?") or name.startswith("_Z")):
        return None
    try:
        # optional
        import cxxfilt

        return cxxfilt.demangle(name)
    except Exception:
        return None
