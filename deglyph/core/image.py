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
    # 32-bit RISC-V
    RISCV32 = "riscv32"
    # 64-bit RISC-V
    RISCV64 = "riscv64"
    UNKNOWN = "unknown"

    @property
    def bits(self) -> int:
        return {
            Arch.X86: 32,
            Arch.X64: 64,
            Arch.ARM: 32,
            Arch.ARM64: 64,
            Arch.RISCV32: 32,
            Arch.RISCV64: 64,
        }.get(self, 0)


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
    # export | symbol | entry | import | sub
    kind: str = "func"
    ordinal: int | None = None
    demangled: str | None = None
    # 0 = unknown (computed lazily)
    size: int = 0
    # "confirmed" for a named address from the container (export/symbol/entry/
    # import) or a direct-call discovery; "candidate" for a recovered start with
    # weaker evidence (reached only by a tail jmp). Surfaced in the UI and JSON.
    confidence: str = "confirmed"
    # Short human-readable reasons the start was recovered, e.g.
    # "direct call from sub_401000". Empty for container-provided functions.
    evidence: tuple[str, ...] = ()

    @property
    def display(self) -> str:
        return self.demangled or self.name

    @property
    def is_candidate(self) -> bool:
        return self.confidence == "candidate"


@dataclass(slots=True)
class Slice:
    """One architecture slice of a fat (universal) Mach-O.

    `index` is the slice's position in the fat header; `arch` is the decoded
    architecture; `cpu` is LIEF's raw cpu_type label for display. `fat_offset`
    is where the slice's Mach-O begins inside the whole file, the value added
    to each section offset so a file seek lands in the right slice.
    """

    index: int
    arch: Arch
    cpu: str
    fat_offset: int

    @property
    def label(self) -> str:
        return self.cpu


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
    # Fat (universal) Mach-O slices, if any; the chosen one is `slice_index`.
    # Empty for a thin binary, PE, or ELF.
    slices: list[Slice] = field(default_factory=list)
    slice_index: int = 0

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
    _raw_cache: dict[tuple[str, int, int], bytes] = field(
        default_factory=dict, repr=False
    )

    def _section_raw(self, s: Section) -> bytes:
        # Key on (name, offset, size), not name alone: a binary can carry two
        # sections with the same name at different offsets (Mach-O's two
        # __const, ELF/PE duplicates), and a name-only key would serve the
        # first section's bytes for every later same-named one.
        key = (s.name, s.raw_off, s.raw_size)
        if key not in self._raw_cache:
            # The single I/O choke point for every whole-image pass; a bad
            # offset/size or a truncated, deleted, or unreadable file (a corrupt
            # LIEF offset folds to a negative raw_off, an unmount races a worker)
            # must degrade to an empty region, not abort the pass.
            try:
                with open(self.path, "rb") as fh:
                    fh.seek(s.raw_off)
                    self._raw_cache[key] = fh.read(s.raw_size)
            except OSError as e:
                log.debug("section %r raw read failed: %s", s.name, e)
                self._raw_cache[key] = b""
        return self._raw_cache[key]

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
            if "RISCV" in mach.upper():
                return Arch.RISCV64 if _elf_is_64bit(b) else Arch.RISCV32
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


def _elf_is_64bit(b) -> bool:
    """True when an ELF is ELFCLASS64, best-effort across LIEF versions."""
    try:
        cls = str(getattr(b.header, "identity_class", ""))
        if "64" in cls:
            return True
        if "32" in cls:
            return False
    except Exception:
        pass
    # Fall back to the imagebase width: a 64-bit ELF addresses above 4 GiB rarely,
    # so default to 64-bit, the common RISC-V target, when the class is unreadable.
    return True


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


def _build_sections(b: Any, base: int, fat_offset: int = 0) -> list[Section]:
    """Section list with PE RVAs promoted to VAs; bad entries are skipped.

    `fat_offset` is the slice's start inside a fat Mach-O file; LIEF reports a
    section `offset` relative to the slice, so add the fat base to land an
    absolute file seek in the right slice (0 for thin / PE / ELF).
    """
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
                    raw_off=int(s.offset) + fat_offset,
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


def _macho_slices(path: str) -> tuple[list[Any], list[Slice]]:
    """Parse a Mach-O as a fat container, returning its slices and metadata.

    Returns `([], [])` when the file is not a (multi-slice) Mach-O, so the
    caller falls back to the plain `lief.parse` path. A thin Mach-O parses as a
    one-entry FatBinary; only a genuine multi-slice file is treated as fat.
    """
    try:
        fat = lief.MachO.parse(path)
    except Exception:
        return [], []
    if fat is None or len(fat) <= 1:
        return [], []
    bins: list[Any] = []
    slices: list[Slice] = []
    for i in range(len(fat)):
        m = fat.at(i)
        bins.append(m)
        cpu = str(getattr(m.header, "cpu_type", "")).split(".")[-1] or f"slice{i}"
        slices.append(
            Slice(
                index=i,
                arch=_detect_arch(m),
                cpu=cpu,
                fat_offset=int(getattr(m, "fat_offset", 0) or 0),
            )
        )
    return bins, slices


def _host_arch() -> Arch:
    """The architecture of the machine deglyph is running on (best effort)."""
    import platform

    m = platform.machine().lower()
    if m in ("arm64", "aarch64"):
        return Arch.ARM64
    if m in ("x86_64", "amd64", "x64"):
        return Arch.X64
    if m in ("i386", "i686", "x86"):
        return Arch.X86
    return Arch.UNKNOWN


def _pick_slice(slices: list[Slice], arch: Arch | None) -> int:
    """Choose a fat slice: an explicit arch, else the host arch, else the first.

    An `arch` override wins when a slice matches it. Otherwise prefer the slice
    matching the host machine so the user sees the code that actually runs here,
    falling back to the first slice when nothing matches.
    """
    if arch is not None:
        for s in slices:
            if s.arch == arch:
                return s.index
    host = _host_arch()
    for s in slices:
        if s.arch == host:
            return s.index
    return slices[0].index


def _resolve_binary(
    path: str, arch: Arch | None, slice_index: int | None
) -> tuple[Any, list[Slice], int, int]:
    """Parse `path` and pick a slice: returns (lief_binary, slices, index, fat_off).

    A fat Mach-O carries several architecture slices; `lief.parse` would hand
    back only the first. Resolve the slices, pick one (explicit index, then the
    requested arch, then the host arch, then the first), and report its fat
    offset so the section reader seeks into that slice rather than the header.
    A thin file returns an empty slice list and a zero fat offset.
    """
    fat_bins, slices = _macho_slices(path)
    if slices:
        chosen = slice_index if slice_index is not None else _pick_slice(slices, arch)
        chosen = next((s.index for s in slices if s.index == chosen), slices[0].index)
        return fat_bins[chosen], slices, chosen, slices[chosen].fat_offset
    # LIEF's parse() return is a format union with incomplete stubs; the loader
    # below is defensively wrapped, so treat the binary as untyped.
    return lief.parse(path), [], 0, 0


def _collect_funcs(b: Any, img: Image, base: int) -> None:
    """Populate `img.funcs` from the binary's exports, imports, symbols, entry.

    Each source is wrapped so one malformed table never aborts the others; an
    address already claimed by an export is not re-added as a symbol/entry.
    """
    seen: set[int] = set()
    # Exported functions
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

    # Imported functions (thunks): useful for the demo's import view
    try:
        for f in b.imported_functions:
            va = int(getattr(f, "address", 0) or 0)
            name = f.name or ""
            if name:
                img.funcs.append(Func(name=name, va=va, kind="import"))
    except Exception:
        pass

    # Generic symbols (named functions in ELF/Mach-O symtabs, and PE COFF symbol
    # tables from mingw/debug builds). Two classes of non-function symbol flood
    # this table on a real binary and are filtered out:
    #
    #   - Section-definition symbols carry the section's own name (.text,
    #     .idata$6, .debug_line, ...) at the section start. LIEF surfaces one per
    #     section; a real function is never literally named ".text".
    #   - Data symbols (IAT slots in .idata, mingw .refptr stubs in .rdata, .bss
    #     and .data variables) are addresses, not code.
    #
    # Both are excluded by requiring a symbol's address to land in an executable
    # section. On a mingw PE this is most of the table (797 of 994 on demo.exe
    # are section or data symbols). The exec test is positive-only: a section
    # whose flags could not be determined ("?") is kept, so an ELF/Mach-O symbol
    # in an oddly-flagged code section is never dropped on uncertainty.
    section_names = {s.name for s in img.sections}
    try:
        for sym in getattr(b, "symbols", []):
            name = getattr(sym, "name", "") or ""
            if not name or name.rstrip("\x00") in section_names:
                continue
            sva = _symbol_va(sym, img)
            if sva is None or sva in seen:
                continue
            sec = img.section_at(sva)
            if sec is None:
                continue
            # Executable, or flags unknown ("?"): keep. Positively non-exec: drop.
            if "X" not in sec.flags.upper() and sec.flags != "?":
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


def load_image(
    path: str,
    *,
    fmt: str | None = None,
    arch: Arch | None = None,
    slice_index: int | None = None,
) -> Image:
    """Parse `path` with LIEF and build a uniform `Image`.

    `fmt` / `arch` override auto-detection (used by the TUI's format picker).
    For a fat (universal) Mach-O, `slice_index` selects a slice directly; with
    none given the host arch is preferred (then `arch`, then the first slice).
    Raises ValueError if the file cannot be parsed as a known object format.
    """
    if not os.path.isfile(path):
        raise ValueError(f"not a file: {path}")

    b, slices, chosen, fat_offset = _resolve_binary(path, arch, slice_index)
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

    img = Image(
        path=path,
        fmt=use_fmt,
        arch=use_arch,
        base=base,
        _lief=b,
        slices=slices,
        slice_index=chosen,
    )
    img.sections = _build_sections(b, base, fat_offset)
    _collect_funcs(b, img, base)
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
    """Best-effort symbol demangling (MSVC / Itanium C++ / Rust legacy + v0)."""
    from .demangle import demangle

    return demangle(name)
