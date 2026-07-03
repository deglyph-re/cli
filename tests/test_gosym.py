# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Go pclntab function-name recovery."""

from __future__ import annotations

from deglyph.core.image import Arch, Image, Section
from deglyph.re.gosym import apply_go_symbols, go_functions


def _go118_pclntab(funcs: list[tuple[int, str]], *, text_start: int = 0x1000) -> bytes:
    """A minimal, valid go1.18 pclntab for `funcs` = [(entry_off, name), ...]."""
    psize = 8
    header_len = 8 + 8 * psize
    functab_off = header_len
    functab_len = (len(funcs) + 1) * 8
    func_structs_off = functab_off + functab_len
    funcname_off = func_structs_off + len(funcs) * 8

    # funcnametab: each name NUL-terminated; record each name's index.
    name_blob = bytearray()
    name_idx: list[int] = []
    for _entry, name in funcs:
        name_idx.append(len(name_blob))
        name_blob += name.encode() + b"\x00"

    total = funcname_off + len(name_blob)
    buf = bytearray(total)

    # pcHeader
    buf[0:4] = (0xFFFFFFF0).to_bytes(4, "little")
    buf[6] = 1
    buf[7] = psize

    def put_ptr(off: int, val: int) -> None:
        buf[off : off + psize] = val.to_bytes(psize, "little")

    def put_u32(off: int, val: int) -> None:
        buf[off : off + 4] = (val & 0xFFFFFFFF).to_bytes(4, "little")

    put_ptr(8, len(funcs))
    put_ptr(8 + 2 * psize, text_start)
    put_ptr(8 + 3 * psize, funcname_off)
    put_ptr(8 + 7 * psize, functab_off)

    for i, (entry, _name) in enumerate(funcs):
        funcoff = func_structs_off + i * 8
        put_u32(functab_off + i * 8, entry)
        put_u32(functab_off + i * 8 + 4, funcoff)
        put_u32(funcoff, entry)
        put_u32(funcoff + 4, name_idx[i])
    # sentinel functab entry
    put_u32(functab_off + len(funcs) * 8, funcs[-1][0] + 0x10)

    buf[funcname_off:] = name_blob
    return bytes(buf)


def _image_with_pclntab(tmp_path, pcln: bytes, *, text_size: int = 0x100) -> Image:
    text = b"\x90" * text_size
    blob = text.ljust(0x200, b"\x00") + pcln
    p = tmp_path / "go.bin"
    p.write_bytes(blob)
    img = Image(path=str(p), fmt="ELF", arch=Arch.X64, base=0)
    img.sections.append(
        Section(
            name=".text",
            va=0x1000,
            size=text_size,
            raw_off=0,
            raw_size=text_size,
            flags="RX",
        )
    )
    img.sections.append(
        Section(
            name=".gopclntab",
            va=0x4000,
            size=len(pcln),
            raw_off=0x200,
            raw_size=len(pcln),
            flags="R",
        )
    )
    img.reindex()
    return img


def test_recovers_go118_names(tmp_path):
    pcln = _go118_pclntab([(0x0, "main.main"), (0x20, "runtime.printlock")])
    img = _image_with_pclntab(tmp_path, pcln)
    funcs = {gf.va: gf.name for gf in go_functions(img)}
    assert funcs[0x1000] == "main.main"
    assert funcs[0x1020] == "runtime.printlock"


def test_apply_registers_named_functions(tmp_path):
    pcln = _go118_pclntab([(0x0, "main.main"), (0x20, "net_http.(*Server).Serve")])
    img = _image_with_pclntab(tmp_path, pcln)
    added = apply_go_symbols(img)
    assert added == 2
    f = img.func_at(0x1020)
    assert f is not None and f.name == "net_http.(*Server).Serve"
    assert f.kind == "symbol" and f.evidence == ("go pclntab",)


def test_container_symbol_wins_over_recovered(tmp_path):
    pcln = _go118_pclntab([(0x0, "main.main")])
    img = _image_with_pclntab(tmp_path, pcln)
    # Pre-place a real symbol at the same VA; recovery must not overwrite it.
    from deglyph.core.image import Func

    img.funcs.append(Func(name="real_main", va=0x1000, kind="symbol"))
    img.reindex()
    added = apply_go_symbols(img)
    assert added == 0
    assert img.func_at(0x1000).name == "real_main"


def test_no_pclntab_returns_empty(code_image):
    img = code_image(b"\x90\x90\xc3")
    assert go_functions(img) == []
    assert apply_go_symbols(img) == 0


def test_magic_scan_finds_pclntab_in_rodata(tmp_path):
    # No .gopclntab section: the header sits in .rodata and must be found by the
    # magic scan.
    pcln = _go118_pclntab([(0x0, "main.main")])
    text = b"\x90" * 0x100
    blob = text.ljust(0x200, b"\x00") + b"\x11" * 0x40 + pcln
    p = tmp_path / "go2.bin"
    p.write_bytes(blob)
    img = Image(path=str(p), fmt="ELF", arch=Arch.X64, base=0)
    img.sections.append(
        Section(
            name=".text", va=0x1000, size=0x100, raw_off=0, raw_size=0x100, flags="RX"
        )
    )
    img.sections.append(
        Section(
            name=".rodata",
            va=0x4000,
            size=0x40 + len(pcln),
            raw_off=0x200,
            raw_size=0x40 + len(pcln),
            flags="R",
        )
    )
    img.reindex()
    funcs = {gf.name for gf in go_functions(img)}
    assert "main.main" in funcs


def test_corrupt_header_yields_nothing(tmp_path):
    # A valid magic but an absurd nfunc must abort cleanly, not loop or crash.
    pcln = bytearray(_go118_pclntab([(0x0, "main.main")]))
    pcln[8:16] = (5_000_000).to_bytes(8, "little")
    img = _image_with_pclntab(tmp_path, bytes(pcln))
    assert go_functions(img) == []
