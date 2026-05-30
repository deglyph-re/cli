# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Whole-image data xrefs and pointer-table decoding (Section 4)."""

from __future__ import annotations

import struct
import tempfile

from deglyph.core.image import Arch, Image, Section
from deglyph.re import referenced_data
from deglyph.re.xref import data_xrefs_to, xrefs_to


def _write(code: bytes) -> str:
    p = tempfile.mktemp()
    with open(p, "wb") as fh:
        fh.write(code)
    return p


def _img(code: bytes, sections: list[Section], arch: Arch = Arch.X64) -> Image:
    img = Image(path=_write(code), fmt="RAW", arch=arch, base=0)
    img.sections.extend(sections)
    img.reindex()
    return img


def _lea(reg_modrm: bytes, at: int, target: int) -> bytes:
    """x86-64 `lea reg, [rip+disp]` (7 bytes) at `at` resolving to `target`."""
    return bytes.fromhex("488d") + reg_modrm + struct.pack("<i", target - (at + 7))


def test_data_xref_finds_every_referencing_site():
    # Two leas, at 0x1000 and 0x1008, both resolving to a datum at 0x1020 in
    # .rdata; the index must record both sites, not just one nearby linear hit.
    code = bytearray(b"\x90" * 0x20)
    code[0x00:0x07] = _lea(b"\x0d", 0x1000, 0x1020)
    code[0x08:0x0F] = _lea(b"\x15", 0x1008, 0x1020)
    code[0x0F] = 0xC3
    img = _img(
        bytes(code) + b"hi\x00\x00\x00\x00\x00",
        [
            Section(
                name=".text", va=0x1000, size=0x20, raw_off=0, raw_size=0x20, flags="RX"
            ),
            Section(
                name=".rdata", va=0x1020, size=8, raw_off=0x20, raw_size=8, flags="R"
            ),
        ],
    )
    assert set(data_xrefs_to(img, 0x1020)) == {0x1000, 0x1008}
    # xrefs_to merges code + data; no code edges to 0x1020 here
    assert set(xrefs_to(img, 0x1020)) == {0x1000, 0x1008}


def test_data_xref_empty_for_unreferenced_address():
    img = _img(
        bytes.fromhex("c3"),
        [Section(name=".text", va=0x1000, size=1, raw_off=0, raw_size=1, flags="RX")],
    )
    assert data_xrefs_to(img, 0x9999) == []


def test_pointer_table_decoded_as_first_class_ref():
    # A function points at a 3-entry pointer array in .data; each entry points
    # back into the mapped image, so referenced_data labels it a table.
    code = bytearray(b"\x90" * 0x10)
    code[0x00:0x07] = _lea(b"\x05", 0x1000, 0x1010)
    code[0x07] = 0xC3
    table = (0x1000).to_bytes(8, "little") * 3
    img = _img(
        bytes(code) + table,
        [
            Section(
                name=".text", va=0x1000, size=0x10, raw_off=0, raw_size=0x10, flags="RX"
            ),
            Section(
                name=".data",
                va=0x1010,
                size=0x18,
                raw_off=0x10,
                raw_size=0x18,
                flags="R",
            ),
        ],
    )
    refs = referenced_data(img, 0x1000)
    assert any(r.kind == "table" and "pointer" in r.text for r in refs)


def test_data_xref_is_arch_neutral_arm64():
    # ldr x0, #0x1008 ; ret -- an AArch64 PC-relative literal load. capstone
    # resolves the literal address into the IMM operand, so the data edge to the
    # .data datum at 0x1008 is recorded through the same arch-neutral path.
    code = bytes.fromhex("40000058") + bytes.fromhex("c0035fd6")
    img = _img(
        code,
        [
            Section(name=".text", va=0x1000, size=8, raw_off=0, raw_size=8, flags="RX"),
            Section(name=".data", va=0x1008, size=8, raw_off=0, raw_size=0, flags="R"),
        ],
        arch=Arch.ARM64,
    )
    assert 0x1000 in data_xrefs_to(img, 0x1008)
