# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""String extraction, encoding labels, categories, and per-function data refs."""

from __future__ import annotations

import os

import pytest

from deglyph.core.image import Arch, Image, Section
from deglyph.re import extract_strings, referenced_data, string_runs

_DEMO = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def test_string_runs_ascii_and_utf16():
    data = b"hello\x00\x00w\x00i\x00d\x00e\x00\x00"
    runs = list(string_runs(data, min_len=4))
    encs = {enc for _, enc, _ in runs}
    texts = {text for _, _, text in runs}
    assert "ascii" in encs and "utf-16le" in encs
    assert "hello" in texts and "wide" in texts


def test_string_runs_detects_utf8():
    # "café menu" -- the e-acute makes it a UTF-8 (not pure-ASCII) run.
    data = "café menu".encode() + b"\x00"
    runs = list(string_runs(data, min_len=4))
    utf8 = [(enc, text) for _, enc, text in runs if enc == "utf-8"]
    assert utf8 and any("café" in t for _, t in utf8)


def test_extract_strings_maps_address_and_section(code_image):
    img = code_image(b"the quick brown fox\x00")
    out = extract_strings(img)
    assert any(s.text.startswith("the quick") for s in out)
    hit = next(s for s in out if s.text.startswith("the quick"))
    assert hit.va == 0x1000
    assert hit.section == ".text"
    assert hit.encoding == "ascii"
    assert hit.category == "literal"


def test_extract_strings_default_drops_unmapped_and_metadata():
    # The default view is mapped, real literals only: no VA-0 runs and no
    # section-name / symbol categories. raw=True restores the full dump.
    if not os.path.isfile(_DEMO):
        pytest.skip("demo.exe not built")
    from deglyph.core.image import load_image

    img = load_image(_DEMO)
    clean = extract_strings(img)
    rawall = extract_strings(img, raw=True)
    assert clean, "expected some mapped literals"
    assert all(s.va != 0 for s in clean)
    assert all(s.category == "literal" for s in clean)
    # the raw dump is strictly larger and carries the dropped categories
    assert len(rawall) > len(clean)
    assert any(s.category == "section-name" for s in rawall)


def test_extract_strings_section_filter():
    if not os.path.isfile(_DEMO):
        pytest.skip("demo.exe not built")
    from deglyph.core.image import load_image

    img = load_image(_DEMO)
    rd = extract_strings(img, section=".rdata")
    assert rd and all(s.section == ".rdata" for s in rd)


def test_extract_strings_min_len():
    img = code_image_blob(b"ab\x00abcdefgh\x00")
    short = {s.text for s in extract_strings(img, min_len=4)}
    long = {s.text for s in extract_strings(img, min_len=8)}
    assert "abcdefgh" in short and "abcdefgh" in long
    # "ab" is below both floors; nothing 2-char appears
    assert all(len(s) >= 8 for s in long)


def code_image_blob(blob: bytes) -> Image:
    # a one-section image over raw bytes at a mapped VA (helper, no fixture)
    import tempfile

    p = tempfile.mktemp()
    with open(p, "wb") as fh:
        fh.write(blob)
    img = Image(path=p, fmt="RAW", arch=Arch.X64, base=0)
    img.sections.append(
        Section(
            name=".text",
            va=0x1000,
            size=len(blob),
            raw_off=0,
            raw_size=len(blob),
            flags="RX",
        )
    )
    img.reindex()
    return img


def test_referenced_data_resolves_strings_on_x86():
    # lea rcx, [rip+2] -> 0x1009, a string in a non-executable section.
    # referenced_data skips executable targets (those are calls/jumps), so the
    # string must live in a data section, not in .text. .rdata starts at 0x1008
    # (raw_off 8); "hello" is at code offset 9, i.e. VA 0x1009.
    #  0x1000: 48 8d 0d 02 00 00 00   lea rcx, [rip+2]   (next_pc 0x1007 + 2)
    #  0x1007: c3                     ret
    code = bytes.fromhex("488d0d02000000c3") + b"\x00hello\x00\x00"
    import tempfile

    p = tempfile.mktemp()
    with open(p, "wb") as fh:
        fh.write(code)
    img = Image(path=p, fmt="RAW", arch=Arch.X64, base=0)
    img.sections.append(
        Section(name=".text", va=0x1000, size=8, raw_off=0, raw_size=8, flags="RX")
    )
    img.sections.append(
        Section(
            name=".rdata",
            va=0x1008,
            size=len(code) - 8,
            raw_off=8,
            raw_size=len(code) - 8,
            flags="R",
        )
    )
    img.reindex()
    out = referenced_data(img, 0x1000)
    assert any(r.kind == "str" and "hello" in r.text for r in out)


def test_extract_strings_finds_planted_secret():
    if not os.path.isfile(_DEMO):
        pytest.skip("demo.exe not built")
    from deglyph.core.image import load_image

    img = load_image(_DEMO)
    out = extract_strings(img)
    assert any("S3cr3t" in s.text for s in out)
