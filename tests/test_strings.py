# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Value extraction: image-wide strings and per-function data references."""

from __future__ import annotations

import os

import pytest

from deglyph.core.image import load_image
from deglyph.re import extract_strings, referenced_data, string_runs

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def test_string_runs_ascii_and_utf16():
    # ascii "HELLO", then (after a non-NUL gap) utf16 "WIDE", then a too-short "ab"
    data = b"\x01HELLO\xff\xffW\x00I\x00D\x00E\x00\x00ab"
    found = {(enc, text) for _off, enc, text in string_runs(data, min_len=4)}
    assert ("ascii", "HELLO") in found
    assert ("utf16", "WIDE") in found
    # below min_len
    assert not any(text == "ab" for _e, text in found)


def test_extract_strings_maps_address_and_section(code_image):
    # printable run at offset 2
    img = code_image(b"\x90\x90API_TOKEN=abcd1234\x00")
    hit = next(s for s in extract_strings(img, min_len=4) if "API_TOKEN" in s.text)
    assert hit.text == "API_TOKEN=abcd1234"
    assert hit.encoding == "ascii"
    assert hit.section == ".text"
    # section va + file offset
    assert hit.va == 0x1000 + 2


def test_referenced_data_is_empty_on_non_x86(code_image):
    from deglyph.core.image import Arch

    img = code_image(bytes.fromhex("00 00 00 00"), arch=Arch.ARM64)
    assert referenced_data(img, 0x1000) == []


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_extract_strings_finds_planted_secret():
    img = load_image(SAMPLE)
    secret = [s for s in extract_strings(img) if "S3cr3t-demo-API-key" in s.text]
    assert secret and secret[0].section == ".rdata"


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_referenced_data_resolves_function_pointers():
    img = load_image(SAMPLE)
    refs = []
    for f in img.funcs:
        refs = referenced_data(img, f.va)
        if refs:
            break
    assert refs, "expected at least one function that references data"
    assert all(r.kind in ("str", "data") for r in refs)
    assert all(img.section_at(r.target) is not None for r in refs)
