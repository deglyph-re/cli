# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Hostile-input robustness: deglyph parses arbitrary, possibly-malformed binaries.
Malformed containers must fail with a clean ValueError (not an arbitrary crash),
and the per-instruction scanners must tolerate garbage without raising.
"""

from __future__ import annotations

import pytest

from deglyph.core import Arch, Disassembler, load_image
from deglyph.re import (
    call_immediate_args,
    callees_of,
    callers_of,
    detect_crc_loops,
    function_constants,
    immediate_stores,
    thunk_chain,
)

UNPARSEABLE = {
    "empty": b"",
    "garbage": bytes(range(256)) * 4,
    "truncated_pe": b"MZ" + b"\x00" * 64,
    "text": b"#!/bin/sh\necho hi\n" * 8,
}


@pytest.mark.parametrize("name,data", list(UNPARSEABLE.items()))
def test_unparseable_raises_valueerror(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    with pytest.raises(ValueError):
        load_image(str(p))


def test_missing_file_raises_valueerror(tmp_path):
    with pytest.raises(ValueError):
        load_image(str(tmp_path / "does-not-exist.bin"))


def test_detectors_tolerate_garbage_code(code_image):
    # Pseudo-random but deterministic bytes; skipdata keeps Capstone from raising.
    blob = bytes((i * 37 + 11) & 0xFF for i in range(512))
    img = code_image(blob)
    # None of these may raise on undecodable / nonsensical streams.
    immediate_stores(img, 0x1000)
    call_immediate_args(img, 0x1000)
    detect_crc_loops(img, 0x1000)
    function_constants(img, 0x1000)
    assert thunk_chain(img, 0x1000)[0] == 0x1000
    callers_of(img, 0x1000)
    callees_of(img, 0x1000)
    list(Disassembler(img).at(0x1000, len(blob)))


def test_detectors_on_empty_region(code_image):
    # A function VA pointing past any mapped bytes yields empty results, no crash.
    # lone ret
    img = code_image(b"\xc3")
    assert immediate_stores(img, 0x1000) == []
    assert detect_crc_loops(img, 0x1000) == []
    assert call_immediate_args(img, 0x1000) == []


def test_load_does_not_crash_on_minimal_elf_header(tmp_path):
    # `\x7fELF` + zeroes is just parseable; it must load (possibly 0 functions)
    # and downstream queries must not raise.
    p = tmp_path / "min.elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    try:
        img = load_image(str(p))
    except ValueError:
        pytest.skip("LIEF rejected the minimal header on this version")
    assert img.arch in tuple(Arch)
    # builds the index over whatever (if any) text exists
    callers_of(img, 0)
