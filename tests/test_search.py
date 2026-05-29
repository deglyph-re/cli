# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Image-wide search: byte patterns, strings, and immediate constants."""

from __future__ import annotations

from deglyph.re import find_bytes, find_immediate, find_string

# "HELLO" ascii, then: shr eax,1 ; xor eax,0x8408 ; ret
BLOB = b"HELLO" + bytes.fromhex("d1 e8  35 08 84 00 00  c3")


def test_find_bytes_wildcard(code_image):
    img = code_image(BLOB)
    # xor eax, 0x..84..
    hits = find_bytes(img, "35 ?? 84")
    assert hits and all(h.kind == "bytes" for h in hits)


def test_find_string_ascii(code_image):
    img = code_image(BLOB)
    hits = find_string(img, "HELLO")
    assert hits and hits[0].detail == "HELLO"
    # section base; string sits at the start
    assert hits[0].va == 0x1000


def test_find_immediate_locates_constant(code_image):
    img = code_image(BLOB)
    hits = find_immediate(img, 0x8408)
    assert hits and hits[0].kind.startswith("imm")


def test_find_string_absent_is_empty(code_image):
    img = code_image(BLOB)
    assert find_string(img, "NOTPRESENT") == []
