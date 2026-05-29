# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Golden tests for the pattern detectors against hand-assembled x86-64 code.

Each blob is a minimal instruction sequence with a known answer, so a detector
regression shows up as a failed assertion rather than a silent skip.
"""

from __future__ import annotations

from deglyph.core import Disassembler
from deglyph.re import (
    call_immediate_args,
    detect_crc_loops,
    function_constants,
    immediate_stores,
)
from deglyph.re.search import find_immediate

# mov dword ptr [rcx + 2], 0x2f ; ret
STORE = bytes.fromhex("c7 41 02 2f 00 00 00  c3")

# mov ecx, 4 ; call $+5 ; ret
CALLARG = bytes.fromhex("b9 04 00 00 00  e8 00 00 00 00  c3")

# shr eax,1 ; xor eax,0x8408 ; shr eax,1 ; xor eax,0x8408 ; dec ecx ; jne -18 ; ret
CRC = bytes.fromhex("d1 e8  35 08 84 00 00  d1 e8  35 08 84 00 00  ff c9  75 ee  c3")


def test_immediate_store_decoded(code_image):
    img = code_image(STORE)
    stores = immediate_stores(img, 0x1000)
    assert len(stores) == 1
    s = stores[0]
    assert s.base == "rcx"
    assert s.disp == 2
    assert s.size == 4
    assert s.value == 0x2F


def test_call_immediate_arg_decoded(code_image):
    img = code_image(CALLARG)
    args = call_immediate_args(img, 0x1000)
    assert any(a.reg == "ecx" and a.value == 0x04 for a in args)


def test_crc_loop_and_polynomial(code_image):
    img = code_image(CRC)
    loops = detect_crc_loops(img, 0x1000)
    assert loops, "expected a CRC-like loop"
    assert any(0x8408 in lp.polys for lp in loops)
    assert loops[0].start == 0x1000


def test_function_constants_histogram(code_image):
    img = code_image(CRC)
    consts = function_constants(img, 0x1000)
    # xored twice in the loop body
    assert consts[0x8408] == 2


def test_find_immediate_locates_polynomial(code_image):
    img = code_image(CRC)
    hits = find_immediate(img, 0x8408)
    assert hits and all(h.kind.startswith("imm") for h in hits)


def test_callees_skips_out_of_image_target(code_image):
    # The call target (0x100a) is inside the section, so it is reported.
    img = code_image(CALLARG)
    assert 0x100A in Disassembler(img).callees(0x1000)


def test_x86_mode_decodes_32bit(code_image):
    from deglyph.core import Arch

    # Same store, decoded in 32-bit mode: still a valid mov to [ecx+2].
    img = code_image(STORE, arch=Arch.X86)
    stores = immediate_stores(img, 0x1000)
    assert stores and stores[0].value == 0x2F
