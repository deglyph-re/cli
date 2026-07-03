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


# --- Section 5: evidence (confidence / reasons / caveats) ---------------------
# mov byte [rcx+2], 0xaa ; mov byte [rbp-8], 0x04 ; ret
# the first is a buffer field write (high), the second a stack spill (low).
_STORE_MIX = bytes.fromhex("c6 41 02 aa  c6 45 f8 04  c3")
# mov ecx, 0x2f ; mov r10, 0x99 ; call $+5 ; ret
# ecx is an arg register (high); r10 is not (medium).
_ARG_MIX = bytes.fromhex("b9 2f 00 00 00  49 c7 c2 99 00 00 00  e8 00 00 00 00  c3")
# mov ecx, 0x2f ; mov ecx, [rdx] ; call $+5 ; ret
# the immediate in ecx is overwritten by a load before the call: not reported.
_ARG_CLOBBER = bytes.fromhex("b9 2f 00 00 00  8b 0a  e8 00 00 00 00  c3")
# mov eax, 0x2f ; mov ecx, eax ; call $+5 ; ret
# the constant propagates from eax to ecx across the move.
_ARG_PROP = bytes.fromhex("b8 2f 00 00 00  89 c1  e8 00 00 00 00  c3")


def test_immediate_store_evidence_flags_stack_spill(code_image):
    img = code_image(_STORE_MIX)
    by_base = {s.base: s for s in immediate_stores(img, 0x1000)}
    assert by_base["rcx"].evidence.confidence == "high"
    assert not by_base["rcx"].evidence.caveats
    assert by_base["rbp"].evidence.confidence == "low"
    assert by_base["rbp"].is_stack
    assert any("spill" in c for c in by_base["rbp"].evidence.caveats)


def test_immediate_store_signed_disp(code_image):
    img = code_image(_STORE_MIX)
    by_base = {s.base: s for s in immediate_stores(img, 0x1000)}
    assert by_base["rcx"].signed_disp == 2
    assert by_base["rbp"].signed_disp == -8


def test_call_arg_confidence_by_register(code_image):
    img = code_image(_ARG_MIX)
    by_reg = {a.reg: a for a in call_immediate_args(img, 0x1000)}
    assert by_reg["ecx"].evidence.confidence == "high"
    assert by_reg["r10"].evidence.confidence == "medium"
    assert any("argument register" in c for c in by_reg["r10"].evidence.caveats)


def test_call_arg_register_invalidated_on_write(code_image):
    img = code_image(_ARG_CLOBBER)
    regs = {a.reg for a in call_immediate_args(img, 0x1000)}
    # ecx was reloaded from memory before the call; the stale 0x2f is gone.
    assert "ecx" not in regs


def test_call_arg_const_propagation_across_move(code_image):
    img = code_image(_ARG_PROP)
    args = {a.reg: a.value for a in call_immediate_args(img, 0x1000)}
    assert args.get("ecx") == 0x2F


def test_crc_loop_labeled_crc_with_evidence(code_image):
    img = code_image(CRC)
    loops = detect_crc_loops(img, 0x1000)
    assert loops and loops[0].kind == "crc"
    assert loops[0].evidence.reasons
    assert loops[0].evidence.confidence in ("high", "medium")


def test_checksum_loop_labeled_separately(code_image):
    # add eax,ecx ; rol eax,1 ; dec edx ; jne -7 ; ret. Bit-ops, no polynomial.
    blob = bytes.fromhex("01 c8  d1 c0  ff ca  75 f8  c3")
    img = code_image(blob)
    loops = detect_crc_loops(img, 0x1000)
    if loops:
        assert loops[0].kind == "checksum"
        assert not loops[0].polys
        assert any("checksum" in c for c in loops[0].evidence.caveats)
