# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Tests for the content-addressed function-identity engine (re/funcsig)."""

from __future__ import annotations

from deglyph.core.disasm import Disassembler
from deglyph.core.image import Arch
from deglyph.re.funcsig import func_sig, normalize_insn, similarity

# mov eax,1; mov ecx,2; add eax,ecx; xor edx,edx; sub eax,ecx; imul eax,ecx;
# or eax,edx; and eax,ecx; ret  -- varied mnemonics so each n-gram is distinct
_BASE = bytes.fromhex("b801000000b90200000001c831d229c80fafc109d021c8c3")
# same, with `xor edx,edx` swapped for `mov edx,3` (one localized edit)
_VARIANT = bytes.fromhex("b801000000b90200000001c8ba0300000029c80fafc109d021c8c3")
# xor eax,eax ; push rbp ; pop rbp ; nop ; nop ; ret
_UNRELATED = bytes.fromhex("31c0555d9090c3")


def _first_insn(code_image, blob: bytes):
    img = code_image(blob)
    return next(Disassembler(img).at(0x1000, len(blob)))


def test_func_sig_basic_features(code_image):
    img = code_image(_BASE)
    sig = func_sig(img, 0x1000)
    assert sig is not None
    # nine instructions, one straight-line block, no calls
    assert sig.n_insns == 9
    assert sig.n_blocks == 1
    assert sig.n_calls == 0
    assert len(sig.exact) == 64


def test_identity_survives_relocation(code_image):
    # The same bytes at a different virtual address keep the same exact hash:
    # normalization drops addresses, so a moved function is still identified.
    a = func_sig(code_image(_BASE, va=0x1000), 0x1000)
    b = func_sig(code_image(_BASE, va=0x9000), 0x9000)
    assert a is not None and b is not None
    assert a.exact == b.exact
    assert similarity(a, b) == 1.0


def test_changed_body_changes_identity_but_stays_similar(code_image):
    base = func_sig(code_image(_BASE), 0x1000)
    var = func_sig(code_image(_VARIANT), 0x1000)
    assert base is not None and var is not None
    # one mutated instruction breaks the exact hash but keeps most n-grams
    assert base.exact != var.exact
    s = similarity(base, var)
    assert 0.0 < s < 1.0


def test_unrelated_functions_score_low(code_image):
    base = func_sig(code_image(_BASE), 0x1000)
    other = func_sig(code_image(_UNRELATED), 0x1000)
    assert base is not None and other is not None
    assert similarity(base, other) < 0.3


def test_no_decode_yields_none(code_image):
    img = code_image(_BASE)
    # a VA with no section under it decodes to nothing
    assert func_sig(img, 0xDEAD0000) is None


def test_normalize_immediate_class_depends_on_branch(code_image):
    # mov al,1: the immediate is a plain value; a relative jump is a branch target.
    mov = _first_insn(code_image, bytes.fromhex("b001"))
    assert normalize_insn(mov) == "mov|R,I"
    jmp = _first_insn(code_image, bytes.fromhex("ebfe"))
    assert normalize_insn(jmp) == "jmp|T"


def test_normalize_stack_vs_other_memory_base(code_image):
    # mov dword [rsp+8], 1 -> stack base (Ms); mov dword [rax+8], 1 -> other (Mm)
    stack = _first_insn(code_image, bytes.fromhex("c744240801000000"))
    other = _first_insn(code_image, bytes.fromhex("c7400801000000"))
    assert normalize_insn(stack) == "mov|Ms,I"
    assert normalize_insn(other) == "mov|Mm,I"


def test_arch_neutral_on_aarch64(code_image):
    # mov w0,#1 ; ret  -> a valid signature on AArch64, exercising the operand walk
    blob = bytes.fromhex("20008052c0035fd6")
    sig = func_sig(code_image(blob, arch=Arch.ARM64), 0x1000)
    assert sig is not None
    assert sig.n_insns == 2
