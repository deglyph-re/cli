# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Heuristic pseudo-C mapping for x86-64."""

from __future__ import annotations

from deglyph.core import Arch
from deglyph.re import pseudo_c


def _code(lines):
    return [ln.code for ln in lines if not ln.is_label]


def test_mov_and_arithmetic(code_image):
    # mov ecx, 4 ; add ecx, 1 ; ret
    img = code_image(bytes.fromhex("b9 04 00 00 00  83 c1 01  c3"))
    code = _code(pseudo_c(img, 0x1000))
    assert "ecx = 4;" in code
    assert "ecx += 1;" in code
    assert "return;" in code


def test_xor_zero_idiom(code_image):
    # xor eax, eax ; ret
    img = code_image(bytes.fromhex("31 c0 c3"))
    assert "eax = 0;" in _code(pseudo_c(img, 0x1000))


def test_cmp_feeds_conditional_jump_with_label(code_image):
    # loc_0x1000: cmp eax, 5 ; jne loc_0x1000 (backward) ; ret
    img = code_image(bytes.fromhex("83 f8 05  75 fb  c3"))
    lines = pseudo_c(img, 0x1000)
    code = _code(lines)
    assert any(c.startswith("if (eax != 5) goto loc_0x1000") for c in code)
    assert any(ln.is_label and ln.code == "loc_0x1000:" for ln in lines)


def test_store_idiom_uses_assignment(code_image):
    # mov dword ptr [rcx + 2], 0x2f ; ret
    img = code_image(bytes.fromhex("c7 41 02 2f 00 00 00 c3"))
    code = _code(pseudo_c(img, 0x1000))
    assert any("[rcx + 2] = 0x2f;" in c for c in code)


def test_unmodeled_instruction_passthrough(code_image):
    # push rbp ; ret. The push has no model, kept as asm("...").
    img = code_image(bytes.fromhex("55 c3"))
    code = _code(pseudo_c(img, 0x1000))
    assert any(c.startswith('asm("push') for c in code)


def test_non_x86_returns_empty(code_image):
    img = code_image(bytes.fromhex("c3"), arch=Arch.ARM64)
    assert pseudo_c(img, 0x1000) == []
