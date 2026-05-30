# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Architecture parity: the operand walker and detectors fire on ARM/AArch64.

The detectors used to read x86 capstone operand structs directly, so they were
silently empty on ARM binaries. They now go through the arch-neutral operand
walker (`Insn.operands` / `Insn.data_ref`), so the same store / call-arg / CRC /
constant facts come back on AArch64. These tests assemble small AArch64 byte
sequences (the frame-encoder shapes from `samples/fixture_src.c`) and assert the
detectors recover them, alongside x86 spot checks that the walk is unchanged.
"""

from __future__ import annotations

from deglyph.core.disasm import Disassembler
from deglyph.core.image import Arch
from deglyph.re import (
    call_immediate_args,
    function_constants,
    immediate_stores,
)


def _mark_discovered(img):
    object.__setattr__(img, "_discovered", True)


# --- operand walker -------------------------------------------------------
def test_operands_are_arch_neutral_x86(code_image):
    # mov byte ptr [rcx], 4
    img = code_image(bytes.fromhex("c60104"))
    ins = next(Disassembler(img).at(0x1000, 8))
    ops = ins.operands()
    assert [o.kind for o in ops] == ["mem", "imm"]
    assert ops[0].mem_base == "rcx"
    assert ops[1].imm == 0x04


def test_operands_are_arch_neutral_arm64(code_image):
    # str x0, [x1, #8]
    img = code_image(bytes.fromhex("200400f9"), arch=Arch.ARM64)
    ins = next(Disassembler(img).at(0x1000, 8))
    ops = ins.operands()
    assert ops[0].kind == "reg" and ops[0].reg == "x0"
    assert ops[1].kind == "mem" and ops[1].mem_base == "x1" and ops[1].mem_disp == 8


def test_imm_target_is_arch_neutral_arm64(code_image):
    # bl #8 -> target 0x1008
    img = code_image(bytes.fromhex("02000094"), arch=Arch.ARM64)
    ins = next(Disassembler(img).at(0x1000, 8))
    assert ins.is_call()
    assert ins.imm_target() == 0x1008


# --- AArch64 detectors ----------------------------------------------------
# movz w8,#0xaa ; strb w8,[x0] ; movz w8,#4 ; strb w8,[x0,#1] ; ret
_ARM_FRAME = bytes.fromhex("48158052 08000039 88008052 08040039 c0035fd6")
# movz w0,#0x2f ; bl #8 ; ret
_ARM_CALL = bytes.fromhex("e0058052 02000094 c0035fd6")


def test_immediate_stores_on_arm64(code_image):
    img = code_image(_ARM_FRAME, arch=Arch.ARM64)
    _mark_discovered(img)
    stores = immediate_stores(img, 0x1000)
    # both strb writes recovered, value carried in from the preceding movz
    by_disp = {s.disp: s for s in stores}
    assert by_disp[0].value == 0xAA and by_disp[0].size == 1 and by_disp[0].base == "x0"
    assert by_disp[1].value == 0x04 and by_disp[1].size == 1


def test_call_immediate_args_on_arm64(code_image):
    img = code_image(_ARM_CALL, arch=Arch.ARM64)
    _mark_discovered(img)
    args = call_immediate_args(img, 0x1000)
    assert any(a.reg == "w0" and a.value == 0x2F for a in args)
    # the call target is resolved (the bl is the 2nd insn at 0x1004, bl #8)
    assert all(a.target == 0x100C for a in args if a.value == 0x2F)


def test_function_constants_on_arm64(code_image):
    img = code_image(_ARM_CALL, arch=Arch.ARM64)
    _mark_discovered(img)
    consts = function_constants(img, 0x1000)
    assert consts[0x2F] >= 1


def test_x86_detectors_unchanged(code_image):
    # mov byte ptr [rcx+2], 4 ; ret  -- the x86 path the detectors always had
    img = code_image(bytes.fromhex("c6410204 c3"))
    _mark_discovered(img)
    stores = immediate_stores(img, 0x1000)
    assert len(stores) == 1
    assert stores[0].base == "rcx" and stores[0].disp == 2 and stores[0].value == 0x04
