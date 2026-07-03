# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""RISC-V loading and linear disassembly.

Scope is deliberately narrow: the container loads, the architecture maps to a
Capstone RISC-V engine, and instructions decode. The pattern detectors, the CFG,
and function discovery are not claimed for RISC-V (Capstone's control-flow group
tagging is unreliable there), so `_analysis_support` reports them off.
"""

from __future__ import annotations

from deglyph.core.disasm import Disassembler
from deglyph.core.image import Arch


def test_riscv64_disassembles(code_image):
    # addi a0, a0, 1 ; ret
    img = code_image(bytes.fromhex("1305150067800000"), arch=Arch.RISCV64)
    insns = list(Disassembler(img).at(0x1000, 8))
    assert [i.mnemonic for i in insns] == ["addi", "ret"]


def test_riscv_arch_alias_parses():
    from deglyph.cli import _arch

    assert _arch("riscv64") is Arch.RISCV64
    assert _arch("rv64") is Arch.RISCV64
    assert _arch("riscv32") is Arch.RISCV32
    assert _arch("riscv") is Arch.RISCV64


def test_riscv_bits():
    assert Arch.RISCV64.bits == 64
    assert Arch.RISCV32.bits == 32


def test_analysis_support_off_for_riscv():
    from deglyph.cli import _analysis_support

    support = _analysis_support(Arch.RISCV64)
    # Detectors are honestly reported as unavailable, not silently empty.
    assert support["immediate_stores"] is False
    assert support["detect_crc_loops"] is False
    assert support["pseudo_c"] is False
