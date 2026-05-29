# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Capstone wrapper: maps `Arch` to a configured Cs engine, decodes instructions
from an `Image`, and provides linear function disassembly plus call/branch target
extraction. Kept deliberately small and dependency-light so startup stays fast.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import capstone
from capstone import x86

from .image import Arch, Image

_ARCH_MODE = {
    Arch.X86: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    Arch.X64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    Arch.ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    # AArch64 has no sub-mode; the endianness flag is the mode (LITTLE == 0).
    Arch.ARM64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN),
}

# Mnemonics that terminate a basic block / function tail
_TERMINATORS = {"ret", "retf", "iret", "iretd", "iretq", "hlt"}
_BRANCH = {
    "jmp",
    "je",
    "jne",
    "jz",
    "jnz",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jg",
    "jge",
    "jl",
    "jle",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jnp",
    "jcxz",
    "jecxz",
    "jrcxz",
    "loop",
    "loope",
    "loopne",
    "b",
    "bl",
    "br",
    "blr",
}


@dataclass(slots=True)
class Insn:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    # underlying capstone insn (detail), lazy use
    _cs: Any = None

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".rstrip()

    def is_ret(self) -> bool:
        return self.mnemonic in _TERMINATORS

    def is_call(self) -> bool:
        return self.mnemonic in ("call", "bl", "blr")

    def is_branch(self) -> bool:
        return self.mnemonic in _BRANCH or self.is_call()

    def imm_target(self) -> int | None:
        """Direct (immediate) branch/call target, if any."""
        if not self._cs:
            return None
        try:
            for op in self._cs.operands:
                if op.type == x86.X86_OP_IMM:
                    return op.imm & 0xFFFFFFFFFFFFFFFF
        except Exception:
            return None
        return None


class Disassembler:
    def __init__(self, image: Image):
        self.image = image
        a, m = _ARCH_MODE.get(image.arch, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        self.md = capstone.Cs(a, m)
        self.md.detail = True
        self.md.skipdata = True

    def at(self, va: int, max_bytes: int = 0x2000) -> Iterator[Insn]:
        data = self.image.read_va(va, max_bytes)
        for i in self.md.disasm(data, va):
            yield Insn(i.address, i.size, i.mnemonic, i.op_str, bytes(i.bytes), _cs=i)

    def func(self, va: int, max_insns: int = 4000) -> list[Insn]:
        """Linear disassembly from `va` up to (and including) the first ret tail.

        Stops at the first terminator at top level or the instruction cap. Linear
        decode suits the small exported thunks and methods this targets; it does
        not chase branches into a full CFG.
        """
        out: list[Insn] = []
        for ins in self.at(va, max_bytes=max_insns * 16):
            out.append(ins)
            if ins.is_ret() or len(out) >= max_insns:
                break
        return out

    def follow_thunk(self, va: int, depth: int = 8) -> int:
        """Resolve a wrapper that ends in `jmp <imm>` (tail call) to its target.

        Returns the deepest in-`.text` target reached, or `va` if not a thunk.
        Used to map exported wrappers to the real implementation.
        """
        text = self.image.text
        cur = va
        for _ in range(depth):
            nxt = None
            for ins in self.at(cur, 64):
                if ins.mnemonic == "jmp":
                    t = ins.imm_target()
                    if t and text and text.contains(t):
                        nxt = t
                    break
                if ins.is_ret():
                    break
            if nxt is None or nxt == cur:
                break
            cur = nxt
        return cur

    def callees(self, va: int) -> list[int]:
        """Direct call targets within the function at `va` (in code order)."""
        text = self.image.text
        out: list[int] = []
        for ins in self.func(va):
            if ins.is_call():
                t = ins.imm_target()
                if t and text and text.contains(t) and t not in out:
                    out.append(t)
        return out
