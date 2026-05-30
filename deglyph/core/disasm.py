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

from .image import Arch, Image

# Capstone operand-type ids are shared across x86 / ARM / AArch64 (CS_OP_REG=1,
# CS_OP_IMM=2, CS_OP_MEM=3), so the operand walker is arch-neutral and never
# imports a per-arch constant module.
_OP_REG = 1
_OP_IMM = 2
_OP_MEM = 3

_ARCH_MODE = {
    Arch.X86: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    Arch.X64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    Arch.ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    # AArch64 has no sub-mode; the endianness flag is the mode (LITTLE == 0).
    Arch.ARM64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN),
}

# Mnemonics that terminate a basic block / function tail
_TERMINATORS = {"ret", "retf", "iret", "iretd", "iretq", "hlt"}

# Unconditional jumps: control leaves with no fall-through. x86 `jmp`, ARM `b`
# (and the indirect `br`, which carries no static target).
_UNCOND_JMP = {"jmp", "b", "br"}

# Conditional branches that fall through when not taken. x86 Jcc / loop, plus the
# AArch64 compare-and-branch forms (`b.<cc>` is matched by its `b.` prefix).
_COND_BRANCH = {
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
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
}

_BRANCH = _UNCOND_JMP | _COND_BRANCH | {"bl", "blr"}


@dataclass(slots=True)
class Operand:
    """One decoded operand, arch-neutral.

    `kind` is "reg" | "imm" | "mem" | "other". `reg` is a register name for a
    register operand (or a memory base/index); `imm` is the immediate value;
    `mem_base` / `mem_index` are register names (or None) and `mem_disp` the
    signed displacement for a memory operand. The walker fills only the fields
    that apply, so a consumer can branch on `kind` without touching capstone.
    """

    kind: str
    reg: str | None = None
    imm: int | None = None
    mem_base: str | None = None
    mem_index: str | None = None
    mem_disp: int = 0
    # access width in bytes (capstone op.size); 0 when unknown
    size: int = 0

    @property
    def is_reg(self) -> bool:
        return self.kind == "reg"

    @property
    def is_imm(self) -> bool:
        return self.kind == "imm"

    @property
    def is_mem(self) -> bool:
        return self.kind == "mem"


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
        return self.is_uncond_jmp() or self.is_cond_branch() or self.is_call()

    def is_uncond_jmp(self) -> bool:
        """An unconditional jump (no fall-through): x86 `jmp`, ARM `b` / `br`."""
        return self.mnemonic in _UNCOND_JMP

    def is_cond_branch(self) -> bool:
        """A conditional branch (falls through when not taken).

        Covers x86 Jcc / loop and the AArch64 compare-and-branch forms, plus
        `b.<cc>` (matched by its `b.` prefix, e.g. `b.eq`).
        """
        return self.mnemonic in _COND_BRANCH or self.mnemonic.startswith("b.")

    def imm_target(self) -> int | None:
        """Direct (immediate) branch/call target, if any (any architecture)."""
        for op in self.operands():
            if op.is_imm and op.imm is not None:
                return op.imm & 0xFFFFFFFFFFFFFFFF
        return None

    def operands(self) -> list[Operand]:
        """Decoded operands as arch-neutral `Operand`s ([] when detail is off).

        Reads the capstone detail once and maps each operand to the shared
        (reg / imm / mem) shape, so x86, ARM, and AArch64 are walked the same
        way and no caller imports a per-arch capstone constant module. Register
        ids become names (`rip`, `x0`); a bad detail record degrades to [].
        """
        cs = self._cs
        if not cs:
            return []
        out: list[Operand] = []
        try:
            ops = cs.operands
        except Exception:
            return []
        for op in ops:
            try:
                size = int(getattr(op, "size", 0) or 0)
                if op.type == _OP_IMM:
                    out.append(
                        Operand("imm", imm=op.imm & 0xFFFFFFFFFFFFFFFF, size=size)
                    )
                elif op.type == _OP_REG:
                    out.append(Operand("reg", reg=cs.reg_name(op.reg), size=size))
                elif op.type == _OP_MEM:
                    mem = op.mem
                    base = cs.reg_name(mem.base) if mem.base else None
                    index = cs.reg_name(mem.index) if getattr(mem, "index", 0) else None
                    out.append(
                        Operand(
                            "mem",
                            mem_base=base,
                            mem_index=index,
                            mem_disp=mem.disp,
                            size=size,
                        )
                    )
                else:
                    out.append(Operand("other"))
            except Exception:
                out.append(Operand("other"))
        return out

    def data_ref(self) -> int | None:
        """Address of a data location this instruction references, or None.

        Resolves the arch-specific addressing modes that point at a constant /
        string / table: x86 RIP-relative (`[rip + disp]`, folded against the
        next instruction) and absolute (`[disp]`); AArch64 `adrp`/`ldr`-literal
        and other PC-relative immediates (capstone already resolves these to the
        target address in the IMM operand). Returns the first such address.
        """
        next_pc = self.addr + self.size
        for op in self.operands():
            if op.is_mem:
                base = (op.mem_base or "").lower()
                if base in ("rip", "pc"):
                    return (next_pc + op.mem_disp) & 0xFFFFFFFFFFFFFFFF
                if op.mem_base is None and op.mem_index is None and op.mem_disp:
                    return op.mem_disp & 0xFFFFFFFFFFFFFFFF
            elif op.is_imm and op.imm:
                # adrp / ldr-literal / movz-of-address: capstone resolves the
                # PC-relative target into the IMM, so an immediate that lands in
                # a mapped section is a data pointer (the caller section-filters).
                return op.imm & 0xFFFFFFFFFFFFFFFF
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
