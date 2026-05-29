# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Generic instruction-pattern detectors used to recover protocol/structure facts
from a function without a decompiler:

  * immediate_stores  — `mov [mem], imm8/16/32` writes (reg+disp and absolute),
                        revealing structured-buffer field assignments (opcodes,
                        lengths, magic header bytes).
  * detect_crc_loops  — small loops dominated by xor/shr/shl over a byte stream,
                        the signature of CRC / checksum routines; reports the
                        polynomial-like immediate constants involved.
  * function_constants— histogram of immediate constants referenced.

These are heuristics, not proofs — they point you at the right instructions fast.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from capstone import x86

from ..core.disasm import Disassembler
from ..core.image import Image


@dataclass(slots=True)
class Store:
    # instruction address
    addr: int
    # base register name, or None for absolute
    base: str | None
    # displacement / absolute address
    disp: int
    # 1/2/4/8 bytes
    size: int
    # immediate stored
    value: int
    text: str

    @property
    def is_absolute(self) -> bool:
        return self.base is None


def immediate_stores(image: Image, va: int, *, max_insns: int = 1500) -> list[Store]:
    """All `mov [mem], imm` writes in the function at `va`, in code order."""
    dis = Disassembler(image)
    out: list[Store] = []
    for ins in dis.func(va, max_insns=max_insns):
        cs = ins._cs
        if not cs or ins.mnemonic not in ("mov", "movb", "movw", "movl"):
            continue
        try:
            if len(cs.operands) != 2:
                continue
            d, s = cs.operands
            if d.type != x86.X86_OP_MEM or s.type != x86.X86_OP_IMM:
                continue
            base_reg = cs.reg_name(d.mem.base) if d.mem.base else None
            # ignore stack frame spills (rsp/rbp relative) — rarely structure fields
            out.append(
                Store(
                    addr=ins.addr,
                    base=base_reg,
                    disp=d.mem.disp & 0xFFFFFFFFFFFFFFFF,
                    size=d.size,
                    value=s.imm & 0xFFFFFFFFFFFFFFFF,
                    text=ins.text,
                )
            )
        except Exception:
            continue
    return out


@dataclass(slots=True)
class CrcLoop:
    start: int
    end: int
    # candidate polynomial constants (xor immediates)
    polys: list[int]
    # candidate init value (0xFFFF / 0x0000 seen pre-loop)
    init: int | None
    insn_count: int


def detect_crc_loops(image: Image, va: int, *, max_insns: int = 2000) -> list[CrcLoop]:
    """Heuristically locate CRC/checksum loops in the function at `va`.

    Looks for a backward branch whose body is dominated by xor/shr/shl/and and
    contains xor-with-immediate (the polynomial). Reports each such region.
    """
    dis = Disassembler(image)
    insns = dis.func(va, max_insns=max_insns)
    by_addr = {i.addr: idx for idx, i in enumerate(insns)}
    out: list[CrcLoop] = []

    # candidate init: last `mov reg, 0xFFFF/0x0000` before a loop
    recent_init: int | None = None

    for idx, ins in enumerate(insns):
        if ins.mnemonic == "mov" and ins._cs:
            try:
                ops = ins._cs.operands
                if ops[1].type == x86.X86_OP_IMM and ops[1].imm in (
                    0xFFFF,
                    0x0000,
                    0xFFFFFFFF,
                ):
                    recent_init = ops[1].imm
            except Exception:
                pass

        # backward conditional/unconditional branch = loop tail
        if ins.is_branch() and ins.imm_target() is not None:
            tgt = ins.imm_target()
            if tgt in by_addr and by_addr[tgt] < idx:
                body = insns[by_addr[tgt] : idx + 1]
                mn = Counter(i.mnemonic for i in body)
                bitops = (
                    mn["xor"]
                    + mn["shr"]
                    + mn["shl"]
                    + mn["and"]
                    + mn["sar"]
                    + mn["ror"]
                    + mn["rol"]
                )
                # Collect xor-with-immediate constants > 0xFF: the polynomial signature.
                polys: list[int] = []
                for bi in body:
                    if bi.mnemonic == "xor" and bi._cs:
                        try:
                            o = bi._cs.operands
                            if (
                                len(o) == 2
                                and o[1].type == x86.X86_OP_IMM
                                and o[1].imm > 0xFF
                            ):
                                polys.append(o[1].imm & 0xFFFFFFFF)
                        except Exception:
                            pass
                # Accept if the body is bit-op heavy OR it xors a polynomial-like
                # constant repeatedly (CRC tables/loops, possibly unrolled with
                # test/je control flow that would otherwise dilute the ratio).
                shifty = mn["shr"] + mn["shl"] + mn["sar"] + mn["ror"] + mn["rol"]
                looks_crc = (len(body) >= 4 and bitops >= max(3, len(body) // 2)) or (
                    polys and shifty >= 2 and len(set(polys)) <= 2
                )
                if looks_crc:
                    out.append(
                        CrcLoop(
                            start=tgt,
                            end=ins.addr,
                            polys=sorted(set(polys)),
                            init=recent_init,
                            insn_count=len(body),
                        )
                    )
    return out


@dataclass(slots=True)
class CallArg:
    # the call instruction
    call_addr: int
    # direct call target, if immediate
    target: int | None
    # register holding the loaded immediate
    reg: str
    # immediate value
    value: int
    # where the immediate was loaded
    load_addr: int


def call_immediate_args(
    image: Image, va: int, *, max_insns: int = 1500
) -> list[CallArg]:
    """Immediates loaded into a register that is still live at the next `call`.

    Complements `immediate_stores`: many APIs pass the command/opcode in a
    register (e.g. `mov cl, 0x10` then `call send`) rather than writing it into a
    buffer. The most recent `mov reg, imm` per register is tracked, and the live
    set is snapshotted at each call site.
    """
    dis = Disassembler(image)
    # reg -> (value, load_addr)
    live: dict[str, tuple[int, int]] = {}
    out: list[CallArg] = []
    for ins in dis.func(va, max_insns=max_insns):
        cs = ins._cs
        if cs and ins.mnemonic == "mov" and len(cs.operands) == 2:
            d, s = cs.operands
            if d.type == x86.X86_OP_REG and s.type == x86.X86_OP_IMM:
                live[cs.reg_name(d.reg)] = (s.imm & 0xFFFFFFFFFFFFFFFF, ins.addr)
        if ins.is_call():
            tgt = ins.imm_target()
            for reg, (val, la) in live.items():
                out.append(CallArg(ins.addr, tgt, reg, val, la))
            # values are consumed by the call boundary
            live.clear()
    return out


def function_constants(image: Image, va: int, *, max_insns: int = 1500) -> Counter:
    """Histogram of immediate constants referenced in the function at `va`."""
    dis = Disassembler(image)
    c: Counter = Counter()
    for ins in dis.func(va, max_insns=max_insns):
        if not ins._cs:
            continue
        try:
            for op in ins._cs.operands:
                if op.type == x86.X86_OP_IMM:
                    c[op.imm & 0xFFFFFFFFFFFFFFFF] += 1
        except Exception:
            pass
    return c
