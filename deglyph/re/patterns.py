# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Generic instruction-pattern detectors used to recover protocol/structure facts
from a function without a decompiler:

  * immediate_stores  — immediate-into-memory writes (x86 `mov [mem], imm`;
                        AArch64 `strb/strh/str [base, #off]` fed by a `movz`),
                        revealing structured-buffer field assignments (opcodes,
                        lengths, magic header bytes).
  * call_immediate_args — immediates loaded into a register still live at a call.
  * detect_crc_loops  — small loops dominated by xor/shift/and over a byte stream,
                        the signature of CRC / checksum routines; reports the
                        polynomial-like immediate constants involved.
  * function_constants— histogram of immediate constants referenced.

The operand walk is arch-neutral (`Insn.operands`), and the mnemonic sets cover
x86 and AArch64, so the detectors fire on both. They are heuristics, not proofs —
they point you at the right instructions fast.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ..core.disasm import Insn
from ..core.image import Image
from .cfg import function_insns

# Mnemonics that write a register/immediate to memory (x86 + AArch64 stores). The
# AArch64 width is encoded in the suffix: strb=1, strh=2, str(w)=4/8.
_STORE_MNEMONICS = {"mov", "movb", "movw", "movl", "strb", "strh", "str", "stur"}
# Width of an AArch64 store by mnemonic; x86 takes the operand size instead.
_ARM_STORE_WIDTH = {"strb": 1, "strh": 2}
# Mnemonics that load an immediate into a register (x86 mov; AArch64 movz/movn,
# and mov which capstone emits as an alias of orr/movz).
_IMM_LOAD = {"mov", "movabs", "movz", "movn"}
# Bit-twiddling ops that dominate a CRC/checksum body (x86 + AArch64).
_BITOPS = {"xor", "shr", "shl", "sar", "ror", "rol", "and", "eor", "lsr", "lsl", "asr"}
_SHIFTS = {"shr", "shl", "sar", "ror", "rol", "lsr", "lsl", "asr"}
# The xor-with-constant mnemonic carrying the polynomial (x86 xor / AArch64 eor).
_XOR = {"xor", "eor"}
# CRC init constants commonly moved into the accumulator before the loop.
_INIT_CONSTS = (0xFFFF, 0x0000, 0xFFFFFFFF)


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


def _store_width(ins: Insn, mem_size: int) -> int:
    """Byte width of a store: the AArch64 mnemonic suffix, else the operand size."""
    return _ARM_STORE_WIDTH.get(ins.mnemonic, mem_size or 0)


def immediate_stores(image: Image, va: int, *, max_insns: int = 1500) -> list[Store]:
    """All immediate-into-memory writes in the function at `va`, in code order.

    Recognizes x86 `mov [mem], imm` and AArch64 `strb/strh/str [base, #off]`
    whose stored value is a register most-recently loaded with a `movz`/`mov`
    immediate (AArch64 cannot store an immediate directly, so the constant rides
    in via a register).
    """
    out: list[Store] = []
    # AArch64: reg -> last immediate loaded into it (for str of a movz'd value).
    reg_imm: dict[str, int] = {}
    for ins in function_insns(image, va, max_insns=max_insns):
        ops = ins.operands()

        # track immediate-into-register loads so an ARM str can resolve its value
        if ins.mnemonic in _IMM_LOAD and len(ops) >= 2 and ops[0].is_reg:
            if ops[1].is_imm and ops[1].imm is not None:
                reg_imm[ops[0].reg or ""] = ops[1].imm
            else:
                reg_imm.pop(ops[0].reg or "", None)

        if ins.mnemonic not in _STORE_MNEMONICS or len(ops) != 2:
            continue
        # x86: mov [mem], imm  (dest mem, src imm)
        if ops[0].is_mem and ops[1].is_imm and ops[1].imm is not None:
            out.append(
                Store(
                    addr=ins.addr,
                    base=ops[0].mem_base,
                    disp=ops[0].mem_disp & 0xFFFFFFFFFFFFFFFF,
                    size=_store_width(ins, ops[0].size),
                    value=ops[1].imm & 0xFFFFFFFFFFFFFFFF,
                    text=ins.text,
                )
            )
        # AArch64: str <reg>, [base, #off]  (src reg, dest mem) — value via reg_imm
        elif ops[0].is_reg and ops[1].is_mem and ops[0].reg in reg_imm:
            out.append(
                Store(
                    addr=ins.addr,
                    base=ops[1].mem_base,
                    disp=ops[1].mem_disp & 0xFFFFFFFFFFFFFFFF,
                    size=_store_width(ins, ops[1].size),
                    value=reg_imm[ops[0].reg] & 0xFFFFFFFFFFFFFFFF,
                    text=ins.text,
                )
            )
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

    Looks for a backward branch whose body is dominated by xor/shift/and and
    contains xor-with-immediate (the polynomial). Covers x86 (xor/shr/...) and
    AArch64 (eor/lsr/...) bit-op mnemonics.
    """
    insns = function_insns(image, va, max_insns=max_insns)
    by_addr = {i.addr: idx for idx, i in enumerate(insns)}
    out: list[CrcLoop] = []

    # candidate init: last immediate-into-register of an init constant before a loop
    recent_init: int | None = None

    for idx, ins in enumerate(insns):
        if ins.mnemonic in _IMM_LOAD:
            ops = ins.operands()
            for op in ops:
                if op.is_imm and op.imm in _INIT_CONSTS:
                    recent_init = op.imm
                    break

        # backward conditional/unconditional branch = loop tail
        if ins.is_branch() and ins.imm_target() is not None:
            tgt = ins.imm_target()
            if tgt in by_addr and by_addr[tgt] < idx:
                body = insns[by_addr[tgt] : idx + 1]
                mn = Counter(i.mnemonic for i in body)
                bitops = sum(mn[m] for m in _BITOPS)
                # Collect xor-with-immediate constants > 0xFF: the polynomial.
                polys: list[int] = []
                for bi in body:
                    if bi.mnemonic in _XOR:
                        bops = bi.operands()
                        for op in bops:
                            if op.is_imm and op.imm is not None and op.imm > 0xFF:
                                polys.append(op.imm & 0xFFFFFFFF)
                # Accept if the body is bit-op heavy OR it xors a polynomial-like
                # constant repeatedly (CRC tables/loops, possibly unrolled with
                # test/je control flow that would otherwise dilute the ratio).
                shifty = sum(mn[m] for m in _SHIFTS)
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
    """Immediates loaded into a register that is still live at the next call.

    Complements `immediate_stores`: many APIs pass the command/opcode in a
    register (e.g. x86 `mov cl, 0x10` then `call send`, or AArch64 `movz w0, #0x10`
    then `bl send`) rather than writing it into a buffer. The most recent
    immediate-into-register per register is tracked, and the live set is
    snapshotted at each call site.
    """
    live: dict[str, tuple[int, int]] = {}
    out: list[CallArg] = []
    for ins in function_insns(image, va, max_insns=max_insns):
        ops = ins.operands()
        if (
            ins.mnemonic in _IMM_LOAD
            and len(ops) >= 2
            and ops[0].is_reg
            and ops[1].is_imm
            and ops[1].imm is not None
        ):
            live[ops[0].reg or ""] = (ops[1].imm & 0xFFFFFFFFFFFFFFFF, ins.addr)
        if ins.is_call():
            tgt = ins.imm_target()
            for reg, (val, la) in live.items():
                out.append(CallArg(ins.addr, tgt, reg, val, la))
            # values are consumed by the call boundary
            live.clear()
    return out


def function_constants(image: Image, va: int, *, max_insns: int = 1500) -> Counter:
    """Histogram of immediate constants referenced in the function at `va`."""
    c: Counter = Counter()
    for ins in function_insns(image, va, max_insns=max_insns):
        for op in ins.operands():
            if op.is_imm and op.imm is not None:
                c[op.imm & 0xFFFFFFFFFFFFFFFF] += 1
    return c
