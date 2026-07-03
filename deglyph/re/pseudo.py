# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Heuristic pseudo-C for x86 / x86-64.

`pseudo_c` maps a linear disassembly to C-like statements one instruction at a
time: registers become variables, `mov` becomes assignment, arithmetic becomes
compound assignment, compares feed the following conditional jump, and calls and
jumps become `name(...)` / `goto loc_*`. Instructions with no model are passed
through as `asm("...")` so the listing stays complete.

This is a readable annotation of the assembly, not a decompiler: there is no type
recovery, no variable renaming, and no control-flow structuring. Confirm against
the disassembly. x86 only; other architectures yield an empty result.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.image import Arch, Image
from .cfg import function_insns

# mnemonic -> compound-assignment operator
_BINOP = {
    "add": "+=",
    "sub": "-=",
    "and": "&=",
    "or": "|=",
    "xor": "^=",
    "shl": "<<=",
    "sal": "<<=",
    "shr": ">>=",
    "sar": ">>=",
    "imul": "*=",
}

# conditional-jump mnemonic -> comparison operator (paired with a prior cmp)
_COND = {
    "je": "==",
    "jz": "==",
    "jne": "!=",
    "jnz": "!=",
    "jg": ">",
    "jge": ">=",
    "jl": "<",
    "jle": "<=",
    "ja": ">",
    "jae": ">=",
    "jb": "<",
    "jbe": "<=",
}


@dataclass(slots=True)
class PseudoLine:
    addr: int
    code: str
    is_label: bool = False


def _operands(op_str: str) -> list[str]:
    """Split an x86 operand string into top-level operands (no comma in `[...]`)."""
    return [p.strip() for p in op_str.split(", ")] if op_str else []


def _loc(addr: int) -> str:
    return f"loc_{addr:#x}"


def pseudo_c(image: Image, va: int, *, max_insns: int = 2000) -> list[PseudoLine]:
    """Pseudo-C for the function at `va`. Empty on non-x86 targets."""
    if image.arch not in (Arch.X86, Arch.X64):
        return []
    insns = function_insns(image, va, max_insns=max_insns)
    if not insns:
        return []

    lo, hi = insns[0].addr, insns[-1].addr + insns[-1].size
    targets: set[int] = set()
    for ins in insns:
        if ins.is_branch():
            t = ins.imm_target()
            if t is not None and lo <= t < hi:
                targets.add(t)

    out: list[PseudoLine] = []
    # (lhs, rhs) of the last cmp/test
    pending: tuple[str, str] | None = None

    for ins in insns:
        if ins.addr in targets:
            out.append(PseudoLine(ins.addr, f"{_loc(ins.addr)}:", is_label=True))
        code, pending = _statement(image, ins, pending, targets)
        out.append(PseudoLine(ins.addr, code))
    return out


def _statement(
    image: Image, ins, pending: tuple[str, str] | None, labels: set[int]
) -> tuple[str, tuple[str, str] | None]:
    m = ins.mnemonic
    ops = _operands(ins.op_str)

    if m in ("mov", "movzx", "movsx", "movabs") and len(ops) == 2:
        return f"{ops[0]} = {ops[1]};", None
    if m == "lea" and len(ops) == 2:
        return f"{ops[0]} = &{ops[1].strip('[]')};", None
    if m == "xor" and len(ops) == 2 and ops[0] == ops[1]:
        # zero idiom
        return f"{ops[0]} = 0;", None
    if m in _BINOP and len(ops) == 2:
        return f"{ops[0]} {_BINOP[m]} {ops[1]};", None
    if m in ("inc", "dec") and ops:
        return f"{ops[0]}{'++' if m == 'inc' else '--'};", None
    if m == "neg" and ops:
        return f"{ops[0]} = -{ops[0]};", None
    if m == "not" and ops:
        return f"{ops[0]} = ~{ops[0]};", None
    if m in ("cmp", "test") and len(ops) == 2:
        return f"// {m} {ops[0]}, {ops[1]}", (ops[0], ops[1])
    if m == "jmp":
        return f"goto {_target_name(image, ins, labels)};", None
    if m in _COND:
        cond = _condition(m, pending)
        return f"if ({cond}) goto {_target_name(image, ins, labels)};", None
    if m in ("call", "bl", "blr"):
        return f"{_target_name(image, ins, labels)}();", None
    if ins.is_ret():
        return "return;", None
    if m in ("nop", "endbr64", "endbr32", "leave", "hlt", "int3"):
        return f"// {ins.text}", pending
    # No model: keep the instruction verbatim so the listing stays faithful.
    return f'asm("{ins.text}");', None


def _condition(mnem: str, pending: tuple[str, str] | None) -> str:
    op = _COND[mnem]
    if pending is None:
        return f"/* {mnem} */"
    lhs, rhs = pending
    return f"{lhs} {op} {rhs}"


def _target_name(image: Image, ins, labels: set[int]) -> str:
    """Symbol for a branch/call target: in-function label, function name, or sub_*."""
    t = ins.imm_target()
    if t is None:
        # indirect call/jump
        return f"(*{ins.op_str})"
    if t in labels:
        return _loc(t)
    f = image.func_at(t)
    if f:
        return f.display
    return f"sub_{t:#x}"
