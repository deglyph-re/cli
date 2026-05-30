# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Generic instruction-pattern detectors used to recover protocol/structure facts
from a function without a decompiler:

  * immediate_stores  — immediate-into-memory writes (x86 `mov [mem], imm`;
                        AArch64 `strb/strh/str [base, #off]` fed by a `movz`),
                        revealing structured-buffer field assignments (opcodes,
                        lengths, magic header bytes).
  * call_immediate_args — immediates loaded into a register still live at a call,
                        with calling-convention-aware confidence and constant
                        propagation across register moves.
  * detect_crc_loops  — small loops dominated by xor/shift/and over a byte stream,
                        labeled CRC-like (a polynomial xor) or checksum-like.
  * function_constants— histogram of immediate constants referenced.

Every hit carries an `Evidence` record: a confidence, the reasons it matched, the
caveats (why it might be wrong), and the supporting instruction addresses. The
operand walk is arch-neutral (`Insn.operands`), and the mnemonic sets cover x86
and AArch64, so the detectors fire on both. They are heuristics, not proofs --
the evidence makes the uncertainty explicit; confirm in the disassembly.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..core.disasm import Insn
from ..core.image import Arch, Image
from .cfg import function_insns

# Mnemonics that write a register/immediate to memory (x86 + AArch64 stores). The
# AArch64 width is encoded in the suffix: strb=1, strh=2, str(w)=4/8.
_STORE_MNEMONICS = {"mov", "movb", "movw", "movl", "strb", "strh", "str", "stur"}
# Width of an AArch64 store by mnemonic; x86 takes the operand size instead.
_ARM_STORE_WIDTH = {"strb": 1, "strh": 2}
# Mnemonics that load an immediate into a register (x86 mov; AArch64 movz/movn,
# and mov which capstone emits as an alias of orr/movz).
_IMM_LOAD = {"mov", "movabs", "movz", "movn"}
# Register-to-register copies that propagate a tracked constant.
_REG_MOVE = {"mov", "movzx", "movsx", "mov.w"}
# Bit-twiddling ops that dominate a CRC/checksum body (x86 + AArch64).
_BITOPS = {"xor", "shr", "shl", "sar", "ror", "rol", "and", "eor", "lsr", "lsl", "asr"}
_SHIFTS = {"shr", "shl", "sar", "ror", "rol", "lsr", "lsl", "asr"}
# The xor-with-constant mnemonic carrying the polynomial (x86 xor / AArch64 eor).
_XOR = {"xor", "eor"}
# CRC init constants commonly moved into the accumulator before the loop.
_INIT_CONSTS = (0xFFFF, 0x0000, 0xFFFFFFFF)
# Stack / frame registers: a store through one of these is usually a local spill,
# not a structured-buffer field write.
_STACK_REGS = {"rsp", "esp", "sp", "rbp", "ebp", "x29", "w29", "fp"}
# Calling-convention integer argument registers, by architecture. A const that is
# live in one of these at a call is far more likely a real argument. Sub-register
# names map to their 64-bit parent so width does not hide the match.
# SysV x64 integer-argument registers and their 32/16/8-bit sub-register names
# (the Windows-x64 set rcx/rdx/r8/r9 is a subset), so an arg of any width matches.
_X64_ARGS = {
    "rdi",
    "edi",
    "dil",
    "rsi",
    "esi",
    "sil",
    "rdx",
    "edx",
    "dl",
    "rcx",
    "ecx",
    "cl",
    "r8",
    "r8d",
    "r8b",
    "r9",
    "r9d",
    "r9b",
}
_ARG_REGS = {
    Arch.X64: _X64_ARGS,
    Arch.X86: {"eax", "ecx", "edx", "al", "cl", "dl"},
    Arch.ARM64: {f"x{i}" for i in range(8)} | {f"w{i}" for i in range(8)},
}


@dataclass(slots=True)
class Evidence:
    """Why a detector hit was reported, and how much to trust it.

    `confidence` is "high" | "medium" | "low"; `reasons` say why it matched;
    `caveats` say why it might be wrong; `support` is the addresses of the
    instructions that back the claim. The shape is shared across detectors so a
    consumer (CLI / TUI / AI / JSON) renders uncertainty uniformly.
    """

    confidence: str = "medium"
    reasons: tuple[str, ...] = ()
    caveats: tuple[str, ...] = ()
    support: tuple[int, ...] = ()


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
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def is_absolute(self) -> bool:
        return self.base is None

    @property
    def is_stack(self) -> bool:
        return (self.base or "").lower() in _STACK_REGS

    @property
    def signed_disp(self) -> int:
        """Displacement as a signed value (a frame offset is usually negative)."""
        d = self.disp & 0xFFFFFFFFFFFFFFFF
        return d - (1 << 64) if d >> 63 else d


def _store_width(ins: Insn, mem_size: int) -> int:
    """Byte width of a store: the AArch64 mnemonic suffix, else the operand size."""
    return _ARM_STORE_WIDTH.get(ins.mnemonic, mem_size or 0)


def _store_evidence(base: str | None, disp: int, addr: int) -> Evidence:
    """Confidence + reasons for an immediate store, demoting stack-frame spills."""
    if base is not None and base.lower() in _STACK_REGS:
        return Evidence(
            confidence="low",
            reasons=(f"immediate written to [{base}{_disp_str(disp)}]",),
            caveats=("stack-frame store (likely a local spill, not a buffer field)",),
            support=(addr,),
        )
    where = "absolute address" if base is None else f"[{base}{_disp_str(disp)}]"
    return Evidence(
        confidence="high",
        reasons=(f"immediate written to {where}",),
        support=(addr,),
    )


def _disp_str(disp: int) -> str:
    """Signed-displacement suffix for a memory operand (`+0x4` / `-0x8` / '')."""
    d = disp & 0xFFFFFFFFFFFFFFFF
    s = d - (1 << 64) if d >> 63 else d
    if s == 0:
        return ""
    return f"+{s:#x}" if s > 0 else f"-{-s:#x}"


def immediate_stores(image: Image, va: int, *, max_insns: int = 1500) -> list[Store]:
    """All immediate-into-memory writes in the function at `va`, in code order.

    Recognizes x86 `mov [mem], imm` and AArch64 `strb/strh/str [base, #off]`
    whose stored value is a register most-recently loaded with a `movz`/`mov`
    immediate. Stack-frame stores are kept but marked low-confidence with a
    caveat, since they are usually local spills rather than structured fields.
    """
    out: list[Store] = []
    # AArch64: reg -> (immediate, load_addr) for str of a movz'd value.
    reg_imm: dict[str, tuple[int, int]] = {}
    for ins in function_insns(image, va, max_insns=max_insns):
        ops = ins.operands()

        # track immediate-into-register loads so an ARM str can resolve its value
        if ins.mnemonic in _IMM_LOAD and len(ops) >= 2 and ops[0].is_reg:
            if ops[1].is_imm and ops[1].imm is not None:
                reg_imm[ops[0].reg or ""] = (ops[1].imm, ins.addr)
            else:
                reg_imm.pop(ops[0].reg or "", None)

        if ins.mnemonic not in _STORE_MNEMONICS or len(ops) != 2:
            continue
        # x86: mov [mem], imm  (dest mem, src imm)
        if ops[0].is_mem and ops[1].is_imm and ops[1].imm is not None:
            base, disp = ops[0].mem_base, ops[0].mem_disp & 0xFFFFFFFFFFFFFFFF
            out.append(
                Store(
                    addr=ins.addr,
                    base=base,
                    disp=disp,
                    size=_store_width(ins, ops[0].size),
                    value=ops[1].imm & 0xFFFFFFFFFFFFFFFF,
                    text=ins.text,
                    evidence=_store_evidence(base, disp, ins.addr),
                )
            )
        # AArch64: str <reg>, [base, #off]  (src reg, dest mem) -- value via reg_imm
        elif ops[0].is_reg and ops[1].is_mem and ops[0].reg in reg_imm:
            base, disp = ops[1].mem_base, ops[1].mem_disp & 0xFFFFFFFFFFFFFFFF
            value, load_addr = reg_imm[ops[0].reg]
            ev = _store_evidence(base, disp, ins.addr)
            # the value rode in via a register, so cite the load and note the hop
            ev = Evidence(
                confidence=ev.confidence,
                reasons=ev.reasons
                + (f"value from {ops[0].reg} loaded at {load_addr:#x}",),
                caveats=ev.caveats,
                support=ev.support + (load_addr,),
            )
            out.append(
                Store(
                    addr=ins.addr,
                    base=base,
                    disp=disp,
                    size=_store_width(ins, ops[1].size),
                    value=value & 0xFFFFFFFFFFFFFFFF,
                    text=ins.text,
                    evidence=ev,
                )
            )
    return out


def group_stores(stores: list[Store]) -> dict[str | None, list[Store]]:
    """Group stores by their destination base register (likely one buffer each).

    A run of `mov [rcx+0], 0xaa; mov [rcx+1], 0x04; ...` is one structure being
    filled; grouping by base surfaces that without changing the flat list. The
    key is the base register name (or None for absolute stores).
    """
    groups: dict[str | None, list[Store]] = {}
    for s in stores:
        groups.setdefault(s.base, []).append(s)
    return groups


@dataclass(slots=True)
class CrcLoop:
    start: int
    end: int
    # candidate polynomial constants (xor immediates)
    polys: list[int]
    # candidate init value (0xFFFF / 0x0000 seen pre-loop)
    init: int | None
    insn_count: int
    # "crc" (a polynomial xor in the loop) | "checksum" (bit-ops, no polynomial)
    kind: str = "crc"
    evidence: Evidence = field(default_factory=Evidence)


def detect_crc_loops(image: Image, va: int, *, max_insns: int = 2000) -> list[CrcLoop]:
    """Heuristically locate CRC / checksum loops in the function at `va`.

    Finds a backward branch whose body is dominated by xor/shift/and. A body that
    xors a polynomial-like constant (> 0xFF) is labeled `kind="crc"`; one that is
    bit-op heavy without such a constant is `kind="checksum"`. Covers x86
    (xor/shr/...) and AArch64 (eor/lsr/...) mnemonics. Reflection / init are noted
    in the evidence when visible; a register-folded polynomial can be missed.
    """
    insns = function_insns(image, va, max_insns=max_insns)
    by_addr = {i.addr: idx for idx, i in enumerate(insns)}
    out: list[CrcLoop] = []

    # candidate init: last immediate-into-register of an init constant before a loop
    recent_init: int | None = None
    init_addr: int | None = None

    for idx, ins in enumerate(insns):
        if ins.mnemonic in _IMM_LOAD:
            for op in ins.operands():
                if op.is_imm and op.imm in _INIT_CONSTS:
                    recent_init = op.imm
                    init_addr = ins.addr
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
                poly_addrs: list[int] = []
                for bi in body:
                    if bi.mnemonic in _XOR:
                        for op in bi.operands():
                            if op.is_imm and op.imm is not None and op.imm > 0xFF:
                                polys.append(op.imm & 0xFFFFFFFF)
                                poly_addrs.append(bi.addr)
                shifty = sum(mn[m] for m in _SHIFTS)
                looks_crc = (len(body) >= 4 and bitops >= max(3, len(body) // 2)) or (
                    polys and shifty >= 2 and len(set(polys)) <= 2
                )
                if not looks_crc:
                    continue
                hit = _crc_evidence(
                    tgt,
                    ins.addr,
                    body,
                    polys,
                    poly_addrs,
                    shifty,
                    recent_init,
                    init_addr,
                )
                out.append(hit)
    return out


def _crc_evidence(
    start: int,
    end: int,
    body: list[Insn],
    polys: list[int],
    poly_addrs: list[int],
    shifty: int,
    init: int | None,
    init_addr: int | None,
) -> CrcLoop:
    """Build a CrcLoop with its kind, reasons, and caveats from the loop body."""
    uniq_polys = sorted(set(polys))
    kind = "crc" if uniq_polys else "checksum"
    reasons: list[str] = []
    caveats: list[str] = []
    support: list[int] = [start, end]
    if uniq_polys:
        reasons.append(
            "xors a polynomial-like constant ("
            + ", ".join(f"{p:#x}" for p in uniq_polys)
            + ")"
        )
        support.extend(poly_addrs)
        confidence = "high" if shifty >= 2 else "medium"
    else:
        reasons.append(f"bit-op-heavy loop ({shifty} shift/rotate ops, no polynomial)")
        caveats.append("no polynomial constant: a sum/xor checksum, not a true CRC")
        confidence = "medium"
    if init is not None:
        reasons.append(f"accumulator initialized to {init:#x} before the loop")
        if init_addr is not None:
            support.append(init_addr)
    caveats.append(
        "a register-folded polynomial would be missed; confirm the loop body"
    )
    return CrcLoop(
        start=start,
        end=end,
        polys=uniq_polys,
        init=init,
        insn_count=len(body),
        kind=kind,
        evidence=Evidence(
            confidence=confidence,
            reasons=tuple(reasons),
            caveats=tuple(caveats),
            support=tuple(support),
        ),
    )


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
    evidence: Evidence = field(default_factory=Evidence)


def _reg_parent(reg: str) -> str:
    """Best-effort 64-bit parent of a sub-register for ABI matching (x86 subset)."""
    return reg


def call_immediate_args(
    image: Image, va: int, *, max_insns: int = 1500
) -> list[CallArg]:
    """Immediates loaded into a register that is still live at the next call.

    Tracks the most recent immediate per register, propagates a constant across a
    register-to-register move (`mov rdx, rax`), and invalidates a register when it
    is overwritten by a non-immediate write (a load, arithmetic, etc.) so a stale
    value is not reported. A value live in a calling-convention argument register
    at the call is `high` confidence; otherwise `medium` with a caveat.
    """
    arg_regs = _ARG_REGS.get(image.arch, set())
    # reg -> (value, load_addr)
    live: dict[str, tuple[int, int]] = {}
    out: list[CallArg] = []
    for ins in function_insns(image, va, max_insns=max_insns):
        ops = ins.operands()

        if ins.mnemonic in _IMM_LOAD and len(ops) >= 2 and ops[0].is_reg:
            dst = ops[0].reg or ""
            if ops[1].is_imm and ops[1].imm is not None:
                live[dst] = (ops[1].imm & 0xFFFFFFFFFFFFFFFF, ins.addr)
            elif ops[1].is_reg and (ops[1].reg in live):
                # const propagation across a register move
                live[dst] = live[ops[1].reg]
            else:
                # overwritten by a non-constant value: the tracked const is dead
                live.pop(dst, None)
        elif ops and ops[0].is_reg and not ins.is_call():
            # any other instruction writing reg invalidates its tracked const
            dst = ops[0].reg or ""
            if dst in live and ins.mnemonic not in ("cmp", "test", "push"):
                live.pop(dst, None)

        if ins.is_call():
            tgt = ins.imm_target()
            for reg, (val, la) in live.items():
                out.append(
                    CallArg(
                        ins.addr,
                        tgt,
                        reg,
                        val,
                        la,
                        evidence=_callarg_evidence(reg, la, ins.addr, arg_regs),
                    )
                )
            # the call boundary may clobber caller-saved regs; clear the live set
            live.clear()
    return out


def _callarg_evidence(
    reg: str, load_addr: int, call_addr: int, arg_regs: set[str]
) -> Evidence:
    """Confidence for a register-passed constant by calling-convention slot."""
    if reg in arg_regs:
        return Evidence(
            confidence="high",
            reasons=(
                f"constant in argument register {reg} loaded at {load_addr:#x}, "
                f"live at the call",
            ),
            support=(load_addr, call_addr),
        )
    return Evidence(
        confidence="medium",
        reasons=(f"constant in {reg} loaded at {load_addr:#x}, live at the call",),
        caveats=(f"{reg} is not a standard argument register here",),
        support=(load_addr, call_addr),
    )


def function_constants(image: Image, va: int, *, max_insns: int = 1500) -> Counter:
    """Histogram of immediate constants referenced in the function at `va`."""
    c: Counter = Counter()
    for ins in function_insns(image, va, max_insns=max_insns):
        for op in ins.operands():
            if op.is_imm and op.imm is not None:
                c[op.imm & 0xFFFFFFFFFFFFFFFF] += 1
    return c
