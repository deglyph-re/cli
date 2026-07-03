# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
A bounded control-flow graph for a single function.

`disasm.func` decodes linearly until the first `ret`, which silently drops any
code after an early return or behind a forward conditional branch, and never
shows what bytes it skipped. `function_cfg` instead does a bounded recursive
descent from the function start: it follows fall-through, conditional branches
(both edges), and in-bounds unconditional jumps, stops at a `ret`, a neighboring
function start, or the section end, and reports the bytes inside the function's
extent that it never reached.

Public names: `BasicBlock`, `FunctionCFG`, `function_cfg`. The CFG is the backing
model the linear disassembly view, callees, xrefs, pseudo-C, and detectors can
share so they all agree on which bytes belong to the function. An indirect `jmp`
through a memory-operand jump table (`jmp [table + index*width]`) has its arms
recovered when the idiom is unambiguous (`_jump_table_targets`); a
register-computed indirect jump still ends a block with no successor, so its
arms surface as an undecoded gap rather than being silently merged in.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field

from ..core.disasm import Disassembler, Insn
from ..core.image import Arch, Image

# A descent never decodes more than this many instructions, so a runaway or a
# pathological self-referential stream cannot stall a whole-image scan.
_MAX_INSNS = 20000

# The most jump-table arms read from one indexed indirect jump; a real switch is
# well under this, and the cap stops a misread table from running away.
_MAX_JUMP_ARMS = 256


@dataclass(slots=True)
class BasicBlock:
    """A maximal straight-line run of instructions ending in a branch/ret/fallthrough."""

    start: int
    insns: list[Insn]
    # VAs this block can transfer control to (fall-through and/or branch target)
    successors: list[int] = field(default_factory=list)
    # "ret" | "jmp" | "cond" | "indirect" | "jumptable" | "fallthrough"
    kind: str = "fallthrough"

    @property
    def end(self) -> int:
        """One past the last decoded byte of the block."""
        if not self.insns:
            return self.start
        last = self.insns[-1]
        return last.addr + last.size


@dataclass(slots=True)
class Gap:
    """A run of bytes inside the function extent that the descent never reached."""

    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(slots=True)
class FunctionCFG:
    va: int
    blocks: list[BasicBlock]
    # bytes inside [va, extent) that no block covered (undecoded / data / padding)
    gaps: list[Gap]
    # one past the highest decoded byte reached from the start
    extent: int

    def instructions(self) -> list[Insn]:
        """All decoded instructions in address order (the linear view, CFG-backed)."""
        out: list[Insn] = []
        for b in sorted(self.blocks, key=lambda b: b.start):
            out.extend(b.insns)
        return out

    def covered(self) -> int:
        """Total bytes covered by decoded blocks."""
        return sum(b.end - b.start for b in self.blocks)


def _next_start(starts: list[int], va: int) -> int | None:
    """The smallest known function start strictly greater than `va`, if any."""
    i = bisect_right(starts, va)
    return starts[i] if i < len(starts) else None


def function_cfg(
    image: Image,
    va: int,
    *,
    boundary: list[int] | None = None,
    max_insns: int = _MAX_INSNS,
) -> FunctionCFG:
    """Bounded recursive-descent CFG of the function at `va`.

    `boundary` is a sorted list of known function starts; the descent stops when
    it reaches one (the next function), so a missing `ret` does not bleed into
    the neighbor. With none given, only the section end bounds the walk. Decoding
    is wrapped per block so one bad region ends that block instead of the CFG.
    """
    sec = image.section_at(va)
    if sec is None:
        return FunctionCFG(va=va, blocks=[], gaps=[], extent=va)

    starts = boundary or []
    stop_at = _next_start(starts, va) if starts else None
    limit = sec.end if stop_at is None else min(sec.end, stop_at)

    dis = Disassembler(image)
    blocks: dict[int, BasicBlock] = {}
    worklist = [va]
    budget = max_insns

    while worklist and budget > 0:
        bstart = worklist.pop()
        if bstart in blocks or not (va <= bstart < limit):
            continue
        block = _decode_block(dis, bstart, limit, budget)
        if not block.insns:
            continue
        budget -= len(block.insns)
        blocks[bstart] = block
        for succ in block.successors:
            if va <= succ < limit and succ not in blocks:
                worklist.append(succ)

    ordered = sorted(blocks.values(), key=lambda b: b.start)
    extent = max((b.end for b in ordered), default=va)
    gaps = _find_gaps(ordered, va, extent)
    return FunctionCFG(va=va, blocks=ordered, gaps=gaps, extent=extent)


def function_insns(image: Image, va: int, *, max_insns: int = _MAX_INSNS) -> list[Insn]:
    """CFG-reached instructions of the function at `va`, in address order.

    The shared entry point for the per-function analyzers (detectors, pseudo-C,
    data refs). Unlike `Disassembler.func` (decode until the first `ret`), this
    reaches code behind a forward conditional branch or after an early return, so
    a detector no longer misses a store / call that sits past the first `ret`.
    The function's neighbors bound the walk (so it cannot bleed into the next
    function), and the result is address-ordered, a strict superset of the old
    linear stream for the common fall-through case, which keeps the order-
    sensitive detectors (CRC loops, call-arg liveness) behaving as before there.
    """
    boundary = sorted(f.va for f in image.funcs)
    return function_cfg(
        image, va, boundary=boundary, max_insns=max_insns
    ).instructions()


def _decode_block(dis: Disassembler, start: int, limit: int, budget: int) -> BasicBlock:
    """Decode one basic block from `start`, stopping at the first control transfer."""
    insns: list[Insn] = []
    block = BasicBlock(start=start, insns=insns)
    span = min(limit - start, budget * 16)
    for ins in dis.at(start, max_bytes=span):
        if ins.addr >= limit:
            break
        insns.append(ins)
        if len(insns) >= budget:
            block.kind = "fallthrough"
            break
        if ins.is_ret():
            block.kind = "ret"
            return block
        if ins.is_uncond_jmp():
            tgt = ins.imm_target()
            if tgt is not None:
                block.kind = "jmp"
                block.successors = [tgt]
            else:
                # An indirect jump has no immediate target. Recover the arms of a
                # memory-operand jump table when the idiom is unambiguous; a
                # register-indirect jump stays a plain indirect with no successor.
                arms = _jump_table_targets(dis, ins)
                if arms:
                    block.kind = "jumptable"
                    block.successors = arms
                else:
                    block.kind = "indirect"
            return block
        if ins.is_cond_branch():
            tgt = ins.imm_target()
            fall = ins.addr + ins.size
            block.kind = "cond"
            block.successors = [s for s in (fall, tgt) if s is not None]
            return block
    # Fell off the end of the span without a terminator: fall through to the
    # next instruction address, unless the block is empty.
    if insns:
        nxt = insns[-1].addr + insns[-1].size
        if nxt < limit:
            block.successors = [nxt]
    return block


def _jump_table_targets(dis: Disassembler, ins: Insn) -> list[int]:
    """Arms of an x86 memory-operand jump table, or [] when not that idiom.

    Handles the form `jmp [<table> + index*width]` (and its RIP-relative
    variant), where the table holds consecutive absolute code pointers, one per
    switch case. The width comes from the access size (a `qword ptr` table on
    x86-64, a `dword ptr` table on x86); the table address is either the
    RIP-relative or absolute displacement. Register-computed tables and the
    offset-plus-base form (`jmp reg` after `lea`/`add`) are not resolved here.

    Precision gates, so a data region is never misread as code: the operand must
    be indexed, the pointer width must match the architecture, and every arm
    must be a mapped executable address read consecutively from the table with
    no gap. Fewer than two valid arms is treated as "not a table".
    """
    image = dis.image
    mem = next((op for op in ins.operands() if op.is_mem), None)
    if mem is None or mem.mem_index is None:
        return []
    width = mem.size
    if width == 8 and image.arch not in (Arch.X64, Arch.ARM64):
        return []
    if width == 4 and image.arch != Arch.X86:
        return []
    if width not in (4, 8):
        return []
    base = (mem.mem_base or "").lower()
    if base in ("rip", "pc"):
        table = (ins.addr + ins.size + mem.mem_disp) & 0xFFFFFFFFFFFFFFFF
    elif mem.mem_base is None:
        table = mem.mem_disp & 0xFFFFFFFFFFFFFFFF
    else:
        # A general-register base means the table address is computed at runtime;
        # it cannot be resolved from this instruction alone.
        return []
    if image.section_at(table) is None:
        return []
    arms: list[int] = []
    for i in range(_MAX_JUMP_ARMS):
        raw = image.read_va(table + i * width, width)
        if len(raw) < width:
            break
        target = int.from_bytes(raw, "little")
        if target == 0:
            break
        sec = image.section_at(target)
        if sec is None or "X" not in sec.flags.upper():
            break
        arms.append(target)
    if len(arms) < 2:
        return []
    # Preserve order, drop duplicate case targets.
    seen: set[int] = set()
    unique: list[int] = []
    for a in arms:
        if a not in seen:
            seen.add(a)
            unique.append(a)
    return unique


def _find_gaps(blocks: list[BasicBlock], lo: int, hi: int) -> list[Gap]:
    """Byte ranges in `[lo, hi)` not covered by any block (undecoded / data)."""
    if not blocks:
        return [Gap(lo, hi)] if hi > lo else []
    gaps: list[Gap] = []
    cursor = lo
    for b in blocks:
        if b.start > cursor:
            gaps.append(Gap(cursor, b.start))
        cursor = max(cursor, b.end)
    if cursor < hi:
        gaps.append(Gap(cursor, hi))
    return gaps
