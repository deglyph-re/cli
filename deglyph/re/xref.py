# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Cross-references and call-graph helpers: who calls a function, what it calls,
and resolving exported-wrapper -> real-implementation thunk chains.

`callers_of` builds a one-shot index by scanning every executable section once;
the result is cached on the Image so repeated lookups in the TUI are instant.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..cache import cache_get, cache_put, file_sha256
from ..core.disasm import Disassembler
from ..core.image import Image


@dataclass(slots=True)
class XrefIndex:
    # callee_va -> list of caller instruction addresses (code: call / jmp)
    to: dict[int, list[int]]
    # data_va -> list of referencing instruction addresses (data: rip-rel / adrp
    # / absolute / literal). Lets a string or table show every site that uses it.
    data: dict[int, list[int]]


def _build_index(image: Image) -> XrefIndex:
    dis = Disassembler(image)
    to: dict[int, list[int]] = {}
    data: dict[int, list[int]] = {}
    text = image.text
    if not text:
        return XrefIndex(to, data)
    for ins in dis.at(text.va, text.size):
        if ins.addr >= text.end:
            break
        # code edges: direct call / jmp into .text
        if ins.is_call() or ins.mnemonic == "jmp":
            t = ins.imm_target()
            if t is not None and text.contains(t):
                to.setdefault(t, []).append(ins.addr)
        # data edge: an operand that resolves to a mapped, non-executable address
        d = ins.data_ref()
        if d is not None and not text.contains(d):
            sec = image.section_at(d)
            if sec is not None and "X" not in sec.flags.upper():
                data.setdefault(d, []).append(ins.addr)
    return XrefIndex(to, data)


def _serialize(idx: XrefIndex) -> dict:
    return {
        "to": {hex(k): [hex(a) for a in v] for k, v in idx.to.items()},
        "data": {hex(k): [hex(a) for a in v] for k, v in idx.data.items()},
    }


def _deserialize(doc: dict) -> XrefIndex:
    def _m(raw: dict | None) -> dict[int, list[int]]:
        return {int(k, 16): [int(a, 16) for a in v] for k, v in (raw or {}).items()}

    return XrefIndex(_m(doc.get("to")), _m(doc.get("data")))


def _index(image: Image) -> XrefIndex:
    cached = getattr(image, "_xref_index", None)
    if cached is not None:
        return cached
    # On-disk cache keyed by file hash: the index scans every byte of .text,
    # so reopening an unchanged build reuses the prior run's result.
    digest = file_sha256(image.path)
    payload = cache_get(digest, "xrefs")
    if payload is not None:
        cached = _deserialize(payload)
    else:
        cached = _build_index(image)
        cache_put(digest, "xrefs", _serialize(cached))
    try:
        object.__setattr__(image, "_xref_index", cached)
    except Exception:
        image._xref_index = cached  # type: ignore[attr-defined]
    return cached


def callers_of(image: Image, va: int) -> list[int]:
    """Instruction addresses that call/jmp to `va` (whole-image, cached scan)."""
    return list(_index(image).to.get(va, []))


def data_xrefs_to(image: Image, va: int) -> list[int]:
    """Instruction addresses that reference the data at `va` (cached scan).

    The complement of `callers_of` for non-code targets: every site whose
    operand resolves to `va` (a string, pointer table, or other datum), so a
    string's full use set is visible, not just nearby linear hits.
    """
    return list(_index(image).data.get(va, []))


def xrefs_to(image: Image, va: int) -> list[int]:
    """All instruction addresses referencing `va`, code (call/jmp) and data."""
    idx = _index(image)
    return sorted(set(idx.to.get(va, [])) | set(idx.data.get(va, [])))


def callees_of(image: Image, va: int) -> list[int]:
    """Direct call targets inside the function at `va`."""
    return Disassembler(image).callees(va)


@dataclass(slots=True)
class CallNode:
    va: int
    children: list[CallNode]
    # expansion stopped here: cycle, depth/width cap, or budget
    elided: bool = False


def call_tree(
    image: Image,
    va: int,
    *,
    callers: bool = False,
    depth: int = 3,
    max_children: int = 10,
    budget: int = 200,
) -> CallNode:
    """Bounded call tree rooted at `va`.

    `callers=False` walks callees (what each function calls); `callers=True` walks
    callers, each mapped to its enclosing function. A cycle, the depth/width caps,
    or an exhausted total-node `budget` marks a node `elided` instead of expanding.
    """
    dis = Disassembler(image)

    def neighbors(v: int) -> list[int]:
        if not callers:
            return dis.callees(v)
        out: list[int] = []
        for caller_addr in callers_of(image, v):
            f = image.nearest_func(caller_addr)
            fva = f.va if f else caller_addr
            if fva != v and fva not in out:
                out.append(fva)
        return out

    remaining = budget

    def build(v: int, d: int, seen: frozenset[int]) -> CallNode:
        nonlocal remaining
        node = CallNode(v, [])
        if v in seen or d <= 0 or remaining <= 0:
            node.elided = v in seen or d <= 0
            return node
        kids = neighbors(v)
        for k in kids[:max_children]:
            if remaining <= 0:
                node.elided = True
                break
            remaining -= 1
            node.children.append(build(k, d - 1, seen | {v}))
        if len(kids) > max_children:
            node.elided = True
        return node

    return build(va, depth, frozenset())


def _has_body(image: Image, va: int) -> bool:
    """True if the function at `va` does real work itself rather than being a pure
    argument-marshalling wrapper. Heuristic: it writes a structured buffer
    (immediate memory stores) OR it loads an immediate into a register and then
    calls (the command-dispatch idiom used by HID-style APIs)."""
    # avoid cycle
    from .patterns import call_immediate_args, immediate_stores

    if immediate_stores(image, va, max_insns=400):
        return True
    # A wrapper that loads a command immediate then calls a shared sender is the
    # target implementation; stop here rather than descend into the sender.
    return len(call_immediate_args(image, va, max_insns=400)) > 0


def thunk_chain(image: Image, va: int, depth: int = 8) -> list[int]:
    """Resolution chain from an exported wrapper to its real implementation.

    Returns [va, ..., real]. Follows tail-`jmp` thunks freely. For
    argument-marshalling wrappers (validate handle, shuffle args, then `call`
    the impl) it follows the last in-image call — but stops as soon as it reaches
    a function that builds structure itself, so it doesn't descend into the
    implementation's own sub-helpers (CRC, transport, etc.).
    """
    dis = Disassembler(image)
    text = image.text
    chain = [va]
    cur = va
    seen = {va}
    for _ in range(depth):
        # 1) prefer a tail-jmp thunk hop (cheap, unambiguous)
        nxt = dis.follow_thunk(cur, depth=1)
        if nxt != cur and text and text.contains(nxt):
            chain.append(nxt)
            seen.add(nxt)
            cur = nxt
            if _has_body(image, cur):
                break
            continue
        # 2) if the current function already builds structure, it's the impl — stop
        if _has_body(image, cur):
            break
        # 3) otherwise treat as a marshalling wrapper: hop to its last in-text call
        calls = dis.callees(cur)
        nxt = calls[-1] if calls else cur
        if nxt == cur or nxt in seen or not (text and text.contains(nxt)):
            break
        chain.append(nxt)
        seen.add(nxt)
        cur = nxt
        if _has_body(image, cur):
            break
    return chain
