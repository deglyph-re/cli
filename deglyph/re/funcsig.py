# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Content-addressed function identity: a relocation-stable, fuzzy-comparable
signature for a single function, computed from its CFG-reached instructions.

The signature normalizes each instruction to its mnemonic plus the *class* of
each operand (register, immediate, memory, branch target), discarding concrete
register names, immediate values, and displacements. Two builds of the same
function differ in those concrete values (relocations, inlined constants, stack
layout) but share the normalized stream, so the identity survives a rebuild that
a raw-byte hash would not.

Public names:

  * FuncSig       a function's signature: an exact hash plus an n-gram set.
  * func_sig      compute the signature of the function at a VA.
  * similarity    Jaccard similarity of two signatures (0.0 .. 1.0).
  * normalize_insn the per-instruction normalizer (one token).

This is the engine shared by function fingerprinting (`re/funcdb.py`), semantic
binary diffing (`re/bindiff.py`), the content-keyed knowledge base (`store.py`),
and the older baseline diff (`scan.py`). It is a heuristic identity: a different
function can share a signature (a hash collision or a genuinely identical shape),
so a match is evidence to confirm, not a proof.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..core.disasm import Insn
from ..core.image import Image
from .cfg import function_cfg

# Default instruction cap for a signature. Long enough to characterize a real
# function, short enough to bound the n-gram set (and the corpus that stores it).
_MAX_INSNS = 256

# Length of the instruction n-grams hashed for fuzzy similarity. Four captures a
# short idiom (load / op / store / branch) without exploding the set.
_NGRAM = 4

# Stack / frame base registers: a memory access through one is a local-frame
# reference, kept distinct from a heap/struct access so the shape carries it.
_STACK_REGS = frozenset({"rsp", "esp", "sp", "rbp", "ebp", "x29", "w29", "fp"})


@dataclass(slots=True)
class FuncSig:
    """A function's content-addressed identity.

    `exact` is the sha256 of the normalized instruction stream (a relocation-
    stable fingerprint); `ngrams` is the set of hashed instruction n-grams used
    for fuzzy similarity; `n_insns` / `n_blocks` / `n_calls` are coarse size
    features. Two functions with the same `exact` are structurally identical
    under the normalization; `similarity` grades the partial-match case.
    """

    va: int
    exact: str
    ngrams: frozenset[str] = field(default_factory=frozenset)
    n_insns: int = 0
    n_blocks: int = 0
    n_calls: int = 0


def normalize_insn(ins: Insn) -> str:
    """One normalized token for an instruction: mnemonic plus operand classes.

    Each operand collapses to its class so a relocation or an inlined constant
    does not change the token: a register, an immediate value, a memory operand
    (split by stack/frame base versus other), and a direct branch/call target
    each map to a short code (see the mapping below). The token is stable across
    builds that differ only in addresses.
    """
    is_branch = ins.is_branch()
    parts: list[str] = []
    for op in ins.operands():
        if op.is_imm:
            parts.append("T" if is_branch else "I")
        elif op.is_reg:
            parts.append("R")
        elif op.is_mem:
            base = (op.mem_base or "").lower()
            parts.append("Ms" if base in _STACK_REGS else "Mm")
        else:
            parts.append("O")
    return ins.mnemonic + "|" + ",".join(parts)


def _ngrams(tokens: list[str]) -> frozenset[str]:
    """Hashed n-grams of the normalized token stream, for Jaccard similarity.

    Uses sha1 rather than the builtin `hash` so the set is stable across
    processes and machines (the corpus stores it). A stream shorter than one
    n-gram collapses to a single hash of the whole stream.
    """
    if not tokens:
        return frozenset()
    if len(tokens) < _NGRAM:
        windows = ["".join(tokens)]
    else:
        windows = [
            "".join(tokens[i : i + _NGRAM]) for i in range(len(tokens) - _NGRAM + 1)
        ]
    return frozenset(
        hashlib.sha1(w.encode("utf-8", "replace")).hexdigest()[:12] for w in windows
    )


def func_sig(image: Image, va: int, *, max_insns: int = _MAX_INSNS) -> FuncSig | None:
    """Signature of the function at `va`, or None when nothing decodes.

    Builds the function's CFG once (so the block count is free), normalizes its
    address-ordered instructions, and derives the exact hash and n-gram set.
    Decode failures degrade to None rather than raising, matching the per-region
    tolerance used elsewhere in the analysis core.
    """
    try:
        boundary = sorted(f.va for f in image.funcs)
        cfg = function_cfg(image, va, boundary=boundary, max_insns=max_insns)
        insns = cfg.instructions()
    except Exception:
        return None
    if not insns:
        return None
    tokens = [normalize_insn(i) for i in insns]
    digest = hashlib.sha256("\n".join(tokens).encode("utf-8", "replace")).hexdigest()
    n_calls = sum(1 for i in insns if i.is_call())
    return FuncSig(
        va=va,
        exact=digest,
        ngrams=_ngrams(tokens),
        n_insns=len(insns),
        n_blocks=len(cfg.blocks),
        n_calls=n_calls,
    )


def similarity(a: FuncSig, b: FuncSig) -> float:
    """Jaccard similarity of two signatures, in [0.0, 1.0].

    An identical exact hash short-circuits to 1.0. Otherwise the score is the
    Jaccard index of the two n-gram sets (intersection over union), so a small
    edit to one function yields a high-but-sub-1.0 score and an unrelated
    function yields near zero.
    """
    if a.exact == b.exact:
        return 1.0
    if not a.ngrams or not b.ngrams:
        return 0.0
    inter = len(a.ngrams & b.ngrams)
    if not inter:
        return 0.0
    union = len(a.ngrams | b.ngrams)
    return inter / union
