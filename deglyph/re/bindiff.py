# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Semantic function-level diff between two builds of the same binary.

Where a name / address diff reports a moved or recompiled function as
removed + added, `diff_functions` matches functions by content using the
relocation-stable signatures from `re/funcsig`: an exact-hash pass pairs
unchanged functions, a fuzzy pass pairs recompiled ones (carrying a similarity
score), and whatever stays unpaired is genuinely added or removed. Functions
with no decodable body (a named import-thunk target, a zero-size stub) fall back
to name identity so the diff still places them.

Public names: `FuncDelta`, `diff_functions`, `diff_text`, `diff_json`,
`diff_markdown`. The result is a heuristic: a fuzzy match is a likely
correspondence to confirm in the disassembly, not a proof of equivalence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.image import Func, Image
from .funcsig import FuncSig, func_sig, similarity

# Default Jaccard floor for calling two functions the same one recompiled. Below
# this a pair is treated as unrelated (added + removed), not modified.
_MIN_SIMILARITY = 0.85


@dataclass(slots=True)
class FuncDelta:
    """One function's fate between a baseline and a current build.

    `kind` is "unchanged" | "modified" | "added" | "removed". `va` is the
    current address (None for a removed function), `baseline_va` the baseline
    address (None for an added one). `similarity` is 1.0 for an exact match and
    the n-gram Jaccard for a fuzzy one; `evidence` names why the pairing was made.
    """

    kind: str
    name: str
    va: int | None
    baseline_va: int | None
    similarity: float
    evidence: str


def _disp(f: Func) -> str:
    return f.display


def _signed(image: Image) -> tuple[list[tuple[Func, FuncSig]], list[Func]]:
    """Split non-import functions into (signed, unsigned) for the two diff passes."""
    signed: list[tuple[Func, FuncSig]] = []
    unsigned: list[Func] = []
    for f in image.funcs:
        if f.kind == "import":
            continue
        sig = func_sig(image, f.va)
        if sig is None:
            unsigned.append(f)
        else:
            signed.append((f, sig))
    return signed, unsigned


def _exact_pass(
    cur: list[tuple[Func, FuncSig]], base: list[tuple[Func, FuncSig]]
) -> tuple[list[FuncDelta], list[tuple[Func, FuncSig]], list[tuple[Func, FuncSig]]]:
    """Pair functions with an identical exact hash; return deltas + the leftovers."""
    base_by_exact: dict[str, list[tuple[Func, FuncSig]]] = {}
    for f, s in base:
        base_by_exact.setdefault(s.exact, []).append((f, s))
    deltas: list[FuncDelta] = []
    cur_left: list[tuple[Func, FuncSig]] = []
    for f, s in cur:
        bucket = base_by_exact.get(s.exact)
        if bucket:
            bf, _bs = bucket.pop()
            deltas.append(
                FuncDelta(
                    "unchanged", _disp(f), f.va, bf.va, 1.0, "exact content match"
                )
            )
        else:
            cur_left.append((f, s))
    base_left = [pair for bucket in base_by_exact.values() for pair in bucket]
    return deltas, cur_left, base_left


def _fuzzy_pass(
    cur: list[tuple[Func, FuncSig]],
    base: list[tuple[Func, FuncSig]],
    min_similarity: float,
) -> tuple[list[FuncDelta], list[tuple[Func, FuncSig]], list[tuple[Func, FuncSig]]]:
    """Greedily pair the closest remaining functions above `min_similarity`."""
    candidates: list[tuple[float, int, int]] = []
    for ci, (_cf, cs) in enumerate(cur):
        for bi, (_bf, bs) in enumerate(base):
            lo, hi = sorted((cs.n_insns or 1, bs.n_insns or 1))
            # n-gram Jaccard cannot exceed the size ratio, so skip a mismatch
            if hi and lo / hi < min_similarity:
                continue
            sim = similarity(cs, bs)
            if sim >= min_similarity:
                candidates.append((sim, ci, bi))
    candidates.sort(key=lambda t: t[0], reverse=True)
    used_c: set[int] = set()
    used_b: set[int] = set()
    deltas: list[FuncDelta] = []
    for sim, ci, bi in candidates:
        if ci in used_c or bi in used_b:
            continue
        used_c.add(ci)
        used_b.add(bi)
        cf = cur[ci][0]
        bf = base[bi][0]
        deltas.append(
            FuncDelta(
                "modified", _disp(cf), cf.va, bf.va, sim, f"{sim:.0%} n-gram similarity"
            )
        )
    cur_left = [p for i, p in enumerate(cur) if i not in used_c]
    base_left = [p for i, p in enumerate(base) if i not in used_b]
    return deltas, cur_left, base_left


def _name_pass(cur: list[Func], base: list[Func]) -> list[FuncDelta]:
    """Diff functions with no decodable body by name (the fallback identity)."""
    cur_by_name = {_disp(f): f for f in cur}
    base_by_name = {_disp(f): f for f in base}
    deltas: list[FuncDelta] = []
    for name, f in cur_by_name.items():
        if name in base_by_name:
            deltas.append(
                FuncDelta(
                    "unchanged", name, f.va, base_by_name[name].va, 1.0, "name match"
                )
            )
        else:
            deltas.append(
                FuncDelta(
                    "added", name, f.va, None, 0.0, "name-only (no decodable body)"
                )
            )
    for name, f in base_by_name.items():
        if name not in cur_by_name:
            deltas.append(
                FuncDelta(
                    "removed", name, None, f.va, 0.0, "name-only (no decodable body)"
                )
            )
    return deltas


def diff_functions(
    image: Image, baseline: Image, *, min_similarity: float = _MIN_SIMILARITY
) -> list[FuncDelta]:
    """Match functions across two builds; return one `FuncDelta` per function.

    Imports are excluded (they diff by name elsewhere). Signed functions match
    exact-then-fuzzy by content; unsigned ones (no decodable body) match by name.
    A current function left unpaired is "added", a baseline one "removed".
    """
    cur_signed, cur_unsigned = _signed(image)
    base_signed, base_unsigned = _signed(baseline)

    exact, cur_signed, base_signed = _exact_pass(cur_signed, base_signed)
    fuzzy, cur_signed, base_signed = _fuzzy_pass(
        cur_signed, base_signed, min_similarity
    )

    out: list[FuncDelta] = []
    out.extend(exact)
    out.extend(fuzzy)
    for f, _s in cur_signed:
        out.append(FuncDelta("added", _disp(f), f.va, None, 0.0, "no baseline match"))
    for f, _s in base_signed:
        out.append(FuncDelta("removed", _disp(f), None, f.va, 0.0, "no current match"))
    out.extend(_name_pass(cur_unsigned, base_unsigned))
    return out


# --- rendering --------------------------------------------------------------

# Display order for the kinds, surfaced changes first.
_KIND_ORDER = ("modified", "added", "removed", "unchanged")


def _counts(deltas: list[FuncDelta]) -> dict[str, int]:
    out = {k: 0 for k in _KIND_ORDER}
    for d in deltas:
        out[d.kind] = out.get(d.kind, 0) + 1
    return out


def diff_text(deltas: list[FuncDelta]) -> str:
    """Human-readable diff: a summary line then the changed functions."""
    c = _counts(deltas)
    lines = [
        f"{c['modified']} modified, {c['added']} added, "
        f"{c['removed']} removed, {c['unchanged']} unchanged"
    ]
    for kind in ("modified", "added", "removed"):
        group = [d for d in deltas if d.kind == kind]
        if not group:
            continue
        lines.append(f"\n{kind.title()} ({len(group)}):")
        for d in sorted(group, key=lambda d: d.name):
            loc = f"{d.va:#x}" if d.va is not None else f"{d.baseline_va:#x}"
            extra = f"  {d.similarity:.0%}" if kind == "modified" else ""
            lines.append(f"  {loc:<14} {d.name}{extra}")
    return "\n".join(lines)


def diff_json(deltas: list[FuncDelta]) -> dict:
    """Machine-readable diff for tooling / gating."""
    return {
        "tool": "deglyph",
        "summary": _counts(deltas),
        "functions": [
            {
                "kind": d.kind,
                "name": d.name,
                "va": None if d.va is None else hex(d.va),
                "baseline_va": None if d.baseline_va is None else hex(d.baseline_va),
                "similarity": round(d.similarity, 4),
                "evidence": d.evidence,
            }
            for d in deltas
        ],
    }


def diff_markdown(deltas: list[FuncDelta]) -> str:
    """PR-comment-shaped diff (changed functions only)."""
    c = _counts(deltas)
    lines = [
        f"## deglyph diff: {c['modified']} modified, {c['added']} added, "
        f"{c['removed']} removed"
    ]
    for kind in ("modified", "added", "removed"):
        group = [d for d in deltas if d.kind == kind]
        if not group:
            continue
        lines.append(f"\n### {kind.title()} ({len(group)})")
        for d in sorted(group, key=lambda d: d.name):
            loc = d.va if d.va is not None else d.baseline_va
            extra = f" ({d.similarity:.0%} similar)" if kind == "modified" else ""
            lines.append(f"- `{d.name}` at `{loc:#x}`{extra}")
    return "\n".join(lines)
