# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Function discovery for binaries without exports or symbols.

A stripped EXE exposes only its entrypoint and import thunks; its real functions
sit unnamed in `.text`. `discover_functions` recovers them from three signals,
each registered as a `sub_<va>` entry:

  - **unwind-table start** (`re/unwind.py`) -- an authoritative boundary the OS
    unwinds the stack off (Mach-O function-starts, PE `.pdata`, ELF `eh_frame`);
    registered as `confidence="confirmed"`.
  - **direct `call` target** -- a strong, low-false-positive function start;
    registered as `confidence="confirmed"`.
  - **tail `jmp` target that leaves the calling function** -- a function reached
    only by an optimized tail call (no `call` site); weaker, registered as
    `confidence="candidate"`.

Every recovered start carries `evidence` (the instructions that named it) so the
UI and JSON can show why it was recovered. Obvious mid-function false positives
(a branch into the body of an already-known function) are suppressed.

This is a heuristic recovery, not a complete CFG: indirect calls and jump-table
targets are still missed. Treat `sub_*` entries, and especially candidates, as
recovered starts to confirm in the disassembly, not as proven boundaries.
"""

from __future__ import annotations

import logging
import time
from bisect import bisect_right
from dataclasses import dataclass

from ..cache import cache_get, cache_put, file_sha256
from ..core.disasm import Disassembler
from ..core.image import Func, Image
from .unwind import unwind_starts

log = logging.getLogger(__name__)


@dataclass(slots=True)
class _Hit:
    """A recovered start before it is reconciled against known functions."""

    va: int
    confirmed: bool
    evidence: list[str]


def _executable(image: Image):
    return [s for s in image.sections if "X" in s.flags.upper()]


def _enclosing_start(starts: list[int], va: int) -> int | None:
    """The greatest known/confirmed start at or below `va` (its function), if any."""
    i = bisect_right(starts, va)
    return starts[i - 1] if i else None


def scan_call_targets(
    image: Image, *, max_bytes: int = 64 * 1024 * 1024, max_seconds: float | None = None
) -> list[int]:
    """Direct-`call` targets in code not already named (back-compat shim).

    Retained for callers that only want the confirmed call-target set; the TUI
    worker uses `scan_targets` for the richer hit list. Read-only.
    """
    hits = scan_targets(image, max_bytes=max_bytes, max_seconds=max_seconds)
    return [h.va for h in hits if h.confirmed]


def scan_targets(
    image: Image, *, max_bytes: int = 64 * 1024 * 1024, max_seconds: float | None = None
) -> list[_Hit]:
    """Recovered starts (call + tail-jmp) not already named, with evidence.

    Read-only: it does not mutate the image, so it is safe to run on a worker
    thread while the UI reads the same image. Apply the result with
    `add_discovered`. Scans up to `max_bytes` of code (this is the slow step on
    large binaries -- Capstone decodes every byte of `.text`).

    Two passes over the decode: the first collects direct-`call` targets (the
    confirmed set), which then anchor the function-start boundaries used in the
    second pass to tell an intra-function `jmp` from a tail call that leaves the
    function. A `jmp` whose target sits inside the same function it came from is
    a branch, not a start, and is dropped.

    The default-bound call is cached on disk by the binary content hash, so
    reopening an unchanged build skips the decode; a non-default `max_bytes`
    always recomputes. `max_seconds` bounds the decode by wall clock, returning
    the partial result so far; a budgeted call neither reads nor writes the cache.
    """
    default_args = max_bytes == 64 * 1024 * 1024
    digest = file_sha256(image.path) if (default_args and max_seconds is None) else None
    if digest is not None:
        cached = cache_get(digest, "discover")
        if cached is not None:
            return [
                _Hit(va=va, confirmed=conf, evidence=list(ev))
                for va, conf, ev in cached
            ]
    dis = Disassembler(image)
    exec_sections = _executable(image)

    def in_exec(t: int) -> bool:
        return any(sec.contains(t) for sec in exec_sections)

    # Authoritative starts from the unwind metadata. The OS unwinds the stack
    # off these tables, so each is a real boundary; they seed the confirmed set
    # and anchor the tail-jmp suppression below.
    unwind: dict[int, str] = {}
    for va, source in unwind_starts(image):
        if in_exec(va) and image.func_at(va) is None:
            unwind[va] = source

    decoded: list = []
    calls: dict[int, list[str]] = {}
    scanned = 0
    t0 = time.perf_counter()
    for s in exec_sections:
        if scanned >= max_bytes:
            break
        if max_seconds is not None and time.perf_counter() - t0 > max_seconds:
            break
        span = min(s.size, max_bytes - scanned)
        scanned += span
        # One pathological section must not abort the whole-image scan (the
        # catch-and-continue contract); a Capstone error ends this section only.
        try:
            for ins in dis.at(s.va, span):
                if ins.addr >= s.va + span:
                    break
                decoded.append(ins)
                if ins.is_call():
                    t = ins.imm_target()
                    if t is not None and in_exec(t):
                        calls.setdefault(t, []).append(f"direct call at {ins.addr:#x}")
        except Exception as e:
            log.debug("discovery skipped section %r: %s", s.name, e)
            continue

    # Function-start anchors: unwind starts and call targets plus every name the
    # container already gave us. A tail jmp counts as a new start only when it
    # crosses out of the function enclosing the jmp instruction.
    starts = sorted(set(unwind) | set(calls) | {f.va for f in image.funcs})

    jmps: dict[int, list[str]] = {}
    for ins in decoded:
        if ins.mnemonic not in ("jmp", "b"):
            continue
        t = ins.imm_target()
        if t is None or not in_exec(t) or t in calls or image.func_at(t) is not None:
            continue
        src_fn = _enclosing_start(starts, ins.addr)
        dst_fn = _enclosing_start(starts, t)
        # Same enclosing function -> intra-function branch, not a new start.
        if src_fn is not None and src_fn == dst_fn:
            continue
        # Target lands inside the body of a *bounded* known function (between a
        # start and the next start, not at the start itself) -> mid-function
        # false positive. A target past the last known start is unbounded and
        # treated as a genuine tail-call start, not suppressed.
        if dst_fn is not None and dst_fn != t:
            i = bisect_right(starts, dst_fn)
            next_start = starts[i] if i < len(starts) else None
            if next_start is not None and t < next_start:
                continue
        jmps.setdefault(t, []).append(f"tail jmp at {ins.addr:#x}")

    hits: dict[int, _Hit] = {}
    # Unwind-table starts are the strongest signal; record them first so a call
    # target at the same VA merges its evidence rather than overwriting.
    for va, source in unwind.items():
        hits[va] = _Hit(va=va, confirmed=True, evidence=[source])
    for va, ev in calls.items():
        if image.func_at(va) is not None:
            continue
        if va in hits:
            hits[va].evidence = (hits[va].evidence + ev)[:4]
        else:
            hits[va] = _Hit(va=va, confirmed=True, evidence=ev[:4])
    for va, ev in jmps.items():
        if va in hits or image.func_at(va) is not None:
            continue
        hits[va] = _Hit(va=va, confirmed=False, evidence=ev[:4])
    result = [hits[va] for va in sorted(hits)]
    if digest is not None:
        cache_put(digest, "discover", [[h.va, h.confirmed, h.evidence] for h in result])
    return result


def add_discovered(image: Image, targets: list) -> int:
    """Register `sub_<va>` functions for `targets` and reindex. Returns the count.

    Accepts a list of `_Hit` (confidence + evidence carried through) or a plain
    list of int VAs (treated as confirmed call targets, no evidence) for the
    back-compat call-target path.
    """
    added = 0
    for t in targets:
        if isinstance(t, int):
            va, confirmed, evidence = t, True, ()
        else:
            va, confirmed, evidence = t.va, t.confirmed, tuple(t.evidence)
        if image.func_at(va) is None:
            image.funcs.append(
                Func(
                    name=f"sub_{va:x}",
                    va=va,
                    kind="sub",
                    confidence="confirmed" if confirmed else "candidate",
                    evidence=evidence,
                )
            )
            added += 1
    if added:
        image.reindex()
    try:
        object.__setattr__(image, "_discovered", True)
    except Exception:
        image._discovered = True  # type: ignore[attr-defined]
    return added


def discover_functions(
    image: Image, *, max_bytes: int = 64 * 1024 * 1024, max_seconds: float | None = None
) -> int:
    """Scan for and register unexported functions in one synchronous pass.

    Convenience for headless use and tests; the TUI runs `scan_targets` on a
    worker and applies `add_discovered` on the UI thread. Idempotent.
    """
    if getattr(image, "_discovered", False):
        return 0
    hits = scan_targets(image, max_bytes=max_bytes, max_seconds=max_seconds)
    return add_discovered(image, hits)
