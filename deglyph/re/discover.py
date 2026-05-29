# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Function discovery for binaries without exports or symbols.

A stripped EXE exposes only its entrypoint and import thunks; its real functions
sit unnamed in `.text`. `discover_functions` recovers them by scanning executable
sections for direct `call` targets -- a strong, low-false-positive signal for a
function start -- and registers each new one as a `sub_<va>` entry.

This is a heuristic recovery, not a complete CFG: indirect calls, jump tables, and
functions reached only by tail-`jmp` are missed, and a `call` into the middle of a
routine (rare) would name a false start. Treat `sub_*` entries as candidates.
"""

from __future__ import annotations

from ..core.disasm import Disassembler
from ..core.image import Func, Image


def _executable(image: Image):
    return [s for s in image.sections if "X" in s.flags.upper()]


def scan_call_targets(image: Image, *, max_bytes: int = 64 * 1024 * 1024) -> list[int]:
    """Call targets in executable code that are not already named functions.

    Read-only: it does not mutate the image, so it is safe to run on a worker
    thread while the UI reads the same image. Apply the result with
    `add_discovered`. Scans up to `max_bytes` of code (this is the slow step on
    large binaries -- Capstone decodes every byte of `.text`).
    """
    dis = Disassembler(image)
    exec_sections = _executable(image)
    targets: set[int] = set()
    scanned = 0
    for s in exec_sections:
        if scanned >= max_bytes:
            break
        span = min(s.size, max_bytes - scanned)
        scanned += span
        for ins in dis.at(s.va, span):
            if ins.addr >= s.va + span:
                break
            if ins.is_call():
                t = ins.imm_target()
                if t is not None and any(sec.contains(t) for sec in exec_sections):
                    targets.add(t)
    return sorted(t for t in targets if image.func_at(t) is None)


def add_discovered(image: Image, targets: list[int]) -> int:
    """Register `sub_<va>` functions for `targets` and reindex. Returns the count."""
    added = 0
    for va in targets:
        if image.func_at(va) is None:
            image.funcs.append(Func(name=f"sub_{va:x}", va=va, kind="sub"))
            added += 1
    if added:
        image.reindex()
    try:
        object.__setattr__(image, "_discovered", True)
    except Exception:
        image._discovered = True  # type: ignore[attr-defined]
    return added


def discover_functions(image: Image, *, max_bytes: int = 64 * 1024 * 1024) -> int:
    """Scan for and register unexported functions in one synchronous pass.

    Convenience for headless use and tests; the TUI runs `scan_call_targets` on a
    worker and applies `add_discovered` on the UI thread. Idempotent.
    """
    if getattr(image, "_discovered", False):
        return 0
    return add_discovered(image, scan_call_targets(image, max_bytes=max_bytes))
