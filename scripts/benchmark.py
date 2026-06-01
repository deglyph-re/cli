#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Timing benchmark for the whole-image analysis passes.

Times the cold (cache-disabled) cost of loading a binary and running each
expensive pass: discovery, the cross-reference index, string extraction, and
the CI scan. Kept out of the test suite (it is not a `test_*` module and pytest
does not collect `scripts/`); run it directly to spot regressions on a large or
stripped binary.

    python3 scripts/benchmark.py [path ...]

With no path it benchmarks the committed sample binary. Each pass is run with
`DEGLYPH_NO_CACHE` set so the reported time is a cold scan, not a cache hit.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _time(label: str, fn: Callable[[], Any]) -> tuple[str, float, str]:
    """Run `fn`, returning its label, wall-clock seconds, and a result note."""
    start = time.perf_counter()
    try:
        result = fn()
        note = _describe(result)
    except Exception as exc:
        note = f"error: {exc}"
    elapsed = time.perf_counter() - start
    return label, elapsed, note


def _describe(result: Any) -> str:
    """A short note about a pass result (a count for sized collections)."""
    try:
        return f"{len(result)} items"
    except TypeError:
        return "ok"


def _benchmark(path: str) -> None:
    from deglyph.core.image import load_image
    from deglyph.re import callers_of, extract_strings
    from deglyph.re.discover import scan_targets
    from deglyph.scan import scan_image

    print(f"\n{path}")
    image = load_image(path)
    rows = [_time("load_image", lambda: image)]
    rows.append(_time("discover", lambda: scan_targets(image)))
    # callers_of forces the cross-reference index to build over all of .text.
    rows.append(_time("xref index", lambda: callers_of(image, image.base)))
    rows.append(_time("strings", lambda: extract_strings(image)))
    rows.append(_time("scan", lambda: scan_image(image, cve=False)))
    width = max(len(label) for label, _, _ in rows)
    for label, elapsed, note in rows:
        print(f"  {label:<{width}}  {elapsed * 1000:8.1f} ms   {note}")


def main(argv: list[str]) -> int:
    paths = argv[1:]
    if not paths:
        default = os.path.join(_ROOT, "samples", "demo.exe")
        if not os.path.isfile(default):
            print("no path given and samples/demo.exe is absent; pass a binary path")
            return 1
        paths = [default]
    # Time cold scans: the on-disk cache would otherwise hide the real cost.
    os.environ["DEGLYPH_NO_CACHE"] = "1"
    missing = [p for p in paths if not os.path.isfile(p)]
    for p in missing:
        print(f"skip (not a file): {p}")
    targets = [p for p in paths if os.path.isfile(p)]
    if not targets:
        return 1
    for p in targets:
        _benchmark(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
