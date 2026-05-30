# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Authoritative function-start recovery from unwind metadata."""

from __future__ import annotations

import os

from deglyph.core.image import Arch, Image, load_image
from deglyph.re.unwind import unwind_starts


def test_no_lief_binary_yields_nothing():
    # The synthetic Image used by detector tests carries no LIEF object; unwind
    # extraction must degrade to empty, never raise.
    img = Image(path="x", fmt="RAW", arch=Arch.X64, base=0)
    assert unwind_starts(img) == []


def test_unknown_format_yields_nothing():
    img = Image(path="x", fmt="WASM", arch=Arch.X64, base=0, _lief=object())
    assert unwind_starts(img) == []


def test_macho_function_starts_are_authoritative(host_binary):
    # A host Mach-O exposes LF_FUNCTION_STARTS; every start must be a VA inside a
    # mapped section and tagged as table-derived.
    img = load_image(host_binary)
    if img.fmt != "MachO":
        import pytest

        pytest.skip("host binary is not Mach-O")
    starts = unwind_starts(img)
    assert starts, "a host Mach-O should carry function-starts"
    for va, source in starts:
        assert img.section_at(va) is not None
        assert "function-starts" in source
    # de-duplicated and sorted
    vas = [v for v, _ in starts]
    assert vas == sorted(set(vas))


def test_unwind_starts_seed_confirmed_discovery(host_binary):
    from deglyph.re.discover import scan_targets

    img = load_image(host_binary)
    uw = {v for v, _ in unwind_starts(img)}
    if not uw:
        import pytest

        pytest.skip("host binary has no unwind table")
    hits = {h.va: h for h in scan_targets(img)}
    # Every unwind start not already a named function is a confirmed hit citing
    # the table as its evidence.
    seeded = [va for va in uw if img.func_at(va) is None]
    assert seeded, "expected unnamed unwind starts on a stripped-ish host binary"
    for va in seeded[:20]:
        assert va in hits
        assert hits[va].confirmed
        assert any("starts" in e or "table" in e for e in hits[va].evidence)


def test_pe_without_pdata_returns_empty():
    # The committed demo.exe is 32-bit x86: SEH, no table-based unwind, so the
    # exception-function source yields nothing (and must not raise).
    demo = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")
    if not os.path.isfile(demo):
        import pytest

        pytest.skip("demo.exe fixture missing")
    img = load_image(demo)
    assert unwind_starts(img) == []
