# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Function-recovery regression tests on stripped real-format binaries.

The fixtures are built by `samples/build_fixtures.sh` (stripped PE / ELF / Mach-O
/ fat Mach-O from `samples/fixture_src.c`); each test is skipif-absent so the
suite still runs on a checkout that has not built them. They exercise the whole
Section-1 pipeline on a real container: unwind-table starts -> confirmed
discovery -> confidence + evidence, the path the synthetic byte-blob tests cannot
cover because they have no real unwind metadata.
"""

from __future__ import annotations

import os

import pytest

from deglyph.core.image import load_image
from deglyph.re import discover_functions, unwind_starts

_SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

# label -> (filename, expected arch substring, expected slice count)
_FIXTURES = {
    "macho_x64": ("fixture_macho_x64", "x86", 0),
    "macho_arm64": ("fixture_macho_arm64", "arm64", 0),
    "macho_fat": ("fixture_macho_fat", "", 2),
    "elf_x64": ("fixture_elf_x64", "x86", 0),
    "elf_arm64": ("fixture_elf_arm64", "arm64", 0),
    "pe_x64": ("fixture_pe_x64.exe", "x86", 0),
}


def _path(label: str) -> str:
    return os.path.join(_SAMPLES, _FIXTURES[label][0])


def _require(label: str):
    p = _path(label)
    if not os.path.isfile(p):
        pytest.skip(f"{_FIXTURES[label][0]} not built (run samples/build_fixtures.sh)")
    return p


@pytest.mark.parametrize("label", list(_FIXTURES))
def test_fixture_loads_and_discovers_with_evidence(label):
    """A stripped fixture: discovery recovers functions, all carrying evidence."""
    img = load_image(_require(label))

    arch_sub = _FIXTURES[label][1]
    if arch_sub:
        assert arch_sub in img.arch.value

    discover_functions(img)
    subs = [f for f in img.funcs if f.kind == "sub"]
    assert subs, "discovery should recover functions in a stripped binary"
    # every recovered start explains itself
    assert all(f.evidence for f in subs)
    # a recovered start lands inside a mapped section (a real VA, never 0)
    assert all(f.va and img.section_at(f.va) is not None for f in subs)


@pytest.mark.parametrize("label", list(_FIXTURES))
def test_fixture_unwind_starts_are_confirmed(label):
    """Unwind-table starts seed confirmed discovery citing the table as evidence."""
    img = load_image(_require(label))
    uw = {va for va, _ in unwind_starts(img)}
    if not uw:
        pytest.skip(f"{label} exposes no unwind table")

    discover_functions(img)
    seeded = [va for va in uw if (f := img.func_at(va)) and f.kind == "sub"]
    assert seeded, "unwind starts should appear as discovered subs"
    for va in seeded:
        f = img.func_at(va)
        assert f.confidence == "confirmed"
        assert any("starts" in e or "table" in e or "eh_frame" in e for e in f.evidence)


def test_fat_macho_reports_both_slices():
    """The fat fixture exposes >1 architecture slice and picks a valid one."""
    img = load_image(_require("macho_fat"))
    assert len(img.slices) >= 2
    assert img.slice_index in {s.index for s in img.slices}
    discover_functions(img)
    assert [f for f in img.funcs if f.kind == "sub"]


def test_fixtures_recover_the_known_call_graph():
    """The fixture's helper functions form a recoverable call chain.

    fixture_src.c: _start -> set_volume -> {encode_frame -> crc16, send_frame}.
    On a stripped binary these are unnamed; discovery + the call index must still
    surface several distinct recovered starts wired by real call edges (the entry
    itself is a `Func` of kind "entry", so the helpers come back as `sub`s).
    """
    img = load_image(_require("macho_arm64"))
    discover_functions(img)
    from deglyph.re import callees_of

    subs = [f for f in img.funcs if f.kind == "sub"]
    assert len(subs) >= 3
    # at least one recovered function calls another recovered function (the
    # set_volume -> encode_frame / send_frame edges survive stripping)
    sub_vas = {f.va for f in subs}
    assert any(set(callees_of(img, f.va)) & sub_vas for f in subs)
