# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Property tests for the address model: VA <-> offset translation and section
reads. These are deterministic parametrized sweeps (no generative dependency),
asserting invariants that must hold for every section and every in-range and
out-of-range address, on a synthetic image and on the committed sample binary.
"""

from __future__ import annotations

import os

import pytest

from deglyph.core.image import Image, load_image

_DEMO = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def _images(code_image) -> list[tuple[str, Image]]:
    """The images under test: a synthetic blob plus demo.exe when present."""
    out = [("synthetic", code_image(bytes(range(64)) + b"\xc3"))]
    if os.path.isfile(_DEMO):
        out.append(("demo.exe", load_image(_DEMO)))
    return out


def _mapped_sections(img: Image):
    """Sections with on-disk bytes; a NOBITS section (.bss) has no readable data."""
    return [s for s in img.sections if s.raw_size > 0]


def test_section_at_is_consistent_within_and_outside_bounds(code_image):
    for _label, img in _images(code_image):
        for sec in img.sections:
            # the start and the last contained VA resolve to a section that
            # also contains them (sections may abut, so not necessarily `sec`)
            assert img.section_at(sec.va) is not None or sec.size == 0
            last = sec.end - 1
            if sec.size:
                hit = img.section_at(last)
                assert hit is not None and hit.contains(last)
            # one past the end is not inside this section
            assert not sec.contains(sec.end)


def test_read_va_round_trips_mapped_bytes(code_image):
    for _label, img in _images(code_image):
        for sec in _mapped_sections(img):
            raw = img._section_raw(sec)
            # the first mapped byte reads back exactly
            first = img.read_va(sec.va, 1)
            assert first == raw[:1]
            # an interior window matches the raw slice at the same offset
            off = min(8, max(0, sec.raw_size - 1))
            n = min(16, sec.raw_size - off)
            if n > 0:
                assert img.read_va(sec.va + off, n) == raw[off : off + n]


def test_read_va_never_over_reads_a_section(code_image):
    for _label, img in _images(code_image):
        for sec in _mapped_sections(img):
            # asking for more than is mapped yields at most the remaining bytes
            got = img.read_va(sec.va, sec.raw_size + 64)
            assert len(got) <= sec.raw_size


@pytest.mark.parametrize("delta", [-0x1000, -1, 0])
def test_read_va_out_of_range_returns_empty_not_raises(code_image, delta):
    for _label, img in _images(code_image):
        base = min((s.va for s in img.sections), default=0)
        # a VA below the first section maps to no section
        if img.section_at(base + delta) is None:
            assert img.read_va(base + delta, 16) == b""


def test_read_va_past_last_section_is_empty(code_image):
    for _label, img in _images(code_image):
        if not img.sections:
            continue
        far = max(s.end for s in img.sections) + 0x10000
        assert img.section_at(far) is None
        assert img.read_va(far, 16) == b""


def test_func_at_is_exact_and_nearest_is_monotone(code_image):
    for _label, img in _images(code_image):
        for f in img.funcs:
            # an exact VA resolves to a function at that VA
            assert img.func_at(f.va) is not None
            assert img.func_at(f.va).va == f.va
            # nearest_func at the start is at or below the start
            near = img.nearest_func(f.va)
            assert near is not None and near.va <= f.va


def test_nearest_func_below_first_is_none(code_image):
    for _label, img in _images(code_image):
        if not img.funcs:
            continue
        lowest = min(f.va for f in img.funcs)
        assert img.nearest_func(lowest - 1) is None
