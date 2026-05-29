# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Cross-platform hardening posture detector."""

from __future__ import annotations

import os

import pytest

from deglyph import scan
from deglyph.core.image import Func

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def _rules(findings):
    return {f.rule for f in findings}


def test_synthetic_image_without_lief_returns_no_findings(code_image):
    # The synthetic Image fixture carries _lief=None; the detector skips it.
    img = code_image(bytes.fromhex("c3"))
    assert scan.scan_hardening(img) == []


def test_canary_symbol_detection(code_image):
    img = code_image(bytes.fromhex("c3"))
    img.funcs.append(Func(name="__stack_chk_fail", va=0x9000, kind="import"))
    img.reindex()
    assert scan._has_stack_canary(img) is True

    img2 = code_image(bytes.fromhex("c3"))
    assert scan._has_stack_canary(img2) is False


def test_macho_pie_helper_reads_flags():
    class _Hdr:
        flags = 0x200000
        flags_list = []

    class _Bin:
        header = _Hdr()

    assert scan._macho_is_pie(_Bin()) is True
    _Hdr.flags = 0
    assert scan._macho_is_pie(_Bin()) is False


def test_elf_stack_executable_helper():
    class _Seg:
        type = "SEGMENT_TYPES.GNU_STACK"
        # PF_R | PF_X
        flags = 0x5

    class _Bin:
        segments = [_Seg()]

    assert scan._elf_stack_is_executable(_Bin()) is True
    # PF_R | PF_W
    _Seg.flags = 0x6
    assert scan._elf_stack_is_executable(_Bin()) is False


def test_elf_relro_levels():
    class _SegRelro:
        type = "GNU_RELRO"

    class _DynBindNow:
        tag = "DYNAMIC_TAGS.BIND_NOW"
        value = 0

    class _BinFull:
        segments = [_SegRelro()]
        dynamic_entries = [_DynBindNow()]

    class _BinPartial:
        segments = [_SegRelro()]
        dynamic_entries = []

    class _BinNone:
        segments = []
        dynamic_entries = []

    assert scan._elf_relro_level(_BinFull()) == "full"
    assert scan._elf_relro_level(_BinPartial()) == "partial"
    assert scan._elf_relro_level(_BinNone()) == "none"


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_hardening_runs_on_real_pe():
    from deglyph.core.image import load_image

    img = load_image(SAMPLE)
    findings = scan.scan_hardening(img)
    # demo.exe is a known cooperative binary - it will produce a finite set
    # of hardening findings (zero or more). The contract here is just that the
    # detector executes against a real PE without raising.
    for f in findings:
        assert f.rule.startswith("harden/")
        assert f.where == "hardening"
        assert f.level in ("note", "warning", "error")


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_scan_image_includes_hardening_findings_by_default():
    from deglyph.core.image import load_image

    img = load_image(SAMPLE)
    rules = _rules(scan.scan_image(img, fingerprint=False))
    # at least one hardening rule should be present (the demo is not maximally hardened)
    assert any(r.startswith("harden/") for r in rules)


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_no_hardening_flag_suppresses_them():
    from deglyph.core.image import load_image

    img = load_image(SAMPLE)
    rules = _rules(scan.scan_image(img, hardening=False, fingerprint=False))
    assert not any(r.startswith("harden/") for r in rules)
