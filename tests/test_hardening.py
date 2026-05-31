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


def test_pe_security_cookie_helper():
    class _LC:
        security_cookie = 0x14001A000

    class _Bin:
        load_configuration = _LC()

    assert scan._pe_has_security_cookie(_Bin()) is True
    _LC.security_cookie = 0
    assert scan._pe_has_security_cookie(_Bin()) is False


def test_pe_canary_detected_via_load_config(code_image):
    # A stripped release PE (X64 fixture, no canary symbol) still proves /GS via
    # the load-config cookie, so no-stack-canary must not fire.
    img = code_image(bytes.fromhex("c3"))

    class _LC:
        security_cookie = 0x14001A000
        se_handler_count = 0

    class _OH:
        # DYNAMIC_BASE | NX_COMPAT | GUARD_CF | HIGH_ENTROPY_VA -> all hardened
        dll_characteristics = 0x4160

    class _Bin:
        optional_header = _OH()
        load_configuration = _LC()
        signatures = []

    rules = _rules(scan._hardening_pe(img, _Bin()))
    assert "harden/no-stack-canary" not in rules

    # With no cookie and no symbol, the warning fires as before.
    _LC.security_cookie = 0
    assert "harden/no-stack-canary" in _rules(scan._hardening_pe(img, _Bin()))


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


# --- Section 6: hardening findings carry decoded evidence in their message ----
def test_pe_findings_carry_dllcharacteristics_evidence(code_image):
    # dll=0 -> every PE protection missing; each message names the flag it lacks.
    img = code_image(bytes.fromhex("c3"))

    class _OH:
        dll_characteristics = 0

    class _LC:
        security_cookie = 0
        se_handler_count = 0

    class _Bin:
        optional_header = _OH()
        load_configuration = _LC()
        signatures = []

    findings = scan._hardening_pe(img, _Bin())
    by_rule = {f.rule: f for f in findings}
    assert "DYNAMIC_BASE" in by_rule["harden/no-aslr"].message
    assert "NX_COMPAT" in by_rule["harden/no-dep"].message
    assert "GUARD_CF" in by_rule["harden/no-cfg"].message
    # every hardening finding is a fact (a verifiable container flag)
    assert all(f.category == "fact" for f in findings)


# --- Section 6: synthetic platform hardening matrix --------------------------
# Real per-variant fixtures need cross-toolchains unavailable on every host;
# these inline fake-LIEF objects exercise each hardening path deterministically.
def _pe_bin(dll, *, cookie=0, se_count=0, signed=False):
    class _OH:
        dll_characteristics = dll

    class _LC:
        security_cookie = cookie
        se_handler_count = se_count

    class _Bin:
        optional_header = _OH()
        load_configuration = _LC()
        signatures = [object()] if signed else []

    return _Bin()


def test_pe_matrix_hardened_vs_unhardened(code_image):
    # x64 by default
    img = code_image(bytes.fromhex("c3"))
    # fully hardened: DYNAMIC_BASE|NX|GUARD_CF|HIGH_ENTROPY, cookie set, signed
    hard = scan._hardening_pe(img, _pe_bin(0x4160, cookie=1, signed=True))
    assert _rules(hard) == set()
    # nothing set: every PE protection missing
    bare = _rules(scan._hardening_pe(img, _pe_bin(0)))
    assert {
        "harden/no-aslr",
        "harden/no-dep",
        "harden/no-cfg",
        "harden/no-high-entropy-va",
        "harden/no-stack-canary",
        "harden/unsigned",
    } <= bare


def test_pe_matrix_individual_flags(code_image):
    img = code_image(bytes.fromhex("c3"))
    # ASLR on, DEP off -> only no-dep
    r = _rules(scan._hardening_pe(img, _pe_bin(0x40, cookie=1, signed=True)))
    assert "harden/no-aslr" not in r and "harden/no-dep" in r
    # DEP on, ASLR off -> only no-aslr
    r = _rules(scan._hardening_pe(img, _pe_bin(0x100, cookie=1, signed=True)))
    assert "harden/no-dep" not in r and "harden/no-aslr" in r


def _elf_bin(*, pie, relro, bind_now, stack_x):
    class _Seg:
        def __init__(self, t, fl=0x6):
            self.type = t
            self.flags = fl

    class _Dyn:
        tag = "DYNAMIC_TAGS.BIND_NOW"
        value = 0

    segs = []
    if relro:
        segs.append(_Seg("GNU_RELRO"))
    segs.append(_Seg("SEGMENT_TYPES.GNU_STACK", 0x5 if stack_x else 0x6))

    class _Hdr:
        # ET_DYN (PIE) = 3, ET_EXEC = 2
        file_type = "E_TYPE.DYNAMIC" if pie else "E_TYPE.EXECUTABLE"

    class _Bin:
        header = _Hdr()
        segments = segs
        dynamic_entries = [_Dyn()] if bind_now else []
        is_pie = pie

    return _Bin()


def test_elf_matrix_full_relro_pie():
    from deglyph.core.image import Arch, Image

    img = Image(path="x", fmt="ELF", arch=Arch.X64, base=0)
    img.funcs.append(Func(name="__stack_chk_fail", va=0x1, kind="import"))
    img.funcs.append(Func(name="__memcpy_chk", va=0x2, kind="import"))
    img.reindex()
    b = _elf_bin(pie=True, relro=True, bind_now=True, stack_x=False)
    r = _rules(scan._hardening_elf(img, b))
    assert "harden/no-pie" not in r
    assert "harden/no-relro" not in r and "harden/partial-relro" not in r
    assert "harden/no-dep" not in r
    assert "harden/no-stack-canary" not in r


def test_elf_matrix_partial_relro_and_no_pie():
    from deglyph.core.image import Arch, Image

    img = Image(path="x", fmt="ELF", arch=Arch.X64, base=0)
    b = _elf_bin(pie=False, relro=True, bind_now=False, stack_x=True)
    r = _rules(scan._hardening_elf(img, b))
    assert "harden/no-pie" in r
    assert "harden/partial-relro" in r
    # executable stack
    assert "harden/no-dep" in r
    # no canary symbol
    assert "harden/no-stack-canary" in r


def test_macho_matrix_pie_canary_signed(code_image):
    img = code_image(bytes.fromhex("c3"))
    img.funcs.append(Func(name="___stack_chk_fail", va=0x1, kind="import"))
    img.reindex()

    class _Hdr:
        # MH_PIE
        flags = 0x200000
        flags_list = []

    class _Bin:
        header = _Hdr()
        has_code_signature = True
        code_signature = object()

    r = _rules(scan._hardening_macho(img, _Bin()))
    # PIE set, canary symbol present, signed -> nothing missing
    assert "harden/no-pie" not in r
    assert "harden/no-stack-canary" not in r


def test_macho_matrix_unhardened(code_image):
    img = code_image(bytes.fromhex("c3"))

    class _Hdr:
        flags = 0
        flags_list = []

    class _Bin:
        header = _Hdr()
        has_code_signature = False

    r = _rules(scan._hardening_macho(img, _Bin()))
    assert "harden/no-pie" in r
    assert "harden/no-stack-canary" in r
    assert "harden/unsigned" in r
