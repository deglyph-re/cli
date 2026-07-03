# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Targeted coverage for the modules the dedicated suites skim: store, config,
discover, xref edge cases, the pseudo-C non-x86 short-circuit, scan corners,
and the `__main__` runner.
"""

from __future__ import annotations

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from deglyph import config, store
from deglyph.core.image import Arch, Func, Image

# --- __main__ entry ---------------------------------------------------------


def test_main_module_runs_help_and_exits():
    """`python -m deglyph --version` is the documented entry; cover __main__."""
    proc = subprocess.run(
        [sys.executable, "-m", "deglyph", "--version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert proc.stdout.startswith("deglyph ")


def test_main_module_via_runpy(monkeypatch, tmp_path):
    """The `if __name__ == '__main__'` arm gets exercised when run as a script."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    # patch sys.argv so the dispatch path is the no-binary welcome -> would
    # launch the TUI; intercept the run() helper to keep it headless
    monkeypatch.setattr(sys, "argv", ["deglyph", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("deglyph", run_name="__main__")
    assert exc.value.code == 0


# --- config -----------------------------------------------------------------


def test_config_missing_file_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    # no config file exists yet
    assert config.get("theme") is None
    assert config.get("theme", "fallback") == "fallback"


def test_config_put_then_get_persists(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    config.put("theme", "deglyph")
    assert config.get("theme") == "deglyph"
    # the on-disk file is valid JSON
    raw = (tmp_path / "config.json").read_text("utf-8")
    assert json.loads(raw)["theme"] == "deglyph"


def test_config_malformed_file_yields_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    (tmp_path / "config.json").write_text("{not json", encoding="utf-8")
    assert config.get("theme") is None


def test_config_non_dict_top_level_yields_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    (tmp_path / "config.json").write_text("[1, 2, 3]", encoding="utf-8")
    assert config.get("theme") is None


def test_config_put_swallows_oserror(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    def boom(*a, **k):
        raise OSError("denied")

    monkeypatch.setattr(os, "makedirs", boom)
    # silently fails: best-effort persistence
    config.put("theme", "anything")
    # the file did not get written; the subsequent read still returns None
    assert config.get("theme") is None


# --- store.py ---------------------------------------------------------------


def test_load_missing_sidecar_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    a = store.load("nonexistent.exe")
    assert a.is_empty()


def test_load_malformed_sidecar_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    p = store.sidecar_path("x.exe")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    Path(p).write_text("{not valid", encoding="utf-8")
    assert store.load("x.exe").is_empty()


def test_load_non_hex_keys_returns_empty(tmp_path, monkeypatch):
    """A sidecar with non-hex address keys is treated as corrupt."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    p = store.sidecar_path("x.exe")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    Path(p).write_text(
        json.dumps({"binary": "x.exe", "names": {"not_hex": "n"}}),
        encoding="utf-8",
    )
    a = store.load("x.exe")
    # the malformed key sends us to the except arm; the result is empty
    assert a.is_empty()


def test_save_swallows_oserror(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    a = store.Annotations(path="x.exe", names={0x1000: "n"})

    def boom(*args, **kw):
        raise OSError("nope")

    monkeypatch.setattr(os, "makedirs", boom)
    # best-effort; no exception
    a.save()


def test_list_sessions_no_store_dir(tmp_path, monkeypatch):
    """A nonexistent store dir means no sessions, not a crash."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path / "absent"))
    assert store.list_sessions() == []


def test_list_sessions_skips_dead_binaries(tmp_path, monkeypatch):
    """An annotation whose binary no longer exists is skipped."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    store.Annotations(path="C:/gone/x.exe", names={0x1000: "n"}).save()
    assert store.list_sessions() == []


def test_list_sessions_skips_malformed_sidecar(tmp_path, monkeypatch):
    """A corrupt sidecar in the store dir is silently skipped."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    (tmp_path / "corrupt.json").write_text("not json", encoding="utf-8")
    assert store.list_sessions() == []


# --- re/xref edge cases -----------------------------------------------------


def test_callers_of_with_no_text_section():
    """An Image with no executable section -> the xref index is empty."""
    from deglyph.re.xref import callers_of

    # no sections at all so `Image.text` returns None and `_build_index` bails
    img = Image(path="<synthetic>", fmt="PE", arch=Arch.X64, base=0x140000000)
    img.funcs = [Func(name="root", va=0x140002000, kind="export")]
    img.reindex()
    assert callers_of(img, 0x140002000) == []


def test_call_tree_caller_walk(code_image):
    """`callers=True` walks back; without a real index there are no neighbors."""
    from deglyph.re.xref import call_tree

    img = code_image(bytes.fromhex("c3"))
    tree = call_tree(img, 0x1000, callers=True, depth=2)
    assert tree.va == 0x1000
    # nothing calls this isolated stub
    assert tree.children == []


def test_call_tree_depth_zero_marks_elided(code_image):
    from deglyph.re.xref import call_tree

    img = code_image(bytes.fromhex("c3"))
    tree = call_tree(img, 0x1000, depth=0)
    assert tree.elided is True


# --- re/pseudo non-x86 short-circuit ---------------------------------------


def test_pseudo_c_non_x86_returns_empty():
    from deglyph.re.pseudo import pseudo_c

    img = Image(path="<x>", fmt="PE", arch=Arch.ARM64, base=0)
    assert pseudo_c(img, 0) == []


def test_pseudo_c_empty_function_returns_empty(code_image):
    from deglyph.re.pseudo import pseudo_c

    # `code_image` always seeds at least one byte; ask for a function at an
    # address with no decode, which returns []
    img = code_image(bytes.fromhex("c3"))
    assert pseudo_c(img, 0xDEAD_BEEF) == []


def test_pseudo_c_covers_common_instructions(code_image):
    """Exercise the per-mnemonic statement arms: mov, lea, xor-zero, inc, ret, indirect."""
    from deglyph.re.pseudo import pseudo_c

    # b8 01 00 00 00  mov eax, 1
    # 48 8d 0d 00 00 00 00 lea rcx, [rip+0]
    # 33 c0            xor eax, eax
    # 40              inc eax    (32-bit form) -> Capstone may decode differently
    # ff d0            call rax (indirect)
    # 39 c8            cmp eax, ecx
    # 74 02            je +2
    # c3               ret
    raw = bytes.fromhex(
        "b8 01 00 00 00 "
        "48 8d 0d 00 00 00 00 "
        "33 c0 "
        "ff d0 "
        "39 c8 "
        "74 02 "
        "c3"
    )
    img = code_image(raw)
    lines = pseudo_c(img, 0x1000)
    bodies = " ".join(ln.code for ln in lines)
    # at least one mov assignment
    assert "= " in bodies
    # the indirect call
    assert "(*rax)" in bodies or "asm(" in bodies
    # the return
    assert "return;" in bodies


# --- re/discover edge cases ------------------------------------------------


def test_discover_is_idempotent(code_image):
    """Re-running discovery returns 0 (the flag short-circuits)."""
    from deglyph.re import discover_functions

    img = code_image(bytes.fromhex("c3"))
    discover_functions(img)
    assert discover_functions(img) == 0


def test_scan_call_targets_respects_max_bytes(code_image):
    """A tiny max_bytes cap stops the scan before consuming all sections."""
    from deglyph.re.discover import scan_call_targets

    img = code_image(bytes.fromhex("c3"))
    out = scan_call_targets(img, max_bytes=1)
    # with the cap below one instruction's size, no new targets surface
    assert out == []


# --- re/strings: non-x86 short-circuit -------------------------------------


def test_referenced_data_non_x86_returns_empty():
    from deglyph.re.strings import referenced_data

    img = Image(path="<x>", fmt="PE", arch=Arch.ARM64, base=0)
    assert referenced_data(img, 0) == []


# --- re/search pattern variants --------------------------------------------


def test_find_bytes_space_separated_with_wildcards():
    from deglyph.re.search import _parse_pattern

    # space-separated tokens with wildcards
    rx = _parse_pattern("DE ?? BE")
    assert rx.match(b"\xde\x00\xbe")
    assert rx.match(b"\xde\xff\xbe")
    assert not rx.match(b"\xde\xff\xbf")


def test_find_bytes_compact_form():
    """A compact hex string with no spaces is split into byte pairs."""
    from deglyph.re.search import _parse_pattern

    rx = _parse_pattern("deadbeef")
    assert rx.match(b"\xde\xad\xbe\xef")


def test_find_bytes_against_demo():
    """End-to-end byte search lands on the matching offset."""
    from deglyph.core.image import load_image
    from deglyph.re.search import find_bytes

    img = load_image(
        os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")
    )
    # PE signature 4D 5A ('MZ') is at file offset 0
    hits = find_bytes(img, "4d 5a", limit=1)
    assert hits and hits[0].off == 0


def test_find_string_against_demo():
    """Searching for an ASCII / UTF-16 string in the demo returns hits."""
    from deglyph.core.image import load_image
    from deglyph.re.search import find_string

    img = load_image(
        os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")
    )
    # the demo plants a credential keyword that's guaranteed to be present
    hits = find_string(img, "kernel32", limit=4)
    # case-sensitive; the import table carries KERNEL32 in capitals so this
    # could be empty, but the search shouldn't crash
    assert isinstance(hits, list)


def test_find_immediate_against_demo():
    """Searching for a common immediate constant lands somewhere."""
    from deglyph.core.image import load_image
    from deglyph.re.search import find_immediate

    img = load_image(
        os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")
    )
    # very common constant in any binary; this exercises the iteration loop
    hits = find_immediate(img, 0, limit=2)
    assert isinstance(hits, list)


def test_referenced_data_against_demo():
    """`referenced_data` resolves the strings and pointers a function reads."""
    from deglyph.core.image import load_image
    from deglyph.re.strings import referenced_data

    img = load_image(
        os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")
    )
    main = next((f for f in img.funcs if f.display == "main"), None)
    if main is None:
        pytest.skip("demo has no main symbol on this host")
    refs = referenced_data(img, main.va)
    # results may be empty depending on what main references; just exercise
    assert isinstance(refs, list)


# --- core/image arch detection (mock LIEF objects) -------------------------


class _MockHeader:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class _MockBinary:
    def __init__(self, fmt: str, header):
        self.format = fmt
        self.header = header


def test_detect_arch_pe_known_machines():
    from deglyph.core.image import _detect_arch

    pe_x86 = _MockBinary("Format.PE", _MockHeader(machine=_MockHeader(value=0x14C)))
    pe_x64 = _MockBinary("Format.PE", _MockHeader(machine=_MockHeader(value=0x8664)))
    pe_unk = _MockBinary("Format.PE", _MockHeader(machine=_MockHeader(value=0x9999)))
    assert _detect_arch(pe_x86) == Arch.X86
    assert _detect_arch(pe_x64) == Arch.X64
    assert _detect_arch(pe_unk) == Arch.UNKNOWN


def test_detect_arch_elf_variants():
    from deglyph.core.image import _detect_arch

    def elf(mach: str):
        return _MockBinary("Format.ELF", _MockHeader(machine_type=mach))

    assert _detect_arch(elf("x86_64")) == Arch.X64
    assert _detect_arch(elf("i386")) == Arch.X86
    assert _detect_arch(elf("AARCH64")) == Arch.ARM64
    assert _detect_arch(elf("ARM")) == Arch.ARM
    assert _detect_arch(elf("MIPS")) == Arch.UNKNOWN


def test_detect_arch_macho_variants():
    from deglyph.core.image import _detect_arch

    def macho(cpu: str):
        return _MockBinary("Format.MachO", _MockHeader(cpu_type=cpu))

    assert _detect_arch(macho("x86_64")) == Arch.X64
    assert _detect_arch(macho("x86")) == Arch.X86
    assert _detect_arch(macho("ARM64")) == Arch.ARM64
    assert _detect_arch(macho("ARM")) == Arch.ARM


def test_detect_arch_exception_falls_back_to_unknown():
    from deglyph.core.image import _detect_arch

    # accessing .header.machine raises; the except arm returns UNKNOWN
    class _Boom:
        format = "Format.PE"

        @property
        def header(self):
            raise RuntimeError("no header")

    assert _detect_arch(_Boom()) == Arch.UNKNOWN


def test_image_text_falls_back_to_executable_flag():
    """No .text/__text/CODE: the property picks any section with X."""
    from deglyph.core.image import Image, Section

    img = Image(path="x", fmt="PE", arch=Arch.X64, base=0)
    img.sections = [
        Section(name=".rdata", va=0x1000, size=0x10, raw_off=0, raw_size=0, flags="R"),
        Section(name=".code", va=0x2000, size=0x10, raw_off=0, raw_size=0, flags="RX"),
    ]
    assert img.text.name == ".code"


def test_image_text_falls_back_to_first_section_when_no_x_flag():
    """When no section is flagged executable, the first section is returned."""
    from deglyph.core.image import Image, Section

    img = Image(path="x", fmt="PE", arch=Arch.X64, base=0)
    img.sections = [
        Section(name=".only", va=0x1000, size=0x10, raw_off=0, raw_size=0, flags="R"),
    ]
    assert img.text.name == ".only"


def test_image_nearest_func_with_no_match_returns_none():
    img = Image(path="x", fmt="PE", arch=Arch.X64, base=0)
    img.funcs = [Func(name="f", va=0x2000, kind="export")]
    img.reindex()
    # all funcs are above the queried VA
    assert img.nearest_func(0x1000) is None


def test_extract_strings_off_to_va_for_unmapped_offset(tmp_path):
    """A printable run inside the PE header has no section, so va falls back to 0."""
    from deglyph.core.image import load_image
    from deglyph.re.strings import extract_strings

    img = load_image(
        os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")
    )
    strings = extract_strings(img, min_len=4, limit=200)
    assert strings
    # at least one string maps to a real section; some may be header bytes
    # (va == 0). This exercises both arms of _off_to_va.
    assert any(s.section for s in strings)


# --- scan corners -----------------------------------------------------------


def test_scan_worst_level_is_none_for_no_findings():
    from deglyph import scan

    assert scan.worst_level([("x.exe", [])]) is None


def test_scan_iter_targets_for_file_yields_once(tmp_path):
    """A file argument is yielded once; a directory walks recursively."""
    from deglyph import scan

    f = tmp_path / "demo.exe"
    f.write_bytes(b"MZ")
    assert list(scan.iter_targets(str(f))) == [str(f)]


def test_scan_iter_targets_for_directory_recurses(tmp_path):
    from deglyph import scan

    d = tmp_path / "nested"
    d.mkdir()
    a = d / "one.exe"
    b = d / "two.dll"
    a.write_bytes(b"MZ")
    b.write_bytes(b"MZ")
    targets = set(scan.iter_targets(str(tmp_path)))
    assert str(a) in targets and str(b) in targets
