# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Self-contained regression tests.

Unit tests for the pure analysis logic run anywhere. Integration tests load a
binary that exists on the host (a system Mach-O on macOS / ELF on Linux); if none
is found they are skipped rather than failed, so the suite is portable.
"""

import importlib.util
import os
import platform
import sys
from pathlib import Path

import pytest

from deglyph.core import Arch, Disassembler, load_image
from deglyph.re import (
    call_immediate_args,
    callers_of,
    immediate_stores,
    thunk_chain,
)
from deglyph.re.search import _parse_pattern

# --- pure-logic unit tests --------------------------------------------------


def test_pattern_wildcards():
    rx = _parse_pattern("DE ?? BE")
    assert rx.match(b"\xde\x00\xbe")
    assert rx.match(b"\xde\xff\xbe")
    # too short / mismatch start
    assert not rx.match(b"\xde\xbe\xbe"[:2])


def test_pattern_contiguous_hex():
    rx = _parse_pattern("deadbeef")
    assert rx.search(b"\x11\xde\xad\xbe\xef\x22")


def test_arch_bits():
    assert Arch.X86.bits == 32
    assert Arch.X64.bits == 64
    assert Arch.ARM64.bits == 64


# --- integration: load a real host binary -----------------------------------


def _host_binary():
    cands = []
    if platform.system() == "Darwin":
        cands = ["/bin/ls", "/usr/bin/true", "/bin/echo"]
    elif platform.system() == "Linux":
        cands = ["/bin/ls", "/usr/bin/true", "/bin/cat"]
    elif platform.system() == "Windows":
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        sys32 = os.path.join(sysroot, "System32")
        cands = [os.path.join(sys32, n) for n in ("kernel32.dll", "user32.dll")]
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


HOST = _host_binary()
needs_host = pytest.mark.skipif(HOST is None, reason="no host binary available")


@needs_host
def test_load_host_binary():
    img = load_image(HOST)
    assert img.fmt in ("MachO", "MACHO", "ELF", "PE")
    assert img.arch in (Arch.X64, Arch.ARM64, Arch.X86)
    assert img.text is not None
    assert len(img.funcs) > 0


@needs_host
def test_disassemble_entry():
    img = load_image(HOST)
    dis = Disassembler(img)
    f = img.funcs[0]
    insns = dis.func(f.va)
    # decodes without throwing
    assert isinstance(insns, list)


@needs_host
def test_xref_index_builds():
    img = load_image(HOST)
    f = img.funcs[0]
    # builds + caches the whole-image index without error
    callers_of(img, f.va)


# --- integration: the committed sample binary (samples/demo.exe) -------------

_DEMO = Path(__file__).resolve().parent.parent / "samples" / "demo.exe"
needs_demo = pytest.mark.skipif(not _DEMO.exists(), reason="samples/demo.exe absent")


@needs_demo
def test_demo_opcode_recovered():
    """set_volume hands opcode 0x2f to send_frame; recover it end to end."""
    img = load_image(str(_DEMO))
    matches = [f for f in img.funcs if "set_volume" in f.display.lower()]
    assert matches, "set_volume not found"
    real = thunk_chain(img, matches[0].va)[-1]
    found = {s.value for s in immediate_stores(img, real)}
    found |= {a.value for a in call_immediate_args(img, real)}
    assert 0x2F in found, f"0x2f not among {sorted(hex(v) for v in found)}"


@needs_demo
def test_demo_frame_header_stored():
    """encode_frame writes the immediate header (0xaa) and frame type (0x04)."""
    img = load_image(str(_DEMO))
    matches = [f for f in img.funcs if "encode_frame" in f.display.lower()]
    assert matches, "encode_frame not found"
    real = thunk_chain(img, matches[0].va)[-1]
    vals = {s.value for s in immediate_stores(img, real)}
    assert 0xAA in vals and 0x04 in vals


# --- tone verifier (scripts/verify.py) --------------------------------------

_VERIFY = Path(__file__).resolve().parent.parent / "scripts" / "verify.py"


def _load_verify():
    spec = importlib.util.spec_from_file_location("glyph_verify", _VERIFY)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: a slots dataclass resolves its module namespace at
    # class-creation time, which fails if the module is not yet in sys.modules.
    sys.modules["glyph_verify"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_verify_project_is_clean(tmp_path):
    """The shipped docs and sources must pass the tone verifier."""
    v = _load_verify()
    findings = []
    for p in (v.repo_root() / "deglyph").rglob("*.py"):
        if "__pycache__" not in p.parts:
            findings += v.scan_python(p)
    for name in ("README.md", "CLAUDE.md"):
        findings += v.scan_markdown(
            v.repo_root() / name, user_facing=(name != "CLAUDE.md")
        )
    tone = [f for f in findings if f.kind in ("tone", "first-person", "non-ascii")]
    assert not tone, "\n".join(f"{f.path.name}:{f.line} {f.message}" for f in tone)


def test_verify_catches_violations(tmp_path):
    """Regression guard for the linter itself: known-bad input must be flagged."""
    v = _load_verify()

    bad_md = tmp_path / "bad.md"
    bad_md.write_text("# x\n\nThis is seamless and we built it.\n", encoding="utf-8")
    md = v.scan_markdown(bad_md, user_facing=True)
    assert any(f.kind == "tone" for f in md)
    assert any(f.kind == "first-person" for f in md)

    bad_py = tmp_path / "bad.py"
    bad_py.write_text(
        'def f():\n    """Note that we do it."""\n    try:\n        pass\n'
        "    except:\n        pass\n",
        encoding="utf-8",
    )
    py = v.scan_python(bad_py)
    assert any(f.kind == "tone" for f in py)
    assert any(f.kind == "bare-except" for f in py)


def test_verify_suppression(tmp_path):
    """`verify off/on` markers must silence the enclosed region only."""
    v = _load_verify()
    md = tmp_path / "s.md"
    md.write_text(
        "# x\n\n<!-- verify off -->\nseamless\n<!-- verify on -->\nseamless\n",
        encoding="utf-8",
    )
    tone = [f for f in v.scan_markdown(md, user_facing=True) if f.kind == "tone"]
    assert len(tone) == 1 and tone[0].line == 6
