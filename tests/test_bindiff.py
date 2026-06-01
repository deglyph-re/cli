# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Tests for semantic function-level diffing (re/bindiff)."""

from __future__ import annotations

from collections import Counter

from deglyph.core.image import Arch, Func, Image, Section
from deglyph.re.bindiff import diff_functions, diff_json, diff_markdown, diff_text

# Three small functions, each ending in `ret`.
_A = bytes.fromhex("b801000000b90200000001c831d229c80fafc109d021c8c3")
# `_A` with `xor edx,edx` swapped for `mov edx,3` (one localized edit)
_A_MOD = bytes.fromhex("b801000000b90200000001c8ba0300000029c80fafc109d021c8c3")
# xor eax,eax ; push rbp ; pop rbp ; nop ; nop ; ret
_B = bytes.fromhex("31c0555d9090c3")


def _img(tmp_path, segments, *, name="m.bin", arch=Arch.X64, va=0x1000) -> Image:
    """An image whose functions are the given (name, code) segments, laid contiguous."""
    blob = b"".join(code for _n, code in segments)
    p = tmp_path / name
    p.write_bytes(blob)
    img = Image(path=str(p), fmt="RAW", arch=arch, base=0)
    img.sections.append(
        Section(
            name=".text",
            va=va,
            size=len(blob),
            raw_off=0,
            raw_size=len(blob),
            flags="RX",
        )
    )
    off = va
    for n, code in segments:
        img.funcs.append(Func(name=n, va=off, kind="sub"))
        off += len(code)
    img.reindex()
    return img


def test_identical_builds_are_all_unchanged(tmp_path):
    base = _img(tmp_path, [("a", _A), ("b", _B)], name="base.bin")
    cur = _img(tmp_path, [("a", _A), ("b", _B)], name="cur.bin")
    kinds = Counter(d.kind for d in diff_functions(cur, base))
    assert kinds["unchanged"] == 2
    assert kinds["modified"] == kinds["added"] == kinds["removed"] == 0


def test_moved_function_is_not_added_plus_removed(tmp_path):
    # `b` shifts because `a` grew, but its body is identical, so it is unchanged.
    base = _img(tmp_path, [("a", _A), ("b", _B)], name="base.bin")
    cur = _img(tmp_path, [("a", _A_MOD), ("b", _B)], name="cur.bin")
    deltas = diff_functions(cur, base, min_similarity=0.1)
    kinds = Counter(d.kind for d in deltas)
    assert kinds["modified"] == 1
    assert kinds["unchanged"] == 1
    mod = next(d for d in deltas if d.kind == "modified")
    assert 0.0 < mod.similarity < 1.0
    assert mod.va is not None and mod.baseline_va is not None


def test_added_and_removed(tmp_path):
    base = _img(tmp_path, [("a", _A)], name="base.bin")
    cur = _img(tmp_path, [("a", _A), ("b", _B)], name="cur.bin")
    kinds = Counter(d.kind for d in diff_functions(cur, base))
    assert kinds["added"] == 1
    assert kinds["unchanged"] == 1
    assert kinds["removed"] == 0
    added = next(d for d in diff_functions(cur, base) if d.kind == "added")
    assert added.va is not None and added.baseline_va is None


def test_unsigned_functions_diff_by_name(tmp_path):
    # A named function whose VA has no decodable body falls back to name identity.
    base = _img(tmp_path, [("a", _A)], name="base.bin")
    base.funcs.append(Func(name="old_helper", va=0xF000, kind="func"))
    base.reindex()
    cur = _img(tmp_path, [("a", _A)], name="cur.bin")
    cur.funcs.append(Func(name="new_helper", va=0xF000, kind="func"))
    cur.reindex()
    deltas = diff_functions(cur, base)
    names = {(d.kind, d.name) for d in deltas}
    assert ("added", "new_helper") in names
    assert ("removed", "old_helper") in names


def test_renderers_smoke(tmp_path):
    base = _img(tmp_path, [("a", _A)], name="base.bin")
    cur = _img(tmp_path, [("a", _A_MOD)], name="cur.bin")
    deltas = diff_functions(cur, base, min_similarity=0.1)
    assert "modified" in diff_text(deltas).lower()
    j = diff_json(deltas)
    assert j["summary"]["modified"] >= 1
    assert j["functions"][0]["va"] is not None
    assert diff_markdown(deltas).startswith("## deglyph diff")
