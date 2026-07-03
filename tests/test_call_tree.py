# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Bounded, cycle-safe call-tree construction."""

from __future__ import annotations

from deglyph import cache
from deglyph.re import call_tree, callers_of
from deglyph.re.xref import _index


def test_callee_tree_follows_direct_calls(code_image):
    # f0 @0x1000: call f1 ; ret   f1 @0x1006: call f2 ; ret   f2 @0x100c: ret
    # call +1 (-> 0x1006) ; ret
    f0 = b"\xe8\x01\x00\x00\x00\xc3"
    # call +1 (-> 0x100c) ; ret
    f1 = b"\xe8\x01\x00\x00\x00\xc3"
    # ret
    f2 = b"\xc3"
    img = code_image(f0 + f1 + f2)
    root = call_tree(img, 0x1000, depth=3)
    assert root.va == 0x1000
    assert [c.va for c in root.children] == [0x1006]
    assert [c.va for c in root.children[0].children] == [0x100C]


def test_depth_cap_marks_elided(code_image):
    f0 = b"\xe8\x01\x00\x00\x00\xc3"
    f1 = b"\xe8\x01\x00\x00\x00\xc3"
    f2 = b"\xc3"
    img = code_image(f0 + f1 + f2)
    root = call_tree(img, 0x1000, depth=1)
    # depth 1: root expands its direct callee, which is then a depth-0 boundary.
    assert root.children[0].va == 0x1006
    assert root.children[0].elided is True
    assert root.children[0].children == []


def test_self_recursion_is_cycle_safe(code_image):
    # 0x1000: call 0x1000 ; ret. A self-call must not recurse forever.
    # call -5 (-> 0x1000) ; ret
    img = code_image(b"\xe8\xfb\xff\xff\xff\xc3")
    root = call_tree(img, 0x1000, depth=8)
    assert root.va == 0x1000
    assert root.children[0].va == 0x1000
    # cycle stops here
    assert root.children[0].elided is True
    assert root.children[0].children == []


def test_budget_bounds_total_nodes(code_image):
    f0 = b"\xe8\x01\x00\x00\x00\xc3"
    f1 = b"\xe8\x01\x00\x00\x00\xc3"
    f2 = b"\xc3"
    img = code_image(f0 + f1 + f2)
    root = call_tree(img, 0x1000, depth=8, budget=1)

    def count(n):
        return 1 + sum(count(c) for c in n.children)

    # root + at most one expanded child
    assert count(root) <= 2


def test_xref_index_is_cached_by_file_hash(code_image, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    # 0x1000: call 0x100a ; pad ; ret  (a single code edge to discover).
    img = code_image(bytes.fromhex("e8 05 00 00 00") + b"\x90" * 5 + b"\xc3")
    digest = cache.file_sha256(img.path)
    assert cache.cache_get(digest, "xrefs") is None
    first = callers_of(img, 0x100A)
    assert first == [0x1000]
    # the whole-image scan is now persisted under the file's content hash
    assert cache.cache_get(digest, "xrefs") is not None
    # a fresh image with identical bytes (same hash, no in-memory memo) is
    # served from disk: _build_index must not run again.
    img2 = code_image(bytes.fromhex("e8 05 00 00 00") + b"\x90" * 5 + b"\xc3")
    monkeypatch.setattr(
        "deglyph.re.xref._build_index",
        lambda image: (_ for _ in ()).throw(AssertionError("rebuilt despite cache")),
    )
    assert callers_of(img2, 0x100A) == first


def test_xref_index_budget_is_uncached(code_image, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    img = code_image(bytes.fromhex("e8 05 00 00 00") + b"\x90" * 5 + b"\xc3")
    digest = cache.file_sha256(img.path)
    # a budgeted index is partial-by-design: it neither reads/writes the cache
    # nor memoizes on the image, so a truncated run can't poison a later one
    idx = _index(img, max_seconds=0.0)
    assert isinstance(idx.to, dict)
    assert cache.cache_get(digest, "xrefs") is None
    assert getattr(img, "_xref_index", None) is None
