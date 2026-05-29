# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Bounded, cycle-safe call-tree construction."""

from __future__ import annotations

from deglyph.re import call_tree


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
    # 0x1000: call 0x1000 ; ret  — self-call must not recurse forever.
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
