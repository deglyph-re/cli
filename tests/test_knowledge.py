# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Tests for the content-keyed knowledge base (store.to_knowledge/apply_knowledge)."""

from __future__ import annotations

from deglyph.store import Annotations, apply_knowledge, to_knowledge

# mov eax,1; ... ; ret  (a multi-instruction body so it signs)
_A = bytes.fromhex("b801000000b90200000001c831d229c80fafc109d021c8c3")
_OTHER = bytes.fromhex("31c0555d9090c3")


def _annotated(code_image, blob, va=0x1000):
    img = code_image(blob, va=va)
    anno = Annotations(path=img.path)
    anno.names[va] = "parse_header"
    anno.comments[va] = "validates the magic"
    return img, anno


def test_knowledge_reattaches_across_relocation(code_image):
    # Export from a build where the function is at 0x1000; import into a build
    # where the same body sits at 0x9000. The content hash carries the rename.
    src, anno = _annotated(code_image, _A, va=0x1000)
    doc = to_knowledge(src, anno)
    assert doc["deglyph_knowledge_version"] == 1
    assert len(doc["names"]) == 1

    dst = code_image(_A, va=0x9000)
    applied = apply_knowledge(dst, doc)
    assert applied.names == {0x9000: "parse_header"}
    assert applied.comments == {0x9000: "validates the magic"}


def test_knowledge_does_not_apply_to_a_different_body(code_image):
    src, anno = _annotated(code_image, _A)
    doc = to_knowledge(src, anno)
    dst = code_image(_OTHER, va=0x9000)
    assert apply_knowledge(dst, doc).is_empty()


def test_apply_knowledge_tolerates_malformed_doc(code_image):
    dst = code_image(_A)
    assert apply_knowledge(dst, {"names": "not-a-dict"}).is_empty()
    assert apply_knowledge(dst, []).is_empty()


def test_undecodable_function_is_skipped_on_export(code_image):
    img = code_image(_A)
    anno = Annotations(path=img.path)
    # a VA with no decodable body contributes nothing to the knowledge doc
    anno.names[0xDEAD] = "ghost"
    doc = to_knowledge(img, anno)
    assert doc["names"] == {}
