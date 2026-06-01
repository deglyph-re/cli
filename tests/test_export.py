# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Versioned JSON analysis export."""

from __future__ import annotations

import json
import os

import pytest

from deglyph import export
from deglyph.core.image import Func

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def test_schema_version_is_pinned():
    # A change to the document shape must bump this deliberately.
    assert export.SCHEMA_VERSION == 1


def test_build_export_on_synthetic_image(code_image):
    # nop ; ret  at 0x1000, with one named function
    img = code_image(bytes.fromhex("90 c3"))
    doc = export.build_export(img)
    assert doc["deglyph_export_version"] == export.SCHEMA_VERSION
    assert set(doc) >= {
        "tool",
        "binary",
        "functions",
        "xrefs",
        "detectors",
        "strings",
        "findings",
    }
    assert doc["tool"]["name"] == "deglyph"
    # CFG is opt-in
    assert "cfg" not in doc
    assert "cfg" in export.build_export(img, include_cfg=True)
    # the whole document is JSON-serializable
    json.dumps(doc)


def test_build_export_function_and_detector_shape(code_image):
    img = code_image(bytes.fromhex("90 c3"))
    img.funcs.append(Func(name="probe", va=0x1000, kind="export"))
    img.reindex()
    doc = export.build_export(img)
    f = next(e for e in doc["functions"] if e["name"] == "probe")
    assert f["va"] == "0x1000"
    assert f["kind"] == "export"
    assert "confidence" in f and "evidence" in f
    # xrefs are keyed by the function VA
    assert "0x1000" in doc["xrefs"]


def test_build_export_max_funcs_marks_truncation(code_image):
    # A real backing file is needed (build_export reads section bytes for
    # strings); the synthetic fixture writes one and seeds func "f" at 0x1000.
    img = code_image(bytes.fromhex("90 c3"))
    for i in range(5):
        img.funcs.append(Func(name=f"f{i}", va=0x1100 + i * 0x10, kind="symbol"))
    img.reindex()
    doc = export.build_export(img, max_funcs=2)
    assert len(doc["functions"]) == 2
    assert doc["truncated"] == {
        "functions_shown": 2,
        "functions_total": len(img.funcs),
    }


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_build_export_on_demo_is_complete_and_serializable():
    doc = export.export_file(SAMPLE)
    assert doc["deglyph_export_version"] == export.SCHEMA_VERSION
    assert doc["binary"]["name"] == "demo.exe"
    assert doc["binary"]["format"] == "PE"
    assert doc["binary"]["sha256"]
    assert doc["functions"], "demo.exe should expose functions"
    # strings carry their encoding and category
    for s in doc["strings"][:5]:
        assert {"va", "section", "encoding", "category", "text"} <= set(s)
    # findings stay labeled by category, never asserted as proven
    for f in doc["findings"]:
        assert f["category"] in ("fact", "heuristic", "policy")
    json.dumps(doc)
