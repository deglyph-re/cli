# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Golden / snapshot tests over the committed sample binary (samples/demo.exe).

Pins the shape of the machine-readable outputs (scan JSON, SARIF, and the
export document) so an accidental field drop or reshape fails loudly. Volatile
fields (file paths, the tool version, the content hash) are masked before the
compare; schema-version fields are kept so a breaking reshape is caught. The
full export is large and version/hash volatile, so it is snapshotted to a
stable skeleton (schema version, per-section counts, masked binary block)
rather than pinned byte for byte.

Regenerate after an intended schema change:

    DEGLYPH_REGEN_GOLDEN=1 pytest tests/test_golden.py
"""

from __future__ import annotations

import json
import os

import pytest

from deglyph import export, scan
from deglyph.core.image import load_image

_SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")
_GOLDEN = os.path.join(os.path.dirname(__file__), "golden")

pytestmark = pytest.mark.skipif(
    not os.path.isfile(_SAMPLE), reason="demo.exe not built"
)


def _mask_path(p: str) -> str:
    return os.path.basename(p.replace("\\", "/"))


def _norm_scan_json(doc: dict) -> dict:
    for f in doc.get("files", []):
        f["path"] = _mask_path(f["path"])
    return doc


def _norm_sarif(doc: dict) -> dict:
    for run in doc.get("runs", []):
        for r in run.get("results", []):
            for loc in r.get("locations", []):
                art = loc.get("physicalLocation", {}).get("artifactLocation", {})
                if "uri" in art:
                    art["uri"] = _mask_path(art["uri"])
    return doc


def _snapshot_export(doc: dict) -> dict:
    binary = dict(doc["binary"])
    binary["sha256"] = "X"
    binary["name"] = _mask_path(binary["name"])
    return {
        "deglyph_export_version": doc["deglyph_export_version"],
        "tool_name": doc["tool"]["name"],
        "binary": binary,
        "counts": {
            k: len(doc[k])
            for k in ("functions", "xrefs", "detectors", "strings", "findings")
        },
        "top_keys": sorted(doc.keys()),
    }


def _artifacts() -> dict[str, dict]:
    img = load_image(_SAMPLE)
    results = [(_SAMPLE, scan.scan_image(img))]
    return {
        "scan_json.json": _norm_scan_json(scan.to_json(results, version="test")),
        "sarif.json": _norm_sarif(scan.to_sarif(results, version="test")),
        "export_snapshot.json": _snapshot_export(export.build_export(img)),
    }


def _roundtrip(obj: dict) -> dict:
    """Normalize through JSON so tuples/sets compare like the loaded golden."""
    return json.loads(json.dumps(obj, sort_keys=True))


@pytest.mark.parametrize(
    "name", ["scan_json.json", "sarif.json", "export_snapshot.json"]
)
def test_output_matches_golden(name: str) -> None:
    current = _roundtrip(_artifacts()[name])
    path = os.path.join(_GOLDEN, name)
    if os.environ.get("DEGLYPH_REGEN_GOLDEN"):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(current, fh, indent=2, sort_keys=True)
            fh.write("\n")
    with open(path, encoding="utf-8") as fh:
        golden = json.load(fh)
    assert current == golden, f"{name} drifted from its golden; regen if intended"


def test_schema_versions_are_pinned() -> None:
    arts = _artifacts()
    assert arts["sarif.json"]["version"] == "2.1.0"
    assert (
        arts["export_snapshot.json"]["deglyph_export_version"] == export.SCHEMA_VERSION
    )
