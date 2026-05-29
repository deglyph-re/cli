# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""CycloneDX + SPDX SBOM emitters."""

from __future__ import annotations

import json
import os

import pytest

from deglyph import sbom
from deglyph.re.fingerprint import LibHit

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def _hits():
    return [
        LibHit(
            name="zlib",
            version="1.2.13",
            purl="pkg:generic/zlib@1.2.13",
            offset=0x100,
            snippet="inflate 1.2.13 Copyright",
        ),
        LibHit(
            name="openssl",
            version="3.0.7",
            purl="pkg:generic/openssl@3.0.7",
            offset=0x200,
            snippet="OpenSSL 3.0.7",
        ),
        LibHit(
            name="boost",
            version=None,
            purl="pkg:generic/boost",
            offset=0x300,
            snippet="boost",
        ),
    ]


def test_cyclonedx_shape(code_image):
    img = code_image(b"\x90")
    doc = sbom.sbom_cyclonedx(img, _hits(), sha256="a" * 64)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["type"] == "application"
    assert doc["metadata"]["component"]["hashes"][0]["alg"] == "SHA-256"
    by_name = {c["name"]: c for c in doc["components"]}
    assert by_name["zlib"]["version"] == "1.2.13"
    assert by_name["zlib"]["purl"] == "pkg:generic/zlib@1.2.13"
    assert "version" not in by_name["boost"]


def test_spdx_shape(code_image):
    img = code_image(b"\x90")
    doc = sbom.sbom_spdx(img, _hits(), sha256="b" * 64)
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["documentNamespace"].startswith("https://deglyph.dev/sbom/")
    pkg_ids = {p["SPDXID"] for p in doc["packages"]}
    # The root + one package per detected lib (deduped on (name, version) string)
    assert "SPDXRef-Package-root" in pkg_ids
    assert any("zlib" in pid for pid in pkg_ids)
    # Every dependency relates back to the root.
    deps = [r for r in doc["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
    assert deps and all(r["spdxElementId"] == "SPDXRef-Package-root" for r in deps)


def test_cyclonedx_empty_components_for_no_hits(code_image):
    img = code_image(b"\x90")
    doc = sbom.sbom_cyclonedx(img, [], sha256="c" * 64)
    assert doc["components"] == []


def test_build_sbom_rejects_unknown_format(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x90")
    with pytest.raises(ValueError, match="unknown SBOM format"):
        sbom.build_sbom(str(p), fmt="protobuf")


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_build_sbom_against_demo_is_valid_json():
    doc = sbom.build_sbom(SAMPLE, fmt="cyclonedx")
    # Round-trip via json to confirm everything is serializable.
    text = json.dumps(doc, indent=2)
    assert "CycloneDX" in text
    assert doc["metadata"]["component"]["name"] == "demo.exe"
