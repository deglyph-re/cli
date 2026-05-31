# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Binary SBOM emitter.

Builds a CycloneDX 1.5 or SPDX 2.3 software bill of materials from a loaded
`Image` and the `LibHit` records produced by `re.fingerprint.scan_fingerprint`.
The root component describes the scanned binary (SHA-256 of file contents);
each detected library becomes a `library`-typed component with its purl. This is
"binary SBOM": SBOM-from-build (syft / Trivy) covers source / containers, this
covers what actually got linked into the final artifact.

Limits: components are only as complete as the fingerprint catalog. An empty
components list does not mean a self-contained binary; it means no catalog
signature matched. State that when reporting.

Public: build_sbom, sbom_cyclonedx, sbom_spdx.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone

from . import __version__
from .core.image import Arch, Image, load_image
from .re.fingerprint import LibHit, scan_fingerprint


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _spdx_id(label: str) -> str:
    """Sanitize an arbitrary string into a valid SPDX element id token."""
    out = []
    for c in label:
        if c.isalnum() or c in "-.":
            out.append(c)
        else:
            out.append("-")
    return f"SPDXRef-Package-{''.join(out)}"


def sbom_cyclonedx(image: Image, hits: list[LibHit], *, sha256: str) -> dict:
    """Render hits as a CycloneDX 1.5 BOM document."""
    components = []
    for h in hits:
        comp: dict = {
            "type": "library",
            "name": h.name,
            "purl": h.purl,
        }
        if h.version:
            comp["version"] = h.version
        # deglyph match metadata: how confident the fingerprint is and which
        # ecosystem the purl belongs to, so a consumer can weight the hit.
        comp["properties"] = [
            {"name": "deglyph:confidence", "value": h.confidence},
            {"name": "deglyph:ecosystem", "value": h.ecosystem},
        ]
        components.append(comp)

    root_hashes = [{"alg": "SHA-256", "content": sha256}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _utc_now(),
            "tools": [
                {
                    "vendor": "deglyph",
                    "name": "deglyph",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": "root",
                "name": os.path.basename(image.path),
                "hashes": root_hashes,
            },
        },
        "components": components,
    }


def sbom_spdx(image: Image, hits: list[LibHit], *, sha256: str) -> dict:
    """Render hits as an SPDX 2.3 JSON document."""
    name = os.path.basename(image.path)
    root_id = "SPDXRef-Package-root"
    packages = [
        {
            "SPDXID": root_id,
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha256}],
        }
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    seen_ids: set[str] = {root_id}
    for h in hits:
        sid = _spdx_id(h.name + ("-" + h.version if h.version else ""))
        if sid in seen_ids:
            continue
        seen_ids.add(sid)
        pkg: dict = {
            "SPDXID": sid,
            "name": h.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": h.purl,
                }
            ],
        }
        if h.version:
            pkg["versionInfo"] = h.version
        pkg["comment"] = f"deglyph: confidence={h.confidence}; ecosystem={h.ecosystem}"
        packages.append(pkg)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": sid,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"https://deglyph.dev/sbom/{sha256}",
        "creationInfo": {
            "created": _utc_now(),
            "creators": [f"Tool: deglyph-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def build_sbom(
    path: str,
    *,
    fmt: str = "cyclonedx",
    arch: Arch | None = None,
    force_fmt: str | None = None,
) -> dict:
    """Load `path`, fingerprint linked libraries, and emit the requested SBOM."""
    # Validate the format before touching the file, so an unknown format is a
    # clean ValueError rather than masked by a LIEF parse error on bad input.
    fmt_lc = fmt.lower()
    if fmt_lc not in ("cyclonedx", "cdx", "cyclone", "spdx"):
        raise ValueError(
            f"unknown SBOM format: {fmt!r} (expected 'cyclonedx' or 'spdx')"
        )
    img = load_image(path, fmt=force_fmt, arch=arch)
    with open(path, "rb") as fh:
        data = fh.read()
    hits = scan_fingerprint(img, data)
    digest = _sha256(path)
    if fmt_lc == "spdx":
        return sbom_spdx(img, hits, sha256=digest)
    return sbom_cyclonedx(img, hits, sha256=digest)
