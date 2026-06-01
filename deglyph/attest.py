# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Signed, machine-checkable provenance for a scan result.

An attestation is a canonical, sorted JSON record of what deglyph saw: the tool
version, the scanned binary's sha256, the function-corpus version, and the sorted
per-finding fingerprints. A sha256 `digest` over that body makes the record
tamper-evident on its own; an optional ed25519 signature over the digest makes it
verifiable by anyone holding the public key. Re-attesting a changed binary, or a
binary whose findings changed, yields a different digest, so a stored attestation
is a comparable, gateable artifact.

Public names: ATTESTATION_VERSION, build_attestation, attestation_digest,
sign_attestation, verify_attestation, generate_keypair, signing_available,
unavailable_reason.

Signing is an optional capability: it imports `cryptography` lazily (the `sign`
extra), so the rest of deglyph stays importable without it. `signing_available()`
reports whether the extra is installed; `unavailable_reason()` returns an
actionable string when it is not.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter

# Bump on a breaking change to the attestation document shape.
ATTESTATION_VERSION = 1


def _sha256_file(path: str) -> str | None:
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def attestation_digest(doc: dict) -> str:
    """The sha256 over the canonical attestation body (excluding digest/signature).

    Canonicalization is sorted-key, tight-separator JSON, so the same content
    always hashes the same regardless of dict ordering or whitespace.
    """
    body = {k: v for k, v in doc.items() if k not in ("digest", "signature")}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_attestation(
    path: str,
    findings: list,
    *,
    tool_version: str,
    funcdb_version: int = 0,
) -> dict:
    """A tamper-evident attestation for a scan of the binary at `path`.

    `findings` is the `scan.Finding` list for the binary; each is reduced to its
    stable fingerprint so the attestation records the finding set without the
    volatile message text. The returned doc carries its own `digest`.
    """
    from .scan import fingerprint_of

    fps = sorted(fingerprint_of(f) for f in findings)
    counts = Counter(getattr(f, "level", "") for f in findings)
    doc: dict = {
        "deglyph_attestation_version": ATTESTATION_VERSION,
        "tool": {"name": "deglyph", "version": tool_version},
        "subject": {
            "name": os.path.basename(path),
            "sha256": _sha256_file(path),
        },
        "funcdb_version": funcdb_version,
        "summary": {
            "findings": len(findings),
            "error": counts.get("error", 0),
            "warning": counts.get("warning", 0),
            "note": counts.get("note", 0),
        },
        "findings": fps,
    }
    doc["digest"] = attestation_digest(doc)
    return doc


# --- signing (optional: needs the `sign` extra / `cryptography`) -------------


def signing_available() -> bool:
    """True when the optional signing dependency (`cryptography`) is importable."""
    try:
        import cryptography  # noqa: F401

        return True
    except Exception:
        return False


def unavailable_reason() -> str | None:
    """An actionable message when signing is unavailable, else None."""
    if signing_available():
        return None
    return "signing needs the optional dependency: pip install 'deglyph[sign]'"


def generate_keypair() -> tuple[bytes, bytes]:
    """A fresh ed25519 keypair as (private PEM, public PEM) byte strings."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def sign_attestation(doc: dict, priv_pem: bytes) -> dict:
    """Return a copy of `doc` with an ed25519 `signature` over its digest."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = serialization.load_pem_private_key(priv_pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("expected an ed25519 private key")
    digest = doc.get("digest") or attestation_digest(doc)
    sig = priv.sign(digest.encode("ascii"))
    out = dict(doc)
    out["digest"] = digest
    out["signature"] = sig.hex()
    return out


def _verify_signature(digest_hex: str, sig_hex: str, pub_pem: bytes) -> bool:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pub = serialization.load_pem_public_key(pub_pem)
    if not isinstance(pub, Ed25519PublicKey):
        return False
    try:
        pub.verify(bytes.fromhex(sig_hex), digest_hex.encode("ascii"))
        return True
    except Exception:
        return False


def verify_attestation(doc: dict, *, pub_pem: bytes | None = None) -> dict:
    """Check an attestation's integrity and, if a key is given, its signature.

    Returns `{"digest_ok": bool, "signature_ok": bool | None}`: `digest_ok` is
    whether the recomputed digest matches the recorded one (tamper check, always
    run); `signature_ok` is the ed25519 result when a public key and a signature
    are both present, else None.
    """
    digest_ok = attestation_digest(doc) == doc.get("digest")
    signature_ok: bool | None = None
    sig = doc.get("signature")
    if pub_pem is not None and isinstance(sig, str):
        signature_ok = _verify_signature(str(doc.get("digest", "")), sig, pub_pem)
    return {"digest_ok": digest_ok, "signature_ok": signature_ok}
