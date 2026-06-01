# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Tests for signed, machine-checkable provenance (attest)."""

from __future__ import annotations

import pytest

from deglyph import attest
from deglyph.scan import Finding

_FINDINGS = [
    Finding("secret/aws-access-key", "error", "AWS key: 'AKIA...'", "0x1000"),
    Finding("harden/no-aslr", "warning", "ASLR is disabled", "hardening"),
]

_needs_crypto = pytest.mark.skipif(
    not attest.signing_available(), reason="cryptography (the 'sign' extra) absent"
)


def _doc(tmp_path):
    p = tmp_path / "subject.bin"
    p.write_bytes(b"\x90\x90\xc3")
    return attest.build_attestation(
        str(p), _FINDINGS, tool_version="test", funcdb_version=1
    )


def test_build_attestation_shape_and_digest(tmp_path):
    doc = _doc(tmp_path)
    assert doc["deglyph_attestation_version"] == attest.ATTESTATION_VERSION
    assert doc["summary"]["findings"] == 2
    assert doc["summary"]["error"] == 1 and doc["summary"]["warning"] == 1
    assert len(doc["findings"]) == 2
    # the recorded digest matches a fresh recomputation
    assert doc["digest"] == attest.attestation_digest(doc)


def test_digest_detects_tampering(tmp_path):
    doc = _doc(tmp_path)
    res = attest.verify_attestation(doc)
    assert res["digest_ok"] is True
    assert res["signature_ok"] is None
    # mutate a finding fingerprint: the digest no longer matches
    doc["findings"].append("deadbeefcafe")
    assert attest.verify_attestation(doc)["digest_ok"] is False


def test_unavailable_reason_consistent():
    if attest.signing_available():
        assert attest.unavailable_reason() is None
    else:
        assert "sign" in attest.unavailable_reason()


@_needs_crypto
def test_sign_and_verify_round_trip(tmp_path):
    priv_pem, pub_pem = attest.generate_keypair()
    signed = attest.sign_attestation(_doc(tmp_path), priv_pem)
    assert "signature" in signed
    res = attest.verify_attestation(signed, pub_pem=pub_pem)
    assert res["digest_ok"] is True
    assert res["signature_ok"] is True


@_needs_crypto
def test_signature_fails_under_a_wrong_key(tmp_path):
    priv_pem, _pub = attest.generate_keypair()
    _other_priv, other_pub = attest.generate_keypair()
    signed = attest.sign_attestation(_doc(tmp_path), priv_pem)
    res = attest.verify_attestation(signed, pub_pem=other_pub)
    assert res["digest_ok"] is True
    assert res["signature_ok"] is False


@_needs_crypto
def test_signature_catches_a_digest_an_attacker_recomputed(tmp_path):
    priv_pem, pub_pem = attest.generate_keypair()
    signed = attest.sign_attestation(_doc(tmp_path), priv_pem)
    # An attacker edits the body and recomputes the digest to keep digest_ok, but
    # cannot re-sign without the private key: the signature check is what fails.
    signed["summary"]["error"] = 99
    signed["digest"] = attest.attestation_digest(signed)
    res = attest.verify_attestation(signed, pub_pem=pub_pem)
    assert res["digest_ok"] is True
    assert res["signature_ok"] is False
