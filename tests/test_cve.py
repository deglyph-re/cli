# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""CVE matcher against osv.dev (network stubbed)."""

from __future__ import annotations

import json
import os

import pytest

from deglyph import cve
from deglyph.re.fingerprint import LibHit


class _FakeResp:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def offline_store(tmp_path, monkeypatch):
    """Point the CVE cache at a tmp dir so tests don't touch the user's HOME."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    return tmp_path


def _stub_urlopen(monkeypatch, payload):
    captured = {}

    def fake(req, timeout=10):
        captured["url"] = req.full_url
        captured["body"] = req.data
        return _FakeResp(payload)

    monkeypatch.setattr(cve.urllib.request, "urlopen", fake)
    return captured


def test_query_osv_returns_vulns(offline_store, monkeypatch):
    payload = {
        "vulns": [
            {"id": "CVE-2022-37434", "summary": "zlib heap buffer overflow"},
            {"id": "GHSA-xxxx", "details": "another issue with details only"},
        ]
    }
    cap = _stub_urlopen(monkeypatch, payload)
    out = cve.query_osv("pkg:generic/zlib@1.2.11")
    assert len(out) == 2
    assert out[0]["id"] == "CVE-2022-37434"
    assert "zlib@1.2.11" in cap["body"].decode("utf-8")


def test_query_osv_caches_on_disk(offline_store, monkeypatch):
    payload = {"vulns": [{"id": "CVE-XYZ"}]}
    _stub_urlopen(monkeypatch, payload)

    cve.query_osv("pkg:generic/openssl@3.0.7")
    # Cache file should exist now.
    assert os.path.isfile(cve.cache_path("pkg:generic/openssl@3.0.7"))

    # A second call must not require the network: blow up urlopen and confirm
    # the cached value is returned.
    def explode(*a, **k):
        raise AssertionError("network hit on cached purl")

    monkeypatch.setattr(cve.urllib.request, "urlopen", explode)
    again = cve.query_osv("pkg:generic/openssl@3.0.7")
    assert again[0]["id"] == "CVE-XYZ"


def test_query_osv_handles_network_failure(offline_store, monkeypatch):
    def bang(*a, **k):
        raise cve.urllib.error.URLError("no route to host")

    monkeypatch.setattr(cve.urllib.request, "urlopen", bang)
    assert cve.query_osv("pkg:generic/zlib@1.2.13") == []


def test_scan_cve_skips_unversioned_hits(offline_store, monkeypatch):
    monkeypatch.setattr(cve, "query_osv", lambda purl, timeout=10.0: [{"id": "CVE-1"}])
    hits = [
        LibHit("zlib", None, "pkg:generic/zlib", 0, "zlib"),
        LibHit("openssl", "3.0.7", "pkg:generic/openssl@3.0.7", 0, "OpenSSL 3.0.7"),
    ]
    findings = cve.scan_cve(hits)
    assert len(findings) == 1
    assert "openssl" in findings[0].message
    assert findings[0].rule == "cve/known"
    assert findings[0].level == "error"


def test_scan_cve_truncates_long_summaries(offline_store, monkeypatch):
    long_summary = "x" * 200
    monkeypatch.setattr(
        cve,
        "query_osv",
        lambda purl, timeout=10.0: [{"id": "CVE-LONG", "summary": long_summary}],
    )
    hits = [LibHit("z", "1.0", "pkg:generic/z@1.0", 0, "z")]
    f = cve.scan_cve(hits)[0]
    assert f.message.endswith("...")
    # capped before 80 raw chars
    assert "x" * 80 not in f.message
