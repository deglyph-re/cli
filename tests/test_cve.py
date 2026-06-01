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

    def read(self, amt: int | None = None) -> bytes:
        if amt is None:
            return self._body
        return self._body[:amt]

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
    monkeypatch.setattr(
        cve, "_fetch_osv", lambda purl, timeout: {"vulns": [{"id": "CVE-1"}]}
    )
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
        "_fetch_osv",
        lambda purl, timeout: {"vulns": [{"id": "CVE-LONG", "summary": long_summary}]},
    )
    hits = [LibHit("z", "1.0", "pkg:generic/z@1.0", 0, "z")]
    f = cve.scan_cve(hits)[0]
    # capped before 80 raw chars
    assert "x" * 80 not in f.message


def test_scan_cve_records_provenance(offline_store, monkeypatch):
    monkeypatch.setattr(
        cve,
        "_fetch_osv",
        lambda purl, timeout: {"vulns": [{"id": "CVE-2018-25032"}]},
    )
    hits = [LibHit("zlib", "1.2.11", "pkg:generic/zlib@1.2.11", 0, "zlib")]
    f = cve.scan_cve(hits)[0]
    assert f.rule == "cve/known"
    assert "CVE-2018-25032" in f.message
    assert "osv.dev" in f.message


def test_scan_cve_offline_reports_not_checked(offline_store, monkeypatch):
    monkeypatch.setattr(
        cve, "_fetch_osv", lambda purl, timeout: pytest.fail("offline must not query")
    )
    hits = [LibHit("zlib", "1.2.11", "pkg:generic/zlib@1.2.11", 0, "zlib")]
    out = cve.scan_cve(hits, offline=True)
    assert len(out) == 1
    assert out[0].rule == "cve/not-checked"
    assert "offline" in out[0].message


def test_scan_cve_lookup_failure_reports_not_checked(offline_store, monkeypatch):
    def _boom(purl, timeout):
        raise cve.CveLookupError("no route to host")

    monkeypatch.setattr(cve, "_fetch_osv", _boom)
    hits = [LibHit("zlib", "1.2.11", "pkg:generic/zlib@1.2.11", 0, "zlib")]
    out = cve.scan_cve(hits)
    assert len(out) == 1
    assert out[0].rule == "cve/not-checked"
    assert "no route to host" in out[0].message


def test_cache_records_provenance_wrapper(offline_store, monkeypatch):
    monkeypatch.setattr(cve, "_fetch_osv", lambda purl, timeout: {"vulns": []})
    cve.scan_cve([LibHit("zlib", "1.2.11", "pkg:generic/zlib@1.2.11", 0, "zlib")])
    doc = json.loads(
        open(cve.cache_path("pkg:generic/zlib@1.2.11"), encoding="utf-8").read()
    )
    assert doc["source"] == "osv.dev"
    assert doc["purl"] == "pkg:generic/zlib@1.2.11"
    assert "queried_at" in doc and "payload" in doc


def test_legacy_bare_cache_is_read(offline_store, monkeypatch):
    # A pre-provenance cache stored the bare OSV payload; it must still be read.
    p = cve.cache_path("pkg:generic/zlib@1.2.11")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"vulns": [{"id": "CVE-LEGACY", "summary": "old"}]}, fh)
    monkeypatch.setattr(
        cve, "_fetch_osv", lambda purl, timeout: pytest.fail("must use cache")
    )
    out = cve.scan_cve([LibHit("zlib", "1.2.11", "pkg:generic/zlib@1.2.11", 0, "zlib")])
    assert len(out) == 1
    assert "CVE-LEGACY" in out[0].message
