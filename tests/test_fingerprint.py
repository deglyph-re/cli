# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Third-party library identification by embedded version strings."""

from __future__ import annotations

from deglyph.re.fingerprint import SIGNATURES, scan_fingerprint


def test_detects_zlib(code_image):
    blob = b"\x00inflate 1.2.13 Copyright 1995-2022 Mark Adler\x00"
    img = code_image(blob)
    hits = scan_fingerprint(img, blob)
    names = {h.name for h in hits}
    assert "zlib" in names
    zlib = next(h for h in hits if h.name == "zlib")
    assert zlib.version == "1.2.13"
    assert zlib.purl == "pkg:generic/zlib@1.2.13"


def test_detects_openssl_and_curl(code_image):
    blob = b"\x00OpenSSL 3.0.7 1 Nov 2022\x00" b"libcurl/7.85.0 OpenSSL/3.0.7\x00"
    img = code_image(blob)
    hits = scan_fingerprint(img, blob)
    by_name = {h.name: h for h in hits}
    assert by_name["openssl"].version == "3.0.7"
    assert by_name["curl"].version == "7.85.0"
    assert by_name["curl"].purl == "pkg:generic/curl@7.85.0"


def test_dedupes_same_name_and_version(code_image):
    # The same string can be matched twice (e.g. ascii + utf-16); only one hit is emitted.
    blob = b"OpenSSL 3.0.7 a\x00OpenSSL 3.0.7 b\x00"
    img = code_image(blob)
    hits = scan_fingerprint(img, blob)
    openssl_hits = [h for h in hits if h.name == "openssl" and h.version == "3.0.7"]
    assert len(openssl_hits) == 1


def test_no_match_means_empty(code_image):
    blob = b"nothing interesting here, just opaque bytes\x00"
    img = code_image(blob)
    assert scan_fingerprint(img, blob) == []


def test_catalog_compiles_and_has_purl_bases():
    for sig in SIGNATURES:
        assert sig.purl_base.startswith("pkg:generic/")
        assert sig.pattern is not None
        # Each signature should declare exactly one capture group for version.
        assert sig.pattern.groups == 1


def test_scan_image_emits_lib_findings(code_image):
    from deglyph import scan

    blob = b"\x00OpenSSL 3.0.7 1 Nov 2022\x00"
    img = code_image(blob)
    findings = scan.scan_image(img, hardening=False)
    rules = {f.rule for f in findings}
    assert "lib/detected" in rules
    lib = next(f for f in findings if f.rule == "lib/detected")
    assert "openssl" in lib.message and "3.0.7" in lib.message
