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


def test_catalog_names_are_unique():
    names = [sig.name for sig in SIGNATURES]
    assert len(names) == len(set(names))


def test_detects_added_banners(code_image):
    # Each embedded banner is the literal string upstream compiles into its
    # builds; verify the pattern extracts the version and does not over-match.
    cases = {
        "expat": (b"\x00expat_2.6.1\x00", "2.6.1"),
        "glibc": (
            b"\x00GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3) stable"
            b" release version 2.35.\x00",
            "2.35",
        ),
        "openssh": (b"\x00OpenSSH_9.6p1 Ubuntu\x00", "9.6"),
        "libressl": (b"\x00LibreSSL 3.8.2\x00", "3.8.2"),
        "zlib-ng": (b"\x00zlib-ng 2.1.6\x00", "2.1.6"),
        "libjpeg-turbo": (
            b"\x00libjpeg-turbo version 2.1.5 (build 20230101)\x00",
            "2.1.5",
        ),
        "busybox": (b"\x00BusyBox v1.36.1 (2023-11-07 12:00:00)\x00", "1.36.1"),
        "pcre2": (b"\x00PCRE2 10.42 2022-12-11\x00", "10.42"),
        "zstd": (b"\x00Zstandard v1.5.5\x00", "1.5.5"),
    }
    for name, (blob, version) in cases.items():
        img = code_image(blob)
        hits = {h.name: h for h in scan_fingerprint(img, blob)}
        assert name in hits, f"{name} not detected"
        assert hits[name].version == version, name


def test_banner_does_not_false_positive(code_image):
    # A run mentioning a library name without its banner form must not match.
    blob = b"\x00this build links against openssh and glibc somewhere\x00"
    img = code_image(blob)
    assert scan_fingerprint(img, blob) == []


def test_scan_image_emits_lib_findings(code_image):
    from deglyph import scan

    blob = b"\x00OpenSSL 3.0.7 1 Nov 2022\x00"
    img = code_image(blob)
    findings = scan.scan_image(img, hardening=False)
    rules = {f.rule for f in findings}
    assert "lib/detected" in rules
    lib = next(f for f in findings if f.rule == "lib/detected")
    assert "openssl" in lib.message and "3.0.7" in lib.message
