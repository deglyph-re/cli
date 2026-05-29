# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Third-party library identification via embedded version strings.

Most C / C++ libraries embed a "<name> X.Y.Z" string in their `.rodata` for the
version they were built from. `scan_fingerprint` walks the image's string runs
and matches the curated `SIGNATURES` table against each, returning `LibHit`
records that feed the scan output, the SBOM emitter, and the CVE matcher.

Limits: this is exact-string matching against an opt-in catalog. A stripped
binary that did not link the version string (some LTO builds drop it) will not
be detected, and the catalog favors high-signal matches over coverage. A hit is
high confidence; an absent hit is not proof of absence.

Public: LibSignature, LibHit, SIGNATURES, scan_fingerprint.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.image import Image
from .strings import string_runs


@dataclass(slots=True)
class LibSignature:
    name: str
    # capture group 1 holds the version when present
    pattern: re.Pattern
    # purl base, "@<version>" appended when a version is captured
    purl_base: str
    note: str = ""


@dataclass(slots=True)
class LibHit:
    name: str
    version: str | None
    purl: str
    # file offset of the string run that matched
    offset: int
    # the matched line, truncated for display
    snippet: str


# Curated catalog. Each pattern is chosen to fire on a single, distinctive
# string the upstream project embeds in every build; add a new entry only when
# you have verified the string is stable across versions.
SIGNATURES: list[LibSignature] = [
    LibSignature(
        name="zlib",
        pattern=re.compile(r"(?:in|de)flate (\d+\.\d+\.\d+) Copyright"),
        purl_base="pkg:generic/zlib",
        note="compression",
    ),
    LibSignature(
        name="openssl",
        pattern=re.compile(r"OpenSSL (\d+\.\d+\.\d+[a-z]?)"),
        purl_base="pkg:generic/openssl",
        note="TLS / crypto",
    ),
    LibSignature(
        name="libpng",
        pattern=re.compile(r"libpng version (\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/libpng",
        note="PNG codec",
    ),
    LibSignature(
        name="sqlite",
        pattern=re.compile(r"SQLite version (\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/sqlite",
        note="embedded database",
    ),
    LibSignature(
        name="curl",
        pattern=re.compile(r"libcurl/(\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/curl",
        note="HTTP / network",
    ),
    LibSignature(
        name="lz4",
        pattern=re.compile(r"LZ4 v(\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/lz4",
        note="compression",
    ),
    LibSignature(
        name="mbedtls",
        pattern=re.compile(r"mbed TLS (\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/mbedtls",
        note="TLS / crypto",
    ),
    LibSignature(
        name="nghttp2",
        pattern=re.compile(r"nghttp2/(\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/nghttp2",
        note="HTTP/2",
    ),
    LibSignature(
        name="libssh2",
        pattern=re.compile(r"libssh2/(\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/libssh2",
        note="SSH client",
    ),
    LibSignature(
        name="lua",
        pattern=re.compile(r"Lua (\d+\.\d+(?:\.\d+)?)\b"),
        purl_base="pkg:generic/lua",
        note="scripting engine",
    ),
    LibSignature(
        name="qt",
        pattern=re.compile(r"\bQt (\d+\.\d+\.\d+)\b"),
        purl_base="pkg:generic/qt",
        note="C++ UI framework",
    ),
    LibSignature(
        name="cpython",
        pattern=re.compile(r"Python (\d+\.\d+\.\d+) \("),
        purl_base="pkg:generic/cpython",
        note="embedded CPython",
    ),
]


def scan_fingerprint(image: Image, data: bytes) -> list[LibHit]:
    """Identify linked libraries by matching version strings in the image."""
    hits: list[LibHit] = []
    seen: set[tuple[str, str | None]] = set()
    for off, _enc, text in string_runs(data, min_len=6):
        for sig in SIGNATURES:
            m = sig.pattern.search(text)
            if not m:
                continue
            version = m.group(1) if m.groups() else None
            key = (sig.name, version)
            if key in seen:
                continue
            seen.add(key)
            purl = f"{sig.purl_base}@{version}" if version else sig.purl_base
            snippet = text if len(text) <= 60 else text[:57] + "..."
            hits.append(LibHit(sig.name, version, purl, off, snippet))
    return hits
