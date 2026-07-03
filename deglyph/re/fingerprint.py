# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Third-party library identification via embedded version strings and byte marks.

Most C / C++ libraries embed a "<name> X.Y.Z" string in their `.rodata` for the
version they were built from. `scan_fingerprint` walks the image's string runs
and matches the curated `SIGNATURES` table against each. When the version string
is stripped (some LTO builds drop it) a second pass matches `byte_pattern`
signatures: distinctive constant bytes a library always carries (a CRC table, a
magic seed). Each result is a `LibHit` carrying a confidence grade and the
evidence that produced it.

The catalog is pluggable: `load_signatures(path)` merges the built-in
`SIGNATURES` with a JSON database so a consumer can extend coverage without
editing the source.

Limits: this is signature matching against an opt-in catalog. A version-string
hit is high confidence; a byte-pattern hit is medium (the bytes are distinctive
but not unique across all builds). An absent hit is never proof of absence.

Public: LibSignature, LibHit, SIGNATURES, load_signatures, scan_fingerprint.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from ..core.image import Image
from .strings import string_runs

log = logging.getLogger(__name__)


@dataclass(slots=True)
class LibSignature:
    name: str
    # capture group 1 holds the version when present
    pattern: re.Pattern
    # purl base, "@<version>" appended when a version is captured
    purl_base: str
    # OSV / purl ecosystem; "generic" is the broad C-library path osv.dev accepts
    ecosystem: str = "generic"
    note: str = ""
    # optional fallback: distinctive constant bytes present in every build, used
    # when no version string is found. A medium-confidence, versionless match.
    byte_pattern: bytes | None = None


@dataclass(slots=True)
class LibHit:
    name: str
    version: str | None
    purl: str
    # file offset of the string run or byte run that matched
    offset: int
    # the matched line, truncated for display
    snippet: str
    # "high" for a version-string match, "medium" for a byte-pattern match
    confidence: str = "high"
    # what produced the hit, for the report ("version string", "byte signature ...")
    evidence: str = ""
    # OSV / purl ecosystem carried through to the CVE matcher and SBOM
    ecosystem: str = "generic"
    note: str = field(default="")


# Curated catalog. Each pattern is chosen to fire on a single, distinctive
# string the upstream project embeds in every build; add a new entry only when
# you have verified the string is stable across versions. `byte_pattern` is an
# optional version-less fallback for stripped builds.
SIGNATURES: list[LibSignature] = [
    LibSignature(
        name="zlib",
        pattern=re.compile(r"(?:in|de)flate (\d+\.\d+\.\d+) Copyright"),
        purl_base="pkg:generic/zlib",
        note="compression",
        # the first 8 entries of zlib's static CRC-32 table (crc_table[0..1])
        byte_pattern=bytes.fromhex("00000000 96300777".replace(" ", "")),
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
    LibSignature(
        name="expat",
        pattern=re.compile(r"expat_(\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/expat",
        note="XML parser",
    ),
    LibSignature(
        name="glibc",
        pattern=re.compile(r"GNU C Library.*?version (\d+\.\d+)"),
        purl_base="pkg:generic/glibc",
        note="GNU C runtime",
    ),
    LibSignature(
        name="openssh",
        pattern=re.compile(r"OpenSSH_(\d+\.\d+)(?:p\d+)?"),
        purl_base="pkg:generic/openssh",
        note="SSH client / server",
    ),
    LibSignature(
        name="libressl",
        pattern=re.compile(r"LibreSSL (\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/libressl",
        note="TLS / crypto",
    ),
    LibSignature(
        name="zlib-ng",
        pattern=re.compile(r"zlib-ng (\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/zlib-ng",
        note="compression",
    ),
    LibSignature(
        name="libjpeg-turbo",
        pattern=re.compile(r"libjpeg-turbo version (\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/libjpeg-turbo",
        note="JPEG codec",
    ),
    LibSignature(
        name="busybox",
        pattern=re.compile(r"BusyBox v(\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/busybox",
        note="embedded userland",
    ),
    LibSignature(
        name="pcre2",
        pattern=re.compile(r"PCRE2 (\d+\.\d+) \d{4}-\d{2}-\d{2}"),
        purl_base="pkg:generic/pcre2",
        note="regex engine",
    ),
    LibSignature(
        name="zstd",
        pattern=re.compile(r"Zstandard v(\d+\.\d+\.\d+)"),
        purl_base="pkg:generic/zstd",
        note="compression",
    ),
]


def _purl(sig: LibSignature, version: str | None) -> str:
    """The package URL for a hit: signature base, with the version when known."""
    return f"{sig.purl_base}@{version}" if version else sig.purl_base


def _signature_from_json(entry: dict) -> LibSignature | None:
    """Build a LibSignature from one JSON catalog entry, or None if malformed."""
    try:
        name = str(entry["name"])
        pattern = re.compile(str(entry["pattern"]))
        purl_base = str(entry["purl_base"])
    except (KeyError, re.error, TypeError) as e:
        log.warning("skipping malformed library signature %r: %s", entry, e)
        return None
    raw_bytes = entry.get("byte_pattern")
    byte_pattern: bytes | None = None
    if raw_bytes:
        try:
            byte_pattern = bytes.fromhex(str(raw_bytes))
        except ValueError as e:
            log.warning("ignoring bad byte_pattern for %s: %s", name, e)
    return LibSignature(
        name=name,
        pattern=pattern,
        purl_base=purl_base,
        ecosystem=str(entry.get("ecosystem", "generic")),
        note=str(entry.get("note", "")),
        byte_pattern=byte_pattern,
    )


def load_signatures(path: str) -> list[LibSignature]:
    """Built-in SIGNATURES merged with a JSON database at `path`.

    The file holds `{"signatures": [{"name", "pattern", "purl_base",
    "ecosystem"?, "note"?, "byte_pattern"?}, ...]}`. A later entry with the same
    name overrides the built-in. Malformed entries are skipped with a warning so
    one bad row never voids the catalog.
    """
    extra: list[LibSignature] = []
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        log.warning("could not read library signature database %s: %s", path, e)
        return list(SIGNATURES)
    for entry in doc.get("signatures") or []:
        if isinstance(entry, dict):
            sig = _signature_from_json(entry)
            if sig is not None:
                extra.append(sig)
    by_name = {sig.name: sig for sig in SIGNATURES}
    for sig in extra:
        by_name[sig.name] = sig
    return list(by_name.values())


def _scan_strings(
    data: bytes, signatures: list[LibSignature]
) -> tuple[list[LibHit], set[str]]:
    """Version-string pass: high-confidence hits and the set of names found."""
    hits: list[LibHit] = []
    seen: set[tuple[str, str | None]] = set()
    found: set[str] = set()
    for off, _enc, text in string_runs(data, min_len=6):
        for sig in signatures:
            m = sig.pattern.search(text)
            if not m:
                continue
            version = m.group(1) if m.groups() else None
            key = (sig.name, version)
            if key in seen:
                continue
            seen.add(key)
            found.add(sig.name)
            snippet = text if len(text) <= 60 else text[:57] + "..."
            hits.append(
                LibHit(
                    name=sig.name,
                    version=version,
                    purl=_purl(sig, version),
                    offset=off,
                    snippet=snippet,
                    confidence="high",
                    evidence=f"version string {snippet!r}",
                    ecosystem=sig.ecosystem,
                    note=sig.note,
                )
            )
    return hits, found


def _scan_bytes(
    data: bytes, signatures: list[LibSignature], already: set[str]
) -> list[LibHit]:
    """Byte-pattern pass for libraries the string pass did not already identify."""
    hits: list[LibHit] = []
    for sig in signatures:
        if sig.byte_pattern is None or sig.name in already:
            continue
        off = data.find(sig.byte_pattern)
        if off < 0:
            continue
        already.add(sig.name)
        hexmark = sig.byte_pattern.hex()
        hits.append(
            LibHit(
                name=sig.name,
                version=None,
                purl=_purl(sig, None),
                offset=off,
                snippet=f"<byte signature {hexmark}>",
                confidence="medium",
                evidence=f"byte signature {hexmark} at offset {off:#x}",
                ecosystem=sig.ecosystem,
                note=sig.note,
            )
        )
    return hits


def scan_fingerprint(
    image: Image, data: bytes, *, signatures: list[LibSignature] | None = None
) -> list[LibHit]:
    """Identify linked libraries by version string, then by byte signature.

    Version-string matches are graded high confidence; byte-signature matches
    (used only for libraries no version string identified) are graded medium.
    Pass `signatures` to override the built-in catalog (see `load_signatures`).
    """
    sigs = signatures if signatures is not None else SIGNATURES
    hits, found = _scan_strings(data, sigs)
    hits.extend(_scan_bytes(data, sigs, found))
    return hits
