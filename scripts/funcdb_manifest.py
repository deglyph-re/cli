#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Build the target manifest for `scripts/build_funcdb.py` on a CI runner.

Resolves two kinds of target: distribution libraries installed via apt (globbed
by soname, versioned via dpkg) and libraries built from source (passed as
`--source lib:version:path`). A candidate whose file is absent is dropped, so the
manifest reflects what the runner actually has. Output is the JSON manifest
`build_funcdb.py` consumes.

Used only by .github/workflows/build-funcdb.yml; kept as a script (not inline
YAML) so it lints and reads like the rest of the tooling.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess

# apt-installed shared libraries to fingerprint: (lib, soname glob, dpkg package).
# A glob tolerates a soname version bump (libcrypto.so.3 -> .so.4) without an edit.
_APT_LIBS: list[tuple[str, str, str]] = [
    ("openssl", "/usr/lib/x86_64-linux-gnu/libcrypto.so.*", "libssl3"),
    ("openssl", "/usr/lib/x86_64-linux-gnu/libssl.so.*", "libssl3"),
    ("curl", "/usr/lib/x86_64-linux-gnu/libcurl.so.*", "libcurl4"),
    ("zstd", "/usr/lib/x86_64-linux-gnu/libzstd.so.*", "libzstd1"),
    ("bzip2", "/usr/lib/x86_64-linux-gnu/libbz2.so.*", "libbz2-1.0"),
    ("xz", "/usr/lib/x86_64-linux-gnu/liblzma.so.*", "liblzma5"),
    ("pcre2", "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.*", "libpcre2-8-0"),
    ("expat", "/usr/lib/x86_64-linux-gnu/libexpat.so.*", "libexpat1"),
]


def _dpkg_version(package: str) -> str | None:
    """The installed version of an apt package, or None when it cannot be read."""
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", package],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    # Trim an epoch ("1:3.0.13-...") and Debian revision ("-0ubuntu3") to the
    # upstream version, which is what a purl / CVE lookup wants.
    ver = out.stdout.strip()
    if not ver:
        return None
    ver = ver.split(":", 1)[-1]
    return ver.split("-", 1)[0] or None


def _resolve_soname(pattern: str) -> str | None:
    """The first concrete (non-symlink-to-missing) file matching a soname glob."""
    for cand in sorted(glob.glob(pattern)):
        real = os.path.realpath(cand)
        if os.path.isfile(real):
            return real
    return None


def _apt_targets() -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for lib, pattern, package in _APT_LIBS:
        path = _resolve_soname(pattern)
        if path is None or path in seen:
            continue
        seen.add(path)
        out.append(
            {
                "path": path,
                "lib": lib,
                "version": _dpkg_version(package),
                "ecosystem": "generic",
            }
        )
    return out


def _source_targets(specs: list[str]) -> list[dict]:
    """Parse `lib:version:path` specs into manifest targets (existing files only)."""
    out: list[dict] = []
    for spec in specs:
        parts = spec.split(":", 2)
        if len(parts) != 3:
            continue
        lib, version, path = parts
        if not os.path.isfile(path):
            continue
        out.append(
            {
                "path": path,
                "lib": lib,
                "version": version or None,
                "ecosystem": "generic",
            }
        )
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Emit the build_funcdb target manifest.")
    ap.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="LIB:VERSION:PATH",
        help="a from-source library build (repeatable)",
    )
    ap.add_argument("--output", "-o", default="manifest.json")
    args = ap.parse_args(argv)

    targets = _source_targets(args.source) + _apt_targets()
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"targets": targets}, fh, indent=2)
        fh.write("\n")
    for t in targets:
        print(f"manifest: {t['lib']} {t['version'] or '?'} -> {t['path']}")
    print(f"manifest: {len(targets)} target(s) -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
