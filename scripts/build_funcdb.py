#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Build the function-signature corpus from a set of well-known binaries.

Run in CI (see .github/workflows/build-funcdb.yml) after the target libraries
are installed (apt) or built from source. Each target is one binary plus the
library / version / ecosystem to attribute its functions to. For every named,
non-trivial function the loader recovers, this records a `FuncSignature`
(`re/funcdb`) and writes the merged corpus to `deglyph/data/funcdb.json` plus a
human summary to `doc/help/Function-Database.md`.

Manifest format (JSON):

    {"targets": [
        {"path": "/usr/lib/x86_64-linux-gnu/libz.so.1",
         "lib": "zlib", "version": "1.3.1", "ecosystem": "generic"},
        ...
    ]}

A target whose file is missing or fails to load is skipped with a warning, so a
partial toolchain still yields a corpus (the same best-effort contract as
samples/build_fixtures.sh). Output is deterministic: signatures are sorted and
no timestamp is written, so re-running over the same inputs produces no diff.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Run from a checkout without an editable install (mirrors tests/conftest.py).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from deglyph.core.image import load_image  # noqa: E402
from deglyph.re.discover import discover_functions  # noqa: E402
from deglyph.re.funcdb import BUNDLED_VERSION, FuncSignature  # noqa: E402
from deglyph.re.funcsig import func_sig  # noqa: E402

# Skip functions shorter than this: a handful of instructions collide easily and
# would produce low-value, false-positive-prone signatures.
_MIN_INSNS = 8


def _is_named(name: str) -> bool:
    """A real symbol worth cataloguing (not a recovered sub_, not an entry stub)."""
    if not name or name.startswith("sub_"):
        return False
    return name not in ("entry", "_start", "start")


def _harvest(target: dict) -> list[FuncSignature]:
    """Sign every named, non-trivial function in one target binary."""
    path = target.get("path", "")
    lib = target.get("lib", "")
    if not path or not lib or not os.path.isfile(path):
        print(f"build_funcdb: skip (missing): {path!r}", file=sys.stderr)
        return []
    try:
        image = load_image(path)
        discover_functions(image)
    except Exception as e:
        print(f"build_funcdb: skip (load failed): {path!r}: {e}", file=sys.stderr)
        return []

    version = target.get("version") or None
    ecosystem = target.get("ecosystem", "generic")
    arch = image.arch.value
    out: list[FuncSignature] = []
    for f in image.funcs:
        if f.kind == "import" or not _is_named(f.display):
            continue
        sig = func_sig(image, f.va)
        if sig is None or sig.n_insns < _MIN_INSNS:
            continue
        out.append(
            FuncSignature(
                name=f.display,
                lib=lib,
                version=version,
                ecosystem=ecosystem,
                arch=arch,
                exact=sig.exact,
                n_insns=sig.n_insns,
                ngrams=sig.ngrams,
            )
        )
    return out


def _dedup(sigs: list[FuncSignature]) -> list[FuncSignature]:
    """One signature per (lib, version, arch, exact); deterministic order."""
    by_key: dict[tuple, FuncSignature] = {}
    for s in sigs:
        by_key[(s.lib, s.version or "", s.arch, s.exact)] = s
    return [by_key[k] for k in sorted(by_key)]


def _ensure_parent(path: str) -> None:
    """Create the parent directory of `path` (a no-op for a bare filename)."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _write_corpus(path: str, sigs: list[FuncSignature]) -> None:
    doc = {
        "funcdb_version": BUNDLED_VERSION,
        "generated": "",
        "note": (
            "Function-signature corpus built by scripts/build_funcdb.py. An empty "
            "list means no catalogued functions, not a self-contained binary."
        ),
        "functions": [s.to_dict() for s in sigs],
    }
    _ensure_parent(path)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _summary_rows(sigs: list[FuncSignature]) -> list[tuple[str, str, str, str, int]]:
    """Per (lib, version, ecosystem, arch) function counts, sorted for the table."""
    counts: dict[tuple[str, str, str, str], int] = {}
    for s in sigs:
        key = (s.lib, s.version or "(versionless)", s.ecosystem, s.arch)
        counts[key] = counts.get(key, 0) + 1
    return [(*k, n) for k, n in sorted(counts.items())]


def _write_markdown(path: str, sigs: list[FuncSignature]) -> None:
    rows = _summary_rows(sigs)
    libs = sorted({s.lib for s in sigs})
    lines = [
        "# Function Database",
        "",
        "The function database is a corpus of per-function signatures harvested "
        "from well-known libraries. With it, `deglyph scan --identify` can name a "
        "recovered `sub_<address>` as the library function it matches, the same "
        "way [Library Fingerprinting](Library-Fingerprinting.md) names a whole "
        "library from its strings.",
        "",
        "Each signature is the relocation-stable identity from the analysis core: "
        "the function's normalized instruction stream, hashed. A build that only "
        "moved a function keeps its signature; a changed body does not. The corpus "
        "is rebuilt in CI over many programs and shipped with the tool.",
        "",
        f"This catalog holds {len(sigs)} function signature(s) across "
        f"{len(libs)} library(ies).",
        "",
        "## Catalogued libraries",
        "",
        "| Library | Version | Ecosystem | Architecture | Functions |",
        "| --- | --- | --- | --- | --- |",
    ]
    for lib, version, ecosystem, arch, n in rows:
        lines.append(f"| {lib} | {version} | {ecosystem} | {arch} | {n} |")
    if not rows:
        lines.append("| (none yet) | | | | 0 |")
    lines += [
        "",
        "## How to read a match",
        "",
        "A match is a candidate identification, not a proof. An exact-hash hit "
        "is high confidence; a fuzzy hit carries a similarity score. Two unrelated "
        "functions can share a normalized shape, so confirm a surprising match in "
        "the disassembly. An absent match means the corpus has no entry for that "
        "function, never that the function is original.",
        "",
        "## See also",
        "",
        "- [Library Fingerprinting](Library-Fingerprinting.md): whole-library "
        "identification from version strings.",
        "- [Baseline Diff](Baseline-Diff.md): the same signatures power the "
        "function-level build diff.",
        "- [Heuristics, Not Proofs](Heuristics.md): how to read a candidate match.",
    ]
    _ensure_parent(path)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def _update_help_index(path: str) -> None:
    """Add the Function-Database entry to doc/help/help.json if it is absent."""
    try:
        with open(path, encoding="utf-8") as fh:
            entries = json.load(fh)
    except (OSError, ValueError):
        return
    if any(e.get("id") == "function-database" for e in entries):
        return
    entry = {
        "id": "function-database",
        "title": "Function Database",
        "section": "Reference",
        "file": "Function-Database.md",
    }
    entries.append(entry)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(entries, fh, indent=2)
        fh.write("\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the function-signature corpus.")
    ap.add_argument("--manifest", required=True, help="JSON manifest of targets")
    ap.add_argument(
        "--out",
        default=os.path.join(_REPO_ROOT, "deglyph", "data", "funcdb.json"),
        help="corpus output path",
    )
    ap.add_argument(
        "--markdown",
        default=os.path.join(_REPO_ROOT, "doc", "help", "Function-Database.md"),
        help="human summary output path",
    )
    ap.add_argument(
        "--help-index",
        default=os.path.join(_REPO_ROOT, "doc", "help", "help.json"),
        help="help.json to register the summary in",
    )
    args = ap.parse_args(argv)

    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    targets = manifest.get("targets", []) if isinstance(manifest, dict) else []

    sigs: list[FuncSignature] = []
    for target in targets:
        harvested = _harvest(target)
        print(f"build_funcdb: {target.get('lib')}: {len(harvested)} function(s)")
        sigs.extend(harvested)
    sigs = _dedup(sigs)

    _write_corpus(args.out, sigs)
    _write_markdown(args.markdown, sigs)
    _update_help_index(args.help_index)
    print(f"build_funcdb: wrote {len(sigs)} signature(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
