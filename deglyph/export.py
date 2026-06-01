# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Stable, versioned JSON export of a binary's analysis for other tools.

`build_export(image)` returns one self-describing document covering the facts a
downstream tool needs: the recovered functions (with confidence / evidence),
cross-references, string literals, the structure-detector hits (each carrying its
`Evidence`), and the scanner findings. Per-function control-flow blocks are
included only when `include_cfg=True` (the descent is the slow step on large
binaries).

The shape is keyed by virtual address, sorted for deterministic output, and every
heuristic stays labeled as such: a detector hit is a candidate to confirm, not a
proof. `SCHEMA_VERSION` is bumped on any breaking change to the document shape;
tests pin it so a change is deliberate.

Public: SCHEMA_VERSION, build_export.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

from . import __version__
from .core.image import Image, load_image
from .re import (
    call_immediate_args,
    callees_of,
    callers_of,
    detect_crc_loops,
    extract_strings,
    function_cfg,
    function_constants,
    immediate_stores,
    referenced_data,
    thunk_chain,
)

log = logging.getLogger(__name__)

# Bump on any breaking change to the document shape (a removed/renamed field or a
# changed meaning). Additive fields do not require a bump. Pinned by tests.
# v2 added the opt-in `function_identifications` section (corpus fingerprinting).
SCHEMA_VERSION = 2


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _evidence(ev) -> dict:
    """Serialize an `Evidence` record; uncertainty travels with every hit."""
    return {
        "confidence": ev.confidence,
        "reasons": list(ev.reasons),
        "caveats": list(ev.caveats),
        "support": [hex(a) for a in ev.support],
    }


def _func(f) -> dict:
    return {
        "va": hex(f.va),
        "name": f.display,
        "raw_name": f.name,
        "kind": f.kind,
        "confidence": f.confidence,
        "evidence": list(f.evidence),
    }


def _detectors(image: Image, va: int) -> dict:
    """The structure-detector hits for one function, on its resolved impl."""
    real = thunk_chain(image, va)[-1]
    stores = [
        {
            "addr": hex(s.addr),
            "base": s.base,
            "disp": s.signed_disp,
            "size": s.size,
            "value": hex(s.value),
            "absolute": s.is_absolute,
            "evidence": _evidence(s.evidence),
        }
        for s in immediate_stores(image, real)
    ]
    args = [
        {
            "call_addr": hex(a.call_addr),
            "target": hex(a.target) if a.target is not None else None,
            "reg": a.reg,
            "value": hex(a.value),
            "evidence": _evidence(a.evidence),
        }
        for a in call_immediate_args(image, real)
    ]
    crcs = [
        {
            "start": hex(c.start),
            "end": hex(c.end),
            "kind": c.kind,
            "polys": [hex(p) for p in c.polys],
            "init": hex(c.init) if c.init is not None else None,
            "evidence": _evidence(c.evidence),
        }
        for c in detect_crc_loops(image, real)
    ]
    consts = [
        {"value": hex(v), "count": n}
        for v, n in function_constants(image, real).most_common(16)
    ]
    out: dict = {"resolved_impl": hex(real)}
    if stores:
        out["immediate_stores"] = stores
    if args:
        out["call_arguments"] = args
    if crcs:
        out["crc_loops"] = crcs
    if consts:
        out["constants"] = consts
    return out


def _xrefs(image: Image, va: int) -> dict:
    callers = sorted(set(callers_of(image, va)))
    callees = sorted(set(callees_of(image, va)))
    return {"callers": [hex(c) for c in callers], "callees": [hex(c) for c in callees]}


def _cfg(image: Image, va: int) -> dict:
    cfg = function_cfg(image, va)
    return {
        "extent": hex(cfg.extent),
        "blocks": [
            {
                "start": hex(b.start),
                "end": hex(b.end),
                "kind": b.kind,
                "successors": [hex(s) for s in b.successors],
            }
            for b in sorted(cfg.blocks, key=lambda b: b.start)
        ],
        "gaps": [{"start": hex(g.start), "end": hex(g.end)} for g in cfg.gaps],
    }


def _referenced(image: Image, va: int) -> list:
    real = thunk_chain(image, va)[-1]
    return [
        {
            "addr": hex(r.addr),
            "target": hex(r.target),
            "section": r.section,
            "kind": r.kind,
            "text": r.text,
        }
        for r in referenced_data(image, real)
    ]


def _findings(image: Image) -> list:
    """Scanner findings, run without the network (no CVE), labeled by category."""
    try:
        from .scan import scan_image

        findings = scan_image(image, cve=False)
    except Exception:
        return []
    return [
        {
            "rule": f.rule,
            "level": f.level,
            "category": f.category,
            "message": f.message,
            "where": f.where,
        }
        for f in findings
    ]


def _identifications(image: Image) -> list:
    """Corpus function identifications for the image (opt-in; runs discovery)."""
    from .re.discover import discover_functions
    from .re.funcdb import identify_functions, load_func_db

    discover_functions(image)
    db = load_func_db()
    return [
        {
            "va": hex(m.va),
            "name": m.current_name,
            "lib": m.lib,
            "func": m.func,
            "version": m.version,
            "ecosystem": m.ecosystem,
            "confidence": m.confidence,
            "similarity": round(m.similarity, 4),
            "evidence": m.evidence,
        }
        for m in identify_functions(image, db)
    ]


def build_export(
    image: Image,
    *,
    include_cfg: bool = False,
    include_identify: bool = False,
    max_funcs: int | None = None,
) -> dict[str, Any]:
    """A versioned analysis document for `image`, for consumption by other tools.

    Covers functions, cross-references, referenced data, the structure detectors,
    string literals, and scanner findings; per-function CFG blocks are added when
    `include_cfg` is set. `include_identify` runs function discovery and adds a
    `function_identifications` section (corpus fingerprinting; slower). `max_funcs`
    caps the per-function sections (functions, xrefs, detectors, cfg) for a quick
    partial dump; strings and findings are whole-image regardless. Output is
    deterministic (sorted by VA).
    """
    # Recover unexported functions first so they appear in every section.
    identifications = _identifications(image) if include_identify else None

    funcs = sorted(image.funcs, key=lambda f: (f.va, f.name))
    # Guard against a negative cap: funcs[:-5] would silently keep all-but-the-
    # last-5 instead of the first 5. Clamp to 0 (an explicit empty selection).
    cap = None if max_funcs is None else max(0, max_funcs)
    capped = funcs if cap is None else funcs[:cap]

    functions = []
    xrefs = {}
    detectors = {}
    cfgs = {}
    for f in capped:
        key = hex(f.va)
        # One malformed function on a hostile binary must skip, not abort the
        # whole export.
        try:
            functions.append(_func(f))
            xrefs[key] = _xrefs(image, f.va)
            det = _detectors(image, f.va)
            refs = _referenced(image, f.va)
            if refs:
                det["referenced_data"] = refs
            if len(det) > 1:
                detectors[key] = det
            if include_cfg:
                cfgs[key] = _cfg(image, f.va)
        except Exception as e:
            log.debug("export skipped function %s: %s", key, e)
            continue

    strings = [
        {
            "va": hex(s.va),
            "section": s.section,
            "encoding": s.encoding,
            "category": s.category,
            "text": s.text,
        }
        for s in extract_strings(image)
    ]

    doc: dict[str, Any] = {
        "deglyph_export_version": SCHEMA_VERSION,
        "tool": {"name": "deglyph", "version": __version__},
        "binary": {
            "name": os.path.basename(image.path),
            "format": image.fmt,
            "arch": image.arch.value,
            "base": hex(image.base),
            "sha256": _sha256(image.path) if os.path.isfile(image.path) else None,
        },
        "functions": functions,
        "xrefs": xrefs,
        "detectors": detectors,
        "strings": strings,
        "findings": _findings(image),
    }
    if include_cfg:
        doc["cfg"] = cfgs
    if identifications is not None:
        doc["function_identifications"] = identifications
    if cap is not None and cap < len(funcs):
        doc["truncated"] = {
            "functions_shown": len(capped),
            "functions_total": len(funcs),
        }
    return doc


def export_file(
    path: str,
    *,
    fmt: str | None = None,
    arch=None,
    include_cfg: bool = False,
    include_identify: bool = False,
    max_funcs: int | None = None,
) -> dict[str, Any]:
    """Load `path` and build its analysis export document."""
    img = load_image(path, fmt=fmt, arch=arch)
    return build_export(
        img,
        include_cfg=include_cfg,
        include_identify=include_identify,
        max_funcs=max_funcs,
    )
