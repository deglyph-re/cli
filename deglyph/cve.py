# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
CVE matcher against detected library versions, via osv.dev.

`scan_cve` takes the `LibHit` records produced by the fingerprint pass and
queries the OSV API for each `purl`, caching responses on disk so a CI run
that re-scans the same build doesn't re-hit the network. Returns `Finding`
records (one per CVE), graded `error` by default. Network failures degrade
to "no findings" so an offline runner never blocks the gate on this check.

Cache: `~/.deglyph/cve-cache/<sha1(purl)>.json` (or under `$DEGLYPH_STORE_DIR`),
keyed by purl, with a 24h TTL (override via `$DEGLYPH_CVE_TTL` in seconds).

Public: scan_cve, query_osv, cache_path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request

from .account import _base_dir

log = logging.getLogger(__name__)

OSV_URL = "https://api.osv.dev/v1/query"
DEFAULT_TTL = 24 * 60 * 60


def _ttl() -> int:
    raw = os.environ.get("DEGLYPH_CVE_TTL")
    if not raw:
        return DEFAULT_TTL
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_TTL


def _cache_dir() -> str:
    return os.path.join(_base_dir(), "cve-cache")


def cache_path(purl: str) -> str:
    digest = hashlib.sha1(purl.encode("utf-8")).hexdigest()
    return os.path.join(_cache_dir(), f"{digest}.json")


def _read_cache(purl: str) -> dict | None:
    p = cache_path(purl)
    try:
        st = os.stat(p)
    except OSError:
        return None
    if time.time() - st.st_mtime > _ttl():
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(purl: str, payload: dict) -> None:
    p = cache_path(purl)
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except OSError as e:
        log.debug("cve cache write failed for %s: %s", purl, e)


def query_osv(purl: str, *, timeout: float = 10.0) -> list[dict]:
    """POST a purl to osv.dev and return the `vulns` list (cached on disk)."""
    cached = _read_cache(purl)
    if cached is not None:
        return list(cached.get("vulns") or [])

    body = json.dumps({"package": {"purl": purl}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"content-type": "application/json", "user-agent": "deglyph-cve"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("osv.dev query failed for %s: %s", purl, e)
        return []
    try:
        payload = json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError as e:
        log.warning("osv.dev returned non-JSON for %s: %s", purl, e)
        return []
    _write_cache(purl, payload)
    return list(payload.get("vulns") or [])


def scan_cve(hits, *, timeout: float = 10.0):
    """Findings for each known CVE against a detected library version.

    `hits` is the LibHit list from `re.fingerprint.scan_fingerprint`. Hits
    without a version are skipped: an unversioned purl is not actionable.
    """
    from .scan import RULES, Finding

    rule = "cve/known"
    level, desc = RULES[rule]
    out = []
    for h in hits:
        if not h.version:
            continue
        for v in query_osv(h.purl, timeout=timeout):
            cve_id = v.get("id") or "UNKNOWN"
            summary = v.get("summary") or v.get("details", "")
            if summary and len(summary) > 80:
                summary = summary[:77] + "..."
            label = f"{h.name} {h.version}"
            msg = (
                f"{cve_id} in {label}: {summary}" if summary else f"{cve_id} in {label}"
            )
            out.append(Finding(rule, level, msg, "cve"))
    return out
