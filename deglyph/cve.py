# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
CVE matcher against detected library versions, via osv.dev.

`scan_cve` takes the `LibHit` records produced by the fingerprint pass and
queries the OSV API for each `purl`, caching responses on disk so a CI run that
re-scans the same build doesn't re-hit the network. Returns `Finding` records:
one `cve/known` per CVE (graded `error`), plus one `cve/not-checked` note per
library the database could not be consulted for. The not-checked signal is the
point: an offline or unreachable run reports "not checked" instead of silently
implying a clean result.

Each cached entry records its provenance: the source (`osv.dev`), the purl
queried, and the query timestamp, surfaced in the finding evidence so a report
shows when and against what a library was checked.

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
from datetime import datetime, timezone

from .account import _base_dir

log = logging.getLogger(__name__)

OSV_URL = "https://api.osv.dev/v1/query"
SOURCE = "osv.dev"
DEFAULT_TTL = 24 * 60 * 60
# Cap on a single OSV response body. The timeout bounds inactivity, not total
# bytes, so a compromised or misconfigured endpoint could stream gigabytes and
# exhaust memory; 16 MiB is far above any real OSV reply.
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class CveLookupError(Exception):
    """The CVE database could not be reached or returned an unusable response."""


def _read_capped(resp, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    """Read at most `limit` bytes, raising once the cap is exceeded."""
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise CveLookupError(f"response exceeded {limit} bytes")
    return data


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


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_cache(purl: str) -> dict | None:
    """The cached provenance wrapper for `purl`, or None when stale / absent.

    Back-compat: a pre-provenance cache stored the bare OSV payload; wrap it so
    callers always see the `{source, queried_at, purl, payload}` shape.
    """
    p = cache_path(purl)
    try:
        st = os.stat(p)
    except OSError:
        return None
    if time.time() - st.st_mtime > _ttl():
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(doc, dict) and "payload" in doc:
        return doc
    return {
        "source": SOURCE,
        "queried_at": st.st_mtime,
        "purl": purl,
        "payload": doc,
    }


def _write_cache(purl: str, payload: dict, queried_at: float) -> None:
    p = cache_path(purl)
    wrapper = {
        "source": SOURCE,
        "queried_at": queried_at,
        "purl": purl,
        "payload": payload,
    }
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(wrapper, fh)
    except OSError as e:
        log.debug("cve cache write failed for %s: %s", purl, e)


def _fetch_osv(purl: str, timeout: float) -> dict:
    """POST a purl to osv.dev and return the parsed payload, or raise."""
    body = json.dumps({"package": {"purl": purl}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"content-type": "application/json", "user-agent": "deglyph-cve"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = _read_capped(resp)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("osv.dev query failed for %s: %s", purl, e)
        raise CveLookupError(str(e)) from e
    try:
        doc = json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError as e:
        log.warning("osv.dev returned non-JSON for %s: %s", purl, e)
        raise CveLookupError("non-JSON response") from e
    # Validate the shape at the boundary so a hostile / malformed payload is
    # never written to cache and never crashes a later read with AttributeError.
    if not isinstance(doc, dict):
        raise CveLookupError("osv.dev returned a non-object payload")
    return doc


def _query(purl: str, *, timeout: float) -> tuple[list[dict], str]:
    """The CVEs for `purl` and a provenance label, from cache or the network.

    Raises CveLookupError when the database cannot be consulted (so the caller
    can emit a not-checked finding rather than mistake the failure for "clean").
    """
    cached = _read_cache(purl)
    if cached is not None:
        # queried_at may be absent or non-numeric in a hand-edited cache; fall
        # back rather than KeyError/TypeError out of the (caught) lookup path.
        qa = cached.get("queried_at")
        when = _iso(qa) if isinstance(qa, (int, float)) else "unknown time"
        return (
            _vulns_of(cached.get("payload")),
            f"{cached.get('source', SOURCE)}, cached {when}",
        )
    now = time.time()
    payload = _fetch_osv(purl, timeout)
    _write_cache(purl, payload, now)
    return _vulns_of(payload), f"{SOURCE}, queried {_iso(now)}"


def _vulns_of(payload: object) -> list[dict]:
    """The `vulns` list from an OSV payload, coercing any odd shape to [].

    A cache predating boundary validation, or a hand-corrupted file, can hold a
    non-dict payload or a non-list `vulns`; both degrade to an empty list rather
    than raising through the whole CVE pass.
    """
    if not isinstance(payload, dict):
        return []
    vulns = payload.get("vulns")
    if not isinstance(vulns, list):
        return []
    return [v for v in vulns if isinstance(v, dict)]


def query_osv(purl: str, *, timeout: float = 10.0) -> list[dict]:
    """POST a purl to osv.dev and return the `vulns` list (cached on disk).

    Network or parse failures degrade to an empty list; use `scan_cve` when you
    need the failure surfaced as a not-checked finding.
    """
    try:
        vulns, _ = _query(purl, timeout=timeout)
    except CveLookupError:
        return []
    return vulns


def scan_cve(hits, *, timeout: float = 10.0, offline: bool = False):
    """Findings for known CVEs against detected library versions.

    `hits` is the LibHit list from `re.fingerprint.scan_fingerprint`. Hits
    without a version are skipped: an unversioned purl is not actionable. For
    each versioned hit the database is consulted; when `offline` is set, or a
    lookup fails, a `cve/not-checked` note is emitted instead of silently
    omitting the library, so the report never implies an unchecked lib is clean.
    """
    from .scan import RULES, Finding

    known_level, _ = RULES["cve/known"]
    nc_level, _ = RULES["cve/not-checked"]
    out = []
    for h in hits:
        if not h.version:
            continue
        label = f"{h.name} {h.version}"
        if offline:
            out.append(
                Finding(
                    "cve/not-checked",
                    nc_level,
                    f"{label}: CVE lookup skipped (offline)",
                    "cve",
                )
            )
            continue
        try:
            vulns, provenance = _query(h.purl, timeout=timeout)
        except CveLookupError as e:
            out.append(
                Finding(
                    "cve/not-checked",
                    nc_level,
                    f"{label}: CVE lookup failed ({e})",
                    "cve",
                )
            )
            continue
        for v in vulns:
            cve_id = v.get("id") or "UNKNOWN"
            summary = v.get("summary") or v.get("details", "")
            if summary and len(summary) > 80:
                summary = summary[:77] + "..."
            head = f"{cve_id} in {label}"
            body = f": {summary}" if summary else ""
            out.append(
                Finding("cve/known", known_level, f"{head}{body} ({provenance})", "cve")
            )
    return out
