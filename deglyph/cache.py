# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
On-disk analysis cache keyed by a binary's content hash.

Recomputing the slow whole-image passes (string extraction, the cross-reference
index, discovery, detector sweeps) on every run wastes time when the binary has
not changed. `cache_get` / `cache_put` store a JSON payload under
`~/.deglyph/analysis-cache/<sha256[:2]>/<sha256>.<kind>.json` (or under
`$DEGLYPH_STORE_DIR`), so re-opening the same build is instant and a changed
build misses cleanly: the key is the file's SHA-256, so any edit invalidates it.

`CACHE_VERSION` is bumped when a cached payload's shape changes, so a stale entry
from an older deglyph is ignored rather than mis-read. Caching is opt-out via
`$DEGLYPH_NO_CACHE`, and every read/write degrades to a miss on any error so the
cache can never break analysis.

Public: CACHE_VERSION, file_sha256, cache_get, cache_put, clear_cache.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

from .account import _base_dir

log = logging.getLogger(__name__)

# Bump when a cached payload's shape changes; a mismatch is treated as a miss.
CACHE_VERSION = 1


def _enabled() -> bool:
    return not os.environ.get("DEGLYPH_NO_CACHE")


def _cache_dir() -> str:
    return os.path.join(_base_dir(), "analysis-cache")


def file_sha256(path: str) -> str | None:
    """The SHA-256 of `path`, or None if it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _entry_path(digest: str, kind: str) -> str:
    # Shard by the first two hex chars so one directory never holds every file.
    return os.path.join(_cache_dir(), digest[:2], f"{digest}.{kind}.json")


def cache_get(digest: str | None, kind: str) -> Any | None:
    """The cached payload for `(digest, kind)`, or None on a miss / disabled.

    A `None` digest (an unreadable binary) is always a miss. A version mismatch
    or any read error is a miss, never an exception.
    """
    if not digest or not _enabled():
        return None
    p = _entry_path(digest, kind)
    try:
        with open(p, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict) or doc.get("cache_version") != CACHE_VERSION:
        return None
    return doc.get("payload")


def cache_put(digest: str | None, kind: str, payload: Any) -> None:
    """Store `payload` for `(digest, kind)`; best-effort, never raises."""
    if not digest or not _enabled():
        return
    p = _entry_path(digest, kind)
    doc = {"cache_version": CACHE_VERSION, "kind": kind, "payload": payload}
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = f"{p}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.replace(tmp, p)
    except (OSError, TypeError, ValueError) as e:
        log.debug("analysis cache write failed for %s/%s: %s", digest, kind, e)


def clear_cache() -> int:
    """Remove every cached entry; return the number of files deleted."""
    base = _cache_dir()
    removed = 0
    for root, _dirs, files in os.walk(base):
        for name in files:
            try:
                os.remove(os.path.join(root, name))
                removed += 1
            except OSError:
                continue
    return removed
