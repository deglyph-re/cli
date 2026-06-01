# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Persistent per-binary annotations: renames, comments, and bookmarks.

Stored as a JSON sidecar in a per-user directory keyed by the binary's absolute
path, so annotations survive across sessions and work even when the binary lives
in a read-only location (a system directory). The location is
`~/.deglyph/annotations/<sha1(abspath)>.json`, or `$DEGLYPH_STORE_DIR` if set.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# Bump on a breaking change to the portable project document shape (a removed or
# renamed field). Additive fields do not require a bump.
PROJECT_VERSION = 1


def _store_dir() -> str:
    return os.environ.get("DEGLYPH_STORE_DIR") or os.path.join(
        os.path.expanduser("~"), ".deglyph", "annotations"
    )


def sidecar_path(binary_path: str) -> str:
    key = hashlib.sha1(os.path.abspath(binary_path).encode("utf-8", "replace"))
    return os.path.join(_store_dir(), f"{key.hexdigest()}.json")


@dataclass
class Annotations:
    """User edits for one binary, keyed by virtual address."""

    path: str
    names: dict[int, str] = field(default_factory=dict)
    comments: dict[int, str] = field(default_factory=dict)
    bookmarks: set[int] = field(default_factory=set)
    # AI chats keyed by resolved-implementation VA; value is a list of plain
    # message dicts (already JSON-serializable by the time it reaches here).
    chats: dict[int, list] = field(default_factory=dict)
    # Session UI state (filter string, active tab, selected VA). A binary with
    # only a saved view and no edits is still worth reopening, so is_empty()
    # counts it. Analysis results are recomputed on demand, never persisted
    # here: caching them risks serving stale facts after a rebuild.
    view: dict = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not (
            self.names or self.comments or self.bookmarks or self.chats or self.view
        )

    def to_dict(self) -> dict:
        return {
            "binary": self.path,
            "names": {hex(k): v for k, v in sorted(self.names.items())},
            "comments": {hex(k): v for k, v in sorted(self.comments.items())},
            "bookmarks": [hex(v) for v in sorted(self.bookmarks)],
            "chats": {hex(k): v for k, v in sorted(self.chats.items())},
            "view": self.view,
        }

    def to_portable(self) -> dict:
        """A path-independent annotation document for moving work between machines.

        Unlike `to_dict`, this carries no binary path: the sidecar is keyed by the
        binary's absolute path and does not follow the file elsewhere, so the
        portable form holds only the edits (renames, notes, bookmarks, saved view)
        to reattach to whatever binary the import targets. Chats are deliberately
        omitted: they can be large and may carry private conversation.
        """
        return {
            "deglyph_project_version": PROJECT_VERSION,
            "names": {hex(k): v for k, v in sorted(self.names.items())},
            "comments": {hex(k): v for k, v in sorted(self.comments.items())},
            "bookmarks": [hex(v) for v in sorted(self.bookmarks)],
            "view": self.view,
        }

    @staticmethod
    def from_portable(binary_path: str, data: dict) -> "Annotations":
        """Build annotations for `binary_path` from a portable project document.

        Malformed entries (a non-hex key, a wrong-typed field) are dropped rather
        than raised, so a hand-edited or partial file never breaks the import.
        """
        a = Annotations(path=binary_path)
        if not isinstance(data, dict):
            return a

        def _hexmap(raw) -> dict[int, Any]:
            out: dict[int, Any] = {}
            if isinstance(raw, dict):
                for k, v in raw.items():
                    try:
                        out[int(k, 16)] = v
                    except (ValueError, TypeError):
                        continue
            return out

        a.names = _hexmap(data.get("names"))
        a.comments = _hexmap(data.get("comments"))
        marks: set[int] = set()
        for v in data.get("bookmarks") or []:
            try:
                marks.add(int(v, 16))
            except (ValueError, TypeError):
                continue
        a.bookmarks = marks
        a.view = _viewdict(data.get("view", {}))
        return a

    def save(self) -> None:
        """Write the sidecar; failures are logged, not raised (best-effort)."""
        p = sidecar_path(self.path)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh, indent=2, default=str)
        except (OSError, TypeError, ValueError) as e:
            log.warning("could not save annotations to %s: %s", p, e)


def _safe_mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def list_sessions() -> list[Annotations]:
    """Saved sessions (one per sidecar), newest first.

    Each sidecar records the binary it belongs to; entries whose binary is gone or
    whose file is unreadable are skipped, so the welcome screen only offers what it
    can actually reopen.
    """
    base = _store_dir()
    try:
        files = [
            os.path.join(base, fn) for fn in os.listdir(base) if fn.endswith(".json")
        ]
    except OSError:
        return []
    files.sort(key=_safe_mtime, reverse=True)
    out: list[Annotations] = []
    seen: set[str] = set()
    for p in files:
        try:
            with open(p, encoding="utf-8") as fh:
                binary = json.load(fh).get("binary")
        except (OSError, ValueError):
            continue
        if not binary or binary in seen or not os.path.isfile(binary):
            continue
        seen.add(binary)
        out.append(load(binary))
    return out


def load(binary_path: str) -> Annotations:
    """Load annotations for `binary_path`, or an empty set if none/unreadable.

    Any malformed sidecar -- missing file, bad JSON, or non-hex keys -- yields an
    empty set rather than raising, so a corrupt file never breaks startup.
    """
    a = Annotations(path=binary_path)
    try:
        with open(sidecar_path(binary_path), encoding="utf-8") as fh:
            d = json.load(fh)
        a.names = {int(k, 16): v for k, v in d.get("names", {}).items()}
        a.comments = {int(k, 16): v for k, v in d.get("comments", {}).items()}
        a.bookmarks = {int(v, 16) for v in d.get("bookmarks", [])}
        a.chats = {int(k, 16): v for k, v in d.get("chats", {}).items()}
        a.view = _viewdict(d.get("view", {}))
    except (FileNotFoundError, ValueError, AttributeError, TypeError, OSError):
        return Annotations(path=binary_path)
    return a


def _viewdict(raw: object) -> dict:
    """Sanitize a persisted session-view payload; never raise on bad input.

    A malformed `view` must not break startup, so each field is type-checked
    and dropped if wrong; `selected_va` accepts a plain int or a hex string.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    filt = raw.get("filter")
    if isinstance(filt, str):
        out["filter"] = filt
    tab = raw.get("tab")
    if isinstance(tab, str):
        out["tab"] = tab
    va = raw.get("selected_va")
    if isinstance(va, bool):
        pass
    elif isinstance(va, int):
        out["selected_va"] = va
    elif isinstance(va, str):
        try:
            out["selected_va"] = int(va, 16)
        except ValueError:
            pass
    return out
