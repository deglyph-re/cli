# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Tiny persistent app config (e.g. the chosen theme), separate from per-binary
annotations and the auth token. Stored as JSON at `~/.deglyph/config.json`, or
under `$DEGLYPH_STORE_DIR` when set. All reads/writes are best-effort.

Public: get, put.
"""

from __future__ import annotations

import json
import os
from typing import Any


def _path() -> str:
    base = os.environ.get("DEGLYPH_STORE_DIR") or os.path.join(
        os.path.expanduser("~"), ".deglyph"
    )
    return os.path.join(base, "config.json")


def _load() -> dict:
    try:
        with open(_path(), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def get(key: str, default: Any = None) -> Any:
    return _load().get(key, default)


def put(key: str, value: Any) -> None:
    d = _load()
    d[key] = value
    p = _path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)
    except OSError:
        pass
