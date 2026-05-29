# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Account state for the optional hosted (Pro) tier.

`deglyph login` stores a token here; the hosted AI backend (see `ai.py`) sends it
to the server, which runs the model with its own key and enforces entitlements.
With no token the tool is fully local and this module is dormant -- nothing here
contacts the network. The server (`api.deglyph.dev`) is a separate, private repo;
this side is just a token file plus the endpoint URL.
"""

from __future__ import annotations

import os

DEFAULT_API_URL = "https://api.deglyph.dev"


def api_url() -> str:
    return os.environ.get("DEGLYPH_API_URL", DEFAULT_API_URL)


def _base_dir() -> str:
    return os.environ.get("DEGLYPH_STORE_DIR") or os.path.join(
        os.path.expanduser("~"), ".deglyph"
    )


def token_path() -> str:
    return os.path.join(_base_dir(), "token")


def load_token() -> str | None:
    try:
        with open(token_path(), encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def save_token(token: str) -> None:
    p = token_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(token.strip())


def clear_token() -> bool:
    """Remove the stored token; return True if one was present."""
    try:
        os.remove(token_path())
        return True
    except OSError:
        return False


def is_logged_in() -> bool:
    return load_token() is not None
