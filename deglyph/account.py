# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Account state for the optional hosted (Pro) tier.

`deglyph login` stores a token here; the hosted AI backend (see `ai.py`) sends it
to the server, which runs the model with its own key and enforces entitlements.
With no token the tool is fully local and this module is dormant: nothing here
contacts the network. The server (`api.deglyph.dev`) is a separate, private repo;
this side is just a token file plus the endpoint URL.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

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


def save_token(token: str) -> bool:
    """Persist the token; best-effort, returns False on failure rather than raise.

    Written atomically (temp file + replace) so a crash mid-write can't truncate
    an existing token, and with 0o600 perms so it is not world-readable on a
    shared machine.
    """
    p = token_path()
    tmp = f"{p}.tmp"
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        # Create the temp file private from the start, not after a window at 0o644.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token.strip())
        os.replace(tmp, p)
        return True
    except OSError as e:
        log.warning("could not save token to %s: %s", p, e)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def clear_token() -> bool:
    """Remove the stored token; return True if one was present."""
    try:
        os.remove(token_path())
        return True
    except OSError:
        return False


def is_logged_in() -> bool:
    return load_token() is not None
