# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Semantic glyphs with a three-tier fallback: Nerd Font -> Unicode -> ASCII.

`G` maps a semantic name to a character. The tier is chosen once at import:

  - ASCII   when `$DEGLYPH_ASCII` is set or stdout is not UTF-8 (limited terminals).
  - Nerd    when `$DEGLYPH_NERD` is set (the terminal uses a Nerd Font, which
            carries Font Awesome / Material icons in the private-use area); the
            Nerd tier overlays the Unicode tier, so any name it omits falls back.
  - Unicode otherwise (the safe default: plain symbols, no emoji, no font needed).

The CLI's `--ascii` / `--nerd` flags set the matching env var before this module
is imported. Reference `G[name]`, never a bare Unicode literal in a rendered
string, so `--ascii` terminals stay readable.
"""

from __future__ import annotations

import os
import sys

_UNICODE = {
    "mark": "▸ ",
    "arrow": "→",
    "t_mid": "├─ ",
    "t_end": "└─ ",
    "t_bar": "│  ",
    "t_gap": "   ",
    "up": "↑",
    "down": "↓",
    "node": "▶",
    "bullet": "•",
    "recycle": "↻",
    "hint": "↳",
    "times": "×",
    "ndash": "–",
    "mdash": "—",
    "ellipsis": "…",
    # toolbar / navigation
    "nav_back": "◀",
    "nav_fwd": "▶",
    "caret": "▾",
    "recent": "☰",
    # no clean non-emoji glyph; the label text carries the meaning
    "chat": "",
    "search": "⌕",
    "menu": "≡",
    # binary map: a filled block for the content strip, plus density shades
    "block": "█",
    "shade_full": "█",
    "shade_mid": "▓",
    "shade_low": "▒",
    "shade_min": "░",
}

_ASCII = {
    "mark": "> ",
    "arrow": "->",
    "t_mid": "+- ",
    "t_end": "`- ",
    "t_bar": "|  ",
    "t_gap": "   ",
    "up": "^",
    "down": "v",
    "node": ">",
    "bullet": "*",
    "recycle": "(more)",
    "hint": "->",
    "times": "x",
    "ndash": "-",
    "mdash": "--",
    "ellipsis": "...",
    "nav_back": "<",
    "nav_fwd": ">",
    "caret": "v",
    "recent": "=",
    "chat": "",
    "search": "/",
    "menu": "=",
    "block": "#",
    "shade_full": "#",
    "shade_mid": "+",
    "shade_low": ":",
    "shade_min": ".",
}

# Font Awesome codepoints in the Nerd Font private-use area (written as escapes
# since they are invisible without a Nerd Font). Only names that gain from a real
# icon are overridden; the rest fall back to the Unicode tier.
_NERD = {
    # chevron-left
    "nav_back": "",
    # chevron-right
    "nav_fwd": "",
    # caret-down
    "caret": "",
    # history (clock-rotate)
    "recent": "",
    # comment
    "chat": "",
    # caret-right
    "hint": "",
    # play (filled triangle)
    "node": "",
    # magnifying glass
    "search": "",
    # bars
    "menu": "",
}


def _ascii_mode() -> bool:
    if os.environ.get("DEGLYPH_ASCII"):
        return True
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" not in enc


def _nerd_mode() -> bool:
    return not _ascii_mode() and bool(os.environ.get("DEGLYPH_NERD"))


def _resolve() -> dict[str, str]:
    if _ascii_mode():
        return _ASCII
    if _nerd_mode():
        return {**_UNICODE, **_NERD}
    return _UNICODE


G: dict[str, str] = _resolve()

# Spinner frames for in-progress indicators (braille on UTF-8, ASCII otherwise).
SPINNER: str = "|/-\\" if _ascii_mode() else "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
