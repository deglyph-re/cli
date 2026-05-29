# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""The deglyph wordmark and tagline, shown on the welcome screen and About dialog.

The wordmark is a bold Unicode (figlet ansi_shadow) block; regenerated, not
edited by hand. `wordmark_text` paints it two-tone to match the brand logo:
"de" in amber, "glyph" in cream.
"""

from __future__ import annotations

from rich.text import Text

LOGO = """   ▄▄             ▄▄             ▄▄
   ██             ██             ██
▄████ ▄█▀█▄ ▄████ ██ ██ ██ ████▄ ████▄
██ ██ ██▄█▀ ██ ██ ██ ██▄██ ██ ██ ██ ██
▀████ ▀█▄▄▄ ▀████ ██  ▀██▀ ████▀ ██ ██
               ██      ██  ██
             ▀▀▀     ▀▀▀   ▀▀
"""

# Column where "de" ends and "glyph" begins ("de" is fully terminated at 12).
_SPLIT = 12
# amber gold for "de", cream for "glyph" (matches the brand logo).
_DE = "#e3b04b"
_GLYPH = "#ece0c4"

TAGLINE = "Decode what the compiler left behind."


def wordmark() -> str:
    """The deglyph wordmark as a plain block string."""
    return LOGO


def wordmark_text() -> Text:
    """The wordmark as Rich Text, two-tone: "de" amber, "glyph" cream."""
    out = Text()
    for line in LOGO.splitlines():
        out.append(line[:_SPLIT], style=_DE)
        out.append(line[_SPLIT:] + "\n", style=_GLYPH)
    return out
