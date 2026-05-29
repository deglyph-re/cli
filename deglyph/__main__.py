# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Enables `python -m deglyph`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
