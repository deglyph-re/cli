# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Three-tier glyph fallback: every name resolves, and the tier is chosen right."""

from __future__ import annotations

from deglyph.tui import glyphs


def test_ascii_covers_every_unicode_name():
    # G[name] must never KeyError, whatever tier is active.
    assert set(glyphs._ASCII) == set(glyphs._UNICODE)


def test_nerd_is_an_overlay_subset():
    assert set(glyphs._NERD) <= set(glyphs._UNICODE)


def test_resolve_picks_the_right_tier(monkeypatch):
    monkeypatch.setattr(glyphs, "_ascii_mode", lambda: True)
    assert glyphs._resolve() is glyphs._ASCII

    monkeypatch.setattr(glyphs, "_ascii_mode", lambda: False)
    monkeypatch.setattr(glyphs, "_nerd_mode", lambda: False)
    assert glyphs._resolve() is glyphs._UNICODE

    monkeypatch.setattr(glyphs, "_nerd_mode", lambda: True)
    merged = glyphs._resolve()
    # nerd overlay wins
    assert merged["nav_back"] == glyphs._NERD["nav_back"]
    # un-overridden falls back
    assert merged["bullet"] == glyphs._UNICODE["bullet"]


def test_nerd_mode_requires_not_ascii(monkeypatch):
    monkeypatch.setenv("DEGLYPH_NERD", "1")
    monkeypatch.setattr(glyphs, "_ascii_mode", lambda: True)
    # ASCII safety wins over the Nerd opt-in
    assert glyphs._nerd_mode() is False
