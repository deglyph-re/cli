# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Persistent app config (theme, etc.)."""

from __future__ import annotations

from deglyph import config


def test_get_default_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    assert config.get("theme", "deglyph") == "deglyph"
    assert config.get("nope") is None


def test_put_then_get_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    config.put("theme", "textual-dark")
    assert config.get("theme") == "textual-dark"
    # a second key does not clobber the first
    config.put("other", 7)
    assert config.get("theme") == "textual-dark"
    assert config.get("other") == 7


def test_corrupt_config_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    (tmp_path / "config.json").write_text("{ not json", encoding="utf-8")
    assert config.get("theme", "deglyph") == "deglyph"
