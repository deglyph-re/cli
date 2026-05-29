# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Token store and endpoint resolution for the optional hosted (Pro) tier."""

from __future__ import annotations

from deglyph import account


def test_token_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    assert not account.is_logged_in()
    assert account.load_token() is None

    # surrounding whitespace is trimmed
    account.save_token("  tok-123  ")
    assert account.is_logged_in()
    assert account.load_token() == "tok-123"

    assert account.clear_token() is True
    assert not account.is_logged_in()
    # second clear: nothing to remove
    assert account.clear_token() is False


def test_api_url_default_and_override(monkeypatch):
    monkeypatch.delenv("DEGLYPH_API_URL", raising=False)
    assert account.api_url() == account.DEFAULT_API_URL

    monkeypatch.setenv("DEGLYPH_API_URL", "https://api.example.test")
    assert account.api_url() == "https://api.example.test"


def test_cli_login_logout_are_subcommands(tmp_path, monkeypatch, capsys):
    from deglyph.cli import main

    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    assert main(["login", "tok-cli"]) == 0
    assert account.load_token() == "tok-cli"
    # must not fall through to the TUI launcher
    assert main(["logout"]) == 0
    assert account.load_token() is None
    # idempotent when no token is present
    assert main(["logout"]) == 0
    out = capsys.readouterr().out
    assert "stored" in out and "not logged in" in out
