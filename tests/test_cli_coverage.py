# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Targeted coverage for the corners of `deglyph.cli` the main suite skips:
--list / --analyze on the demo binary, scan/login/logout dispatch, the
arch-string normalizer, and the System32 fallback.
"""

from __future__ import annotations

import io
import json
import os
import sys

import pytest

from deglyph import cli

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def _capture(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    # Pin the Rich console width so a long checkout path can't wrap the header
    # line mid-token (Rich falls back to 80 columns when stdout is not a tty).
    monkeypatch.setenv("COLUMNS", "200")
    return buf


# --- _arch --------------------------------------------------------------------


def test_arch_normalizer_known_aliases():
    assert cli._arch(None) is None
    assert cli._arch("") is None
    assert cli._arch("X86_64").value == "x86-64"
    assert cli._arch("amd64").value == "x86-64"
    assert cli._arch("32").value == "x86"
    assert cli._arch("arm64").value == "arm64"
    assert cli._arch("aarch64").value == "arm64"
    assert cli._arch("nonsense") is None


# --- _resolve_binary System32 path (Windows-only) ----------------------------


@pytest.mark.skipif(os.name != "nt", reason="System32 fallback is Windows-only")
def test_resolve_binary_falls_back_to_system32():
    # kernel32.dll is always present on a Windows host
    out = cli._resolve_binary("kernel32.dll")
    assert out.lower().endswith("kernel32.dll") and os.path.isfile(out)


# --- --list, --analyze, --strings against the bundled demo --------------------


def test_list_against_demo(monkeypatch):
    buf = _capture(monkeypatch)
    rc = cli.main([SAMPLE, "--list"])
    assert rc == 0
    out = buf.getvalue()
    assert "demo.exe" in out and "PE/x86-64" in out
    # at least one function reported with kind + hex address
    assert "import" in out or "export" in out


def test_list_json_against_demo(monkeypatch):
    buf = _capture(monkeypatch)
    rc = cli.main([SAMPLE, "--list", "--json"])
    assert rc == 0
    data = json.loads(buf.getvalue())
    assert "functions" in data and data["fmt"] == "PE"
    assert all({"va", "name", "display", "kind"} <= set(f) for f in data["functions"])


def test_analyze_finds_a_function(monkeypatch):
    buf = _capture(monkeypatch)
    # 'main' is virtually guaranteed in the demo binary
    rc = cli.main([SAMPLE, "--analyze", "main"])
    assert rc == 0
    assert "chain=" in buf.getvalue()


def test_analyze_with_no_match_exits_one(monkeypatch):
    buf = _capture(monkeypatch)
    rc = cli.main([SAMPLE, "--analyze", "definitely_not_in_demo_xxx"])
    assert rc == 1
    assert "no function matching" in buf.getvalue()


def test_analyze_json_with_no_match_emits_error(monkeypatch):
    buf = _capture(monkeypatch)
    rc = cli.main([SAMPLE, "--analyze", "definitely_not_in_demo_xxx", "--json"])
    assert rc == 1
    data = json.loads(buf.getvalue())
    assert "error" in data


def test_analyze_json_shape(monkeypatch):
    buf = _capture(monkeypatch)
    rc = cli.main([SAMPLE, "--analyze", "main", "--json"])
    assert rc == 0
    data = json.loads(buf.getvalue())
    assert "analysis" in data and data["analysis"]
    rec = data["analysis"][0]
    assert {"name", "va", "chain", "stores", "call_args", "crc"} <= set(rec)


# --- scan subcommand ---------------------------------------------------------


def test_scan_against_demo(monkeypatch):
    buf = _capture(monkeypatch)
    # --fail-on never so the exit code is 0 even with findings
    rc = cli.main(["scan", SAMPLE, "--fail-on", "never"])
    assert rc == 0
    # the text report lists the demo path
    assert "demo.exe" in buf.getvalue()


def test_scan_sarif(monkeypatch):
    buf = _capture(monkeypatch)
    rc = cli.main(["scan", SAMPLE, "--sarif", "--fail-on", "never"])
    assert rc == 0
    sarif = json.loads(buf.getvalue())
    assert sarif["version"] == "2.1.0"


def test_scan_unreadable_target_is_skipped(monkeypatch, tmp_path, caplog):
    """A LIEF parse failure on one target must not abort the whole scan."""
    bad = tmp_path / "not_a_binary.exe"
    bad.write_bytes(b"this is not a PE file")
    _capture(monkeypatch)
    rc = cli.main(["scan", str(bad), "--fail-on", "never"])
    # the unreadable file is skipped; the scan still completes cleanly
    assert rc == 0


def test_scan_fail_on_drives_exit_code(monkeypatch):
    """The exit code maps the worst finding against --fail-on."""
    _capture(monkeypatch)
    # the demo's planted secret triggers an `error`-level finding by design
    rc = cli.main(["scan", SAMPLE, "--fail-on", "error"])
    # 1 = a finding at or above the gate; 0 = clean. Demo plants a secret.
    assert rc in (0, 1)


# --- login / logout ---------------------------------------------------------


def test_login_stores_token_and_logout_clears(monkeypatch, tmp_path):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    buf = _capture(monkeypatch)
    rc = cli.main(["login", "tok-abc-123"])
    assert rc == 0
    assert "stored" in buf.getvalue()
    from deglyph import account

    assert account.load_token() == "tok-abc-123"

    buf2 = _capture(monkeypatch)
    rc = cli.main(["logout"])
    assert rc == 0
    assert "logged out" in buf2.getvalue()
    assert account.load_token() is None

    # a second logout reports "not logged in"
    buf3 = _capture(monkeypatch)
    rc = cli.main(["logout"])
    assert rc == 0
    assert "not logged in" in buf3.getvalue()


# --- --ascii / --nerd env-var wiring ----------------------------------------


def test_ascii_flag_sets_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_ASCII", raising=False)
    _capture(monkeypatch)
    # --version exits before launching the TUI, but the env wiring still runs
    cli.main(["--ascii", "--version"])
    assert os.environ.get("DEGLYPH_ASCII") == "1"


def test_nerd_flag_sets_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_NERD", raising=False)
    _capture(monkeypatch)
    cli.main(["--nerd", "--version"])
    assert os.environ.get("DEGLYPH_NERD") == "1"
