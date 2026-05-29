# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""CLI entry-point smoke tests: argument routing and clean exit codes."""

from __future__ import annotations

import json
import os

import pytest

from deglyph import __version__
from deglyph.cli import _resolve_binary, main

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def test_resolve_binary_existing_path_unchanged(tmp_path):
    p = tmp_path / "thing.bin"
    p.write_bytes(b"x")
    assert _resolve_binary(str(p)) == str(p)


def test_resolve_binary_falls_back_to_path(tmp_path, monkeypatch):
    p = tmp_path / "tool.exe"
    p.write_bytes(b"x")
    monkeypatch.setattr("shutil.which", lambda n: str(p) if n == "tool.exe" else None)
    assert _resolve_binary("tool.exe") == str(p)


def test_resolve_binary_unresolved_returned_as_given(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda n: None)
    # An unknown bare name is returned unchanged, so the loader reports it.
    assert _resolve_binary("nope-not-real.xyz") == "nope-not-real.xyz"


def test_version(capsys):
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_no_args_opens_welcome(monkeypatch):
    # No binary given: launch the interface on the welcome screen (path=None),
    # rather than erroring. Stub the TUI so no terminal app actually starts.
    import deglyph.tui as tui

    seen = {}
    monkeypatch.setattr(
        tui,
        "run",
        lambda path=None, **kw: seen.update(path=path, welcome=kw.get("welcome")),
    )
    assert main([]) == 0
    assert seen["path"] is None
    # No binary -> show the welcome screen
    assert seen["welcome"] is True


def test_binary_arg_skips_welcome(monkeypatch):
    """With a binary on the command line, open it directly (no welcome screen)."""
    import os

    import deglyph.tui as tui

    seen = {}
    monkeypatch.setattr(
        tui,
        "run",
        lambda path=None, **kw: seen.update(path=path, welcome=kw.get("welcome")),
    )
    sample = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")
    assert main([sample]) == 0
    assert seen["path"] and seen["path"].endswith("demo.exe")
    assert seen["welcome"] is False


def test_list_without_binary_is_usage_error(capsys):
    # Headless modes still need a target.
    assert main(["--list"]) == 2
    assert "require a binary" in capsys.readouterr().err.lower()


def test_help_lists_subcommands(capsys):
    # --help exits 0 via argparse; the subcommands must be discoverable there.
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "scan" in out and "login" in out


def test_strings_without_binary_is_usage_error(capsys):
    assert main(["--strings"]) == 2
    assert "require a binary" in capsys.readouterr().err.lower()


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_strings_flag_dumps_strings(capsys):
    assert main(["--strings", SAMPLE]) == 0
    assert "S3cr3t-demo-API-key-do-not-ship" in capsys.readouterr().out


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_strings_json_shape(capsys):
    assert main(["--strings", "--json", SAMPLE]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert any("S3cr3t" in s["text"] for s in doc["strings"])


def test_headless_load_error_exits_one(tmp_path, capsys):
    p = tmp_path / "not-a-binary.bin"
    p.write_bytes(b"definitely not an object file")
    # --list on an unparseable file: clean exit 1, error surfaced (no traceback).
    assert main(["--list", str(p)]) == 1
    assert "load error" in capsys.readouterr().out.lower()


def test_json_load_error_is_json(tmp_path, capsys):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"not an object file")
    assert main(["--list", "--json", str(p)]) == 1
    assert "error" in json.loads(capsys.readouterr().out)


def test_json_list_shape(host_binary, capsys):
    assert main(["--list", "--json", "--no-discover", host_binary]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["fmt"] in ("PE", "ELF", "MachO", "MACHO")
    assert data["functions"]
    assert {"va", "name", "display", "kind"} <= set(data["functions"][0])
