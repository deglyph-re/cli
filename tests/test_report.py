# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Markdown + HTML report renderers."""

from __future__ import annotations

from deglyph import report
from deglyph.scan import Finding


def _results():
    return [
        (
            "build/app.exe",
            [
                Finding("cve/known", "error", "CVE-2022-37434 in zlib 1.2.11", "cve"),
                Finding("harden/no-aslr", "warning", "ASLR is disabled", "hardening"),
                Finding(
                    "lib/detected", "note", "zlib 1.2.11", "fingerprint", 0x100, 24
                ),
            ],
        )
    ]


def test_markdown_contains_summary_and_grouping():
    md = report.to_markdown(_results())
    assert md.startswith("## deglyph scan:")
    assert "1 error(s)" in md
    assert "1 warning(s)" in md
    assert "1 note(s)" in md
    # grouped by severity
    assert "**Errors**" in md
    assert "**Warnings**" in md
    assert "**Notes**" in md
    # the path is rendered as inline code
    assert "`build/app.exe`" in md
    # findings include rule and message
    assert "cve/known" in md
    assert "ASLR is disabled" in md
    # footer + link to deglyph.dev
    assert "deglyph.dev" in md


def test_markdown_clean_run():
    md = report.to_markdown([("a.bin", [])])
    assert "Clean across all scanned files" in md
    assert "deglyph.dev" in md


def test_markdown_empty_results():
    md = report.to_markdown([])
    assert "_No files scanned._" in md


def test_html_self_contained_document():
    html = report.to_html(_results())
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    # no external script / stylesheet refs
    assert "<script" not in html
    assert "src=" not in html
    assert 'href="https://deglyph.dev"' in html
    assert "ASLR is disabled" in html


def test_html_escapes_payload():
    findings = [
        Finding("secret/private-key", "error", "<script>alert(1)</script>", "0x1000")
    ]
    out = report.to_html([("a.bin", findings)])
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


def test_html_clean_run_shows_clean_pill():
    out = report.to_html([("a.bin", [])])
    assert 'class="pill clean"' in out
