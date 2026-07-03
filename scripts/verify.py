#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
# verify: off
# This file defines the tone rules, so it necessarily quotes the phrases it
# forbids. Its docstring and rule tables are exempted; re-enabled below for the
# logic and its own comments.
"""
Tone and style verifier for deglyph.

Two linters in one tool, matching the project's documentation contract
(see CLAUDE.md):

  * Markdown  - README.md, CLAUDE.md, AGENTS.md, CONTRIBUTING.md, SECURITY.md,
                CHANGELOG.md, and everything under doc/. Flags marketing copy,
                AI-narration phrasing, first-person prose, `--` used as a
                sentence dash, non-ASCII in user-facing docs, and `---` rules
                used as section dividers.
  * Python    - deglyph/, tests/, and scripts/. Flags narration in comments and
                docstrings, bare `except:`, `# type: ignore` without a reason,
                and (advisory) functions over the length cap.

Findings are advisory: the script reports them and exits non-zero so a commit
hook or CI step can choose whether to gate. Code blocks, inline code, and link
URLs are masked before prose rules run, so a flagged word inside `code` or a URL
does not false-positive.

Usage:
    python3 scripts/verify.py                 # scan the default set
    python3 scripts/verify.py path ...        # scan specific files/dirs
    python3 scripts/verify.py --report        # also write .verify-report
    python3 scripts/verify.py --quiet         # only the summary line

Exit codes:
    0 - clean
    1 - findings present
    2 - argument or I/O error

Suppression:
    Markdown   <!-- verify off -->  ...  <!-- verify on -->
    Python     # verify: off        ...  # verify: on
A suppressed region is a review trigger; prefer fixing the root cause.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path

# Same-line comments that are allowed (tool directives must stay on their line).
_COMMENT_DIRECTIVES = ("noqa", "type:", "pragma", "fmt:", "verify:")


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Finding:
    path: Path
    line: int
    col: int
    kind: str
    message: str
    text: str


def _ci(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# A suppression marker toggles only when it is the operative directive: the line,
# stripped, ends with exactly the marker. This way a line that *quotes* the marker
# in prose (such as this file's own usage docs) does not flip the state.
def _is_marker(line: str, marker: str) -> bool:
    return line.rstrip().endswith(marker) and line.strip().startswith(("#", marker[0]))


# ---------------------------------------------------------------------------
# Shared phrase rules (apply to both Markdown prose and Python comments)
# ---------------------------------------------------------------------------
# Marketing copy and blog cliches.
_MARKETING: list[tuple[re.Pattern, str]] = [
    (_ci(r"\bseamless(?:ly)?\b"), "marketing adjective; remove or restate"),
    (_ci(r"\beffortless(?:ly)?\b"), "marketing adjective; remove or restate"),
    (_ci(r"\bworld[-\s]class\b"), "marketing superlative; remove"),
    (_ci(r"\bbest[-\s]in[-\s]class\b"), "marketing superlative; remove"),
    (_ci(r"\bcutting[-\s]edge\b"), "marketing adjective; remove or restate"),
    (_ci(r"\bstate[-\s]of[-\s]the[-\s]art\b"), "marketing adjective; remove"),
    (_ci(r"\bindustry[-\s]leading\b"), "marketing adjective; remove"),
    (_ci(r"\bgame[-\s]chang(?:er|ing)\b"), "marketing cliche; remove or restate"),
    (_ci(r"\bfuture[-\s]proof(?:ed)?\b"), "marketing adjective; remove"),
    (_ci(r"\bturnkey\b"), "marketing adjective; remove"),
    (_ci(r"\bplug[-\s]and[-\s]play\b"), "marketing cliche; restate"),
    (_ci(r"\bbattle[-\s]tested\b"), "marketing cliche; restate"),
    (_ci(r"\bproduction[-\s]ready\b"), "marketing adjective; restate"),
    (_ci(r"\bblazing[-\s]?fast\b"), "marketing adjective; restate or measure"),
    (_ci(r"\blightning[-\s]fast\b"), "marketing adjective; restate or measure"),
    (_ci(r"\bbuttery[-\s]smooth\b"), "marketing adjective; remove"),
    (
        _ci(
            r"\b(?:fast|friendly|powerful|elegant|simple|intuitive)\b"
            r"(?=[^.\n]*\b(?:tool|tui|interface|framework|library|app)\b)"
        ),
        "subjective adjective describing the tool; state the mechanism",
    ),
    (
        _ci(r"\b(?:beautifully|elegantly|cleanly)\s+(?:designed|crafted|built)\b"),
        "marketing phrasing; remove",
    ),
    (_ci(r"\bunder the hood\b"), "blog metaphor; describe the actual path"),
    (_ci(r"\bbehind the scenes\b"), "blog metaphor; describe the actual path"),
    (_ci(r"\bout of the box\b"), "blog phrasing; state the default behavior"),
    (_ci(r"\bgives you\b"), "blog phrasing; use 'provides' or restate"),
    (
        _ci(r"\bthe (?:secret|trick) (?:is|sauce)\b"),
        "blog phrasing; state the mechanism",
    ),
    (_ci(r"\bjust works\b"), "marketing phrasing; state the behavior"),
]

# AI-narration / tutorial voice. The first-person and meta-narration patterns
# are the ones an LLM most often introduces.
_NARRATION: list[tuple[re.Pattern, str]] = [
    (_ci(r"\bnote that\b"), "narration filler; state the fact directly"),
    (
        _ci(r"\bit(?:'s| is) (?:worth|important) (?:noting|to note)\b"),
        "narration filler; state the fact directly",
    ),
    (_ci(r"\bas (?:you can|we can) see\b"), "tutorial voice; remove"),
    # History narration only: the verb sense ("used to map") is fine; the
    # narrative sense ("this used to be", "X used to do") is not.
    (
        _ci(r"\b(?:this|it|that|which|originally)\s+used to\b"),
        "history narration; describe current behavior",
    ),
    (_ci(r"\bpreviously\b"), "history narration; describe current behavior"),
    (_ci(r"\bof course\b"), "filler; remove"),
    (_ci(r"\bobviously\b"), "filler; remove"),
    (_ci(r"\bsimply\b"), "filler; usually removable"),
    (_ci(r"\bbasically\b"), "filler; remove"),
]

# First-person voice. Allowed nowhere in docs or comments. "I" must not be part
# of "I/O", and the pronouns are lower-cased only where unambiguous.
_FIRST_PERSON = re.compile(
    r"(?<![A-Za-z])(?:[Ww]e|I(?![/A-Za-z])|[Oo]ur|let's|lets)(?![A-Za-z])"
)
# verify: on


# ---------------------------------------------------------------------------
# Markdown masking + scanning
# ---------------------------------------------------------------------------
_INLINE_CODE = re.compile(r"`+[^`\n]*?`+")
_LINK_URL = re.compile(r"\]\([^)\n]*\)")
_AUTOLINK = re.compile(r"<[a-zA-Z][^>\s]*://[^>\s]*>")
_HR_RULE = re.compile(r"^\s{0,3}(?:-{3,}|\*{3,}|_{3,})\s*$")
_NON_ASCII = re.compile(r"[^\x00-\x7f]")
# `--` used as a sentence dash: an em-dash substitute that reads like a robot.
# Rewrite the sentence instead (comma / colon / period / parentheses).
_DASH_SUB = re.compile(r"\S -- \S")


def _mask(line: str) -> str:
    """Blank out inline code and link URLs, preserving column positions, so a
    flagged word inside `code` or a (url) is not reported as prose."""

    def blank(m: re.Match) -> str:
        return " " * (m.end() - m.start())

    line = _INLINE_CODE.sub(blank, line)
    line = _LINK_URL.sub(blank, line)
    line = _AUTOLINK.sub(blank, line)
    return line


def _is_developer_doc(path: Path) -> bool:
    """Developer files exempt from the ASCII-only rule: CLAUDE.md and its
    extracted reference under doc/claude/ (Sub-Documentation in CLAUDE.md)."""
    return path.name == "CLAUDE.md" or path.parent.name == "claude"


def scan_markdown(path: Path, *, user_facing: bool) -> list[Finding]:
    """Scan one Markdown file. `user_facing` enables the ASCII rule (CLAUDE.md
    and doc/claude/ are developer files, exempt from ASCII-only)."""
    out: list[Finding] = []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [Finding(path, 0, 0, "io-error", f"could not read: {exc}", "")]

    in_fence = False
    suppressed = False
    for n, line in enumerate(raw.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if _is_marker(line, "<!-- verify off -->"):
            suppressed = True
            continue
        if _is_marker(line, "<!-- verify on -->"):
            suppressed = False
            continue
        if in_fence or suppressed:
            continue

        masked = _mask(line)

        for rx, msg in _MARKETING + _NARRATION:
            for m in rx.finditer(masked):
                out.append(Finding(path, n, m.start() + 1, "tone", msg, line.strip()))
        for m in _FIRST_PERSON.finditer(masked):
            out.append(
                Finding(
                    path,
                    n,
                    m.start() + 1,
                    "first-person",
                    "first-person voice; rewrite impersonally",
                    line.strip(),
                )
            )
        for m in _DASH_SUB.finditer(masked):
            out.append(
                Finding(
                    path,
                    n,
                    m.start() + 1,
                    "dash-substitute",
                    "`--` as a sentence dash; rewrite (comma / colon / period)",
                    line.strip(),
                )
            )
        if _HR_RULE.match(line) and path.name != "README.md":
            out.append(
                Finding(
                    path,
                    n,
                    1,
                    "hr-divider",
                    "`---` rule as a section divider; use a heading",
                    line.strip(),
                )
            )
        if user_facing:
            m = _NON_ASCII.search(line)
            if m:
                out.append(
                    Finding(
                        path,
                        n,
                        m.start() + 1,
                        "non-ascii",
                        f"non-ASCII {m.group()!r} in user-facing doc; use ASCII",
                        line.strip(),
                    )
                )
    return out


# ---------------------------------------------------------------------------
# Python scanning
# ---------------------------------------------------------------------------
_COMMENT = re.compile(r"#.*$")
_TYPE_IGNORE = re.compile(r"#\s*type:\s*ignore(?!\[)")
_BARE_EXCEPT = re.compile(r"^\s*except\s*:")
_DEF = re.compile(r"^(\s*)def\s+\w+\s*\(")
# advisory; matches the project's stated target ceiling
_FUNC_LINE_CAP = 100


def _python_comment_and_doc_lines(src: str) -> list[tuple[int, str]]:
    """Yield (lineno, text) for comment bodies and docstring lines only: the
    spans where prose tone rules apply. Code lines are excluded so an identifier
    or a string literal in code is never flagged as prose."""
    out: list[tuple[int, str]] = []
    in_doc = False
    doc_delim = ""
    for n, line in enumerate(src.splitlines(), 1):
        s = line.strip()
        if in_doc:
            out.append((n, line))
            if doc_delim in s:
                in_doc = False
            continue
        # Opening of a docstring/triple-quoted string.
        for delim in ('"""', "'''"):
            if s.startswith(delim) or s.startswith("r" + delim):
                body = s.split(delim, 1)[1] if delim in s else ""
                out.append((n, line))
                # single-line docstring closes on the same line
                if (
                    body.count(delim) == 0
                    and not s.rstrip().endswith(delim)
                    or s == delim
                ):
                    in_doc = True
                    doc_delim = delim
                elif delim in body:
                    in_doc = False
                break
        else:
            m = _COMMENT.search(line)
            if m and not _in_string_literal(line, m.start()):
                out.append((n, m.group()))
    return out


def _in_string_literal(line: str, hash_pos: int) -> bool:
    """True if the `#` at `hash_pos` falls inside a quoted string (so it is not a
    real comment). A simple quote-parity check, adequate for single lines."""
    prefix = line[:hash_pos]
    return (prefix.count('"') - prefix.count('\\"')) % 2 == 1 or (
        prefix.count("'") - prefix.count("\\'")
    ) % 2 == 1


def _trailing_comments(src: str) -> dict[int, tuple[int, str]]:
    """Map line -> (col, text) for same-line comments (code before the `#`).

    Tool directives (`# noqa`, `# type:`, ...) are exempt; they must stay on
    the line they apply to. Uses the tokenizer so a `#` inside a string is never
    mistaken for a comment.
    """
    out: dict[int, tuple[int, str]] = {}
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError):
        return out
    for tok in toks:
        if tok.type != tokenize.COMMENT or not tok.line[: tok.start[1]].strip():
            continue
        body = tok.string.lstrip("#").strip()
        if not body.startswith(_COMMENT_DIRECTIVES):
            out[tok.start[0]] = (tok.start[1], tok.string)
    return out


def scan_python(path: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        src = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [Finding(path, 0, 0, "io-error", f"could not read: {exc}", "")]

    lines = src.splitlines()
    inline = _trailing_comments(src)

    # Structural rules over raw lines.
    suppressed = False
    for n, line in enumerate(lines, 1):
        if _is_marker(line, "# verify: off"):
            suppressed = True
        if _is_marker(line, "# verify: on"):
            suppressed = False
        if suppressed:
            continue
        if n in inline:
            col, _text = inline[n]
            out.append(
                Finding(
                    path,
                    n,
                    col + 1,
                    "inline-comment",
                    "same-line comment; put it on its own line above the code",
                    line.strip(),
                )
            )
        if _BARE_EXCEPT.search(line):
            out.append(
                Finding(
                    path,
                    n,
                    1,
                    "bare-except",
                    "bare `except:`; catch a specific exception",
                    line.strip(),
                )
            )
        m = _TYPE_IGNORE.search(line)
        if m and not _in_string_literal(line, m.start()):
            out.append(
                Finding(
                    path,
                    n,
                    1,
                    "type-ignore",
                    "`# type: ignore` without `[code]`; narrow it",
                    line.strip(),
                )
            )

    # Function length (advisory).
    out += _scan_function_length(path, lines)

    # Tone rules over comment + docstring spans only.
    suppressed = False
    doc_spans = dict(_python_comment_and_doc_lines(src))
    for n, line in enumerate(lines, 1):
        if _is_marker(line, "# verify: off"):
            suppressed = True
        if _is_marker(line, "# verify: on"):
            suppressed = False
        if suppressed or n not in doc_spans:
            continue
        text = doc_spans[n]
        for rx, msg in _MARKETING + _NARRATION:
            for m in rx.finditer(text):
                out.append(Finding(path, n, m.start() + 1, "tone", msg, line.strip()))
        for m in _FIRST_PERSON.finditer(text):
            out.append(
                Finding(
                    path,
                    n,
                    m.start() + 1,
                    "first-person",
                    "first-person voice in a comment; rewrite impersonally",
                    line.strip(),
                )
            )
    return out


def _scan_function_length(path: Path, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    # (lineno, indent)
    open_def: tuple[int, int] | None = None
    for n, line in enumerate(lines, 1):
        m = _DEF.match(line)
        if m:
            if open_def is not None:
                _emit_long(out, path, open_def, n - 1)
            open_def = (n, len(m.group(1)))
            continue
        if open_def is not None:
            indent = len(line) - len(line.lstrip())
            if (
                line.strip()
                and indent <= open_def[1]
                and not line.lstrip().startswith(")")
            ):
                _emit_long(out, path, open_def, n - 1)
                open_def = (n, open_def[1]) if _DEF.match(line) else None
    if open_def is not None:
        _emit_long(out, path, open_def, len(lines))
    return out


def _emit_long(
    out: list[Finding], path: Path, start: tuple[int, int], end: int
) -> None:
    length = end - start[0] + 1
    if length > _FUNC_LINE_CAP:
        out.append(
            Finding(
                path,
                start[0],
                1,
                "long-function",
                f"function spans {length} lines (cap {_FUNC_LINE_CAP}); split it [advisory]",
                "",
            )
        )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_targets() -> list[Path]:
    root = repo_root()
    return [
        root / "deglyph",
        root / "tests",
        root / "scripts",
        root / "doc",
        root / "README.md",
        root / "CLAUDE.md",
        root / "AGENTS.md",
        root / "CONTRIBUTING.md",
        root / "SECURITY.md",
        root / "CHANGELOG.md",
    ]


def iter_files(targets: list[Path]) -> tuple[list[Path], list[Path]]:
    """Split the target set into (markdown, python), expanding directories."""
    md: list[Path] = []
    py: list[Path] = []
    for t in targets:
        if t.is_dir():
            md += sorted(t.rglob("*.md"))
            py += sorted(p for p in t.rglob("*.py") if "__pycache__" not in p.parts)
        elif t.suffix == ".md":
            md.append(t)
        elif t.suffix == ".py":
            py.append(t)
    return md, py


def write_report(path: Path, findings: list[Finding]) -> None:
    by_kind: dict[str, list[Finding]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f)
    lines = [
        "# deglyph verify report",
        "",
        f"{len(findings)} finding(s) across {len({f.path for f in findings})} file(s).",
        "",
    ]
    for kind in sorted(by_kind):
        lines.append(f"## {kind} ({len(by_kind[kind])})")
        for f in by_kind[kind]:
            rel = (
                f.path.relative_to(repo_root())
                if f.path.is_relative_to(repo_root())
                else f.path
            )
            lines.append(f"- {rel}:{f.line}:{f.col}  {f.message}")
            if f.text:
                lines.append(f"    > {f.text}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="verify.py",
        description="Tone and style verifier for deglyph docs and Python sources.",
    )
    ap.add_argument(
        "paths", nargs="*", help="files or directories (default: project set)"
    )
    ap.add_argument(
        "--report", action="store_true", help="write .verify-report at the repo root"
    )
    ap.add_argument("--quiet", action="store_true", help="print only the summary line")
    args = ap.parse_args(argv)

    targets = [Path(p) for p in args.paths] if args.paths else default_targets()
    targets = [t for t in targets if t.exists()]
    if not targets:
        print("verify: no targets exist", file=sys.stderr)
        return 2

    md_files, py_files = iter_files(targets)
    findings: list[Finding] = []
    for p in md_files:
        findings += scan_markdown(p, user_facing=not _is_developer_doc(p))
    for p in py_files:
        findings += scan_python(p)

    findings.sort(key=lambda f: (str(f.path), f.line, f.col))
    if not args.quiet:
        for f in findings:
            rel = (
                f.path.relative_to(repo_root())
                if f.path.is_relative_to(repo_root())
                else f.path
            )
            print(f"{rel}:{f.line}:{f.col}: {f.kind}: {f.message}")
            if f.text:
                print(f"    {f.text}")

    if args.report:
        write_report(repo_root() / ".verify-report", findings)

    n = len(findings)
    print(
        f"\nverify: {n} finding(s) in {len(md_files)} markdown + {len(py_files)} python file(s)"
    )
    return 1 if n else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
