# CLAUDE.md

## Sub-Documentation

Detailed reference lives in `doc/claude/`. Read the relevant sub-doc before working in that area.

| Document | Read it when |
|----------|--------------|
| [doc/claude/architecture.md](doc/claude/architecture.md) | Touching any subsystem: the address model, fat Mach-O slices, thunk resolution, the TUI tree/render/nav, discovery, the AI assistant, the scanner, hardening, fingerprint, SBOM, CVE, report, the GitHub Action, or the help manual. 18 invariants; the heuristics interlock, so read the entry before editing. |
| [doc/claude/common-mistakes.md](doc/claude/common-mistakes.md) | The full recurring-pitfall table (27 rows). The most frequent are inlined under Common Mistakes below. |
| [doc/claude/extending.md](doc/claude/extending.md) | Adding a pattern detector, or a new container format / architecture. |
| [doc/claude/directory-structure.md](doc/claude/directory-structure.md) | Finding where a subsystem lives: the annotated file tree of `deglyph/`, `tests/`, `doc/`, `scripts/`. |

## Behavioral Rules

- **Read before writing.** Never edit a file you haven't read this session.
- **Read the analysis core in full** (`core/disasm.py`, `re/patterns.py`, `re/xref.py`) before touching it: the heuristics interlock (`thunk_chain` depends on `_has_body`, which depends on both pattern detectors).
- **Plan before multi-file changes** (>3 files): state the plan, get a nod.
- **Edit, don't rewrite.** Targeted edits; full rewrite only when asked or >70% changed.
- **Do not create markdown/doc files** unless asked. Answer in chat.
- **Update CLAUDE.md** (or the relevant `doc/claude/` sub-doc) for any architectural change a future session would otherwise miss.
- **Do not run the gate unprompted** (`ruff check`, `black`, `mypy deglyph`, `pytest`, `python3 scripts/verify.py`): running it on every edit wastes the user's tokens. It is the same gate as CI; `verify.py` is the tone/style contract, keep it at zero findings.

## Trust Contract

- **Stay in your lane.** Every file touched outside the ask costs the reviewer an audit pass. Name an adjacent fix in chat ("noticed X, want it in this pass?") instead of bundling it.
- **Show the why, not the what.** A comment, chat reply, or commit message explains *why* only when the choice was non-obvious. When obvious, say nothing.
- **State the plan before non-trivial work** (any change where a reasonable reviewer could prefer a different approach). Plan visible before execution; a summary after the fact is not a substitute.
- **Self-review before handoff.** Re-read the diff: is this what was asked, and only that? If not, say so before claiming completion.

## What deglyph is

A terminal tool for understanding native binaries. It loads a PE, ELF, or Mach-O object, lists its functions in a searchable tree grouped by kind and name, follows exported wrappers to their real implementations, shows annotated disassembly, walks the call graph, and runs pattern detectors that recover structure facts (constants written to memory, constant call arguments, CRC/checksum routines) without a decompiler. Recovering a binary protocol's command codes and frame layout is one application; nothing in the tool is specific to it.

Stack: Python 3.10+, [LIEF](https://lief.re) (container parsing), [Capstone](https://www.capstone-engine.org) (disassembly), [Textual](https://textual.textualize.io) + [Rich](https://rich.readthedocs.io) (interface). GPLv3 licensed. Author: Alex Spataru.

## Run

```bash
./deglyph.sh <binary>                 # bootstraps .venv on first run, then launches the TUI
./deglyph.sh <binary> --analyze NAME  # headless constant/CRC analysis of a function
./deglyph.sh <binary> --list          # print the function table, no TUI
deglyph scan <path>                   # CI scan: hardening / secrets / libs / CVEs / imports / drift
deglyph scan <path> --format markdown # PR-comment shaped report; --format html for a single-file dashboard
deglyph sbom <path> --format cyclonedx  # CycloneDX / SPDX bill of materials from the binary
deglyph login <token>                 # store a hosted-AI token (Pro); logout clears it

# Development
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"               # anthropic + cxxfilt are runtime deps; dev adds test/lint tools
pytest            # demo.exe-backed cases run in CI; host-binary cases skip if absent
                  # tests/conftest.py prepends the repo root, so bare pytest hits the
                  # checkout even without the editable install (no global-deglyph shadow)
black deglyph tests
```

`deglyph.sh` is CWD-independent. It creates `.venv` from `requirements.txt` plus an editable install on first run, then execs `python -m deglyph.cli`.

## Directory Structure

The annotated file tree (every module's one-line role) lives in **[doc/claude/directory-structure.md](doc/claude/directory-structure.md)**. Read it to find where a subsystem lives before editing.

## Architecture Invariants

The 18 per-subsystem invariants live in **[doc/claude/architecture.md](doc/claude/architecture.md)**. They are not optional background: the heuristics interlock (e.g. `thunk_chain` -> `_has_body` -> the pattern detectors), and several encode hard contracts (VAs everywhere, fat Mach-O offset folding, single-writer TUI render, server-side Pro gate, heuristics-are-not-proofs). Read the entry for the subsystem you are about to touch before editing it.

## Common Mistakes

The full table (27 rows) is in **[doc/claude/common-mistakes.md](doc/claude/common-mistakes.md)**. The highest-frequency ones:

| Mistake | Fix |
|---------|-----|
| Passing an RVA to `read_va` / `func_at` | Everything is a VA; LIEF RVAs already have `base` added in `load_image`. |
| Keying TUI selection by address | Two `Func`s can share a VA. A leaf's `node.data` is its index into `self._rows`. |
| `move_cursor(row=i)` to select a function | The navigator is a `Tree`. Rebuild via `_apply_filter`, then `_select_func_node(va)`. |
| Reporting a detector / `scan` hit as a verified fact | It is a heuristic. Confirm in disassembly; say "candidate", not "leak". |
| Routing a backend off `provider() == "openai"` | Use `provider_family()`; `groq`/`openrouter`/`deepseek` are openai-family under a non-`openai` key. |
| Adding a rebuild site without capturing selection | Capture `keep = self._current_item()` before `_apply_filter`, restore `_select_item(keep)` after. |

## Code Style

`black` is the formatter; its output is the contract. Beyond that:

- Type hints on public functions; `from __future__ import annotations` at the top.
- Dataclasses with `slots=True` for value types (`Func`, `Insn`, `Store`, `Hit`).
- Guard clauses over nested branching; keep nesting shallow.
- Catch and continue around per-instruction / per-section decode so one bad region never aborts a whole-image scan.

### Comments

Code is the spec. Comments label sections and explain non-obvious choices; they do not narrate.

- **Module docstring**: one paragraph stating what the module provides, then a short list of the public names if there is more than one. No tutorial voice.
- **Function docstring**: one line of intent; add a short paragraph only when the contract or an edge case is not obvious from the signature.
- **In-body**: a one-line `#` header **on its own line above** the block it explains. **No same-line / trailing comments** (`x = 1  # ...`); put the note on the line above. The only exception is a tool directive that must sit on its line (`# noqa`, `# type:`, `# pragma`, `# fmt:`, `# verify:`). `scripts/verify.py` flags trailing comments (`inline-comment`).
<!-- verify off -->
- **Forbidden**: first-person ("we", "I"), "Note that", "used to", tutorial voice, marketing adjectives. ASCII only in user-facing Markdown; code comments may use `->` arrows and box characters where they aid a diagram.
- **No `--` as a sentence dash.** It is a robotic em-dash substitute. Rewrite the sentence with a comma, colon, period, or parentheses instead. `verify.py` flags it (`dash-substitute`). The point is human, considered prose, not a mechanical swap of one dash glyph for another.
<!-- verify on -->

`scripts/verify.py` enforces this contract. Run `python3 scripts/verify.py` before a commit; wrap a region that must quote a forbidden phrase in `<!-- verify off -->` / `<!-- verify on -->` (Markdown) or `# verify: off` / `# verify: on` (Python).

## Extending deglyph

How-to guides for adding a pattern detector or a new container format / architecture live in **[doc/claude/extending.md](doc/claude/extending.md)**.
