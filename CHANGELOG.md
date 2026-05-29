# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0]

### Added
- Secret scanning: a high-precision provider-token catalog on top of the
  existing rules, covering GitHub fine-grained PATs, GitLab PATs, Slack
  webhooks, Stripe, npm, SendGrid, OpenAI, and Telegram tokens.
- `deglyph scan --format json`: a flat, machine-readable findings list with a
  level-count summary and a stable per-finding fingerprint, for `jq` and custom
  gates.
- Finding suppression: `--ignore RULE` (repeatable; a trailing `/` suppresses a
  whole category) and a `.deglyphignore` file (auto-discovered, or
  `--ignore-file PATH`) that suppresses by rule, category, or finding
  fingerprint. Suppressed findings are dropped before the exit code is computed.
- GitHub Action: writes the Markdown report to the run summary on every run,
  optionally uploads SARIF to code scanning (the Security tab, `upload-sarif`),
  and accepts `ignore` / `ignore-file` inputs. The summary and upload steps run
  even when the gate fails the job.
- A JSON-indexed help manual under `doc/help/` (`help.json` plus categorized
  Markdown pages), rendered by the project website's documentation page.

### Changed
- The generic credential rule (`secret/credential-keyword`) now requires
  evidence of an actual value (an assignment, or a value-shaped token), so a
  bare keyword (a struct field, an environment-variable name, a format
  placeholder, a mangled symbol) no longer fires. This removes the large
  majority of false positives on real binaries.

### Fixed
- PE stack-canary detection no longer false-reports `harden/no-stack-canary` on
  a stripped release MSVC build: it now also reads the load configuration's
  security cookie, which `/GS` sets even when the `__security_cookie` symbol is
  stripped.

## [1.0.0]

### Added
- About dialog (`F1` / `?`): version, author, repository link, and license.
- PE COFF symbol names: functions in mingw/debug-built PEs now resolve to their
  real names (the symbol's section-relative value is placed via its section).
- `samples/demo.c` + `demo.exe`: a small sample binary that exercises the
  detectors, used for the README screenshot.
- Persistent annotations: rename functions (`n`), add notes (`;`), and bookmark
  (`b`); saved to a per-user sidecar (`~/.deglyph/annotations/` or
  `$DEGLYPH_STORE_DIR`) and applied across the table, disassembly, graph, and xrefs.
  On startup, if a saved context exists for the binary, deglyph asks whether to
  load it or start fresh; it also autosaves on quit.
- `--json` for machine-readable `--list` / `--analyze` output, and `--ascii`
  (also `$DEGLYPH_ASCII`) for ASCII glyphs on limited terminals.
- PyPI release workflow via Trusted Publishing (OIDC), packaging metadata
  (classifiers, project URLs, `py.typed`), and a CI coverage gate.
- Function discovery for stripped binaries: `.text` `call` targets become
  `sub_<address>` entries, so an EXE that exports nothing still shows its real
  functions. Runs on a background worker so large binaries don't freeze startup;
  `--no-discover` skips it.
- Kind filter (`t`): cycle the function table through all / code / export / sub /
  import; `code` hides import thunks.
- Call-graph navigator tab (`c`): a clickable node view centered on the selection
  (callers above, callees below, <=7 nodes visible, paged), click to recenter.
- Theme support: the palette is a registered Textual theme and the stylesheet
  uses theme variables, so the command palette's "Change theme" recolors deglyph.
- Recursive caller and callee trees in the Xrefs view (in-terminal ASCII tree,
  cycle-safe and bounded).
- Pseudo-C tab (`p`): a heuristic, x86-only C-like rendering of the disassembly.
- AI assistant tab (`i`): opt-in, multi-turn chat with Claude about the selected
  function, with the disassembly sent once as cached context. Requires
  `ANTHROPIC_API_KEY` and the `ai` extra (`anthropic`); model is `claude-opus-4-7`,
  overridable with `DEGLYPH_MODEL`. Replies render an animated "thinking" spinner
  while loading, make cited `sub_<addr>` / `0x<addr>` tokens clickable (jump to the
  code), and keep a separate conversation per function (switching back resumes it).
  The assistant is **agentic**: it can call read-only tools (find/list functions,
  disassemble, pseudo-C, analyze, xrefs, search) to investigate the whole binary,
  so you can ask "where does it parse a header / build the frame" and it
  locates and explains the function itself. Tool calls show live in the transcript.
- Clickable branch and call targets in the disassembly view: clicking a target
  inside the image jumps to it (shares the `goto` navigation path).
- Continuous integration: GitHub Actions matrix across Linux, macOS, and Windows
  on Python 3.10-3.13, running ruff, black, mypy, the tone verifier, and pytest.
- Deterministic detector tests over hand-assembled x86-64 code, plus
  hostile-input robustness tests for malformed containers.
- `-v/--verbose` and `--debug` flags that route diagnostics to stderr.
- Dependabot for pip and GitHub Actions updates.
- `CONTRIBUTING.md` and `SECURITY.md`.

### Changed
- The header no longer expands/contracts when clicked (the click toggle was
  confusing); its height is fixed.
- The assistant never goes silent: a question always echoes, and if the assistant
  is unavailable (the `anthropic` extra not installed, or no `ANTHROPIC_API_KEY`)
  it shows an actionable reason immediately instead of failing quietly. The tab
  intro states the same readiness up front.
- The disassembly pane now windows large functions (caps rendered instructions
  around the highlight) so big routines no longer stall the UI.
- Xrefs / Analysis / Pseudo / Graph / Assistant tabs now populate for the current
  selection on tab activation (click or arrow) as well as on cursor movement --
  previously, switching to a tab via the tab bar left it stale until the selection
  changed.
- Single-sourced the package version from `deglyph.__version__`.
- Runtime dependencies are declared only in `pyproject.toml`; `requirements.txt`
  defers to it with an editable install.
- README and CLI describe the detectors generically (constants and CRC routines)
  rather than around one protocol use case.

## [0.1.0]

### Added
- Initial release: PE / ELF / Mach-O loader, Capstone-backed disassembly,
  wrapper-to-implementation thunk resolution, call-graph cross-references,
  immediate-store / call-argument / CRC-loop detectors, and the Textual TUI.

[Unreleased]: https://github.com/deglyph-re/cli/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/deglyph-re/cli/releases/tag/v1.1.0
[1.0.0]: https://github.com/deglyph-re/cli/releases/tag/v1.0.0
[0.1.0]: https://github.com/deglyph-re/cli/releases/tag/v0.1.0
