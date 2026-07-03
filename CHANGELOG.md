# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2026-07-02

### Added
- Content-addressed function identity (`re/funcsig.py`): a relocation-stable
  exact hash plus n-gram similarity over normalized instructions; every
  identity consumer (fingerprinting, diffing, knowledge, baseline drift)
  routes through it.
- Function fingerprinting (`deglyph scan --identify`, `deglyph export
  --identify`): match recovered `sub_*` functions against a bundled corpus of
  library function signatures (x86-64, built in CI) and name them with a
  confidence level.
- Semantic binary diff (`deglyph diff OLD NEW`): functions matched across
  builds by content, reported as unchanged, modified (with a similarity
  score), added, or removed; `scan --baseline` drift routes through the same
  engine, so a recompiled function reports as modified instead of removed
  plus added.
- Knowledge files (`deglyph knowledge export|import`): renames and notes keyed
  by function content hash, so they reattach to the same function in a
  different build or on another machine.
- Signed scan attestations (`deglyph attest`, `deglyph verify-attest`): a
  canonical digest over the scan result with an optional ed25519 signature
  (`pip install 'deglyph[sign]'`).
- Go function-name recovery (`re/gosym.py`): a stripped Go binary is named
  from its pclntab (go1.2 through go1.20 layouts), so discovery yields real
  names like `main.main` and `net/http.(*Server).Serve` instead of `sub_*`.
- Rust symbol demangling (`core/demangle.py`): legacy symbols lose their
  instance-hash suffix, and v0 (`_R`) symbols are decoded (paths, generics,
  references, tuples, backreferences); an undecodable symbol shows raw rather
  than a wrong name.
- 32-bit ARM detector coverage: immediate stores, call-argument constants, and
  CRC/checksum loops now fire on ARM as well as x86, x86-64, and AArch64.
- Jump-table recovery in the CFG: an indirect `jmp` through a memory-operand
  pointer table has its case arms resolved and followed, instead of ending the
  block at an unrecoverable indirect jump.
- RISC-V loading and disassembly (RV32 / RV64, `--arch riscv64`): the container
  loads and instructions decode; the detectors stay off for RISC-V and report
  so.
- Wider library fingerprint catalog: expat, glibc, OpenSSH, LibreSSL, zlib-ng,
  libjpeg-turbo, busybox, pcre2, and zstd banner signatures.
- arm64 function-signature corpus: the CI corpus build cross-compiles its
  from-source libraries for aarch64, so `--identify` names arm64 functions,
  not only x86-64 ones.
- Standalone zipapp release artifacts: each tagged release attaches a
  self-contained `deglyph-<os>.pyz` for Linux, macOS, and Windows.

## [1.3.0] - 2026-06-01

### Added
- TUI workbench: a Data tab with a whole-file content map, a Compare view
  against a second build (`v`), keyboard call-graph navigation, and a command
  palette covering every headless capability.
- `deglyph export`: a versioned, deterministic JSON document of the whole
  analysis (functions with confidence and evidence, xrefs, detector hits,
  strings, findings; per-function CFG blocks opt-in via `--cfg`).
- Portable projects (`deglyph project export|import`): renames, notes, and
  bookmarks in a path-independent file that reattaches on another machine.
- On-disk analysis cache for the slow whole-image passes (strings, xref
  index, discovery), keyed by file hash; optional wall-clock budgets return
  partial, uncached results, and the TUI can cancel a running scan.
- Property-based, golden-snapshot, and fuzz test suites over the address
  model and the scan, SARIF, and export surfaces.
- Export of the last AI investigation (redacted) from the TUI.
- A Limitations page in the help manual.

### Changed
- Non-function symbols are filtered from the function tree.
- I/O boundaries bound response bodies and tolerate corrupt files.

### Fixed
- Tab activation no longer crashes during teardown after the tree unmounts.

## [1.2.0] - 2026-05-29

### Added
- Fat (universal) Mach-O support: slice selection (`--slice N`, a TUI slice
  picker) with section offsets folded to the file, so reads land in the
  chosen slice instead of the fat header.
- `deglyph scan --format badge`: shields.io endpoint JSON for a live badge.

### Changed
- The developer reference split out of CLAUDE.md into `doc/claude/`.
- Markdown report findings use an ASCII separator so Windows runners render
  the step summary correctly.

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
  selection on tab activation (click or arrow) as well as on cursor movement, so
  switching to a tab via the tab bar no longer leaves it stale until the
  selection changes.
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

[Unreleased]: https://github.com/deglyph-re/cli/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/deglyph-re/cli/releases/tag/v1.4.0
[1.3.0]: https://github.com/deglyph-re/cli/releases/tag/v1.3.0
[1.2.0]: https://github.com/deglyph-re/cli/releases/tag/v1.2.0
[1.1.0]: https://github.com/deglyph-re/cli/releases/tag/v1.1.0
[1.0.0]: https://github.com/deglyph-re/cli/releases/tag/v1.0.0
[0.1.0]: https://github.com/deglyph-re/cli/releases/tag/v0.1.0
