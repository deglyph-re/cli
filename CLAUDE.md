# CLAUDE.md

## Behavioral Rules

- **Read before writing.** Never edit a file you haven't read this session.
- **Read the analysis core in full** (`core/disasm.py`, `re/patterns.py`, `re/xref.py`) before touching it: the heuristics interlock (`thunk_chain` depends on `_has_body`, which depends on both pattern detectors).
- **Plan before multi-file changes** (>3 files): state the plan, get a nod.
- **Edit, don't rewrite.** Targeted edits; full rewrite only when asked or >70% changed.
- **Do not create markdown/doc files** unless asked. Answer in chat.
- **Update CLAUDE.md** for any architectural change a future session would otherwise miss.
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
black deglyph tests
```

`deglyph.sh` is CWD-independent. It creates `.venv` from `requirements.txt` plus an editable install on first run, then execs `python -m deglyph.cli`.

## Directory Structure

```
deglyph/
  core/      image.py    LIEF -> Image: base, sections, Func list (export/symbol/import/entry)
             disasm.py   Capstone wrapper: arch map, linear func disasm, thunk follow, callees
  re/        search.py   image-wide byte (?? wildcards) / string (ascii+utf16) / immediate search
             strings.py  value extraction: extract_strings (image-wide) + referenced_data (per-func)
             xref.py     callers_of (cached whole-image index), callees_of, thunk -> impl chain, call_tree
             patterns.py immediate_stores, call_immediate_args, detect_crc_loops, constants
             pseudo.py   heuristic x86-only pseudo-C (linear annotation, not a decompiler)
             discover.py sub_<va> discovery from .text call targets (scan_call_targets/add_discovered)
             fingerprint.py SIGNATURES table + scan_fingerprint -> LibHit list (zlib/openssl/sqlite/...)
  ai.py      agentic Claude assistant (Anthropic SDK, prompt-cached, opt-in); read-only tools over Image
  scan.py    headless CI scanner: hardening posture / secrets / libs / risky imports / baseline diff
  sbom.py    CycloneDX 1.5 + SPDX 2.3 emitters; root = scanned binary, components = fingerprinted libs
  cve.py     osv.dev client + on-disk cache (~/.deglyph/cve-cache/) keyed by purl, 24h TTL
  report.py  to_markdown (PR-comment shaped) + to_html (single-file dashboard) over scan results
  store.py   persistent per-binary annotations (renames/notes/bookmarks/AI chats) -> sidecar JSON
  account.py token store + endpoint URL for the optional hosted (Pro) tier
  config.py  tiny persistent app config (e.g. the chosen theme) -> ~/.deglyph/config.json
  tui/       app.py      Textual application; grouped function tree + tabbed detail view
             render.py   colorized disassembly + hexdump + whole-file content map (Rich Text)
             glyphs.py   three-tier glyph table: Nerd Font -> Unicode -> ASCII ($DEGLYPH_NERD/$DEGLYPH_ASCII)
             logo.py     baked ASCII/Unicode wordmark + tagline (welcome screen, About)
             style.tcss  theme (theme variables, not hardcoded hex)
  cli.py     argparse entry point; TUI launch, headless --list/--analyze, `scan`, `sbom`, `login`/`logout`
  __main__.py            enables `python -m deglyph`
tests/       test_deglyph.py + per-feature tests (detectors, robustness, cli, render, call_tree, pseudo, ai, tui, store, search, discover, scan, account)
samples/     demo.c + demo.exe: domain-neutral toy binary committed as a CI fixture (planted secret, crc16, opcode)
doc/help/    the manual: help.json index + categorized Markdown entries (rendered by the website's docs.html)
action.yml   composite GitHub Action wrapping `deglyph scan`; examples/deglyph-scan.yml is a consumer workflow
deglyph.sh   self-bootstrapping launcher; deglyph.bat is the Windows equivalent
```

## Architecture Invariants

### Address model
`Image` works in **virtual addresses** with the image base already applied. LIEF reports PE export addresses as RVAs; `load_image` adds `base`. Every address into `read_va` / `func_at` / `nearest_func` is a VA. Section raw data is read lazily from disk, cached per section.

### Fat (universal) Mach-O: one slice, offsets folded to the file
A fat Mach-O carries several arch slices (e.g. `x86_64` + `arm64e`). `lief.parse(path)` returns **only the first**, and worse, LIEF reports each section `offset` **relative to its slice** while `_section_raw` seeks the **whole file**, so a fat binary read landed in the fat header's zero padding and disassembly came back as a wall of `add byte ptr [rax], al` (decoded `00 00`). `load_image` fixes both: `_resolve_binary` parses via `lief.MachO.parse` (a `FatBinary`), `_pick_slice` chooses one (**explicit `slice_index` → requested `arch` → host arch → first**), and `_build_sections` **adds the slice's `fat_offset` to every `raw_off`** so the seek lands in the chosen slice. Because `extract_strings` / `search.py` / `scan.py` map file offsets ↔ VA through `raw_off` and read the whole file, this one fix corrects them too (still one string engine, no second extractor). `Image.slices` lists them (`Slice`: index, arch, cpu label, fat_offset); `Image.slice_index` is the chosen one; thin/PE/ELF leave `slices` empty, `fat_offset` 0. CLI: `--slice N`; the TUI offers a per-slice picker under Binary and a `_switch_slice` reload.

### Function identity
`Func` entries are not unique by address: two exports can share a VA (an MSVC constructor and `operator=`, aliased commands). The navigator is a `Tree`, but identity rides on **row index**, never address: `_apply_filter` keeps `self._rows` as the flat leaf list in tree order, and each leaf carries `data = <index into self._rows>` (group folders carry `data is None`). `_current()` reads the highlighted leaf's `data`. `func_at(va)` returns the last `Func` at that exact VA; `nearest_func(va)` returns the greatest `Func` at or below `va` (symbolizing arbitrary offsets).

### Thunk resolution stops at the implementation
`thunk_chain` (`xref.py`) resolves an exported wrapper to the function that does the work: it follows tail-`jmp` thunks and, for arg-marshalling wrappers, the last in-image `call`, but **stops at the first function with a body** (`_has_body`: an immediate memory store, or an immediate-into-register-then-`call` dispatch idiom). Without this stop the chain descends past the implementation into CRC/transport sub-helpers and the opcode is lost.

### Architecture drives the disassembler
`Disassembler` maps `Arch` to a Capstone mode at construction. PE32 is `CS_MODE_32`, PE32+ is `CS_MODE_64`; a 32-bit DLL decoded in 64-bit mode produces plausible-looking garbage, so the arch must be correct. AArch64 has no sub-mode, so `Arch.ARM64` uses `CS_MODE_LITTLE_ENDIAN` (the bare endianness flag, value 0). `load_image(..., arch=...)` overrides detection; the CLI exposes `--arch`, and `--slice` for a fat Mach-O slice (see above).

### Value extraction has one string engine
`re/strings.py` is the single extractor: `string_runs(data, *, min_len)` yields ASCII + UTF-16LE runs, and **`scan.py` consumes it too** (do not add a second extractor). `extract_strings(image)` maps runs to VA + section (Strings tab, `--strings`); `referenced_data(image, va)` resolves the strings / tables / pointer constants a function points at (x86 rip-relative / absolute operands and pointer immediates), returning `[]` on non-x86. The Strings tab list is lazy + cached in `_strings_cache` (reset in `_load_binary`).

### Detectors are heuristics, not proofs
`immediate_stores`, `call_immediate_args`, and `detect_crc_loops` point at the right instructions; they do not certify behavior. A `mov [buf+2], 0x04` store is reported as a structured field write, not proven to be a command opcode (the disassembly view confirms). CRC detection finds clean unrolled bit loops (candidate polynomial + init) but misses register-folded variants; when the CRC panel is empty, `find_immediate(poly)` still locates the routine. State these limits when reporting; never present a hit as a verified fact.

### The function navigator is a grouped tree
The left pane is a `Tree` (`#functions`, `show_root=False`). `_apply_filter` runs the kind + fuzzy filter, then `_group_funcs` (pure, unit-tested) arranges leaves into two levels: **kind** (Exports / Entry / Symbols / Subs / Imports / Other, `_KIND_GROUPS` order), then a **name prefix** (`_group_key`: C++ `Class::`, a leading `_`/`.` token, or an import's library). `sub` functions list flat under their kind; a single-member group (and the `(top level)` bucket) collapses to a bare leaf. Folders show a count; renames flow in via `names`. `_KIND_GROUPS` maps each kind to `(order, label)` (group order and the kind cycle both read its order field), so adding a kind is one entry.

### TUI render ownership
The detail panes have one writer: `on_tree_node_highlighted`. A group folder carries `node.data is None`, so highlighting one renders nothing. It also guards on `item == _last_rendered_item` so a spurious same-item highlight can't clobber a `goto`/`follow` view. `goto` edits the search box programmatically, so it sets `_input_locked` to drop the queued `Input.Changed` events that would re-filter the tree.

Address navigation funnels through `_goto_address(addr)` (the goto handler and the clickable-disassembly path both call it). `render.disasm_text` attaches a `{"@click": "app.goto_addr(<va>)"}` meta to any branch/call operand whose target is inside `image.text`; Textual routes it `action_goto_addr` -> `_goto_address`. Keep new jump entry points on this method. The single cursor primitive after a rebuild is `_select_func_node(va)` (expands ancestors, selects, scrolls via `_va_nodes`); never `move_cursor(row=i)`.

### Pseudo-C and the call tree share the detectors' limits
`pseudo_c` (`re/pseudo.py`) is a linear, x86-only annotation of the disassembly, not a decompiler (no type recovery, no CFG structuring); it returns `[]` on non-x86. `call_tree` (`xref.py`) is cycle-safe and bounded by `depth`/`max_children`/`budget`; a stopped branch is marked `elided`, not dropped. Report both as heuristics.

### Function discovery fills the tree for stripped binaries
A stripped release EXE exports nothing, so `load_image` yields only `entry` + import thunks. `discover_functions` (`re/discover.py`) scans executable sections once for direct `call` targets and adds `sub_<va>` Funcs (kind `"sub"`), caching via an `_discovered` flag. The CLI and TUI run it after load (default on, `--no-discover` to skip). It is what makes clicks land and xrefs/analysis/graph reachable on binaries like `notepad.exe`. Heuristic: misses indirect/tail-call-only functions.

### Detail tabs track the selection; large disasm is windowed
`_show_for` renders Disasm + Info and calls `_refresh_active_tab`, which re-renders whichever of Xrefs/Analysis/Pseudo/Graph is active. `_render_disasm` windows functions larger than `_DISASM_WINDOW` (around the highlight) so a single huge `Static` never stalls the UI; `goto` moves the window.

### Theming goes through Textual theme variables
`style.tcss` references `$primary`/`$surface`/`$panel`/`$accent`/`$boost`/`$text-muted` (never hardcoded hex) so the palette's theme switcher recolors the chrome. `DEGLYPH_THEME` (registered + set in `on_mount`) is the default retro "TVA terminal" palette: amber/brass/cream on warm brown-black. Pane *content* (Rich Text in `render.py`/`app.py`) still uses literal accent colors; `render.py`'s palette constants are hand-synced to the theme (conversion to theme variables is future work).

### The call-graph navigator caps at 7 nodes
`_render_graph` centers on `_graph_va`: up to `_GRAPH_SLOTS` callers above and callees below (center + 3 + 3). A group with more shows a pager node (`app.graph_page`); clicking any node fires `app.graph_center(<va>)` -> `_graph_recenter`. Clicking does not move the table cursor, so it can't loop with `_refresh_active_tab`.

### Discovery runs off the UI thread
A large `.text` scan can take tens of seconds, so the TUI runs `scan_call_targets` on a `@work(thread=True)` worker and applies `add_discovered` on the UI thread via `call_from_thread` (`_discover_worker` / `_discovery_done`). The scan is read-only; only the apply mutates `image.funcs`. Headless `discover_functions` stays synchronous. Never move the mutate into the worker (it races the table build).

The tree is **blank while discovery runs**, not partial. While `_discovery_running`, `_apply_filter` passes `disabled=True` to `_build_functions_section`, which returns before building any rows (`_rows`/`_va_nodes` stay empty). `_start_discovery_spinner` ticks a `SPINNER` in `#status` and on a placeholder leaf (`_tick_discovery`); `#search` is hidden. `_apply_filter` re-adds the placeholder while running, so a mid-discovery rename/bookmark/strings ingest keeps it.

`_discovery_done` calls `_stop_discovery_spinner` **first** (clears the running flag, stops the timer, removes the placeholder, shows `#search`), captures `keep = _current_item()`, applies `add_discovered`, and rebuilds via `_apply_filter` **unconditionally** (the initial build was skipped, so rows must build even when discovery found no new subs), then restores `_select_item(keep)`. Tests must `await app.workers.wait_for_complete()` before reading `_rows` (`_settle_discovery`).

### Command palette preserves yield order
Textual's `SystemCommandsProvider.discover()` sorts commands alphabetically by title. `_OrderedSystemCommands` overrides `discover` to skip the sort (wired via `DeglyphApp.COMMANDS`); `search` is left to the parent for fuzzy ranking. Menu order: About, Keys, AI provider…, Theme, Maximize, Screenshot, Quit.

### Tree opens on the binary leaf; expansion survives rebuild
On `_load_binary`, after `_build_table` the cursor moves to the Binary leaf (`_select_item((_ITEM_BINARY, None))`), landing the right pane on the file overview (`_render_binary_info`); `_select_node` expands ancestors.

`_apply_filter` runs `_snapshot_expansion` before `tree.clear()` and `_restore_expansion` after. The snapshot is a `set[tuple[str, ...]]` of label-path tuples with the count suffix stripped (`_COUNT_SUFFIX_RE`, `"Exports (42)"` -> `"Exports"`) so a count change still matches. All rebuilds (discovery, rename, bookmark, context, strings) preserve expansion here. Selection preservation sits at each caller: capture `keep = self._current_item()` before `_apply_filter`, restore `_select_item(keep)` after. New rebuild sites must do the same.

### Annotations are an app-level overlay, persisted to a sidecar
`store.py` keys renames/notes/bookmarks by VA at `~/.deglyph/annotations/<sha1(abspath)>.json` (or `$DEGLYPH_STORE_DIR`); load/save are best-effort, degrading to empty on a malformed sidecar. The app reads them through `_disp(func)` (rename-or-display) and passes `names=` into `render.disasm_text` (use `_disp`, not `func.display`). Single-line edits (goto/rename/note) funnel through the search box (`self._prompt` + `_handle_prompt`). On startup `_maybe_prompt_context` peeks the sidecar and, if non-empty, pushes `ContextPrompt` (load -> adopt + `_apply_filter`; discard -> stay empty). Edits persist immediately; `action_quit` flushes via `_autosave`, which writes only when the context is non-empty (`is_empty()` counts `chats`), so discard-then-quit never clobbers.

### Startup runs through the welcome screen
`DeglyphApp(path=None, *, welcome=True)`. With `welcome=True` (the CLI default, even with a file) `on_mount` pushes `WelcomeScreen`: logo, tagline, an `OptionList` of recent sessions (`store.list_sessions()`) plus "Open a file…" (a `FilePicker` over `DirectoryTree`); a given file shows as a "Continue" entry on top. It dismisses with `(path, restore)` -> `_on_welcome` -> `_load_binary`. `restore=True` adopts annotations and rehydrates chats directly; otherwise `_maybe_prompt_context` offers load/discard. Tests use `welcome=False`. No-binary launch lands here; `--list`/`--analyze` still require one. Logo is `logo.LOGO` (Unicode) with `LOGO_ASCII` fallback via `wordmark()`.

### Preferences persist via config.py
`on_mount` restores `config.get("theme", "deglyph")` and subscribes to `theme_changed_signal` to `config.put` changes (`~/.deglyph/config.json`, `$DEGLYPH_STORE_DIR`-aware). `config.py` is for small global prefs, distinct from per-binary annotations (`store.py`) and the auth token (`account.py`). The `FilePicker` browses above its root via `_set_root` (Backspace `action_up`, path Input). Subcommands (`scan`/`login`/`logout`) sit in the parser epilog so `deglyph -h` documents them though they dispatch before argparse.

### The header is a custom one-line bar
`_HeaderBar` (a `Horizontal`) replaces Textual's `Header`: a menu glyph (`#hdr-menu` -> `app.command_palette`), title (`#hdr-title`), nav controls (`#hdr-nav`, by `_refresh_toolbar`), and clock (`#hdr-clock`). No tall-toggle. The screen tiles edge to edge (header row 0, footer last, body `1fr`); keep the shell containers full-bleed, no margins/padding.

### TUI glyphs are a three-tier cascade
`glyphs.G` resolves once at import to one tier: **ASCII** (`$DEGLYPH_ASCII` or non-UTF-8 stdout), **Nerd Font** (`$DEGLYPH_NERD`, overlays Unicode), else **Unicode** (the safe default, no emoji). `_ASCII` must define every key `_UNICODE` does (`G[...]` never KeyErrors); `_NERD` is an overlay subset gated on `not _ascii_mode`. The CLI's `--ascii`/`--nerd` set the env vars before import. Add new glyphs to all relevant tiers and reference `G[...]`, never a bare Unicode literal.

### Navigation history funnels through `_record_nav`
Nav controls live in the header (`#hdr-nav`): back/forward over a jump stack (`_nav_history` + `_nav_pos`), plus `recent`/`chats` `NavMenu` pickers (faded when empty). Deliberate jumps (`_goto_address`, `action_follow`) call `_record_nav(dest)`, which also captures the origin; cursor scrolling does **not** record (IDA-style). Replays go through `_nav_to`, which sets `_nav_lock` so `_goto_address` does not re-record them. New jump entry points call `_record_nav` and end on `_goto_address`.

### AI replies render markdown; the chat persists
Replies render through `_markdown` (headings, bullets, `code`, bold, italic), keeping `sub_`/`0x` linkification (`_linkify`); underscore emphasis is unsupported so snake_case stays literal. Each function's chat is cached by resolved-impl VA (`_ai_sessions`) and **persisted** to the sidecar (`Annotations.chats`): `_collect_chats` -> `_serialize_messages` to JSON-safe dicts, `_persist_chats` after each reply, loading rehydrates via `_transcript_from_messages`. The local Anthropic client uses a per-request timeout (`DEGLYPH_AI_TIMEOUT`, default 90s).

### A reply is bound to the function it was asked about
A question can outlive the selection. `_ask_ai(origin, question)` captures the origin VA and runs on a **dedicated assistant copy** (`_assistant_for`), seeded with that function's context and history, so switching functions (which re-points `self._assistant` via `set_context`) can't corrupt the in-flight conversation. `_ai_reply` routes by origin: it appends to that VA's transcript (`_ai_log_for`) and writes messages back to `_ai_sessions[origin]` (never `self._ai_log` from the worker path). If the origin is still shown it refreshes the pane and stops the spinner; otherwise it `notify`s. The spinner is per-displayed-VA (`_ai_sync_context`). Workers share `group="ai-ask"` (not `exclusive`), so questions on different functions run concurrently.

### The assistant is opt-in, agentic, and isolated
`ai.py` is the only module that touches the network, only inside `Assistant.ask` (run on a `@work(thread=True)` worker); it never sends until the user asks. `ask` runs an agentic loop (`_run_loop`, capped at `_max_tool_iters()`, default 24, `DEGLYPH_AI_MAX_ITERS`): the model calls read-only tools (`find_function`, `list_functions`, `disassemble`, `pseudo_c`, `analyze`, `xrefs`, `search`) over the bound `Image` (`bind_image`), `on_event` firing per call for TUI progress. The selected function's disassembly is one cached `system` block (`cache_control: ephemeral`); the agent roams via tools. When the budget runs out with a tool call pending, a final `_force_summary` round **keeps `tools` defined but sets `tool_choice={"type": "none"}`** (the history holds `tool_use` blocks the API rejects when `tools` is absent); the summary nudge rides inside the last user turn, and the OpenAI adapter re-emits it as a trailing user message mapping `{"type": "none"}` -> `"none"`. `ask` floors the reply to a non-empty string. `anthropic` is a runtime dependency but is imported lazily, and `unavailable_reason()` keeps the missing-package guard (keep `core`/`re`/the base TUI importable without it). Default `DEFAULT_MODEL` (`claude-opus-4-7`), override via `DEGLYPH_MODEL`.

### The assistant is provider-agnostic
`provider()` returns the selected *key* (`anthropic` default, `openai`, `groq`, `openrouter`, `deepseek`, `ollama`, `lmstudio`, or custom) from `config.get("ai_provider")` / `$DEGLYPH_AI_PROVIDER`. `provider_family()` maps it to the request *shape* (**anthropic** or **openai**) via the `PROVIDERS` registry (unknown key -> openai-compatible). Route every backend decision off `provider_family()`, never `provider() == "openai"` (that breaks `groq`/`openrouter`/`deepseek`, which are openai-family under a non-`openai` key). `PROVIDERS` (`ai.py`) is the single source for each provider's label/family/base URL/model menu (`known_providers()`, `provider_info(key)`). The palette's "AI provider…" -> `AISettingsScreen` wires provider/model/base-URL `Select`s (a `CUSTOM` sentinel reveals a free-text model Input); save writes `ai_provider`/`ai_base_url`/`ai_model`.

`Assistant.model` is a property: a ctor `model=` / `$DEGLYPH_MODEL` pins it; else the **anthropic** family resolves `config.get("ai_model")` (-> `DEFAULT_MODEL`). The **openai** family ignores `.model` and carries it via `openai_config()`. `OpenAIBackend` POSTs to any OpenAI-compatible `/chat/completions` (stdlib `urllib`, no SDK), configured by `openai_config()` (`DEGLYPH_AI_BASE_URL`/`_MODEL`/`_API_KEY`); `_to_openai_messages`/`_to_openai_tools`/`_from_openai` translate both ways into a `_HostedResponse`, leaving `_run_loop` unchanged. Keep new request fields flowing through both adapters.

### Open-core: route to a backend, gate a service
`_create(**kw)` picks the backend for one round-trip: **injected client** (tests) > **hosted** (`HostedBackend`, when `account.load_token()` returns a token) > **local BYO-key** (`_ensure_client`, needs `ANTHROPIC_API_KEY`). `HostedBackend` is a thin stdlib-`urllib` POST to `account.api_url()` (`api.deglyph.dev`) carrying the token; the server runs the model with its own key and enforces entitlement. `_HostedResponse`/`_HostedBlock` mirror the Anthropic content-block shape so the loop is backend-agnostic. `unavailable_reason()` is None when a client is injected / logged in / a key is present, else an actionable string. This client ships no secrets; the gate is server-side.

### The scanner is heuristics, headless, and CI-shaped
`scan.py` reads a loaded `Image` (never executes it) and returns a flat `Finding` list. `scan_image` runs up to six detectors (secrets + imports always; the rest gated), ordered by trust: `scan_hardening` (LIEF posture, PE/ELF/Mach-O), `scan_secrets` (high-precision provider-token regexes for AWS/GitHub/GitLab/Slack/Stripe/npm/SendGrid/OpenAI/Telegram/JWT/private-keys plus a generic credential rule, all always-on; an entropy catch-all **opt-in** via `--entropy`, noisy on native binaries), `scan_imports` (capability map: exec/injection/memory-protect/dynamic-load/network/anti-debug), `scan_fingerprint` (`LibHit` records feeding the SBOM + CVE), `scan_cve` (osv.dev, opt-in `--cve`), and `diff_baseline` (functions/imports absent in a `--baseline` build). All heuristics: a credential hit is a labeled string, an import hit a capability not a misuse, a hardening "miss" an absent flag, a fingerprint a version the linker may have lied about. Defaults: hardening + fingerprint on (high signal); CVE off (network); entropy off (noisy).

The generic credential rule (`secret/credential-keyword`) fires only with evidence of an actual *value*, never a bare keyword: `_credential_evidence` requires an assignment (`password=<value>`, scored by `_looks_like_secret_value(min_classes=2)`) or the keyword embedded in a single value-shaped token (`min_classes=3`). Classes count over **alnum only** (`_alnum_classes`) so SCREAMING_CASE constants, env-var names (`AWS_ACCESS_KEY_ID`), and mangled C++ symbols don't register; placeholders and paths are rejected. The bare-keyword form flooded scans (167 noise hits on one Qt app); do not loosen it.

`scan_image(..., ignore, ignore_fp)` drops findings before the sort, so the report and the exit code agree (filter once, centrally, never per-renderer). `ignore` matches a rule by exact id or category prefix when the token ends in `/` (`secret/`); `ignore_fp` matches `fingerprint_of` (sha1 of `rule|message`, 12 hex). The CLI exposes `--ignore RULE` (repeatable, comma-separated) and `--ignore-file` (default `.deglyphignore`): `load_ignore_file` parses one token per line (`#` comments; `fingerprint:`/`fp:` -> fp set). `action.yml` threads both inputs into every scan step.

`to_sarif` emits SARIF 2.1.0 from `RULES`; `to_json` emits a flat findings list (per-finding `fingerprint` + a level-count `summary`), both via `--format`. The exit code is `worst_level` vs `--fail-on` (default `warning`). `scan`/`sbom` dispatch before argparse in `main()` (`argv[0] in (...)`), leaving the `deglyph BINARY ...` parser untouched.

### Hardening posture reads LIEF flags, never decodes
`scan_hardening` is the only detector inspecting `image._lief` directly, because the protections live in container-specific structures. PE reads `optional_header.dll_characteristics` (DYNAMIC_BASE/NX/GUARD_CF/HIGH_ENTROPY_VA/NO_SEH) + `load_configuration.se_handler_count`; ELF reads `is_pie`, `GNU_STACK`, `GNU_RELRO` + `BIND_NOW`/`DF_1_NOW`/`DF_BIND_NOW` (RELRO level), and an AARCH64 GNU note (BTI/PAC); Mach-O reads `header.flags` (`MH_PIE`) and `has_code_signature`. Canary detection is symbol-based (`_CANARY_SYMBOLS`); on PE it **also** reads `security_cookie` (`_pe_has_security_cookie`), since a stripped MSVC build has no `__security_cookie` symbol yet a non-zero cookie proves `/GS` (else it false-reports on every stripped PE). Flag constants are kept literal so an older LIEF still works. Every finding is a *missing* protection: critical misses (ASLR/DEP/canary/PIE/RELRO) are `warning` (trips the default gate), posture improvements (CFG/fortify/high-entropy/BTI-PAC/unsigned) are `note`. A new check is a `RULES` entry + a format helper; keep LIEF reads inside the per-format helpers (try/except) or a malformed binary explodes at the dispatcher.

### Library fingerprinting is a curated string catalog
`re/fingerprint.py` matches `SIGNATURES` regexes against the runs `string_runs` yields over the file bytes. Each `LibSignature` carries one high-signal regex (group 1 = version) and a `purl_base` (`pkg:generic/zlib`); `scan_fingerprint` returns `LibHit` records (name, version, purl, offset, snippet) feeding three consumers: `scan_image` (a `lib/detected` note), `sbom.build_sbom`, `cve.scan_cve`. Hits dedupe on `(name, version)`. The catalog favors precision: add a signature only after verifying the string is stable across versions. An empty list means *no catalog match*, never "self-contained".

### SBOM emitter: root = scanned binary, components = fingerprint hits
`sbom.py` turns the `LibHit` list into a CycloneDX 1.5 or SPDX 2.3 JSON doc. The root is the scanned binary (SHA-256 of contents, basename as `name`); each `LibHit` becomes a library component / SPDX package with a purl `externalRef`, and the SPDX path adds one `DEPENDS_ON` per package back to the root. Versionless hits drop `version` but keep the bare purl. `build_sbom(path, fmt=...)` accepts `cyclonedx` (+ aliases) or `spdx`, else `ValueError`; `serialNumber` is a fresh UUID per call. Never write a root `version` you didn't compute from the binary.

### CVE matcher hits osv.dev, caches every query, degrades to offline
`cve.py` posts each detected purl to `https://api.osv.dev/v1/query` (`urllib`) and caches at `~/.deglyph/cve-cache/<sha1(purl)>.json` (or `$DEGLYPH_STORE_DIR`), TTL 24h (`$DEGLYPH_CVE_TTL`). A malformed cache read is a miss; network failures (URLError/TimeoutError/OSError) log and return `[]`, so an offline runner never blocks the gate. `scan_cve(hits)` emits one `cve/known` finding per CVE per versioned hit (versionless skipped, an unversioned purl isn't actionable); the rule defaults to `error`. Network is opt-in: only when `cve=True` / `--cve`.

### Report renderers share the Finding shape, never re-scan
`report.py` renders `to_markdown(results)` / `to_html(results)` over the same `[(path, findings)]` list `scan` returns (never re-scanning), so text/SARIF/markdown/HTML stay consistent. Markdown is PR-comment-shaped (`## deglyph scan: <summary>`, per-file `### path`, severity-grouped bullets); HTML is one self-contained file (inline `<style>`, no scripts, user data `html.escape`'d). A clean run still renders a body, because a sticky comment that goes blank on green looks broken. Output is ASCII (no em dashes): the markdown surface is appended to `$GITHUB_STEP_SUMMARY`, which a Windows runner decodes as cp1252 and mangles non-ASCII.

### The GitHub Action: gate, summarize, publish, comment
`action.yml` (composite) runs four result surfaces off one scan invocation. (1) The gating step (`id: scan`) runs `deglyph scan --fail-on <input>`; it resolves an effective SARIF path and `echo`s it to `$GITHUB_OUTPUT` **before** the scan so the upload finds it even when the gate fails. (2) A `summary` step (default on, `if: always()`) appends `--format markdown --fail-on never` to `$GITHUB_STEP_SUMMARY`. (3) An `upload-sarif` step (`if: always()`, `codeql-action/upload-sarif@v3`). (4) The PR-comment steps (`comment == "true"` **and** `pull_request`) update the `<!-- deglyph-comment -->`-marked comment in place via `github-script@v7` (the marker keeps it sticky). Contracts: (a) inputs reach the shell via `env:`, never `${{ }}` into `run:` (injection); (b) non-gating scans use `--fail-on never`; (c) always-run surfaces use `if: always()`; (d) `upload-sarif` needs the caller's `security-events: write`, `comment` needs `pull-requests: write`. Inputs mirror the CLI flags.

### The help manual is a JSON-indexed Markdown set
`doc/help/help.json` is an array of `{id, title, section, file}`; each `file` is a sibling Markdown entry. The website (`deglyph-re/website`) renders it via `docs.html`, which fetches `help.json` + the Markdown from this repo's raw URL at runtime (Showdown + highlight.js + mermaid, hash routing, section sidebar). Contracts: (1) every `file` must exist and every `id` be unique; (2) cross-link by `file` name (`[Title](Other.md)`), which `docs.html` rewrites to `#id` (a `.md` link not in the index silently fails to rewrite); (3) prose follows the code-comment voice (neutral, no marketing/first-person); (4) the site resolves `main`, so edits go live on push. `docs.html?base=<url>` previews a local `doc/help`.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Passing an RVA to `read_va` / `func_at` | Everything is a VA; LIEF RVAs already have `base` added in `load_image`. |
| Keying TUI selection by address | Two `Func`s can share a VA. A leaf's `node.data` is its index into `self._rows`. |
| `move_cursor(row=i)` to select a function | The navigator is a `Tree`. Rebuild via `_apply_filter`, then `_select_func_node(va)`. |
| Rendering a pane when a group folder is highlighted | Folders carry `node.data is None`; only leaf highlight renders. |
| Disassembling a PE32 DLL in 64-bit mode | Set `Arch.X86` (`--arch x86`); Capstone mode follows `Image.arch`. |
| Extending `thunk_chain` to always follow the last call | It must stop at `_has_body`, or it descends into CRC/transport sub-helpers. |
| Reporting a detector hit as a verified opcode/CRC | It is a heuristic. Confirm in disassembly; state uncertainty. |
| Re-rendering a pane outside the node-highlight path | Single writer (`on_tree_node_highlighted`). For a jump, set `_pending_highlight`. |
| Editing the search box in code without locking | Set `_input_locked`; queued `Input.Changed` events carry stale values. |
| `nearest_func` for a call target in symbolization | Use `func_at` (exact); `nearest_func` names an unrelated export. |
| Reporting a `scan` finding as a confirmed secret | Heuristic. Say "candidate", not "leak". |
| Loosening `secret/credential-keyword` to a bare keyword match | It must require a value (`_credential_evidence`); a bare keyword floods the report (167 noise hits). |
| Adding a `doc/help` page without updating `help.json` (or vice versa) | The site renders only indexed files; keep them in sync with unique `id`s. |
| Putting Pro logic or a key in the public client | The gate is server-side; `HostedBackend` is a token-bearing HTTP client only. |
| Routing a backend off `provider() == "openai"` | Use `provider_family()`; `groq`/`openrouter`/`deepseek` are openai-family under a non-`openai` key. |
| Enabling the entropy rule by default | Noisy on native binaries; keep it behind `--entropy`. |
| Recording nav history on cursor scroll | Only deliberate jumps record (`_record_nav`); scrolling must not. |
| Saving raw SDK/hosted message objects | Run through `_serialize_messages` first; raw blocks aren't JSON-serializable. |
| Adding a glyph to only the Unicode tier | `_ASCII` must define every key or `G[...]` KeyErrors in `--ascii`. |
| Reporting "no libraries detected" as self-contained | Catalog coverage is limited; say "no catalog match." |
| Inlining hardening flag reads outside the per-format helper | A malformed binary explodes at the dispatcher; keep each in its `_hardening_*` helper, try/except. |
| Posting a PR comment without the sticky marker | Without `<!-- deglyph-comment -->`, every push stacks a new comment. |
| Skipping the cache-write in `cve.query_osv` | The 24h TTL stops a CI matrix hammering osv.dev; write on every successful query. |
| Adding a rebuild site without capturing selection | Capture `keep = self._current_item()` before `_apply_filter`, restore `_select_item(keep)` after. |
| Snapshotting expansion by raw label | Labels carry trailing `(N)` counts; `_node_key` strips the suffix, don't bypass it. |
| Forgetting to stop the discovery spinner on early return | `_stop_discovery_spinner` must run before any path touching `#functions`. |
| Emitting a non-ASCII separator in report markdown | The `$GITHUB_STEP_SUMMARY` append is decoded as cp1252 on Windows; keep report output ASCII. |

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

## Adding a detector

A new pattern detector lives in `re/patterns.py`, returns a list of `slots=True` dataclass records (address + decoded fields), and takes `(image, va, *, max_insns)`. Export it from `re/__init__.py`, render it in `app.py:_render_analysis` and `cli.py:_headless`, and add a test asserting against a known function. Prefer `samples/demo.exe` (committed, runs in CI) or a synthetic blob via the `code_image` fixture (`tests/conftest.py`); guard host-binary cases with a skip when absent.

## Adding a container format or architecture

LIEF already parses PE/ELF/Mach-O and fat binaries. To support a new architecture, add it to `Arch`, map it in `disasm.py:_ARCH_MODE`, and extend `image.py:_detect_arch`. The rest of the pipeline is arch-agnostic except the x86-specific operand inspection in `patterns.py` and `search.py` (Capstone's `x86` operand API); a non-x86 target needs its own operand walk there.
