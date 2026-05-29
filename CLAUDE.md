# CLAUDE.md

## Behavioral Rules

- **Read before writing.** Never edit a file you haven't read this session.
- **Read the analysis core in full** (`core/disasm.py`, `re/patterns.py`, `re/xref.py`)
  before touching it — the heuristics interlock, and `thunk_chain` depends on
  `_has_body`, which depends on both pattern detectors.
- **Plan before multi-file changes** (>3 files): state the plan, get a nod.
- **Edit, don't rewrite.** Targeted edits; full rewrite only when asked or >70% changed.
- **Do not create markdown/doc files** unless asked. Answer in chat.
- **Update CLAUDE.md** for any architectural change a future session would otherwise miss.
- **Do not run the gate unprompted.** Don't run `ruff`, `black`, `mypy`, `pytest`, or
  `verify.py` until the user asks — running it on every edit wastes their tokens. The full
  gate (same as CI): `ruff check`, `black`, `mypy deglyph`, `pytest`, `python3
  scripts/verify.py`; `verify.py` is the tone/style contract, keep it at zero findings.

## Trust Contract

- **Stay in your lane.** Every file touched outside the explicit ask costs the
  reviewer an audit pass. Name an adjacent fix in chat ("noticed X — want it in
  this pass?") instead of bundling it into the diff.
- **Show the why, not the what.** A comment, chat reply, or commit message
  explains *why* only when the choice was non-obvious. When obvious, say nothing.
- **State the plan before non-trivial work** — any change where a reasonable
  reviewer could prefer a different approach. Plan visible before execution; a
  summary after the fact is not a substitute.
- **Self-review before handoff.** Re-read the diff: is this what was asked, and
  only that? If not, say so before claiming completion.

## What deglyph is

A terminal reverse-engineering tool for native binaries. It loads a PE, ELF, or
Mach-O object, lists its functions in a searchable tree grouped by kind and name,
follows exported wrappers to their real implementations, shows annotated disassembly,
walks the call graph, and runs pattern detectors that recover structure facts (constants
written to memory, constant call arguments, CRC/checksum routines) without a
decompiler. Recovering a binary protocol's command codes and frame layout is one
application; nothing in the tool is specific to it.

Stack: Python 3.10+, [LIEF](https://lief.re) (container parsing),
[Capstone](https://www.capstone-engine.org) (disassembly),
[Textual](https://textual.textualize.io) + [Rich](https://rich.readthedocs.io)
(interface). GPLv3 licensed. Author: Alex Spataru.

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

`deglyph.sh` is CWD-independent. It creates `.venv` from `requirements.txt` plus an
editable install on first run, then execs `python -m deglyph.cli`.

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
             render.py   colorized disassembly + hexdump (Rich Text)
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

## Architecture — Invariants

### Address model

`Image` works in **virtual addresses** with the image base already applied. LIEF
reports PE export addresses as RVAs; `load_image` adds `base` (`image.py`). When a
detector or the TUI hands an address to `read_va` / `func_at` / `nearest_func`, it
is always a VA. Section raw data is read lazily from disk and cached per section.

### Function identity

`Func` entries are not unique by address — two exports can share one VA (an MSVC
constructor and `operator=`, aliased ISO commands). The function navigator is a
`Tree`, but identity still rides on **row index**, never address: `_apply_filter`
keeps `self._rows` as the flat leaf list in tree order, and each leaf `TreeNode`
carries `data = <index into self._rows>` (group folders carry `data is None`).
`_current()` reads the highlighted leaf's `data` into `self._rows`. `func_at(va)`
returns the last `Func` registered at that exact VA; `nearest_func(va)` returns the
greatest `Func` at or below `va` for symbolizing arbitrary offsets.

### Thunk resolution stops at the implementation

`thunk_chain` (`xref.py`) resolves an exported wrapper to the function that does
the work. It follows tail-`jmp` thunks, and for argument-marshalling wrappers it
follows the last in-image `call` — but it **stops at the first function with a
body**, decided by `_has_body`. A body is either an immediate memory store
(structured-buffer build) or an immediate-into-register-then-`call` (the
command-dispatch idiom). Without this stop the chain descends past the
implementation into its CRC/transport sub-helpers and the opcode is lost.

### Architecture drives the disassembler

`Disassembler` maps `Arch` to a Capstone mode at construction (`disasm.py`).
PE32 is `CS_MODE_32`, PE32+ is `CS_MODE_64` — a 32-bit DLL decoded in 64-bit mode
produces plausible-looking garbage, so the detected/forced arch must be correct.
`load_image(..., arch=...)` overrides detection; the CLI exposes `--arch`.

### Value extraction has one string engine

`re/strings.py` is the single extractor: `string_runs(data, *, min_len)` yields ASCII +
UTF-16LE runs, and **`scan.py` consumes it too** (do not add a second extractor).
`extract_strings(image)` maps runs to VA + section (TUI Strings tab, `--strings`);
`referenced_data(image, va)` resolves the strings / tables / pointer constants a function
points at (x86 rip-relative / absolute operands and pointer immediates, as a string or hex
preview), returning `[]` on non-x86. The Strings tab list is lazy + cached in `_strings_cache`
(reset in `_load_binary`).

### The detectors are heuristics, not proofs

`immediate_stores`, `call_immediate_args`, and `detect_crc_loops` point at the
right instructions; they do not certify behavior. Two consequences:

- A `mov [buf+2], 0x04` store is reported as a structured field write, not proven
  to be a command opcode. The disassembly view is one keystroke away to confirm.
- CRC detection finds clean unrolled bit loops (reports candidate polynomial and
  init) but misses register-folded variants. When the CRC panel is empty,
  `find_immediate(poly)` still locates the routine.

State these limits when reporting a finding. Do not present a detector hit as a
verified fact.

### The function navigator is a grouped tree

The left pane is a `Tree` (`#functions`, `show_root=False`). `_apply_filter` runs the kind +
fuzzy filter, then `_group_funcs` (a pure, unit-tested helper) arranges leaves into two levels:
**kind** (Exports / Entry / Symbols / Subs / Imports / Other, `_KIND_GROUPS` order), then a
**name prefix** (`_group_key`: C++ `Class::`, a leading `_`/`.` token, or an import's library).
`sub` functions list flat under their kind; a single-member group (and the `(top level)`
bucket) collapses to a bare leaf so the user never expands a folder of one. Folders show a
count; renames flow in via `names` so grouping tracks the displayed name. `_KIND_GROUPS` maps
each kind to `(order, label)` — group order and the kind cycle both read its order field, so
adding a kind is one entry.

### TUI render ownership

The detail panes have one writer path: `on_tree_node_highlighted`. A group folder carries
`node.data is None`, so highlighting/expanding one renders nothing (the `data is None` guard).
It also guards on `item == _last_rendered_item` so a spurious same-item highlight can't clobber
an explicit `goto`/`follow` view. `goto` edits the search box programmatically, so it sets
`_input_locked` to drop the queued `Input.Changed` events that would re-filter the tree.

Address navigation funnels through `_goto_address(addr)`: the goto input handler and the
clickable-disassembly path both call it. `render.disasm_text` attaches a `{"@click":
"app.goto_addr(<va>)"}` meta to any branch/call operand whose target is inside `image.text`;
Textual routes it to `action_goto_addr` → `_goto_address`. Keep new jump entry points on this
method so the selection + `_pending_highlight` contract stays in one place. The single cursor
primitive after a rebuild is `_select_func_node(va)` (expands ancestors, selects, scrolls via
`_va_nodes`); goto / follow / rename / bookmark / discovery all rebuild then call it — never
`move_cursor(row=i)`.

### Pseudo-C and the call tree share the detectors' limits

`pseudo_c` (`re/pseudo.py`) is a linear, x86-only annotation of the disassembly,
not a decompiler — no type recovery, no CFG structuring. It returns `[]` on non-x86
targets. `call_tree` (`xref.py`) is cycle-safe and bounded by `depth`/`max_children`/
`budget`; a stopped branch is marked `elided`, not dropped. Both are heuristics —
report them as such, same as the pattern detectors.

### Function discovery fills the tree for stripped binaries

A release EXE exports nothing and is symbol-stripped, so `load_image` yields only
`entry` + import thunks. `discover_functions` (`re/discover.py`) scans executable
sections once for direct `call` targets and adds `sub_<va>` Funcs (kind `"sub"`),
caching via an `_discovered` flag. The CLI and TUI run it after load (default on,
`--no-discover` to skip). It is what makes clicks land, xrefs/analysis reachable,
and the call graph populated on binaries like `notepad.exe`. Heuristic: misses
indirect/tail-call-only functions.

### Detail tabs track the selection; large disasm is windowed

`_show_for` renders Disasm + Info and calls `_refresh_active_tab`, which re-renders
whichever of Xrefs/Analysis/Pseudo/Graph is active — moving the tree selection
updates the visible tab, not just Disasm. `_render_disasm` windows functions larger
than `_DISASM_WINDOW` (around the highlight) so a single huge `Static` never stalls
the UI; `goto` moves the window.

### Theming goes through Textual theme variables

`style.tcss` references `$primary`/`$surface`/`$panel`/`$accent`/`$boost`/`$text-muted`
etc. — never hardcoded hex — so the command palette's theme switcher recolors the
chrome. `DEGLYPH_THEME` (registered + set in `on_mount`) is the default retro
"TVA terminal" palette: amber/brass/cream on warm brown-black. Pane *content* (Rich
Text built in `render.py`/`app.py`) still uses literal accent colors; the
`render.py` palette constants are kept in sync with the theme by hand. Converting
them to theme variables is future work.

### The call-graph navigator caps at 7 nodes

`_render_graph` centers on `_graph_va`: up to `_GRAPH_SLOTS` callers above and
callees below (center + 3 + 3 = 7 max). A group with more shows a pager node
(`app.graph_page`); clicking any node fires `app.graph_center(<va>)` -> `_graph_recenter`.
Clicking does not move the table cursor, so it can't loop with `_refresh_active_tab`.

### Discovery runs off the UI thread

A large `.text` scan (Capstone decodes every byte) can take tens of seconds, so the
TUI runs `scan_call_targets` on a `@work(thread=True)` worker and applies
`add_discovered` on the UI thread via `call_from_thread` (`_discover_worker` /
`_discovery_done`). The scan is read-only (safe while the main thread reads the same
image); only the apply mutates `image.funcs`. Headless/`discover_functions` stays
synchronous. Never move the mutate step into the worker — concurrent `funcs` mutation
races the table build.

The function tree is **blank while discovery runs**, not partial. While the worker runs
(`_discovery_running`), `_apply_filter` passes `disabled=True` to `_build_functions_section`,
which **returns early before building any rows** — `_rows` / `_va_nodes` stay empty and
`_select_func_node` has nothing to select until the rebuild. `_start_discovery_spinner` ticks
a `SPINNER` in `#status` and on a placeholder leaf at the tree bottom (`_tick_discovery`); `#search`
is hidden. `_apply_filter` re-adds the placeholder while `_discovery_running`, so a mid-discovery
rename / bookmark / strings ingest doesn't lose it.

`_discovery_done` calls `_stop_discovery_spinner` **first** (`_discovery_running = False`, timer
stopped, placeholder removed, `#search` shown), captures `keep = _current_item()`, applies
`add_discovered`, and rebuilds via `_apply_filter` **unconditionally** — the initial build was
skipped, so rows must be built now even when discovery found no new subs (a stub-only binary) —
then restores via `_select_item(keep)`. Tests must `await app.workers.wait_for_complete()`
before reading `_rows` (`_settle_discovery` in `tests/test_tui.py` wraps it).

### Command palette preserves yield order

Textual's `SystemCommandsProvider.discover()` sorts `get_system_commands` alphabetically
by title. `app.py` ships `_OrderedSystemCommands` (subclass overriding `discover` to skip
the sort), wired in via `DeglyphApp.COMMANDS = {_OrderedSystemCommands}`; `search` is left
to the parent so a query still ranks by fuzzy score. The menu then matches the yield order:
About, Keys, AI provider…, Theme, Maximize, Screenshot, Quit.

### Tree opens with the binary leaf selected; expansion survives rebuild

On `_load_binary`, after `_build_table` the cursor moves to the Binary leaf
(`_select_item((_ITEM_BINARY, None))`), so the right pane lands on the file overview
(`_render_binary_info`) instead of a blank disasm; `_select_node` expands ancestors, opening
the Binary folder.

`_apply_filter` runs `_snapshot_expansion` before `tree.clear()` and `_restore_expansion`
after. The snapshot is a `set[tuple[str, ...]]` of label-path tuples with the count suffix
stripped (`_COUNT_SUFFIX_RE`, `"Exports (42)"` → `"Exports"`) so a count change still matches
the folder. Discovery, rename, bookmark, context choice, and strings ingest all rebuild
through `_apply_filter`, preserving expansion in one place. Selection preservation sits at each
caller: capture `keep = self._current_item()` before `_apply_filter`, restore with
`_select_item(keep)` after. New rebuild call
sites must do the same, or the cursor jumps.

### Annotations are an app-level overlay, persisted to a sidecar

`store.py` holds renames/notes/bookmarks keyed by VA at
`~/.deglyph/annotations/<sha1(abspath)>.json` (or `$DEGLYPH_STORE_DIR`); load/save are
best-effort, degrading to empty on a malformed sidecar. The app reads them through
`_disp(func)` (rename-or-display) and passes `names=` into `render.disasm_text` — new label
sites use `_disp`, not `func.display`, so renames show everywhere. Single-line edits (goto/
rename/note) funnel through the search box (`self._prompt` + `_handle_prompt`, which restores
focus). On startup `_maybe_prompt_context` peeks the sidecar and, if non-empty, pushes the
`ContextPrompt` modal (load → adopt + `_apply_filter`; discard → stay empty). Edits persist
immediately; `action_quit` flushes via `_autosave`, which only writes when the context is
non-empty (`is_empty()` counts `chats`), so discard-then-quit never clobbers the saved file.

### Startup runs through the welcome screen

`DeglyphApp(path=None, *, welcome=True)`. With `welcome=True` (the CLI default, even with a
file) `on_mount` pushes `WelcomeScreen`: logo, tagline, and an `OptionList` of recent sessions
(`store.list_sessions()`) plus "Open a file…" (a `FilePicker` over Textual's `DirectoryTree`);
a given file is a "Continue" entry on top. It dismisses with `(path, restore)` → `_on_welcome`
→ `_load_binary`. `restore=True` (a picked session) adopts annotations and rehydrates chats
directly; otherwise `_maybe_prompt_context` offers load/discard. Tests use
`DeglyphApp(path, welcome=False)` to skip the welcome. `deglyph` with no binary launches here;
`--list`/`--analyze` still require one. The logo is `logo.LOGO` (Unicode) with `LOGO_ASCII`
fallback via `wordmark()` / `glyphs._ascii_mode()`.

### Preferences persist via config.py

`on_mount` restores `config.get("theme", "deglyph")` and subscribes to
`theme_changed_signal` to `config.put` changes (`~/.deglyph/config.json`,
`$DEGLYPH_STORE_DIR`-aware). `config.py` is for small global prefs — distinct from per-binary
annotations (`store.py`) and the auth token (`account.py`). The `FilePicker` browses above its
root via `_set_root` (Backspace `action_up` and the path Input). Subcommands (`scan`/`login`/
`logout`) are in the parser epilog so `deglyph -h` documents them though they dispatch before
argparse.

### The header is a custom one-line bar

`_HeaderBar` (a `Horizontal`) replaces Textual's `Header`: a menu glyph (`#hdr-menu` →
`app.command_palette`), title (`#hdr-title`), nav controls (`#hdr-nav`, by `_refresh_toolbar`),
and clock (`#hdr-clock`). No tall-toggle, so it can't expand. The screen tiles edge to edge
(header row 0, footer last, body `1fr`) — keep it full-bleed, no margins/padding on the shell
containers.

### TUI glyphs are a three-tier cascade

`glyphs.G` resolves once at import to one of three tiers: **ASCII** (`$DEGLYPH_ASCII`
or non-UTF-8 stdout), **Nerd Font** (`$DEGLYPH_NERD`, Font Awesome glyphs in the PUA;
overlays Unicode so any name it omits falls back), else **Unicode** (the safe default,
no emoji). `_ASCII` must define every key `_UNICODE` does (`G[...]` never KeyErrors);
`_NERD` is an overlay subset. Nerd never wins over ASCII (`_nerd_mode` is gated on
`not _ascii_mode`). The CLI's `--ascii` / `--nerd` set the env vars before import. Add
new glyphs to all relevant tiers and reference `G[...]`, never a bare Unicode literal.

### Navigation history funnels through `_record_nav`

The nav controls live in the header (`#hdr-nav`, written by `_refresh_toolbar`):
back/forward over a browser-style jump stack (`_nav_history` + `_nav_pos`), plus
`recent`/`chats` `NavMenu` pickers (faded when empty: `recent` until there is
history, `chats` until `_chat_vas()` is non-empty). Deliberate jumps (`_goto_address`
and `action_follow`) call `_record_nav(dest)`, which also captures the origin (so back
returns there); cursor scrolling does **not** record (IDA-style). Replays go through
`_nav_to`, which sets `_nav_lock` so `_goto_address` does not re-record them. New jump
entry points should call `_record_nav` and end on `_goto_address`.

### AI replies render markdown; the chat persists

Replies render through `_markdown` (headings, bullets, `code`, **bold**, *italic*), keeping
the `sub_`/`0x` linkification (`_linkify`); underscore emphasis is unsupported so snake_case
stays literal. Each function's chat is cached by resolved-impl VA (`_ai_sessions`) and
**persisted** to the sidecar (`Annotations.chats`): `_collect_chats` → `_serialize_messages`
to JSON-safe dicts, `_persist_chats` after each reply (crash-safe), and loading rehydrates via
`_transcript_from_messages`. The local Anthropic client uses a per-request timeout
(`DEGLYPH_AI_TIMEOUT`, default 90s) so a stall errors instead of hanging.

### A reply is bound to the function it was asked about

A question can outlive the selection. `_ask_ai(origin, question)` captures the origin VA and
runs on a **dedicated assistant copy** (`_assistant_for`), seeded with that function's context
and history, so switching functions (which re-points `self._assistant` via `set_context`)
can't corrupt the in-flight conversation. `_ai_reply` routes by origin: it appends to that VA's
transcript (`_ai_log_for` returns the live `_ai_log` if displayed, else the session's own
`Text`) and writes messages back to `_ai_sessions[origin]` — never append to `self._ai_log`
from the worker path. If the origin is still shown it refreshes the pane and stops the spinner;
otherwise it `notify`s and leaves the pane alone. The spinner is per-displayed-VA
(`_ai_sync_context` starts it only when the shown VA is in `_ai_pending`). Workers share
`group="ai-ask"` (not `exclusive`), so questions on different functions run concurrently.

### The assistant is opt-in, agentic, and isolated

`ai.py` is the only module that touches the network, only inside `Assistant.ask`, which the
TUI runs on a `@work(thread=True)` worker; it never sends until the user asks. `ask` runs an
**agentic loop** (`_run_loop`, capped at `_max_tool_iters()`, default 24,
`DEGLYPH_AI_MAX_ITERS`): the model calls read-only tools (`find_function`, `list_functions`,
`disassemble`, `pseudo_c`, `analyze`, `xrefs`, `search`) over the bound `Image` (`bind_image`),
`on_event` firing per call for TUI progress. The selected function's disassembly is one cached
`system` block (`cache_control: ephemeral`); the agent roams via tools. When the budget runs
out with a tool call pending, the bare tool-use turn would render empty, so a final
`_force_summary` round **keeps `tools` defined but sets `tool_choice={"type": "none"}`** (the
history holds `tool_use` blocks the API rejects when `tools` is absent). The summary nudge
rides inside the last user turn to keep roles valid; the OpenAI adapter re-emits it as a
trailing user message and maps `{"type": "none"}` → `"none"`. `ask` floors the reply to a
non-empty string. `anthropic` is a runtime dependency (declared in
`[project.dependencies]`), but it is still imported lazily and `unavailable_reason()` keeps the
missing-package guard — keep `core`/`re`/the base TUI importable without it. Default model
`DEFAULT_MODEL` (`claude-opus-4-7`),
override via `DEGLYPH_MODEL`.

### The assistant is provider-agnostic

`provider()` returns the selected *key* (`anthropic` default, `openai`, `groq`, `openrouter`,
`deepseek`, `ollama`, `lmstudio`, or a custom key) from `config.get("ai_provider")` /
`$DEGLYPH_AI_PROVIDER`. `provider_family()` maps it to the request *shape* (**anthropic** or
**openai**) via the `PROVIDERS` registry (unknown key → openai-compatible). Route every backend
decision off `provider_family()`, never `provider() == "openai"` (that breaks `groq`/
`openrouter`, openai-family under a non-`openai` key). `PROVIDERS` (`ai.py`) is the single
source for each provider's label/family/default base URL/model menu (`known_providers()`,
`provider_info(key)`). The palette's "AI provider…" → `AISettingsScreen` wires provider/model/
base-URL `Select`s (a `CUSTOM` sentinel reveals a free-text model Input); save writes
`ai_provider` / `ai_base_url` / `ai_model`.

`Assistant.model` is a property: a ctor `model=` / `$DEGLYPH_MODEL` pins it; else the
**anthropic** family resolves `config.get("ai_model")` (→ `DEFAULT_MODEL`), so the dropdown
drives it. The **openai** family ignores `.model` and carries its model via `openai_config()`.
`OpenAIBackend` POSTs to any OpenAI-compatible `/chat/completions` (stdlib `urllib`, no SDK),
configured by `openai_config()` (`DEGLYPH_AI_BASE_URL` / `DEGLYPH_AI_MODEL` /
`DEGLYPH_AI_API_KEY`); `_to_openai_messages` / `_to_openai_tools` / `_from_openai` translate to
OpenAI and back into a `_HostedResponse`, leaving `_run_loop` unchanged. Keep new request
fields flowing through both adapters.

### Open-core: route to a backend, gate a service

`_create(**kw)` picks the backend for one round-trip: **injected client** (tests) > **hosted**
(`HostedBackend`, when `account.load_token()` returns a token) > **local BYO-key**
(`_ensure_client`, needs `ANTHROPIC_API_KEY`). `HostedBackend` is a thin stdlib-`urllib` POST
to `account.api_url()` (`api.deglyph.dev`) carrying the token; the server runs the model with
its own key and enforces entitlement. `_HostedResponse` / `_HostedBlock` mirror the Anthropic
content-block shape so the loop is backend-agnostic. `unavailable_reason()` is None when a
client is injected / logged in / a key is present, else an actionable string (install
`anthropic`, set the key, or `deglyph login`). This client ships no secrets — the gate is server-side. With
no token and no key the hosted path is dormant.

### The scanner is heuristics, headless, and CI-shaped

`scan.py` reads a loaded `Image` (never executes it) and returns a flat `Finding` list.
`scan_image` runs up to six detectors (secrets + imports always; the rest gated by their
flags/args), ordered by trust: `scan_hardening` (LIEF-flag-driven posture report
covering PE / ELF / Mach-O), `scan_secrets` (a catalog of high-precision provider-token
regexes — AWS / GitHub / GitLab / Slack / Stripe / npm / SendGrid / OpenAI / Telegram / JWT /
private keys — plus a generic credential rule, all always on; an entropy catch-all that is
**opt-in** via `entropy=True` / `--entropy` because on native binaries it fires on build paths
and mangled symbols),
`scan_imports` (a curated capability map: exec / injection / memory-protect / dynamic-load /
network / anti-debug), `scan_fingerprint` (string-signature library identification, returning
`LibHit` records that feed the SBOM emitter and CVE matcher), `scan_cve` (osv.dev lookups
against detected library purls, opt-in via `--cve` because it issues network requests), and
`diff_baseline` (functions/imports here but not in a `--baseline` build). Like the pattern
detectors these are heuristics, not proofs: a credential-keyword hit is a labeled string, an
import hit is a capability not a misuse, a hardening "miss" is an absent flag (not
exploitability), a fingerprint hit is a version string the linker may have lied about.
Hardening + fingerprint default on (high signal); CVE off (network); entropy off (noisy on
native binaries).

The generic credential rule (`secret/credential-keyword`) fires only with evidence of an
actual *value*, never a bare keyword: `_credential_evidence` requires either an assignment
(`password=<value>`, value scored by `_looks_like_secret_value(min_classes=2)`) or the keyword
embedded in a single value-shaped token (`S3cr3t-demo-API-key-...`, `min_classes=3`). Classes
are counted over **alnum only** (`_alnum_classes`: upper/lower/digit) so SCREAMING_CASE
constants, dictionary words with stray punctuation (`"Password`), env-var names
(`AWS_ACCESS_KEY_ID`), and mangled C++ symbols do not register; placeholders (`%{}$<>`) and
paths are rejected outright. The bare-keyword form flooded real-binary scans (167 hits on one
Qt app, all noise) — do not loosen it back to a keyword match.

`scan_image(..., ignore=<set>, ignore_fp=<set>)` drops findings before the sort, so the report
and the exit code agree (filter once, centrally — never per-renderer). `ignore` matches a rule
by exact id or by category prefix when the token ends in `/` (`secret/` suppresses every
`secret/*`); `ignore_fp` matches a finding's `fingerprint_of` hash (sha1 of `rule|message`,
12 hex). The CLI exposes `scan --ignore RULE` (repeatable; comma-separated) and `--ignore-file`
(default `.deglyphignore` in CWD): `load_ignore_file` parses one token per line (`#` comments),
a `fingerprint:` / `fp:` prefix going to the fingerprint set, every other token to the rule
set. `action.yml` exposes the `ignore` and `ignore-file` inputs, threaded into every scan step.

`to_sarif` emits SARIF 2.1.0 from the `RULES` catalog; `to_json` emits a flat findings list
(per-finding `fingerprint` + a level-count `summary`) for jq / custom gates, both selected via
`--format`. The exit code is `worst_level` vs `--fail-on` (default `warning`). `deglyph scan` / `deglyph sbom` dispatch before argparse in
`main()` (`argv[0] in ("scan", "sbom")`), leaving the `deglyph BINARY ...` parser untouched.

### Hardening posture reads LIEF flags, never decodes

`scan_hardening` is the only detector that inspects `image._lief` directly (not the `Image`
projection), because the protections live in container-specific structures LIEF parses. PE
reads `optional_header.dll_characteristics` (DYNAMIC_BASE / NX / GUARD_CF / HIGH_ENTROPY_VA /
NO_SEH) and `load_configuration.se_handler_count`; ELF reads `is_pie`, `GNU_STACK` flags,
`GNU_RELRO` + `BIND_NOW` / `DF_1_NOW` / `DF_BIND_NOW` (RELRO level), and an `AARCH64` GNU
property note (BTI/PAC); Mach-O reads `header.flags` for `MH_PIE` and `has_code_signature` /
`code_signature`. Stack-canary detection is symbol-based across all three (`_CANARY_SYMBOLS`,
`__stack_chk_fail` & friends); on PE it **also** reads the load configuration's
`security_cookie` (`_pe_has_security_cookie`), since a stripped release MSVC build has no
`__security_cookie` symbol yet a non-zero cookie VA still proves `/GS` — without this the
canary check false-reports on every stripped PE. Flag constants (`_PE_DYNAMIC_BASE`, `_MH_PIE`, …) are kept
literal so an older LIEF still works. Every finding is a *missing* protection (clean image →
none): critical misses (no ASLR/DEP/canaries/PIE/RELRO) are `warning` (trips the default
gate), posture improvements (CFG, fortify, high-entropy ASLR, BTI/PAC, unsigned) are `note`. A
new check is a new `RULES` entry plus a format helper; keep the LIEF reads inside the
per-format helpers (each wrapped in try/except), or a stripped/malformed binary explodes at
the dispatcher.

### Library fingerprinting is a curated string catalog

`re/fingerprint.py` matches `SIGNATURES` regexes against the runs `string_runs` yields over the
file bytes. Each `LibSignature` carries one high-signal regex (group 1 = version) and a
`purl_base` like `pkg:generic/zlib`; `scan_fingerprint` returns `LibHit` records (name,
version, purl, offset, snippet) feeding three consumers: `scan_image` (a `lib/detected` note),
`sbom.build_sbom` (components), `cve.scan_cve` (purl queries). Hits dedupe on `(name, version)`
(ASCII + UTF-16 copies fire once). The catalog favors precision: add a signature only after
verifying the string is stable across upstream versions. An empty list means *no catalog
match*, never "self-contained" — say so in reports.

### SBOM emitter: root = scanned binary, components = fingerprint hits

`sbom.py` turns the `LibHit` list into a CycloneDX 1.5 or SPDX 2.3 JSON doc. The root
component/package is the scanned binary (SHA-256 of contents, basename as `name`); each
`LibHit` becomes a `library` component / SPDX package with a purl `externalRef`, and the SPDX
path adds one `DEPENDS_ON` per package back to the root. Versionless hits drop `version` but
keep the bare purl. `build_sbom(path, fmt=...)` accepts `cyclonedx` (+ aliases) or `spdx`,
else `ValueError`; `serialNumber` is a fresh UUID per call (schema requires per-BOM
uniqueness). Never write a root `version` you didn't compute from the binary — an unversioned
root is honest, a guessed one is a false positive.

### CVE matcher hits osv.dev, caches every query, degrades to offline

`cve.py` posts each detected purl to `https://api.osv.dev/v1/query` (stdlib `urllib`) and
caches at `~/.deglyph/cve-cache/<sha1(purl)>.json` (or `$DEGLYPH_STORE_DIR`). TTL 24h
(`$DEGLYPH_CVE_TTL`, seconds); malformed cache reads treat as miss; network failures (URLError
/ TimeoutError / OSError) log and return `[]`, so an offline runner never blocks the gate.
`scan_cve(hits)` emits one `cve/known` finding per CVE per versioned hit (versionless hits
skipped — an unversioned purl isn't actionable); the rule defaults to `error`. Network is
opt-in: `scan_image` calls it only when `cve=True` / `--cve`, so default scans stay local.

### Report renderers share the Finding shape, never re-scan

`report.py` renders `to_markdown(results)` / `to_html(results)` over the same `[(path,
findings)]` list `scan` returns — never re-scanning or loading the image, so text/SARIF/
markdown/HTML stay consistent. Markdown is PR-comment-shaped (`## deglyph scan: <summary>`,
per-file `### path`, severity-grouped bullets, link to `deglyph.dev`); HTML is one
self-contained file (inline `<style>`, no scripts/assets, user data `html.escape`'d). A clean
run still renders a body ("Clean across all scanned files"), because a sticky comment that
goes blank on green looks broken.

### The GitHub Action: gate, summarize, publish, comment

`action.yml` (composite) runs four result surfaces off one scan invocation pattern. (1) The
gating step (`id: scan`) runs `deglyph scan --fail-on <input>`; it resolves an effective SARIF
path (the `sarif` input, or a `$RUNNER_TEMP` default when `upload-sarif` is on) and `echo`s it
to `$GITHUB_OUTPUT` **before** the scan so the upload step finds it even when the gate fails.
(2) A `summary` step (default on, `if: always()`) appends `--format markdown --fail-on never`
to `$GITHUB_STEP_SUMMARY` on every run. (3) An `upload-sarif` step (`if: always()`,
`github/codeql-action/upload-sarif@v3`) publishes to code scanning. (4) The PR-comment steps
(`comment == "true"` **and** `pull_request`) render markdown and update the
`<!-- deglyph-comment -->`-marked comment in place via `actions/github-script@v7` — the marker
keeps it sticky instead of stacking. Contracts: (a) inputs reach the shell via `env:`, never
`${{ }}` into `run:` (injection); (b) every non-gating scan uses `--fail-on never` so a failing
gate still produces its surface; (c) the always-run surfaces (`summary`, `upload-sarif`) use
`if: always()` so the failing gate doesn't abort them; (d) `upload-sarif` needs the caller's
job to grant `security-events: write`, `comment` needs `pull-requests: write` (documented in
the header + `examples/deglyph-scan.yml`). Inputs mirror the CLI flags (`cve`, `no-hardening`,
`no-fingerprint`, `ignore`, `ignore-file`).

### The help manual is a JSON-indexed Markdown set

`doc/help/help.json` is an array of `{id, title, section, file}` objects; each `file` is a
sibling Markdown entry. The website (`deglyph-re/website`, separate repo) renders it through
`docs.html`, which fetches `help.json` + the Markdown from this repo's GitHub raw URL at runtime
(client-side Showdown + highlight.js + mermaid, hash routing `#id`, section-grouped sidebar) —
the same pattern serial-studio.com uses against Serial-Studio's `doc/help`. Contracts when
editing the manual: (1) every `help.json` `file` must exist and every entry needs a unique `id`;
(2) cross-link entries by their `file` name (`[Title](Other.md)`), which `docs.html` rewrites to
`#id` — a `.md` link whose file is not in the index silently fails to rewrite; (3) the prose
follows the same neutral, technical voice as the code comments (no marketing, no first person);
(4) the website resolves the source via the cli repo's `main` branch, so manual edits go live
when pushed. `docs.html` accepts `?base=<url>` to point at a local `doc/help` for preview.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Passing an RVA to `read_va` / `func_at` | Everything is a VA; LIEF RVAs already have `base` added in `load_image`. |
| Keying TUI selection by address | Two `Func`s can share a VA. A leaf's `node.data` is its index into `self._rows`. |
| `move_cursor(row=i)` to select a function | The navigator is a `Tree`. Rebuild via `_apply_filter`, then `_select_func_node(va)`. |
| Rendering a pane when a group folder is highlighted | Folders carry `node.data is None`; the highlight handler ignores them. Only leaf highlight renders. |
| Disassembling a PE32 DLL in 64-bit mode | Set `Arch.X86` (`--arch x86`); Capstone mode follows `Image.arch`. |
| Extending `thunk_chain` to always follow the last call | It must stop at `_has_body`, or it descends into CRC/transport sub-helpers. |
| Reporting a detector hit as a verified opcode/CRC | It is a heuristic. Confirm in disassembly; state uncertainty. |
| Re-rendering a pane outside the node-highlight path | Single writer (`on_tree_node_highlighted`). For a jump, set `_pending_highlight` and let the handler render. |
| Editing the search box in code without locking | Set `_input_locked`; queued `Input.Changed` events carry stale values. |
| `nearest_func` for a call target in `→` symbolization | Use `func_at` (exact); `nearest_func` names an unrelated export. |
| Reporting a `scan` finding as a confirmed secret | Heuristic (regex / keyword / entropy). Say "candidate", not "leak". |
| Loosening `secret/credential-keyword` back to a bare keyword match | It must require a value (`_credential_evidence`); a bare keyword is a field/env-name and floods the report (167 noise hits on one app). |
| Adding a `doc/help` page without updating `help.json` (or vice versa) | The website renders only indexed files; an orphan `.md` is invisible and an index entry with no file 404s. Keep them in sync, unique `id`s. |
| Putting Pro logic or a key in the public client | The gate is server-side; `HostedBackend` is a token-bearing HTTP client only. |
| Routing a backend off `provider() == "openai"` | Use `provider_family()`; `groq`/`openrouter`/`deepseek` are openai-family under a non-`openai` key. |
| Enabling the entropy rule by default | Noisy on native binaries; keep it behind `--entropy` / `entropy=True`. |
| Recording nav history on cursor scroll | Only deliberate jumps record (`_record_nav`); scrolling must not, or back/forward is useless. |
| Saving raw SDK/hosted message objects | Run through `_serialize_messages` first; raw blocks aren't JSON-serializable. |
| Adding a glyph to only the Unicode tier | `_ASCII` must define every key or `G[...]` KeyErrors in `--ascii`; Nerd entry only if an icon helps. |
| Reporting "no libraries detected" as self-contained | Catalog coverage is limited; absence is silence. Say "no catalog match." |
| Inlining hardening flag reads outside the per-format helper | A malformed PE/ELF explodes at the dispatcher; keep each in its `_hardening_*` helper, try/except. |
| Posting a PR comment without the sticky marker | Without `<!-- deglyph-comment -->`, every push stacks a new comment. |
| Skipping the cache-write in `cve.query_osv` | The 24h TTL is what stops a CI matrix hammering osv.dev; write on every successful query. |
| Adding a rebuild site without capturing selection | Capture `keep = self._current_item()` before `_apply_filter`, restore `_select_item(keep)` after. |
| Snapshotting expansion by raw label | Labels carry trailing `(N)` counts; `_node_key` strips the suffix — don't bypass it. |
| Forgetting to stop the discovery spinner on early return | `_stop_discovery_spinner` must run before any path touching `#functions`, or the tree stays disabled. |

## Code Style

`black` is the formatter; its output is the contract. Beyond that:

- Type hints on public functions; `from __future__ import annotations` at the top.
- Dataclasses with `slots=True` for value types (`Func`, `Insn`, `Store`, `Hit`).
- Guard clauses over nested branching; keep nesting shallow.
- Catch and continue around per-instruction / per-section decode so one bad
  region never aborts a whole-image scan.

### Comments

Code is the spec. Comments label sections and explain non-obvious choices; they
do not narrate.

- **Module docstring**: one paragraph stating what the module provides, then a
  short list of the public names if there is more than one. No tutorial voice.
- **Function docstring**: one line of intent; add a short paragraph only when the
  contract or an edge case is not obvious from the signature.
- **In-body**: a one-line `#` header **on its own line above** the block it
  explains. **No same-line / trailing comments** (`x = 1  # ...`) — put the note
  on the line above instead. The only exception is a tool directive that must sit
  on its line (`# noqa`, `# type:`, `# pragma`, `# fmt:`, `# verify:`). No
  restating the code. `scripts/verify.py` flags trailing comments (`inline-comment`).
<!-- verify off -->
- **Forbidden**: first-person ("we", "I"), "Note that", "used to", tutorial
  voice, marketing adjectives. ASCII only in user-facing Markdown; code comments
  may use `->` arrows and box characters where they aid a diagram.
- **No `--` as a sentence dash.** It is a robotic em-dash substitute. Rewrite the
  sentence with a comma, colon, period, or parentheses instead. `verify.py` flags
  it (`dash-substitute`). The point of the rule is human, considered prose, not a
  mechanical swap of one dash glyph for another.
<!-- verify on -->

`scripts/verify.py` enforces this contract. Run `python3 scripts/verify.py`
before a commit; wrap a region that must quote a forbidden phrase (like the line
above) in `<!-- verify off -->` / `<!-- verify on -->` (Markdown) or
`# verify: off` / `# verify: on` (Python).

## Adding a detector

A new pattern detector lives in `re/patterns.py`, returns a list of `slots=True`
dataclass records (address + decoded fields), and takes `(image, va, *, max_insns)`.
Export it from `re/__init__.py`, render it in `app.py:_render_analysis` and in
`cli.py:_headless`, and add a case in `tests/` that asserts against a known function.
Prefer asserting against `samples/demo.exe` (committed, runs in CI; see
`tests/test_scan.py` / `test_deglyph.py`) or a synthetic blob via the `code_image`
fixture (`tests/conftest.py`); guard host-binary cases with a skip when absent.

## Adding a container format or architecture

LIEF already parses PE/ELF/Mach-O and fat binaries. To support a new architecture,
add it to `Arch`, map it in `disasm.py:_ARCH_MODE`, and extend
`image.py:_detect_arch`. The rest of the pipeline is arch-agnostic except the
x86-specific operand inspection in `patterns.py` and `search.py` (Capstone's
`x86` operand API) — a non-x86 target needs its own operand walk there.
