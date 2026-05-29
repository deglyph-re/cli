# Common Mistakes

Quick-reference table of recurring pitfalls and their fixes. Full per-subsystem rationale: [Architecture Invariants](architecture.md). Main developer guide: [CLAUDE.md](../../CLAUDE.md).

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
