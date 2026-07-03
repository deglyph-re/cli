# Directory Structure

```
deglyph/
  core/      image.py    LIEF -> Image: base, sections, Func list (export/symbol/import/entry)
             disasm.py   Capstone wrapper: arch map (x86/x64/arm/arm64/riscv), linear func disasm, thunk follow, callees
             demangle.py MSVC/Itanium C++ (via cxxfilt) + Rust legacy hash-strip + Rust v0 (_R) decoder
  re/        search.py   image-wide byte (?? wildcards) / string (ascii+utf16) / immediate search
             strings.py  value extraction: extract_strings (mapped-literals default; ascii/utf-8/utf-16le; category) + referenced_data (per-func, incl. pointer tables)
             xref.py     callers_of + data_xrefs_to / xrefs_to (cached whole-image code+data index), callees_of, thunk -> impl chain, call_tree
             patterns.py immediate_stores / call_immediate_args / detect_crc_loops / constants; every hit carries an Evidence (confidence/reasons/caveats/support)
             pseudo.py   heuristic x86-only pseudo-C (linear annotation, not a decompiler)
             discover.py sub_<va> discovery from Go pclntab names + unwind tables + .text call/tail-jmp targets (scan_targets/add_discovered)
             gosym.py    Go pclntab function-name recovery (go1.2/1.16/1.18/1.20; go_functions/apply_go_symbols)
             unwind.py   authoritative function starts from unwind metadata (Mach-O function-starts / PE .pdata / ELF eh_frame)
             cfg.py      bounded recursive-descent CFG per function (basic blocks + undecoded gaps); backs the linear view
             funcsig.py  content-addressed function identity: normalized-instruction exact hash + n-gram set + Jaccard similarity (the engine)
             funcdb.py   function-level fingerprinting: FuncSignature corpus + identify_functions (sub_ -> "inflate from zlib"); load_func_db merges the bundled data/funcdb.json
             bindiff.py  semantic function diff across two builds (unchanged / modified-with-similarity / added / removed) via funcsig
             fingerprint.py SIGNATURES table + scan_fingerprint -> LibHit list (zlib/openssl/sqlite/...)
  ai.py      agentic Claude assistant (Anthropic SDK, prompt-cached, opt-in); read-only tools over Image
  attest.py  signed, machine-checkable scan provenance: canonical digest + optional ed25519 signature (lazy `cryptography`, the `sign` extra)
  data/      funcdb.json  bundled function-signature corpus (grown and committed by scripts/build_funcdb.py in CI; x86-64 today)
  scan.py    headless CI scanner: hardening / secrets / libs / risky imports / baseline diff / function id (--identify); every Finding has a category (fact/heuristic/policy) + a rule-config (.deglyphrules) overlay
  sbom.py    CycloneDX 1.5 + SPDX 2.3 emitters; root = scanned binary, components = fingerprinted libs
  cve.py     osv.dev client + on-disk cache (~/.deglyph/cve-cache/) keyed by purl, 24h TTL
  cache.py   on-disk analysis cache (~/.deglyph/analysis-cache/) keyed by file sha256 + CACHE_VERSION; cache_get/cache_put/clear_cache, opt-out $DEGLYPH_NO_CACHE. Caches the whole-image passes (strings/xref index/discovery); each pass also takes an optional max_seconds budget returning an uncached partial result
  report.py  to_markdown (PR-comment shaped) + to_html (single-file dashboard) over scan results
  store.py   persistent per-binary annotations (renames/notes/bookmarks/AI chats) -> sidecar JSON; to_knowledge/apply_knowledge share renames keyed by function content hash
  account.py token store + endpoint URL for the optional hosted (Pro) tier
  config.py  tiny persistent app config (e.g. the chosen theme) -> ~/.deglyph/config.json
  tui/       app.py      Textual application; grouped function tree + tabbed detail view
             render.py   colorized disassembly + hexdump + whole-file content map (Rich Text)
             glyphs.py   three-tier glyph table: Nerd Font -> Unicode -> ASCII ($DEGLYPH_NERD/$DEGLYPH_ASCII)
             logo.py     baked ASCII/Unicode wordmark + tagline (welcome screen, About)
             style.tcss  theme (theme variables, not hardcoded hex)
  cli.py     argparse entry point; TUI launch, headless --list/--analyze, `scan`, `sbom`, `export`, `diff`, `knowledge`, `attest`, `verify-attest`, `login`/`logout`
  __main__.py            enables `python -m deglyph`
tests/       test_deglyph.py + per-feature tests (detectors, robustness, cli, render, call_tree, pseudo, ai, tui, store, search, discover, scan, account); test_properties.py (address-model invariants, no generative dep) + test_golden.py vs tests/golden/*.json snapshots (scan JSON / SARIF / export skeleton over demo.exe; regen with DEGLYPH_REGEN_GOLDEN=1)
samples/     demo.c + demo.exe: domain-neutral toy binary committed as a CI fixture (planted secret, crc16, opcode)
             fixture_src.c + build_fixtures.sh: stripped PE/ELF/Mach-O/fat function-recovery fixtures, built (not committed), skipif-absent
doc/help/    the manual: help.json index + categorized Markdown entries (rendered by the website's docs.html)
doc/claude/  developer reference extracted from this file: architecture.md, common-mistakes.md, extending.md, directory-structure.md
scripts/     verify.py (tone/style gate) + benchmark.py (cold-pass timings over a binary; not a pytest test)
             build_funcdb.py (harvest the function-signature corpus from a manifest of binaries) + funcdb_manifest.py (resolve apt + from-source libraries into that manifest on a CI runner)
.github/workflows/  ci.yml (lint/type/tone/test matrix) + build-funcdb.yml (scheduled corpus rebuild, commits to main) + release.yml (tag -> PyPI via Trusted Publishing)
.claude/     settings.json (permissions + hooks), hooks/verify-edit.sh (verify.py on each edit), skills/ (gate, add-detector, new-help-page, release), agents/invariant-reviewer.md
action.yml   composite GitHub Action wrapping `deglyph scan`; examples/deglyph-scan.yml is a consumer workflow
CHANGELOG.md Keep-a-Changelog record; notes accumulate under [Unreleased] and move under the version at release time
deglyph.sh   self-bootstrapping launcher; deglyph.bat is the Windows equivalent
```
