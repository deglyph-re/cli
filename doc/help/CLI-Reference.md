# Command-Line Reference

`deglyph` has one main command for the interface and headless analysis, plus the
`scan`, `sbom`, `export`, `project`, and `login` / `logout` subcommands.

## `deglyph [binary] [options]`

With a binary, opens the interface on it. With no binary, opens the welcome
screen.

| Option | Description |
| --- | --- |
| `--fmt FMT` | Force container format: `PE`, `ELF`, or `MachO` |
| `--arch ARCH` | Force architecture: `x86`, `x64`, `arm`, `arm64` |
| `--slice N` | Pick a slice of a fat (universal) Mach-O by index (default: host arch) |
| `--list` | Print the function table and exit |
| `--analyze NAME` | Headless [pattern analysis](Pattern-Detectors.md) of a function |
| `--strings` | Print mapped string literals (ASCII / UTF-8 / UTF-16LE) and exit |
| `--strings-all` | With `--strings`: include unmapped runs and section names |
| `--strings-min N` | With `--strings`: minimum run length (default 4) |
| `--strings-section NAME` | With `--strings`: restrict to one section |
| `--no-discover` | Skip `sub_*` [function discovery](Function-Discovery.md) |
| `--json` | Emit `--list` / `--analyze` / `--strings` output as JSON |
| `--ascii` | Use ASCII glyphs (for limited terminals) |
| `--nerd` | Use Nerd Font icons |
| `-v`, `--verbose` | Info-level logging to stderr |
| `--debug` | Debug-level logging to stderr |
| `--version` | Print the version and exit |

```bash
deglyph ./app.exe --list
deglyph ./app.exe --analyze crc16 --json
deglyph ./app.exe --strings | grep -i http
```

## `deglyph scan PATH [options]`

Static scanner for CI. See [Scanning Binaries](Scanning.md).

| Option | Description |
| --- | --- |
| `--baseline PATH` | Diff against a prior build |
| `--fmt`, `--arch` | Force format / architecture |
| `--format FMT` | `text`, `markdown`, `html`, `sarif`, `json`, `badge` |
| `--sarif` | Shorthand for `--format sarif` |
| `--output`, `-o PATH` | Write the report to a file |
| `--entropy` | Also flag high-entropy blobs |
| `--cve` | Query osv.dev for CVEs (network) |
| `--offline` | Never touch the network; report CVEs as not-checked |
| `--no-hardening` | Skip the hardening check |
| `--no-fingerprint` | Skip library fingerprinting |
| `--lib-signatures PATH` | Extra library signature database merged with the built-ins |
| `--ignore RULE` | Suppress a rule or category (repeatable) |
| `--ignore-file PATH` | A `.deglyphignore` file (default: CWD) |
| `--rule-config PATH` | Per-rule level overrides (default: `.deglyphrules` in CWD) |
| `--fail-on LEVEL` | Gate threshold: `note` / `warning` / `error` / `never` |

## `deglyph sbom PATH [options]`

Emit a bill of materials from the libraries fingerprinted in a binary.

| Option | Description |
| --- | --- |
| `--format FMT` | `cyclonedx` (default) or `spdx` |
| `--fmt`, `--arch` | Force format / architecture |
| `--output`, `-o PATH` | Write to a file |

```bash
deglyph sbom ./app.exe --format spdx -o app.spdx.json
```

## `deglyph export PATH [options]`

Emit a versioned JSON analysis document for downstream tooling. See
[Export](Export.md).

| Option | Description |
| --- | --- |
| `--cfg` | Include per-function control-flow blocks (slower, larger) |
| `--max-funcs N` | Cap the per-function sections to the first N functions |
| `--fmt`, `--arch` | Force format / architecture |
| `--output`, `-o PATH` | Write to a file |

## `deglyph project export\|import BINARY -f FILE`

Move a binary's renames, notes, bookmarks, and saved view between machines in a
path-independent file. See [Project Files](Project.md).

```bash
deglyph project export ./app.exe -f app.work.json
deglyph project import ./app.exe -f app.work.json
```

## `deglyph login / logout`

`deglyph login <token>` stores a hosted-AI token for the Pro tier; `deglyph
logout` clears it. See [The AI Assistant](AI-Assistant.md).

## See also

- [Scanning Binaries](Scanning.md): the `scan` subcommand in depth.
- [Export](Export.md): the JSON analysis document.
- [Project Files](Project.md): portable annotations.
- [Keyboard Shortcuts](Keyboard-Shortcuts.md): the interface key map.
- [Getting Started](Getting-Started.md): first steps.
