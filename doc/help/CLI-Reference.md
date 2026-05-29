# Command-Line Reference

`deglyph` has one main command for the interface and headless analysis, plus the
`scan`, `sbom`, and `login` / `logout` subcommands.

## `deglyph [binary] [options]`

With a binary, opens the interface on it. With no binary, opens the welcome
screen.

| Option | Description |
| --- | --- |
| `--fmt FMT` | Force container format: `PE`, `ELF`, or `MachO` |
| `--arch ARCH` | Force architecture: `x86`, `x64`, `arm`, `arm64` |
| `--list` | Print the function table and exit |
| `--analyze NAME` | Headless [pattern analysis](Pattern-Detectors.md) of a function |
| `--strings` | Print extracted ASCII / UTF-16 strings and exit |
| `--no-discover` | Skip `sub_*` [function discovery](Function-Discovery.md) |
| `--json` | Emit `--list` / `--analyze` output as JSON |
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
| `--format FMT` | `text`, `json`, `sarif`, `markdown`, `html` |
| `--sarif` | Shorthand for `--format sarif` |
| `--output`, `-o PATH` | Write the report to a file |
| `--entropy` | Also flag high-entropy blobs |
| `--cve` | Query osv.dev for CVEs (network) |
| `--no-hardening` | Skip the hardening check |
| `--no-fingerprint` | Skip library fingerprinting |
| `--ignore RULE` | Suppress a rule or category (repeatable) |
| `--ignore-file PATH` | A `.deglyphignore` file (default: CWD) |
| `--fail-on LEVEL` | Gate threshold: `note` / `warning` / `error` / `never` |

## `deglyph sbom PATH [options]`

Emit a bill of materials from the libraries fingerprinted in a binary.

| Option | Description |
| --- | --- |
| `--format FMT` | `cyclonedx` (default) or `spdx` |
| `--output`, `-o PATH` | Write to a file |

```bash
deglyph sbom ./app.exe --format spdx -o app.spdx.json
```

## `deglyph login / logout`

`deglyph login <token>` stores a hosted-AI token for the Pro tier; `deglyph
logout` clears it. See [The AI Assistant](AI-Assistant.md).

## See also

- [Scanning Binaries](Scanning.md): the `scan` subcommand in depth.
- [Keyboard Shortcuts](Keyboard-Shortcuts.md): the interface key map.
- [Getting Started](Getting-Started.md): first steps.
