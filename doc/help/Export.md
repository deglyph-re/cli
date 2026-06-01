# Export

`deglyph export PATH` emits one self-describing JSON document of a binary's whole
analysis, for feeding another tool, archiving a build, or diffing two versions.
The output is deterministic (keyed and sorted by virtual address), so the same
binary always produces byte-identical output.

```bash
deglyph export ./app.exe -o app.analysis.json
```

## What the document holds

| Section | Contents |
| --- | --- |
| `binary` | Name, format, architecture, image base, SHA-256 |
| `functions` | Every recovered function with its kind, confidence, and evidence |
| `xrefs` | Callers and callees per function |
| `detectors` | Immediate stores, constant call args, CRC loops, constants, referenced data, each with its [evidence](Heuristics.md) |
| `strings` | Mapped string literals (ASCII / UTF-8 / UTF-16LE) with section and category |
| `findings` | The [scan](Scanning.md) findings for the binary |
| `cfg` | Per-function control-flow blocks (only with `--cfg`) |

Every detector hit carries a `confidence`, `reasons`, `caveats`, and `support`
block: uncertainty travels with the data, so a downstream consumer never mistakes
a candidate for a proof. See [Heuristics, Not Proofs](Heuristics.md).

## Versioning

The top-level `deglyph_export_version` is bumped only on a breaking change to the
document shape (a removed or renamed field, or a changed meaning); additive fields
do not bump it. Pin your consumer to the major you tested against. A `tool` block
records the producing `deglyph` version.

## Options

| Option | Description |
| --- | --- |
| `--cfg` | Add per-function control-flow blocks. The recursive descent is the slow step, so this is off by default. |
| `--max-funcs N` | Cap the per-function sections to the first N functions; the document then carries a `truncated` block recording the total. |
| `--output`, `-o PATH` | Write to a file instead of standard output. |
| `--fmt`, `--arch` | Force the container format or architecture. |

## See also

- [Command-Line Reference](CLI-Reference.md): every flag.
- [Pattern Detectors](Pattern-Detectors.md): the detector hits in the document.
- [Heuristics, Not Proofs](Heuristics.md): how to read the evidence fields.
- [Software Bill of Materials](SBOM.md): a narrower, standardized export.
