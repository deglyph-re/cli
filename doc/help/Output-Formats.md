# Output Formats

`deglyph scan` renders its findings in six formats, selected with `--format`.
Every format is built from the same finding list, so they stay consistent. Write
to a file with `--output PATH`, or let the report go to standard output.

```bash
deglyph scan ./app.exe --format json --output findings.json
```

## text (default)

A human-readable report, one section per scanned file, with a level, location,
rule id, and message per finding. This is what you read in a terminal or a raw
CI log.

## json

A flat, machine-readable document for `jq`, custom gates, or other tooling. Each
finding carries its rule, level, message, location, byte offset, and a stable
`fingerprint`. A `summary` block totals findings by level for a quick gate:

```bash
deglyph scan ./app.exe --format json | jq '.summary'
# { "files": 1, "findings": 5, "error": 0, "warning": 2, "note": 3 }
```

The fingerprint is the value a [`.deglyphignore`](Suppressing-Findings.md)
`fingerprint:` line suppresses.

## sarif

SARIF 2.1.0, the format GitHub code scanning ingests. Uploading it surfaces
findings as alerts in the repository Security tab, annotated against the file.
`--sarif` is a shorthand kept for older configurations:

```bash
deglyph scan ./app.exe --format sarif --output deglyph.sarif
```

[The GitHub Action](GitHub-Action.md) can upload this for you.

## markdown

A pull-request-shaped report: a summary heading, a section per file, and findings
grouped by severity. This is what the Action posts as a sticky PR comment and
writes to the run summary. A clean run still renders a short body, so a sticky
comment never goes blank and looks broken.

## html

A single self-contained HTML file with inline styles and no external assets, for
publishing a scan as a browsable dashboard. User-supplied strings are escaped.

## badge

A [shields.io endpoint](https://shields.io/badges/endpoint-badge) object summarizing the run: `clean` in green, otherwise a worst-first count of findings colored by the worst level. Publish it and embed a live badge that tracks your latest scan.

```bash
deglyph scan ./app.exe --fail-on never --format badge --output deglyph.json
```

See [Badges](Badges.md) for the full publish-and-embed walkthrough.

## See also

- [Scanning Binaries](Scanning.md): producing the findings.
- [The GitHub Action](GitHub-Action.md): markdown comments and SARIF upload.
- [Suppressing Findings](Suppressing-Findings.md): using JSON fingerprints.
- [Badges](Badges.md): the `badge` format as a live README badge.
