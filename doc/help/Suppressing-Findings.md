# Suppressing Findings

Real projects accumulate findings that are understood and accepted: a credential
keyword that is really a struct field, an unsigned internal build, a library the
team has already reviewed. Suppressing these keeps the scan meaningful and the
gate green on known-good builds. Suppression is applied
centrally, so the report and the exit code always agree.

## Ignore by rule

Use `--ignore` to drop findings by rule id. It is repeatable, and each value may
be comma-separated:

```bash
deglyph scan ./app.exe --ignore secret/credential-keyword
deglyph scan ./app.exe --ignore harden/unsigned,import/network
```

A token ending in `/` suppresses an entire category:

```bash
deglyph scan ./app.exe --ignore secret/      # every secret/* rule
```

## Ignore by fingerprint

Each finding has a stable **fingerprint**: a short hash of its rule and message,
independent of the file offset. Suppressing by fingerprint silences one specific
finding while leaving every other instance of the same rule active. Fingerprints
are shown in the [JSON output](Output-Formats.md):

```bash
deglyph scan ./app.exe --format json | jq '.files[].findings[] | {rule, fingerprint}'
```

## The `.deglyphignore` file

For a baseline you commit to version control, place a `.deglyphignore` file in
your repository. `deglyph` reads it from the working directory automatically, or
from an explicit `--ignore-file PATH`. One token per line; `#` starts a comment:

```
# Reviewed and accepted for this project.
harden/unsigned                 # internal build, signed at release
secret/credential-keyword       # protobuf field names, not secrets

# Suppress one specific finding by its fingerprint:
fingerprint: 7eaac1ea4ff8
```

A line beginning `fingerprint:` (or `fp:`) suppresses a single finding by its
hash. Every other line is a rule id or a category prefix, matched exactly as
`--ignore` does. Tokens from the file and from `--ignore` are merged.

## Suppression and the exit code

Suppressed findings are removed before the worst-level is computed, so a
suppressed `warning` cannot fail the gate. This is deliberate: a baseline you
have accepted should not block the pipeline. Keep the file under review so it
does not quietly grow to hide new, real findings.

## See also

- [Scanning Binaries](Scanning.md): the scanner and its `--fail-on` gate.
- [Output Formats](Output-Formats.md): where fingerprints are surfaced.
- [The GitHub Action](GitHub-Action.md): the `ignore` and `ignore-file` inputs.
