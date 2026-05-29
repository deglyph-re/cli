# Scanning Binaries

`deglyph scan` is a headless static scanner for continuous integration. It reads
a binary (or a directory of binaries) and reports findings across six detectors.
It never executes the target. The exit code is set by the worst finding, so the
command can gate a pipeline.

```bash
deglyph scan ./build/app.exe
deglyph scan ./build/            # every binary under a directory
```

## The detectors

Findings are produced by up to six detectors, ordered by trust:

| Detector | What it reports | Default |
| --- | --- | --- |
| Hardening | Missing ASLR / DEP / CFG / canaries / PIE / RELRO and similar | On |
| Secrets | Embedded credentials and provider tokens | On |
| Imports | Imported APIs granting exec / injection / network capability | On |
| Fingerprint | Third-party libraries linked into the binary | On |
| CVE | Known CVEs against detected library versions (network) | Off |
| Baseline diff | Functions and imports not present in a prior build | Off |

Hardening and fingerprinting are high-signal and default on. CVE lookups query
osv.dev over the network, so they are opt-in with `--cve`. The baseline diff runs
when you pass `--baseline`. An entropy catch-all for opaque blobs is opt-in with
`--entropy` because it is noisy on native binaries.

```bash
deglyph scan ./app.exe --cve --baseline ./previous/app.exe
```

## Severity and gating

Every finding has a level: `note`, `warning`, or `error`. The process exits
non-zero when the worst finding meets or exceeds the `--fail-on` threshold,
which defaults to `warning`:

```bash
deglyph scan ./app.exe --fail-on error    # only errors fail the job
deglyph scan ./app.exe --fail-on never    # never fail; report only
```

## Findings are heuristics

Like the interface's detectors, the scanner reports leads, not proofs: a secret
hit is a candidate, an import hit is a capability rather than a misuse, a
hardening "miss" is an absent flag rather than an exploit, and a fingerprint hit
is a version string the linker may have stamped. Word findings accordingly. See
[Heuristics, Not Proofs](Heuristics.md).

## Detector pages

- [Secret Detection](Secret-Detection.md): provider tokens and the credential rule.
- [Suppressing Findings](Suppressing-Findings.md): `--ignore` and `.deglyphignore`.
- [Output Formats](Output-Formats.md): text, JSON, SARIF, markdown, HTML.
- [The GitHub Action](GitHub-Action.md): wiring it into a pull-request workflow.

## See also

- [Command-Line Reference](CLI-Reference.md): every `scan` flag.
- [Heuristics, Not Proofs](Heuristics.md): how to read a finding.
