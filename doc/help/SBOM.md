# Software Bill of Materials

`deglyph sbom` emits a software bill of materials for a binary: the scanned file
as the root, and the [fingerprinted libraries](Library-Fingerprinting.md) as its
components. It produces CycloneDX or SPDX, the two formats supply-chain tooling
consumes.

```bash
deglyph sbom ./app.exe --format cyclonedx -o app.cdx.json
deglyph sbom ./app.exe --format spdx       -o app.spdx.json
```

## What the document contains

- **Root.** The scanned binary, identified by the SHA-256 of its contents and its
  basename. The root carries no guessed version: `deglyph` reports a version only
  when it computes one, and an unversioned root is honest where a guessed one
  would be a false positive.
- **Components.** One entry per fingerprinted library, each carrying a package URL
  (purl) so downstream tooling can resolve it. A library detected without a
  version keeps its bare purl and omits the version field.

The SPDX output additionally records a `DEPENDS_ON` relationship from the root to
each library. Every document gets a fresh unique serial number, as the schemas
require per-document uniqueness.

## Formats

| `--format` | Output |
| --- | --- |
| `cyclonedx` (default) | CycloneDX 1.5 JSON |
| `spdx` | SPDX 2.3 JSON |

## What it can and cannot tell you

An SBOM from a binary is only as complete as the fingerprint catalog. It lists the
libraries `deglyph` could identify from their version strings; it is not a build
manifest and will not include a statically linked library that emits no
recognizable banner. An empty component list means "no catalog match", not "no
dependencies". See [Library Fingerprinting](Library-Fingerprinting.md) and
[Heuristics, Not Proofs](Heuristics.md).

## See also

- [Library Fingerprinting](Library-Fingerprinting.md): the source of the components.
- [CVE Scanning](CVE-Scanning.md): matching those components against CVEs.
- [Command-Line Reference](CLI-Reference.md): the `sbom` subcommand.
