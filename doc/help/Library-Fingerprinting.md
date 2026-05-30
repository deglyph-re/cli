# Library Fingerprinting

The fingerprint detector identifies third-party libraries statically linked into
a binary, by matching version strings the libraries leave in their code. It runs
by default in `deglyph scan`, and its results feed both the
[SBOM emitter](SBOM.md) and the [CVE matcher](CVE-Scanning.md).

## How it works

A curated catalog of signatures is matched against the strings extracted from the
binary. Each signature is one high-precision regular expression with a capture
group for the version, paired with a package URL (purl) base such as
`pkg:generic/zlib`. A match produces a library hit recording the name, the
version, the purl, the byte offset, and the matching string snippet.

Hits are deduplicated on name and version, so the ASCII and UTF-16 copies of the
same banner report once. Common libraries with stable version banners are
covered: compression, crypto, and database libraries among them.

## What a hit is, and is not

A fingerprint hit is a **version string the linker stamped into the binary**. It
is strong evidence the library is present, but it is not a build manifest:

- A vendor can patch a library without changing its version string, so the
  reported version may understate what was actually built.
- A version string is the library's own claim; nothing forces it to be truthful.

The catalog favors precision over breadth. A signature is added only after the
string is verified stable across upstream versions, to avoid false matches.

## Absence is silence, not proof

An empty result means **no catalog match**, not that the binary is
self-contained. The library may not be in the catalog, or may not emit a
recognizable banner. When you report results, say "no catalog match", never "no
third-party libraries". See [Heuristics, Not Proofs](Heuristics.md).

## Where hits go

- The scan emits a `lib/detected` note per identified library.
- `deglyph sbom` turns the hits into a [bill of materials](SBOM.md).
- With `--cve`, each versioned hit is queried against
  [osv.dev](CVE-Scanning.md).

## See also

- [Software Bill of Materials](SBOM.md): exporting the hits as CycloneDX / SPDX.
- [CVE Scanning](CVE-Scanning.md): matching versions against known CVEs.
- [Scanning Binaries](Scanning.md): the scanner overview.
