# Function Database

The function database is a corpus of per-function signatures harvested from well-known libraries. With it, `deglyph scan --identify` can name a recovered `sub_<address>` as the library function it matches, the same way [Library Fingerprinting](Library-Fingerprinting.md) names a whole library from its strings.

Each signature is the relocation-stable identity from the analysis core: the function's normalized instruction stream, hashed. A build that only moved a function keeps its signature; a changed body does not. The corpus is rebuilt in CI over many programs and shipped with the tool.

This catalog holds 4418 function signature(s) across 9 library(ies).

## Catalogued libraries

| Library | Version | Ecosystem | Architecture | Functions |
| --- | --- | --- | --- | --- |
| bzip2 | 1.0.8 | generic | x86-64 | 29 |
| curl | (versionless) | generic | x86-64 | 80 |
| expat | 2.6.1 | generic | x86-64 | 30 |
| lz4 | 1.9.4 | generic | x86-64 | 129 |
| openssl | (versionless) | generic | x86-64 | 2398 |
| pcre2 | 10.42 | generic | x86-64 | 43 |
| sqlite | 3.46.1 | generic | x86-64 | 1491 |
| xz | 5.6.1+really5.4.5 | generic | x86-64 | 84 |
| zstd | 1.5.5+dfsg2 | generic | x86-64 | 134 |

## How to read a match

A match is a candidate identification, not a proof. An exact-hash hit is high confidence; a fuzzy hit carries a similarity score. Two unrelated functions can share a normalized shape, so confirm a surprising match in the disassembly. An absent match means the corpus has no entry for that function, never that the function is original.

## See also

- [Library Fingerprinting](Library-Fingerprinting.md): whole-library identification from version strings.
- [Baseline Diff](Baseline-Diff.md): the same signatures power the function-level build diff.
- [Heuristics, Not Proofs](Heuristics.md): how to read a candidate match.
