# FAQ

## Does deglyph run the binary?

No. Every stage is read-only: `deglyph` parses the container, disassembles on
demand, and runs static detectors. It never executes the target, including in the
`scan` subcommand.

## Which formats and architectures are supported?

PE, ELF, and Mach-O containers, including fat binaries. Architectures: x86,
x86-64, ARM, AArch64, and RISC-V (RV32 / RV64). The pattern detectors and
referenced-data view run on x86, x86-64, AArch64, and 32-bit ARM; on RISC-V the
disassembly renders but the detectors report nothing, and the pseudo-C view
stays x86-only. Managed formats (.NET, JVM) are out of scope. See
[Loading Binaries](Loading-Binaries.md).

## The function tree is almost empty. Why?

The binary is probably a stripped release build that exports nothing. `deglyph`
recovers unexported functions by scanning for direct call targets, but that
misses functions reached only indirectly or by tail call. See
[Function Discovery](Function-Discovery.md).

## The Go binary shows real names even though it is stripped. Why?

A Go binary keeps a function table (the pclntab) that names every function, so
`deglyph` reads names like `main.main` and `net/http.(*Server).Serve` straight
from it. C and C++ builds have no such table, which is why they show `sub_*`
instead. Rust symbols are demangled too, including the v0 scheme; a symbol that
cannot be decoded with certainty is shown raw rather than guessed.

## A CRC routine exists but the Analysis panel is empty.

CRC detection recognizes clean unrolled bit loops and misses register-folded
variants. When the panel is empty, search for the known polynomial as an
immediate to locate the routine, then read it in the
[disassembly](Disassembly.md).

## The scan reports a secret that is not one.

Secret findings are candidates from pattern matching, not verified leaks. If a
hit is a known false positive, suppress it by rule or by fingerprint. See
[Secret Detection](Secret-Detection.md) and
[Suppressing Findings](Suppressing-Findings.md).

## The scan keeps failing my build on accepted findings.

Commit a `.deglyphignore` file listing the rules, categories, or fingerprints
your team has reviewed, or raise the gate with `--fail-on`. Suppressed findings
are removed before the exit code is computed. See
[Suppressing Findings](Suppressing-Findings.md).

## Does deglyph need an API key?

No. The interface and the scanner work entirely offline with no account. Only the
optional [AI assistant](AI-Assistant.md) needs a model: either your own API key
or a hosted token. CVE scanning needs network access to osv.dev, and is opt-in.

## How does it run in CI?

Use `deglyph scan` directly, or the bundled GitHub Action. The Action gates the
job, writes a run summary, and can upload SARIF to the Security tab and post a
pull-request comment. See [The GitHub Action](GitHub-Action.md).

## See also

- [Getting Started](Getting-Started.md)
- [Troubleshooting in the scanner docs](Scanning.md)
- [Heuristics, Not Proofs](Heuristics.md)
