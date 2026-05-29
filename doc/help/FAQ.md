# FAQ

## Does deglyph run the binary?

No. Every stage is read-only: `deglyph` parses the container, disassembles on
demand, and runs static detectors. It never executes the target, including in the
`scan` subcommand.

## Which formats and architectures are supported?

PE, ELF, and Mach-O containers, including fat binaries. Architectures: x86,
x86-64, ARM, and AArch64. Operand-level features such as clickable targets and
the pattern detectors use the x86 operand API; on other architectures the
disassembly still renders. See [Loading Binaries](Loading-Binaries.md).

## The function tree is almost empty. Why?

The binary is probably a stripped release build that exports nothing. `deglyph`
recovers unexported functions by scanning for direct call targets, but that
misses functions reached only indirectly or by tail call. See
[Function Discovery](Function-Discovery.md).

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

## Do I need an API key to use deglyph?

No. The interface and the scanner work entirely offline with no account. Only the
optional [AI assistant](AI-Assistant.md) needs a model: either your own API key
or a hosted token. CVE scanning needs network access to osv.dev, and is opt-in.

## How do I run it in CI?

Use `deglyph scan` directly, or the bundled GitHub Action. The Action gates the
job, writes a run summary, and can upload SARIF to the Security tab and post a
pull-request comment. See [The GitHub Action](GitHub-Action.md).

## See also

- [Getting Started](Getting-Started.md)
- [Troubleshooting in the scanner docs](Scanning.md)
- [Heuristics, Not Proofs](Heuristics.md)
