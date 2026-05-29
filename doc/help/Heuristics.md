# Heuristics, Not Proofs

`deglyph` recovers structure from machine code without running it and without a
decompiler. Almost everything it reports is a **heuristic**: it points at the
right instructions or strings, but it does not certify behavior. Reading the
output with that in mind is the difference between a useful lead and a false
claim.

## What this means in practice

**Pattern detectors point, they do not prove.** A `mov [buf+2], 0x04` is reported
as a constant written to a structured field, not as a proven command opcode. CRC
detection finds clean unrolled bit loops and reports a candidate polynomial; it
misses register-folded variants. Confirm a hit in the
[disassembly](Disassembly.md) before relying on it.

**Function discovery is incomplete.** It recovers functions reached by a direct
`call` and misses indirect and tail-call-only functions. An empty result for a
given address means "not found by this method", not "does not exist". See
[Function Discovery](Function-Discovery.md).

**Pseudo-C is an annotation, not a decompilation.** It is a linear, x86-only
rendering with no type recovery and no control-flow structuring. Read it as
commentary on the disassembly, not as source.

**Scan findings are candidates.** A secret hit is a pattern match, not a verified
live credential. An import hit is a capability the binary links, not evidence it
is misused. A hardening "miss" is an absent flag, not a demonstrated exploit. A
fingerprint hit is a version string the linker stamped, which a vendor may have
changed. A "no libraries detected" result means "no catalog match", not
"self-contained".

## How to report a finding

When you write up or act on a result:

- Say "candidate", "likely", or "consistent with", not "is".
- Cite the evidence: the address, the instruction, the matched string.
- Confirm in the disassembly when the cost of being wrong is real.
- State the method's blind spots when the absence of a finding matters.

This is not a limitation to apologize for; it is the honest contract of static
analysis without execution. `deglyph`'s job is to surface strong leads quickly and
show you exactly where to verify them.

## See also

- [Pattern Detectors](Pattern-Detectors.md): what the detectors do and miss.
- [Scanning Binaries](Scanning.md): the scanner's findings as candidates.
- [The AI Assistant](AI-Assistant.md): prose explanations, same contract.
