# Limitations

`deglyph` is built for triage, exploration, and CI review: loading a binary,
finding and reading functions, following call graphs, and surfacing leads that a
human then confirms. It is good at that. It is not a decompiler, and it is not a
replacement for Ghidra, IDA, or Binary Ninja. Knowing where it stops is part of
using it well.

## What it does not do

**It does not run the binary.** Every stage is static. Anything that only exists
at runtime, such as decrypted strings, computed jump targets, JIT or self-modifying
code, and behavior gated on configuration or input, is invisible to it.

**It does not decompile.** The [pseudo-C view](Pseudo-C.md) is a linear, x86-only
annotation with no type recovery and no control-flow structuring. Read it as
commentary on the disassembly, not as source.

**It does not reconstruct full control flow.** Disassembly is linear and the
[CFG](How-It-Works.md) is bounded. Simple memory-operand jump tables have their
cases resolved, but indirect and virtual calls, register-computed jumps, and
tables reached through a register are not, so the call graph through them is
incomplete.

**It does not analyze managed code.** .NET / CLR assemblies, JVM bytecode, and
other managed formats hold intermediate language, not native code; `deglyph`
reads native PE / ELF / Mach-O only. This is a non-goal, not a gap to close.

## Where the analysis is weak

These are the binary classes where results thin out. An empty or sparse result
here means "not recovered by this method", not "not present".

- **Indirect and virtual calls.** C++ vtables, function pointers, and dispatch
  tables break the direct-call graph. See [Cross-References](Cross-References.md).
- **Jump tables and computed jumps.** Switch statements compiled to indexed jumps
  are not followed to their cases.
- **Stripped, heavily optimized C++.** Inlining, tail-call merging, and identical
  COMDAT folding erase the boundaries [function discovery](Function-Discovery.md)
  relies on.
- **Obfuscated or packed binaries.** Control-flow flattening, opaque predicates,
  and packers defeat the pattern detectors and often the disassembler itself.
  `deglyph` does not unpack.
- **Unusual ABIs and architectures.** The disassembler covers x86, x86-64, ARM,
  AArch64, and RISC-V (RV32 / RV64). The [pattern detectors](Pattern-Detectors.md)
  and referenced-data view inspect x86, x86-64, AArch64, and 32-bit ARM; on
  RISC-V the disassembly renders but the detectors report nothing (the
  headless JSON marks them unsupported), and the [pseudo-C view](Pseudo-C.md)
  stays x86-only. MIPS, PowerPC, and other targets are not supported. See
  [Loading Binaries](Loading-Binaries.md).
- **Register-folded CRC and crypto loops.** CRC detection recognizes clean
  unrolled bit loops and misses folded or table-driven variants. See
  [Pattern Detectors](Pattern-Detectors.md).

## Why this is fine

Every result `deglyph` reports is a lead with its evidence attached, meant to be
confirmed in the disassembly. The blind spots above are the honest edge of static
analysis without execution, not bugs to apologize for. When a finding's absence
matters, state the method's blind spot alongside it.

## See also

- [Heuristics, Not Proofs](Heuristics.md): how to read findings as candidates.
- [How deglyph Works](How-It-Works.md): the analysis pipeline and its bounds.
- [Function Discovery](Function-Discovery.md): what recovery finds and misses.
- [FAQ](FAQ.md): common "why is this empty?" questions.
