# Pattern Detectors

The Analysis tab (<kbd>a</kbd>) runs a set of pattern detectors over a function.
They recover structure facts from machine code without a decompiler: constants
written into memory, constant arguments passed to calls, and checksum loops.
The same detectors are available headlessly through `deglyph --analyze`.

## What they find

**Immediate stores.** A `mov [buf+2], 0x04` that writes a constant into a
structured buffer. These often correspond to header magics, frame types, or
field initializers. The detector reports the destination (base register and
displacement, or an absolute address), the access size, and the value.

**Constant call arguments.** A constant loaded into a register immediately before
a call, the command-dispatch idiom. The detector reports the register, the value,
the call address, and the call target where it can be resolved to a function.

**CRC and checksum loops.** A clean unrolled bit loop with the shift-and-xor
shape of a CRC. The detector reports a candidate polynomial and initial value.

## Following a wrapper first

Detectors run against the function that does the work, not an exported wrapper
around it. `deglyph` resolves a wrapper to its implementation before analyzing: it
follows tail-call thunks and argument-marshalling wrappers, but stops at the
first function with a real body, so the analysis lands on the implementation
rather than descending into shared checksum or transport helpers.

## Reading the results

These detectors point at the right instructions; they do not certify behavior.

- A reported store is a constant written to a structured field. It is not proven
  to be a command opcode. The disassembly is one keystroke away to confirm.
- CRC detection finds clean unrolled bit loops. It misses register-folded
  variants. When the panel is empty, an immediate search for a known polynomial
  still locates the routine.

Treat every hit as a lead to verify in the [disassembly](Disassembly.md), not as
a fact. See [Heuristics, Not Proofs](Heuristics.md) for the full contract.

## Headless analysis

The same output is available for scripting:

```bash
deglyph ./firmware.bin --analyze encode_frame
deglyph ./firmware.bin --analyze encode_frame --json
```

This prints the wrapper chain, the immediate stores, the constant call
arguments, and any CRC loops for every function whose name matches.

## See also

- [Disassembly View](Disassembly.md): confirm a detector hit in the code.
- [Heuristics, Not Proofs](Heuristics.md): how much a hit is worth.
- [The AI Assistant](AI-Assistant.md): ask what a function does in prose.
