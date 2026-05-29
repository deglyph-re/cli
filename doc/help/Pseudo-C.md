# Pseudo-C

The Pseudo-C tab (<kbd>p</kbd>) renders the selected function as a C-like
annotation of its disassembly. It is a reading aid, not a decompiler: it makes a
function quicker to skim, but it does not reconstruct source.

## What it is

Pseudo-C is a **linear, x86-only** pass over the instructions. It names
registers as variables, turns common instruction patterns into C-like
statements, and labels calls and branches. The output follows the instruction
order; it is annotation laid over the disassembly, line for line.

## What it is not

- **No type recovery.** Variables are registers and stack slots, not typed
  locals. Sizes come from the access width, not from a reconstructed structure.
- **No control-flow structuring.** There are no recovered `if` / `while` / `for`
  blocks; branches are shown as jumps, not folded into structured control flow.
- **x86 only.** On ARM, AArch64, and other non-x86 targets, the Pseudo-C view is
  empty. Read the [disassembly](Disassembly.md) directly there.

## How to read it

Use Pseudo-C to get the shape of a function fast, then drop to the
[disassembly](Disassembly.md) to confirm anything you intend to rely on. Like the
[pattern detectors](Pattern-Detectors.md), it is a heuristic: it can mislabel an
idiom or miss one. Treat it as commentary, not as ground truth. See
[Heuristics, Not Proofs](Heuristics.md).

For a higher-level explanation in prose, the [AI assistant](AI-Assistant.md) can
read the same function and describe what it does, citing the addresses.

## See also

- [Disassembly View](Disassembly.md): the source of truth Pseudo-C annotates.
- [Pattern Detectors](Pattern-Detectors.md): structured facts, same x86 scope.
- [Heuristics, Not Proofs](Heuristics.md): how much to trust the rendering.
