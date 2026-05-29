# Disassembly View

The Disasm tab (<kbd>d</kbd>) shows the selected function as annotated
disassembly produced by the Capstone engine. It is the canonical view: every
heuristic elsewhere in `deglyph` points back here so you can confirm a finding by
reading the instructions.

## Annotations

Each line carries the instruction address, mnemonic, and operands. Branch and
call operands whose target lands inside the executable section are rendered as
clickable links: selecting one jumps to that address. Targets that resolve to a
known function are symbolized with the function's name (or your rename); other
targets show as a `sub_<va>` or a raw address.

## Navigating code

- **Click** a branch or call target to jump to it.
- Use the goto action to jump to an arbitrary address. The view recenters on it.
- Press <kbd>f</kbd> to follow an exported wrapper to its implementation; see
  the wrapper chain on the [Cross-references](Function-Navigator.md) tab.
- Jumps are recorded in a browser-style history. Press <kbd>[</kbd> and
  <kbd>]</kbd> to move back and forward. Scrolling the cursor does not record a
  jump, so the history stays meaningful.

## Windowing large functions

A very large function is windowed around the current line rather than rendered in
full, so the interface never stalls building one enormous view. Jumping moves the
window to the destination. You always see the code around wherever you are.

## Referenced data

Where a function references a string, table, or pointer constant, `deglyph`
resolves the operand and shows the target as a string or a short hex preview.
This is how a `lea` into a string table or an absolute pointer load becomes
readable inline.

## Architecture notes

Operand-level inspection (clickable targets, referenced data) uses the x86
operand API. On non-x86 targets the disassembly still renders, but the
x86-specific annotations do not apply.

## See also

- [Pattern Detectors](Pattern-Detectors.md): structured facts recovered from code.
- [Function Navigator](Function-Navigator.md): selecting and following functions.
- [Heuristics, Not Proofs](Heuristics.md): how to read detector output.
- [Keyboard Shortcuts](Keyboard-Shortcuts.md): goto, follow, and history keys.
