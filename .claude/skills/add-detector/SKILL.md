---
name: add-detector
description: Add a new pattern detector to deglyph (a heuristic that recovers structure facts from disassembly). Use when the user asks for a new detector, analysis pass, or pattern recognizer.
---

Read `doc/claude/extending.md` and the "Operand reads go through one
arch-neutral walker" and "Every detector hit carries an Evidence record"
entries in `doc/claude/architecture.md` before writing code.

The checklist, in order:

1. **Detector** in `deglyph/re/patterns.py`: signature
   `(image, va, *, max_insns)`, returning a list of `slots=True` dataclass
   records (address plus decoded fields). Fetch instructions through
   `function_insns(image, va, max_insns)` (the CFG-backed stream), and walk
   `Insn.operands()`; never import a per-arch capstone constant module.
   Carry per-arch mnemonic sets so the detector fires on x86 and AArch64
   where the idiom exists.
2. **Evidence** on every hit: confidence (high / medium / low), reasons,
   caveats, supporting instruction addresses. A detector hit is a candidate
   to confirm in disassembly, never a proven fact; phrase every consumer
   that way.
3. **Export** it from `deglyph/re/__init__.py`.
4. **Render sites**: the TUI Analysis pane (`app.py:_render_analysis`),
   headless `--analyze` text and JSON (`cli.py:_headless`), and the export
   document (`export.py`) if the hit type belongs there. Declare arch
   coverage in `cli.py:_analysis_support`.
5. **Tests** in `tests/test_detectors.py`: assert against hand-assembled
   bytes via the `code_image` fixture, or `samples/demo.exe` (committed,
   runs in CI). Guard host-binary cases with a skip when absent.
6. **Docs**: a short section in `doc/help/Pattern-Detectors.md` (keep
   `help.json` untouched, the page already exists), a row in
   `doc/claude/architecture.md` only if the detector adds a new invariant,
   and a `CHANGELOG.md` entry under `[Unreleased]`.

State the plan (detector idiom, record shape, arch coverage) in chat before
writing code; a detector's matching rules are exactly the kind of choice a
reviewer may want to weigh in on.
