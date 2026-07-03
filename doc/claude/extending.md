# Extending deglyph

How-to guides for the two common extension points. Subsystem invariants: [Architecture Invariants](architecture.md). Main developer guide: [CLAUDE.md](../../CLAUDE.md).

## Adding a detector

A new pattern detector lives in `re/patterns.py`, returns a list of `slots=True` dataclass records (address + decoded fields), and takes `(image, va, *, max_insns)`. Export it from `re/__init__.py`, render it in `app.py:_render_analysis` and `cli.py:_headless`, and add a test asserting against a known function. Prefer `samples/demo.exe` (committed, runs in CI) or a synthetic blob via the `code_image` fixture (`tests/conftest.py`); guard host-binary cases with a skip when absent.

## Adding a container format or architecture

LIEF already parses PE/ELF/Mach-O and fat binaries. To support a new architecture, add it to `Arch`, map it in `disasm.py:_ARCH_MODE`, and extend `image.py:_detect_arch`. Operand reads are arch-neutral (`Insn.operands()`, see the [operand-walker invariant](architecture.md)), so most of the pipeline follows automatically. What needs per-arch work, in order of value:

1. **Control-flow classification** in `disasm.py`: add the architecture's branch, call, and return mnemonics to `_COND_BRANCH` / `_UNCOND_JMP` / `_CALLS` / `_TERMINATORS`. Without this the CFG cannot split blocks, so discovery and the detectors run on a degraded instruction stream. Do not rely on Capstone's instruction groups to infer this: they are unreliable for some arches (RISC-V tags `ret` and `j` as calls).
2. **Detector mnemonics** in `patterns.py`: the store / immediate-load / bit-op sets and the `_ARG_REGS` table, so the detectors fire.
3. **Data references** in `disasm.py:Insn.data_ref`: the architecture's PC-relative addressing idioms, so referenced-data and data xrefs resolve.

`pseudo_c` stays x86-only by design. `cli.py:_analysis_support` declares which analyses cover each arch; keep it accurate so JSON consumers can tell "no hits" from "not supported". A load-and-disassemble-only arch (RISC-V today) adds only the `Arch` entry, `_ARCH_MODE`, and detection, and reports the detectors off.
