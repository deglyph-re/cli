# Extending deglyph

How-to guides for the two common extension points. Subsystem invariants: [Architecture Invariants](architecture.md). Main developer guide: [CLAUDE.md](../../CLAUDE.md).

## Adding a detector

A new pattern detector lives in `re/patterns.py`, returns a list of `slots=True` dataclass records (address + decoded fields), and takes `(image, va, *, max_insns)`. Export it from `re/__init__.py`, render it in `app.py:_render_analysis` and `cli.py:_headless`, and add a test asserting against a known function. Prefer `samples/demo.exe` (committed, runs in CI) or a synthetic blob via the `code_image` fixture (`tests/conftest.py`); guard host-binary cases with a skip when absent.

## Adding a container format or architecture

LIEF already parses PE/ELF/Mach-O and fat binaries. To support a new architecture, add it to `Arch`, map it in `disasm.py:_ARCH_MODE`, and extend `image.py:_detect_arch`. The rest of the pipeline is arch-agnostic except the x86-specific operand inspection in `patterns.py` and `search.py` (Capstone's `x86` operand API); a non-x86 target needs its own operand walk there.
