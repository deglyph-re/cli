# Getting Started

`deglyph` is a terminal reverse-engineering tool for native binaries. It loads a
PE, ELF, or Mach-O object, lists the functions inside it, follows exported
wrappers to their real implementations, shows annotated disassembly, walks the
call graph, and runs pattern detectors that recover structure facts without a
decompiler. It never executes the binary it analyzes.

## Install

`deglyph` is published on PyPI and runs on Python 3.10 or newer.

```bash
pip install deglyph
```

This installs the `deglyph` command. The same package provides the terminal
interface, the headless analysis modes, and the `deglyph scan` CI scanner.

## Open a binary

Point `deglyph` at any PE, ELF, or Mach-O file:

```bash
deglyph ./app.exe
```

The interface opens on a welcome screen listing recent sessions and an option to
browse for a file. With a path on the command line, `deglyph` opens it directly.

On first contact with a binary, `deglyph` parses its container, lists every
function it can name from the export and symbol tables, and (for stripped
release builds) scans the executable sections to discover unexported functions.
See [Function Discovery](Function-Discovery.md).

## Read a function

The left pane is a searchable tree of functions grouped by kind and name. Select
a function and the right pane shows its annotated disassembly. From there:

- Press <kbd>d</kbd> for disassembly with clickable branch and call targets.
- Press <kbd>x</kbd> for cross-references: who calls this, what it calls.
- Press <kbd>a</kbd> for the [pattern detectors](Pattern-Detectors.md):
  constants written to memory, constant call arguments, and CRC routines.
- Press <kbd>f</kbd> to follow an exported wrapper to the function that does the
  real work.

The full key map is on the [Keyboard Shortcuts](Keyboard-Shortcuts.md) page.

## Scan a binary in CI

`deglyph` also runs headless as a static scanner for continuous integration. It
reports hardening posture, embedded secrets, linked libraries, known CVEs, risky
imports, and drift against a baseline build:

```bash
deglyph scan ./app.exe
```

The exit code is set by the worst finding so the command can gate a pipeline.
See [Scanning Binaries](Scanning.md) and [The GitHub Action](GitHub-Action.md).

## See also

- [The Interface](The-Interface.md): the panes and how they fit together.
- [Loading Binaries](Loading-Binaries.md): formats, architecture, and overrides.
- [How deglyph Works](How-It-Works.md): the analysis pipeline end to end.
- [Command-Line Reference](CLI-Reference.md): every flag and subcommand.
