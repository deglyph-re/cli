# About deglyph

`deglyph` is a terminal reverse-engineering tool for native binaries. It loads a
PE, ELF, or Mach-O object, lists its functions in a searchable tree, follows
exported wrappers to their real implementations, shows annotated disassembly,
walks the call graph, and runs pattern detectors that recover structure facts
without a decompiler. It also runs headless as a CI scanner for hardening
posture, secrets, libraries, CVEs, risky imports, and drift.

`deglyph` never executes the binary it analyzes. Every stage is read-only.

## What it is for

Reading and understanding compiled code in a terminal: recovering a binary
protocol's command codes and frame layout, auditing a release build before
shipping, identifying linked libraries and their known vulnerabilities, and
checking hardening posture in continuous integration. Nothing in the tool is
specific to any one protocol or vendor.

It is built for triage and reading, not full reverse engineering: it is not a
decompiler and not a replacement for Ghidra, IDA, or Binary Ninja. See
[Limitations](Limitations.md) for what it does not handle.

## The stack

- **LIEF** parses PE, ELF, and Mach-O containers.
- **Capstone** disassembles on demand.
- **Textual** and **Rich** render the terminal interface.
- Python 3.10 or newer.

## License

`deglyph` is free software under the GNU General Public License, version 3 or
later (GPL-3.0-or-later). Author: Alex Spataru.

## Project links

- Source: <https://github.com/deglyph-re/cli>
- Package: <https://pypi.org/project/deglyph/>
- Website: <https://deglyph.dev>

## See also

- [Getting Started](Getting-Started.md): install and first steps.
- [How deglyph Works](How-It-Works.md): the analysis pipeline.
- [Limitations](Limitations.md): what deglyph does not handle.
- [FAQ](FAQ.md): common questions.
