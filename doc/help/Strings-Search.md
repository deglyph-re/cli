# Strings & Search

`deglyph` extracts the strings embedded in a binary and searches its bytes,
strings, and immediate constants. These are often the fastest way into an unknown
binary: a format string, an error message, or a magic constant points straight at
the code that uses it.

## The Strings tab

Press <kbd>s</kbd> to browse every string in the binary. A single extraction
engine yields **ASCII**, **UTF-8**, and **UTF-16LE** runs, each mapped to its
virtual address and section. The list is built lazily and cached, so opening it on a
large binary stays responsive.

The same extraction is available headlessly, in a form that pipes and greps
cleanly:

```bash
deglyph ./app.exe --strings | grep -i password
```

## Referenced data

Within a function, `deglyph` resolves the strings, tables, and pointer constants
the code points at. An x86 rip-relative or absolute operand, or a pointer
immediate, is shown inline as a string or a short hex preview, so a `lea` into a
string table becomes readable without leaving the disassembly. On non-x86 targets
this resolution does not apply.

## Searching

Three kinds of search span the whole image:

- **Byte search** with `??` wildcards, for a known signature with variable bytes,
  for example `48 8b ?? ?? e8`.
- **String search** across both ASCII and UTF-16LE, so a string stored either way
  is found with one query.
- **Immediate search** for a constant value, which is how you locate a routine by
  a known magic number or CRC polynomial.

Immediate search is the fallback when a [pattern detector](Pattern-Detectors.md)
comes up empty: if CRC detection misses a register-folded loop, searching for the
polynomial as an immediate still lands on the routine.

## See also

- [Disassembly View](Disassembly.md): where referenced data is shown.
- [Pattern Detectors](Pattern-Detectors.md): immediate search as a fallback.
- [Command-Line Reference](CLI-Reference.md): the `--strings` headless dump.
