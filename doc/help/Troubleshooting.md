# Troubleshooting

Common problems and their fixes, for both the interface and the scanner. If
something is not covered here, the [FAQ](FAQ.md) and the per-feature pages go
deeper.

## The interface

**The disassembly is garbage.** The architecture is probably wrong: a 32-bit
image decoded in 64-bit mode produces plausible-looking nonsense. Force it with
`--arch x86` (or `x64`, `arm`, `arm64`). See [Loading Binaries](Loading-Binaries.md).

**The function tree is almost empty.** The binary is a stripped release build that
exports nothing. `deglyph` recovers functions from direct call targets, but that
misses indirect and tail-call-only functions. See
[Function Discovery](Function-Discovery.md).

**The file will not open.** The container may be mislabeled or unusual. Force the
format with `--fmt PE` / `--fmt ELF` / `--fmt MachO`. For a fat Mach-O, `deglyph`
selects a slice automatically; force the architecture if it picks the wrong one.

**The Analysis or Pseudo-C tab is empty.** Those features are x86-only at the
operand level. On ARM or AArch64 targets, read the
[disassembly](Disassembly.md) directly.

**A CRC routine is not detected.** Detection recognizes clean unrolled bit loops
and misses register-folded variants. Search for the known polynomial as an
immediate to locate the routine. See [Strings & Search](Strings-Search.md).

**The glyphs render as boxes or question marks.** Your terminal font lacks the
characters. Run with `--ascii` for a plain-text glyph set. See
[Configuration & Environment](Configuration.md).

**The assistant says it is unavailable.** It needs a model. Set an API key
(`ANTHROPIC_API_KEY` or the matching provider key), or run `deglyph login` for
the hosted tier. See [The AI Assistant](AI-Assistant.md) and
[AI Providers](AI-Providers.md).

## The scanner

**The scan reports too many secrets.** If you enabled `--entropy`, it is noisy on
native binaries by design; drop it. For specific false positives, suppress the
rule or the finding fingerprint. See [Secret Detection](Secret-Detection.md) and
[Suppressing Findings](Suppressing-Findings.md).

**The scan keeps failing on accepted findings.** Commit a
[`.deglyphignore`](Suppressing-Findings.md) listing the accepted rules,
categories, or fingerprints, or raise the threshold with `--fail-on`.

**The CVE step finds nothing or hangs.** CVE lookups are opt-in (`--cve`) and need
network access to osv.dev. Offline, the step degrades to no findings rather than
failing. See [CVE Scanning](CVE-Scanning.md).

**No libraries were detected.** That means no catalog match, not that the binary
is self-contained. The library may emit no recognizable version banner. See
[Library Fingerprinting](Library-Fingerprinting.md).

**A whole file was skipped.** One unreadable or unsupported file does not abort a
directory scan; `deglyph` logs it and continues. Run with `-v` to see why.

## See also

- [FAQ](FAQ.md): shorter answers to common questions.
- [Loading Binaries](Loading-Binaries.md): format and architecture overrides.
- [Heuristics, Not Proofs](Heuristics.md): why some findings need confirming.
