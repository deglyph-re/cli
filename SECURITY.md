# Security Policy

## Threat model

deglyph parses untrusted input by design: a binary under analysis may be malformed
or hostile. The container parser (LIEF) and disassembler (Capstone) run over
attacker-controlled bytes. The loader is written to fail with a clean error
rather than crash, and the per-instruction and per-section scanners catch and
continue so one bad region cannot abort a whole-image pass.

deglyph does not execute the binary it analyzes. It reads the file, parses its
structure, and disassembles its code; it never runs the target.

## Data sent to third parties

The optional AI assistant (the `ai` extra) sends data off the machine. When a
question is asked in the Assistant tab, the selected function's disassembly and
the conversation are sent to the Anthropic API over the network. This happens
only after a question is asked and only when `ANTHROPIC_API_KEY` is set; the rest
of deglyph is fully offline. Do not use the assistant on binaries whose contents
may not leave your environment. No other feature contacts the network.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability** (Private Vulnerability
Reporting). Please include:

- the deglyph version (`deglyph --version`) and platform,
- a description of the issue and its impact,
- a minimal input file or steps that reproduce it.

Please do not open a public issue for a security report. A maintainer will
acknowledge the report and coordinate a fix and disclosure timeline.

## Supported versions

deglyph is pre-1.0. Security fixes target the latest release and the `main` branch.
