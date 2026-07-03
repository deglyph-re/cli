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

The optional AI assistant sends data off the machine. When a question is asked
in the Assistant tab, the selected function's disassembly, the conversation, and
whatever the assistant's read-only tools read from the binary are sent to the
configured model provider: the Anthropic API by default, any OpenAI-compatible
endpoint chosen in the provider settings, or the hosted deglyph service when a
`deglyph login` token is stored. A local provider (Ollama, LM Studio) keeps that
traffic on the machine. Nothing is sent until a question is asked and a provider
is configured. Do not use the assistant on binaries whose contents may not leave
your environment.

CVE lookups (`deglyph scan --cve`) send the detected package URLs to osv.dev.
They are opt-in and off by default; `--offline` forces the no-network path. No
other feature contacts the network.

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
