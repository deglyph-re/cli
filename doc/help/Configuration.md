# Configuration & Environment

`deglyph` needs no configuration to run. Its preferences and per-binary state are
stored under your home directory, and a set of environment variables tune
behavior for scripted and headless use.

## Where state lives

| Path | Contents |
| --- | --- |
| `~/.deglyph/config.json` | Global preferences: theme, AI provider / model / base URL |
| `~/.deglyph/annotations/` | Per-binary [renames, notes, bookmarks, chats](Annotations.md) |
| `~/.deglyph/cve-cache/` | Cached [osv.dev](CVE-Scanning.md) responses (24h TTL) |

Set `DEGLYPH_STORE_DIR` to relocate all of this, for example to keep a project's
state self-contained or to isolate it in CI.

## Interface variables

| Variable | Effect |
| --- | --- |
| `DEGLYPH_ASCII` | Force ASCII glyphs (same as `--ascii`) |
| `DEGLYPH_NERD` | Use Nerd Font icons (same as `--nerd`) |
| `DEGLYPH_THEME` | Default theme name |

## AI assistant variables

| Variable | Effect |
| --- | --- |
| `ANTHROPIC_API_KEY` | API key for the Anthropic family |
| `DEGLYPH_AI_PROVIDER` | Provider key (`openai`, `groq`, `ollama`, ...) |
| `DEGLYPH_AI_BASE_URL` | Endpoint for an OpenAI-compatible provider |
| `DEGLYPH_AI_MODEL` | Model for an OpenAI-compatible provider |
| `DEGLYPH_AI_API_KEY` | API key for an OpenAI-compatible provider |
| `DEGLYPH_MODEL` | Pin the model for the Anthropic family |
| `DEGLYPH_AI_TIMEOUT` | Per-request timeout in seconds (default 90) |
| `DEGLYPH_AI_MAX_ITERS` | Agentic tool-call cap per question (default 24) |

See [AI Providers](AI-Providers.md) for how these combine.

## Scanner variables

| Variable | Effect |
| --- | --- |
| `DEGLYPH_CVE_TTL` | [CVE cache](CVE-Scanning.md) lifetime in seconds (default 86400) |
| `DEGLYPH_STORE_DIR` | Also relocates the CVE cache |

## Precedence

Command-line flags win over environment variables, which win over the stored
config. So `--ascii` overrides `DEGLYPH_ASCII`, and `DEGLYPH_AI_MODEL` overrides
the model saved from the settings screen. State files degrade gracefully: a
malformed config or sidecar falls back to defaults rather than failing.

## See also

- [Renames, Notes & Bookmarks](Annotations.md): the per-binary sidecar.
- [AI Providers](AI-Providers.md): the assistant variables in context.
- [Command-Line Reference](CLI-Reference.md): the flags these variables mirror.
