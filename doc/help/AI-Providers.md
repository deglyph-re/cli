# AI Providers

The [AI assistant](AI-Assistant.md) is provider-agnostic. It speaks two request
shapes, the Anthropic API and any OpenAI-compatible endpoint, and ships with a
registry of known providers so you can switch with a dropdown rather than code.

## Choosing a provider

Open the command palette and select "AI provider...". The settings screen exposes
the provider, the model, and the base URL. The built-in providers are:

| Provider | Request shape |
| --- | --- |
| Anthropic | Anthropic |
| OpenAI | OpenAI |
| Groq | OpenAI-compatible |
| OpenRouter | OpenAI-compatible |
| DeepSeek | OpenAI-compatible |
| Ollama | OpenAI-compatible |
| LM Studio | OpenAI-compatible |
| Custom | OpenAI-compatible |

A custom provider lets you point at any OpenAI-compatible `/chat/completions`
endpoint by URL and model name. Selecting it reveals a free-text model field.

## Request shapes, not brand names

Internally, every backend decision is made on the request **shape** (Anthropic or
OpenAI-compatible), not the provider's name. That is why Groq, OpenRouter,
DeepSeek, and a custom endpoint all work: they share the OpenAI shape. The
OpenAI-family backend is a small client over the standard `/chat/completions`
API, with no vendor SDK.

## Configuring without the interface

Settings persist to the app config, and environment variables override them, so
you can configure the assistant in a headless or scripted context:

| Variable | Purpose |
| --- | --- |
| `DEGLYPH_AI_PROVIDER` | Provider key (e.g. `openai`, `groq`, `ollama`) |
| `DEGLYPH_AI_BASE_URL` | Endpoint base URL for an OpenAI-compatible provider |
| `DEGLYPH_AI_MODEL` | Model name for an OpenAI-compatible provider |
| `DEGLYPH_MODEL` | Pin the model for the Anthropic family |
| `DEGLYPH_AI_API_KEY` | API key for an OpenAI-compatible provider |
| `ANTHROPIC_API_KEY` | API key for the Anthropic family |

See [Configuration & Environment](Configuration.md) for the full variable list,
including the request timeout and the agentic iteration cap.

## Local and hosted

The same three access paths apply to every provider: your own key, the hosted
(Pro) tier via `deglyph login`, or dormant when neither is present. The choice of
provider is independent of which path supplies access. See
[The AI Assistant](AI-Assistant.md).

## See also

- [The AI Assistant](AI-Assistant.md): what the assistant does and how to enable it.
- [Configuration & Environment](Configuration.md): every assistant variable.
