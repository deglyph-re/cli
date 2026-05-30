# The AI Assistant

`deglyph` includes an optional assistant that answers questions about a function in
plain language. Press <kbd>i</kbd> with a function selected and ask, for example,
"what does this do?" or "is this a CRC?". The assistant is opt-in and never sends
anything to a network until you ask a question.

## Agentic, with read-only tools

The assistant does not just receive the current disassembly. It runs an agentic
loop with a set of read-only tools over the loaded image, so it can investigate
the way you would:

- `find_function` and `list_functions` to locate code,
- `disassemble` and `pseudo_c` to read it,
- `analyze` to run the [pattern detectors](Pattern-Detectors.md),
- `xrefs` to see callers and callees,
- `search` to find bytes, strings, or immediates.

The selected function's disassembly is provided as cached context; the assistant
roams from there through the tools. Its tools are strictly read-only: it inspects
the image, it cannot modify it or execute it.

## Replies and chat history

Replies render as markdown with `sub_*` and `0x...` addresses linkified, so you
can click straight from an explanation to the code. Each function's chat is kept
separately and persisted to the binary's sidecar, so reopening a binary restores
the conversations you had about it. A question stays bound to the function you
asked about even if you navigate away before the answer arrives.

## Providers

The assistant is provider-agnostic. It speaks two request shapes: the Anthropic
API and any OpenAI-compatible endpoint. It supports Anthropic, OpenAI, Groq,
OpenRouter, DeepSeek, Ollama, LM Studio, and custom endpoints.
Choose a provider, model, and base URL from the command palette under
"AI provider...".

## Enabling it

There are three ways to give the assistant access to a model, tried in order:

1. **Local key.** Set `ANTHROPIC_API_KEY` (or the matching key for an
   OpenAI-compatible provider) and `deglyph` calls the model directly with your
   own key.
2. **Hosted (Pro).** Run `deglyph login <token>` with a hosted token; `deglyph`
   routes requests through the hosted service, which runs the model with its own
   key. `deglyph logout` clears it.
3. **Disabled.** With no key and no token, the assistant is dormant and tells you
   how to enable it.

This client ships no secrets. Entitlement for the hosted tier is enforced
server-side.

## See also

- [Pattern Detectors](Pattern-Detectors.md): the structured facts the assistant can call.
- [Heuristics, Not Proofs](Heuristics.md): the assistant reports leads, not proofs.
- [Keyboard Shortcuts](Keyboard-Shortcuts.md): the ask key and chat navigation.
