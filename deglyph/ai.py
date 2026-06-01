# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Optional LLM-backed assistant for an opt-in, in-app chat about a function.

`Assistant` runs an agentic loop over the bound image. It builds an Anthropic-shaped
request (a cached disassembly system block + read-only tools) and routes one
round-trip to a backend chosen by `provider_family()`: **Anthropic** (local key or
the hosted Pro tier) or any **OpenAI-compatible** endpoint (`OpenAIBackend`: OpenAI,
Groq, OpenRouter, DeepSeek, or a local Ollama / LM Studio, via base URL + model + key).
The OpenAI adapter translates the request and response, so the loop is unchanged.

The `PROVIDERS` registry names each known backend, its request family, default
endpoint, and a starting model menu, so the settings dialog can offer a dropdown
and auto-fill the base URL; a custom key + URL still works for anything unlisted.

Nothing is sent until the user asks. The `anthropic` package is an optional
dependency (the `ai` extra); the OpenAI path uses only the standard library.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_OPENAI_BASE = "https://api.openai.com/v1"
MAX_TOKENS = 4096


class Provider:
    """A known LLM backend: its family, default endpoint, and a model menu.

    `family` is the request shape ("anthropic" or "openai"); `base_url` is the
    OpenAI-compatible endpoint (empty for the anthropic family, which the SDK /
    hosted tier addresses on its own); `models` is the dropdown menu, with the
    first entry the default; `needs_key` is False for local runners.
    """

    __slots__ = ("key", "label", "family", "base_url", "models", "needs_key")

    def __init__(
        self,
        key: str,
        label: str,
        family: str,
        base_url: str,
        models: list[str],
        *,
        needs_key: bool = True,
    ):
        self.key = key
        self.label = label
        self.family = family
        self.base_url = base_url
        self.models = models
        self.needs_key = needs_key


# Known providers, in menu order. The model lists are a curated starting menu,
# not an exhaustive catalog; a provider's API decides what it actually accepts,
# and the dialog keeps a free-text field for a model the menu omits.
PROVIDERS: dict[str, Provider] = {
    "anthropic": Provider(
        "anthropic",
        "Anthropic (Claude)",
        "anthropic",
        "",
        ["claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5"],
    ),
    "openai": Provider(
        "openai",
        "OpenAI",
        "openai",
        "https://api.openai.com/v1",
        ["gpt-4o", "gpt-4o-mini", "o3-mini"],
    ),
    "groq": Provider(
        "groq",
        "Groq",
        "openai",
        "https://api.groq.com/openai/v1",
        ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
    ),
    "openrouter": Provider(
        "openrouter",
        "OpenRouter",
        "openai",
        "https://openrouter.ai/api/v1",
        [
            "anthropic/claude-sonnet-4",
            "openai/gpt-4o",
            "meta-llama/llama-3.3-70b-instruct",
        ],
    ),
    "deepseek": Provider(
        "deepseek",
        "DeepSeek",
        "openai",
        "https://api.deepseek.com/v1",
        ["deepseek-chat", "deepseek-reasoner"],
    ),
    "ollama": Provider(
        "ollama",
        "Ollama (local)",
        "openai",
        "http://localhost:11434/v1",
        ["llama3.1", "qwen2.5-coder", "mistral"],
        needs_key=False,
    ),
    "lmstudio": Provider(
        "lmstudio",
        "LM Studio (local)",
        "openai",
        "http://localhost:1234/v1",
        ["local-model"],
        needs_key=False,
    ),
}


def known_providers() -> list[Provider]:
    """The provider menu, in display order."""
    return list(PROVIDERS.values())


def provider_info(key: str) -> Provider | None:
    """The `Provider` for a key, or None for an unknown / custom key."""
    return PROVIDERS.get((key or "").lower())


def _ai_disp(signed: int) -> str:
    """Signed-displacement suffix for a memory operand in the AI context block."""
    if signed == 0:
        return ""
    return f"+{signed:#x}" if signed > 0 else f"-{-signed:#x}"


def _max_tool_iters() -> int:
    """Tool-call rounds before the loop forces a summary.

    Caps a runaway question while letting a real multi-step investigation finish;
    `DEGLYPH_AI_MAX_ITERS` tunes it without a code change. On the final round the
    loop drops the tools and asks for a summary, so the cap never yields an empty
    reply.
    """
    try:
        return max(1, int(os.environ.get("DEGLYPH_AI_MAX_ITERS", "24")))
    except ValueError:
        return 24


# Back-compat alias for callers/tests that read the module-level constant.
MAX_TOOL_ITERS = _max_tool_iters()


def _request_timeout() -> float:
    """Per-request timeout in seconds; a stall surfaces as an error, not a hang."""
    try:
        return float(os.environ.get("DEGLYPH_AI_TIMEOUT", "90"))
    except ValueError:
        return 90.0


_SYSTEM = (
    "You are a reverse-engineering assistant embedded in a terminal tool, working "
    "over a whole native binary. The user is currently viewing one function (its "
    "annotated disassembly follows in a separate block), but you can investigate "
    "any part of the binary with the provided tools: find or list functions, "
    "list sections, disassemble code, read heuristic pseudo-C, run the structure "
    "detectors, list cross-references (for both code AND data addresses), search "
    "for strings/constants, dump raw bytes (read_data), and decode strings at an "
    "address (string_at). When the user asks about something not in the current "
    "function, use find_function or search to locate it, then disassemble/analyze "
    "it before answering. To trace a string's consumer, call xrefs on the string's "
    "VA — it lists every instruction that loads it, including rip-relative `lea`. "
    "Use read_data / string_at to confirm what a data VA actually points at "
    "before reasoning about its callers. Be concise and concrete. "
    "Cite addresses as sub_<hex> or 0x<hex> so the user can click them. The "
    "disassembly and detector notes are heuristics, not proofs -- say plainly when "
    "the evidence is insufficient rather than guessing. "
    "When the evidence makes a sub_* function's purpose plain (e.g. a stub that "
    "loads a command opcode and forwards to a known sender, or an entrypoint with "
    "the WinMain/main signature), call rename_function to give it that name. Only "
    "rename when you can point to specific evidence in the disassembly. Do not "
    "invent names from intuition. "
    "Cite the tool and address that supports each claim; when no tool output "
    "backs a statement, say it is uncertain and name what to check next. Before "
    "renaming a function you must first inspect it (disassemble, analyze, "
    "pseudo_c, xrefs, read_data, or string_at); a rename without prior "
    "inspection of that function is rejected."
)

# Read-only tools the assistant may call to investigate the binary.
_TOOL_SCHEMAS = [
    {
        "name": "find_function",
        "description": "Find functions whose name contains the query (case-insensitive).",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "list_functions",
        "description": "List functions, optionally filtered by kind (export/import/sub/symbol/entry).",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "limit": {"type": "integer"},
            },
        },
    },
    {
        "name": "disassemble",
        "description": "Disassemble a function by name or 0x-address.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "pseudo_c",
        "description": "Heuristic pseudo-C for a function by name or 0x-address (x86 only).",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "analyze",
        "description": "Run the detectors (immediate stores, call-arg immediates, CRC loops, constants) on a function.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "xrefs",
        "description": (
            "Cross-references for a target by name or 0x-address. For a "
            "function VA: callers and direct callees. For a data VA (string, "
            "table, pointer constant): instructions that reference it — "
            "including rip-relative `lea` and `mov`. Use this to find where a "
            "string is loaded from before reasoning about its consumers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "search",
        "description": "Search the image for a string, or an immediate constant if the query is a 0x-hex number.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "read_data",
        "description": (
            "Hex + ASCII preview of up to 256 bytes at a virtual address. "
            "Use to inspect strings, tables, structs, or pointer arrays at "
            "a data VA — for example, the buffer behind a string literal "
            "found via xrefs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "va": {"type": "string", "description": "0x-address to read"},
                "size": {
                    "type": "integer",
                    "description": "byte count (default 64, max 256)",
                },
            },
            "required": ["va"],
        },
    },
    {
        "name": "string_at",
        "description": (
            "Read a NUL-terminated ASCII or UTF-16LE string at a virtual "
            "address. Returns the decoded text, or '(no string here)' if the "
            "bytes don't look like one. Use this to confirm what a data VA "
            "points at before reasoning about its callers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "va": {"type": "string", "description": "0x-address of the string"},
            },
            "required": ["va"],
        },
    },
    {
        "name": "list_sections",
        "description": (
            "List the binary's sections with name, virtual address range, "
            "size, and flags (R/W/X). Use this to find where code lives "
            "versus data, or to scope a search to one section."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "rename_function",
        "description": (
            "Give a function a meaningful name (e.g. rename sub_140001020 to WinMain "
            "once its signature is recognized). Identifies the function by name or "
            "0x-address; the new name persists alongside the binary."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Current name or 0x-address of the function.",
                },
                "new_name": {
                    "type": "string",
                    "description": "The new display name (e.g. WinMain, decode_frame).",
                },
            },
            "required": ["target", "new_name"],
        },
    },
]


@dataclass(slots=True)
class ToolCall:
    """One read-only tool invocation and its result, for the audit transcript."""

    name: str
    input: dict
    result: str


# Secret-shaped tokens (provider key prefixes) and long opaque runs, masked in
# an exported investigation so a shared bundle never leaks a credential.
_SECRET_PREFIX = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}"
    r"|AKIA[A-Z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{8,})\b"
)
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")


def _redact(text: str, *, paths: list[str] | None = None) -> str:
    """Mask absolute paths and secret-looking tokens for safe sharing."""
    if not text:
        return text
    out = text
    for p in paths or []:
        if p:
            out = out.replace(p, "<path>")
    out = _SECRET_PREFIX.sub("<redacted:key>", out)
    out = _LONG_TOKEN.sub(lambda m: f"<redacted:{len(m.group(0))}>", out)
    return out


class AssistantError(RuntimeError):
    """A configuration, network, or API failure surfaced to the UI."""


# Cap on a single backend response body. A per-request timeout bounds
# inactivity, not total bytes, so a hostile or misconfigured endpoint (the
# OpenAI adapter accepts any base URL) could stream an unbounded reply and
# exhaust memory; 32 MiB is far above any real model response.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def _read_capped(resp, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    """Read at most `limit` bytes from `resp`, raising once the cap is passed."""
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise AssistantError(f"AI response exceeded {limit} bytes")
    return data


def api_key_present() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


# pip spec the install action targets. `anthropic` ships as a runtime
# dependency, so this guard only fires on a broken/partial install; name the
# package directly rather than a no-longer-defined extra.
AI_EXTRA = "anthropic"


def missing_package() -> str | None:
    """The pip spec to install when a needed package is absent, else None.

    Distinct from `unavailable_reason`: this fires only on a *package* gap that
    `pip install` can fix. A missing key (OpenAI, or Anthropic with the package
    present) returns None, since installing nothing helps there. The hosted
    tier runs server-side and the OpenAI-compatible family is stdlib-only, so
    neither needs the `anthropic` SDK.
    """
    from . import account, config

    if account.is_logged_in():
        return None
    provider_key = (
        config.get("ai_provider")
        or os.environ.get("DEGLYPH_AI_PROVIDER")
        or "anthropic"
    ).lower()
    info = provider_info(provider_key)
    family = info.family if info else "openai"
    if family == "openai":
        return None
    try:
        import anthropic  # noqa: F401
    except ModuleNotFoundError:
        return AI_EXTRA
    return None


def install_package(spec: str) -> tuple[bool, str]:
    """Install `spec` into the running interpreter with pip; return (ok, output).

    Runs `python -m pip install` as a subprocess (no shell), capturing pip's
    combined output so the caller can surface a failure verbatim. On a PEP 668
    externally-managed environment the output carries a hint to re-run inside a
    venv; this never adds `--break-system-packages` on the user's behalf.
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", spec],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except Exception as e:
        return False, f"could not launch pip: {e}"
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        return True, output.strip()
    if "externally-managed-environment" in output:
        output += (
            "\n\nThis interpreter is externally managed. Install deglyph in a "
            "virtual environment (see deglyph.sh) and retry."
        )
    return False, output.strip()


class Assistant:
    """Multi-turn chat over a binary: anchored on one function (cached context),
    with read-only tools to find, disassemble, and analyze any other function."""

    def __init__(self, *, model: str | None = None, client: Any | None = None):
        # An explicit model (or DEGLYPH_MODEL) pins the choice; otherwise it
        # resolves per request from config so the settings dialog takes effect.
        self._model_override = model or os.environ.get("DEGLYPH_MODEL")
        self._client: Any = client
        self._system: list[dict] = []
        self._messages: list[dict] = []
        self._context_label = ""
        # bound binary, so tools can roam the whole image
        self._image: Any = None
        # Pending renames the agent has applied this turn: va -> new_name. The
        # TUI drains this with `consume_renames()` after `ask` returns and
        # persists them through Annotations; the dict also acts as an in-flight
        # override so later tool calls in the same turn see the new names.
        self._renames: dict[int, str] = {}
        # Audit transcript of every tool call, and the slice index where the
        # current turn's calls begin, so `last_transcript` can scope to one ask.
        self._transcript: list[ToolCall] = []
        self._turn_start_tc = 0
        # VAs the agent inspected this turn; a rename is gated on prior inspection
        # of that function, so a name is always backed by tool evidence.
        self._inspected: set[int] = set()

    @property
    def model(self) -> str:
        """The Anthropic/hosted model id (the OpenAI path uses `openai_config`).

        An explicit override wins; otherwise the configured `ai_model` applies
        when the active provider is the Anthropic family, falling back to the
        default. The OpenAI family ignores this: `_create` substitutes the
        OpenAI-compatible model from `openai_config`.
        """
        if self._model_override:
            return self._model_override
        if self.provider_family() == "anthropic":
            from . import config

            chosen = config.get("ai_model")
            if chosen:
                return chosen
        return DEFAULT_MODEL

    def bind_image(self, image: Any) -> None:
        """Give the assistant the loaded image so its tools can inspect it."""
        self._image = image

    # -- context -----------------------------------------------------------
    def set_context(self, label: str, disassembly: str) -> None:
        """Load the function under discussion and reset the conversation.

        The disassembly block carries `cache_control`, so it is cached on the
        first turn and read back on every follow-up about the same function.
        """
        self._context_label = label
        self._system = [
            {"type": "text", "text": _SYSTEM},
            {
                "type": "text",
                "text": f"Function: {label}\n\nDisassembly:\n{disassembly}",
                "cache_control": {"type": "ephemeral"},
            },
        ]
        self._messages = []

    @property
    def context_label(self) -> str:
        return self._context_label

    def has_context(self) -> bool:
        return bool(self._system)

    def snapshot(self) -> list[dict]:
        """Copy of the conversation turns, for per-symbol caching."""
        return list(self._messages)

    def restore(self, messages: list[dict]) -> None:
        """Replace the conversation turns (the system/context block is unchanged)."""
        self._messages = list(messages)

    def provider(self) -> str:
        """The selected provider key: 'anthropic' (default), 'openai', 'groq', ...

        A key not in `PROVIDERS` is honored verbatim (a custom endpoint); its
        request shape comes from `provider_family`, which treats the unknown as
        OpenAI-compatible.
        """
        from . import config

        value = config.get("ai_provider") or os.environ.get("DEGLYPH_AI_PROVIDER")
        return (value or "anthropic").lower()

    def provider_family(self) -> str:
        """The request shape for the selected provider: 'anthropic' or 'openai'.

        The Anthropic family routes through the SDK / hosted tier; every other
        provider (including an unknown custom key) is OpenAI-compatible.
        """
        info = provider_info(self.provider())
        return info.family if info else "openai"

    def openai_config(self) -> dict:
        """Base URL, model, and key for the OpenAI-compatible endpoint.

        Defaults follow the selected provider's registry entry, so picking
        Groq/OpenRouter/Ollama fills the right base URL without the user typing
        it; an explicit config / env value still wins.
        """
        from . import config

        info = provider_info(self.provider())
        base = (
            config.get("ai_base_url")
            or os.environ.get("DEGLYPH_AI_BASE_URL")
            or (info.base_url if info else "")
            or DEFAULT_OPENAI_BASE
        )
        model = (
            config.get("ai_model")
            or os.environ.get("DEGLYPH_AI_MODEL")
            or (info.models[0] if info and info.models else "")
            or DEFAULT_OPENAI_MODEL
        )
        key = os.environ.get("DEGLYPH_AI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        return {"base_url": base, "model": model, "api_key": key or ""}

    def unavailable_reason(self) -> str | None:
        """An actionable reason the assistant cannot run, or None if it is ready.

        Lets the UI tell the user what to fix (missing package or key) up front,
        instead of only discovering it when a question is sent.
        """
        if self._client is not None:
            return None
        if self.provider_family() == "openai":
            cfg = self.openai_config()
            local = any(h in cfg["base_url"] for h in ("localhost", "127.0.0.1"))
            # local runners (Ollama, ...) need no key
            if cfg["api_key"] or local:
                return None
            return "set DEGLYPH_AI_API_KEY (or OPENAI_API_KEY) for the OpenAI endpoint"
        from . import account

        # hosted (Pro) tier handles it server-side
        if account.is_logged_in():
            return None
        try:
            import anthropic  # noqa: F401
        except ModuleNotFoundError:
            return (
                'the "anthropic" package is not installed '
                "(pip install anthropic), or run `deglyph login`"
            )
        if not api_key_present():
            return (
                "set ANTHROPIC_API_KEY (BYO key) or run `deglyph login` for hosted AI"
            )
        return None

    # -- chat --------------------------------------------------------------
    def ask(self, question: str, on_event=None) -> str:
        """Answer `question`, calling tools as needed; return the reply text.

        Runs an agentic loop: the model may call read-only tools to investigate
        the binary, and `on_event(name, input)` (if given) is fired for each tool
        call so the UI can show progress. Capped at `MAX_TOOL_ITERS` rounds; on the
        last round the loop forces a text summary, so the reply is never empty.
        """
        if not self._system:
            raise AssistantError("no function context loaded")
        reason = self.unavailable_reason()
        if reason:
            raise AssistantError(reason)
        start = len(self._messages)
        # Per-turn audit state: the transcript slice and the inspected-VA set
        # both scope to this ask, so `last_transcript` and the rename gate see
        # only what this turn established.
        self._turn_start_tc = len(self._transcript)
        self._inspected = set()
        self._messages.append({"role": "user", "content": question})
        try:
            resp = self._run_loop(on_event)
        except AssistantError:
            # roll back the unanswered exchange
            del self._messages[start:]
            del self._transcript[self._turn_start_tc :]
            raise
        # collapse SDK/network errors into one UI message
        except Exception as e:
            del self._messages[start:]
            del self._transcript[self._turn_start_tc :]
            raise AssistantError(str(e)) from e
        text = "".join(
            getattr(b, "text", "")
            for b in resp.content
            if getattr(b, "type", "") == "text"
        )
        # never surface a blank turn (e.g. a model that ends on a bare tool call)
        return text or "(no text in the reply; ask me to continue)"

    def _create(self, **kw: Any) -> Any:
        """One model round-trip, routed to the active backend.

        Injected client (tests/explicit) > OpenAI-compatible (when selected) >
        hosted (when logged in) > local Anthropic BYO-key.
        """
        if self._client is not None:
            return self._client.messages.create(**kw)
        if self.provider_family() == "openai":
            cfg = self.openai_config()
            # the loop builds an Anthropic-shaped request; the backend translates
            kw["model"] = cfg["model"]
            return OpenAIBackend(**cfg).create(**kw)
        from . import account

        token = account.load_token()
        # Pro: the server runs the model and enforces entitlement
        if token:
            return HostedBackend(token).create(**kw)
        return self._ensure_client().messages.create(**kw)

    def _run_loop(self, on_event):
        for _ in range(_max_tool_iters()):
            resp = self._create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=self._system,
                messages=self._messages,
                tools=_TOOL_SCHEMAS,
                timeout=_request_timeout(),
            )
            self._messages.append({"role": "assistant", "content": resp.content})
            tool_uses = [
                b for b in resp.content if getattr(b, "type", "") == "tool_use"
            ]
            if getattr(resp, "stop_reason", "end_turn") != "tool_use" or not tool_uses:
                return resp
            results = []
            for tu in tool_uses:
                if on_event is not None:
                    on_event(tu.name, dict(tu.input))
                content = self._run_tool(tu.name, dict(tu.input))
                self._transcript.append(ToolCall(tu.name, dict(tu.input), content))
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tu.id,
                        "content": content,
                    }
                )
            self._messages.append({"role": "user", "content": results})
        # Budget exhausted with tools still pending: force a text answer so the
        # turn never ends empty. Dropping `tools` makes the model summarize what
        # it found and state what remains, instead of requesting another call.
        return self._force_summary(on_event)

    _SUMMARY_NUDGE = (
        "You have reached the tool-call budget for this turn. Do not request more "
        "tools. Summarize what you found so far, and if the investigation is "
        "incomplete, say which functions or questions remain so the user can tell "
        "you to continue."
    )

    def _force_summary(self, on_event) -> Any:
        """One final tool-less round so an exhausted loop returns prose, not nothing.

        The nudge rides inside the last user turn (alongside the tool results)
        rather than as a new message, so the role sequence stays valid and no
        consecutive-user-turn is sent.
        """
        if on_event is not None:
            on_event("summarize", {})
        last = self._messages[-1] if self._messages else None
        nudge = {"type": "text", "text": self._SUMMARY_NUDGE}
        if last and last["role"] == "user" and isinstance(last["content"], list):
            last["content"].append(nudge)
        else:
            self._messages.append({"role": "user", "content": [nudge]})
        # Keep `tools` defined (the history holds tool_use blocks, which the API
        # requires tools for) but forbid new calls with tool_choice=none, so the
        # model must answer in text.
        resp = self._create(
            model=self.model,
            max_tokens=MAX_TOKENS,
            system=self._system,
            messages=self._messages,
            tools=_TOOL_SCHEMAS,
            tool_choice={"type": "none"},
            timeout=_request_timeout(),
        )
        self._messages.append({"role": "assistant", "content": resp.content})
        return resp

    # -- audit -------------------------------------------------------------
    def transcript(self) -> list[ToolCall]:
        """Every tool call recorded across the conversation."""
        return list(self._transcript)

    def last_transcript(self) -> list[ToolCall]:
        """The tool calls made during the most recent `ask`."""
        return list(self._transcript[self._turn_start_tc :])

    def export_investigation(self) -> dict:
        """A redacted, shareable record of the most recent investigation.

        Bundles the question, the answer, and the tool-call transcript with the
        host path and secret-looking tokens masked, so an investigation can be
        shared without leaking credentials or local paths.
        """
        paths = []
        path = self._image.path if self._image is not None else ""
        if path:
            paths.append(path)
        question = ""
        for m in reversed(self._messages):
            if m["role"] == "user" and isinstance(m["content"], str):
                question = m["content"]
                break
        answer = ""
        for m in reversed(self._messages):
            if m["role"] != "assistant":
                continue
            blocks = m["content"]
            parts = [
                _block_to_dict(b).get("text", "")
                for b in (blocks if isinstance(blocks, list) else [])
                if _block_to_dict(b).get("type") == "text"
            ]
            if parts:
                answer = "\n".join(parts)
                break
        return {
            "context": self._context_label,
            "question": _redact(question, paths=paths),
            "answer": _redact(answer, paths=paths),
            "transcript": [
                {
                    "tool": c.name,
                    "input": c.input,
                    "result": _redact(c.result, paths=paths),
                }
                for c in self.last_transcript()
            ],
            "redacted": True,
        }

    # -- tools -------------------------------------------------------------
    def consume_renames(self) -> dict[int, str]:
        """Drain the renames the agent applied this turn (va -> new_name).

        Caller is the TUI (after `ask` returns): it persists the renames via
        `Annotations.names` and rebuilds the tree. The internal dict is also
        consulted by tool output during the loop, so the agent sees its own
        renames before they have been persisted.
        """
        out = dict(self._renames)
        self._renames.clear()
        return out

    def _display(self, func) -> str:
        """Display name with an in-flight rename applied, if the agent set one."""
        return self._renames.get(func.va, func.display)

    def _resolve(self, target: str) -> int | None:
        """Resolve a tool `target` (a 0x-address or a function-name substring) to a VA.

        Matches both the original display name and any in-flight rename, so the
        agent can refer to a function by the name it just gave it.
        """
        target = (target or "").strip()
        if target.lower().startswith("0x"):
            try:
                return int(target, 16)
            except ValueError:
                return None
        needle = target.lower()
        for f in self._image.funcs:
            if needle in f.display.lower():
                return f.va
            rn = self._renames.get(f.va)
            if rn and needle in rn.lower():
                return f.va
        return None

    # `[A-Za-z_][A-Za-z0-9_]*` plus `::` for C++-style names — what the user
    # would actually type at the rename prompt; anything else (whitespace, path
    # separators, NUL bytes) is rejected so the sidecar can't be poisoned.
    _RENAME_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]*$")

    def _tool_rename(self, inp: dict) -> str:
        """Apply a rename: record it for the TUI to persist, with sanity checks."""
        target = inp.get("target", "")
        new_name = (inp.get("new_name") or "").strip()
        if not new_name:
            return "error: new_name is empty"
        if len(new_name) > 96 or not self._RENAME_OK.match(new_name):
            return (
                f"error: {new_name!r} is not a valid identifier "
                "(letters, digits, `_`, `::`; max 96 chars)"
            )
        va = self._resolve(target)
        if va is None:
            return f"error: could not resolve {target!r}"
        func = self._image.func_at(va)
        if func is None:
            return f"error: no function at {va:#x}"
        if va not in self._inspected:
            return (
                f"error: inspect {self._display(func)} ({va:#x}) first "
                "(disassemble / analyze / pseudo_c / xrefs / read_data / string_at) "
                "so the new name is backed by evidence"
            )
        prior = self._display(func)
        self._renames[va] = new_name
        return f"renamed {prior} ({va:#x}) to {new_name}"

    # Per-call read cap for raw byte inspection; protects the context budget.
    _READ_DATA_MAX = 256

    def _tool_read_data(self, inp: dict) -> str:
        """Hex + ASCII dump of `size` bytes at `va`, like a tiny `xxd`."""
        va = self._resolve(str(inp.get("va", "")))
        if va is None:
            return f"error: could not resolve {inp.get('va')!r}"
        self._inspected.add(va)
        try:
            size = int(inp.get("size", 64))
        except (TypeError, ValueError):
            size = 64
        size = max(1, min(size, self._READ_DATA_MAX))
        raw = self._image.read_va(va, size)
        if not raw:
            return f"error: no mapped data at {va:#x}"
        sec = self._image.section_at(va)
        header = f"{va:#x}  ({sec.name if sec else 'no section'})  {len(raw)} bytes"
        lines = [header]
        for i in range(0, len(raw), 16):
            chunk = raw[i : i + 16]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            ascii_ = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            lines.append(f"{va + i:#012x}  {hexs:<47}  {ascii_}")
        return "\n".join(lines)

    def _tool_string_at(self, inp: dict) -> str:
        """Decode a NUL-terminated ASCII or UTF-16LE string at `va`."""
        va = self._resolve(str(inp.get("va", "")))
        if va is None:
            return f"error: could not resolve {inp.get('va')!r}"
        self._inspected.add(va)
        raw = self._image.read_va(va, 512)
        if not raw:
            return "(no mapped data here)"
        # ASCII: run of printable bytes terminated by NUL
        ascii_bytes = []
        for b in raw:
            if b == 0:
                break
            if 0x20 <= b <= 0x7E:
                ascii_bytes.append(b)
            else:
                ascii_bytes = []
                break
        if len(ascii_bytes) >= 2:
            return f'ascii ({len(ascii_bytes)} chars): "{bytes(ascii_bytes).decode()}"'
        # UTF-16LE: pairs of (printable, 0)
        chars: list[str] = []
        i = 0
        while i + 1 < len(raw):
            lo, hi = raw[i], raw[i + 1]
            if lo == 0 and hi == 0:
                break
            if hi == 0 and 0x20 <= lo <= 0x7E:
                chars.append(chr(lo))
                i += 2
            else:
                chars = []
                break
        if len(chars) >= 2:
            return f'utf-16 ({len(chars)} chars): "{"".join(chars)}"'
        return "(no string here)"

    def _tool_list_sections(self) -> str:
        """Section table with name, VA range, size, and flags."""
        secs = self._image.sections
        if not secs:
            return "(no sections)"
        lines = ["name          va             end            size       flags"]
        for s in secs:
            lines.append(
                f"{s.name:<12}  {s.va:#012x}   {s.end:#012x}   "
                f"{s.size:#10x}  {s.flags}"
            )
        return "\n".join(lines)

    def _run_tool(self, name: str, inp: dict) -> str:
        """Execute a read-only tool against the bound image; return text (capped)."""
        if self._image is None:
            return "error: no binary is loaded"
        from .core.disasm import Disassembler
        from .re import (
            call_immediate_args,
            callees_of,
            callers_of,
            detect_crc_loops,
            find_immediate,
            find_string,
            function_constants,
            immediate_stores,
            pseudo_c,
            thunk_chain,
        )

        img = self._image
        try:
            if name == "rename_function":
                return self._tool_rename(inp)
            if name == "read_data":
                return self._tool_read_data(inp)
            if name == "string_at":
                return self._tool_string_at(inp)
            if name == "list_sections":
                return self._tool_list_sections()
            if name == "find_function":
                q = inp.get("query", "").lower()
                hits = [
                    f
                    for f in img.funcs
                    if q in f.display.lower() or q in self._display(f).lower()
                ][:30]
                return (
                    "\n".join(
                        f"{self._display(f)}  {f.va:#x}  ({f.kind})" for f in hits
                    )
                    or "no matching function"
                )
            if name == "list_functions":
                kind = inp.get("kind")
                limit = int(inp.get("limit", 40))
                fs = [f for f in img.funcs if not kind or f.kind == kind]
                return (
                    "\n".join(
                        f"{self._display(f)}  {f.va:#x}  ({f.kind})" for f in fs[:limit]
                    )
                    or "no functions"
                )
            if name in ("disassemble", "pseudo_c", "analyze", "xrefs"):
                va = self._resolve(inp.get("target", ""))
                if va is None:
                    return f"error: could not resolve {inp.get('target')!r}"
                self._inspected.add(va)
                if name == "disassemble":
                    insns = Disassembler(img).func(va)[:120]
                    return "\n".join(f"{i.addr:#012x}  {i.text}" for i in insns)
                if name == "pseudo_c":
                    lines = pseudo_c(img, va)[:120]
                    return "\n".join(ln.code for ln in lines) or "(no pseudo-C)"
                if name == "analyze":
                    real = thunk_chain(img, va)[-1]
                    stores = [
                        f"[{s.base}{_ai_disp(s.signed_disp)}]={s.value:#x}"
                        f"({s.evidence.confidence})"
                        for s in immediate_stores(img, real)[:16]
                    ]
                    args = [
                        f"{a.reg}={a.value:#x}({a.evidence.confidence})"
                        for a in call_immediate_args(img, real)[:12]
                    ]
                    crc = [hex(p) for c in detect_crc_loops(img, real) for p in c.polys]
                    consts = [
                        hex(v) for v, _ in function_constants(img, real).most_common(8)
                    ]
                    return (
                        f"impl={real:#x}\nstores: {stores}\ncall_args: {args}\n"
                        f"crc_polys: {crc}\nconstants: {consts}"
                    )
                # Distinguish a function VA from a data VA: for data, the
                # callers/callees indices return nothing, so fall back to a
                # whole-image scan that catches rip-relative references too.
                sec = img.section_at(va)
                is_data = (
                    img.func_at(va) is None
                    and sec is not None
                    and "X" not in sec.flags.upper()
                )
                if is_data:
                    hits = find_immediate(img, va)[:30]
                    if not hits:
                        return f"no code references to {va:#x} (in {sec.name})"
                    return f"REFERENCES TO {va:#x} (in {sec.name})\n" + "\n".join(
                        f"  {h.va:#x}  {h.kind}  {h.detail}" for h in hits
                    )
                callers = callers_of(img, va)[:30]
                callees = callees_of(img, va)[:30]

                def _nm(a: int) -> str:
                    f = img.func_at(a) or img.nearest_func(a)
                    return self._display(f) if f else f"{a:#x}"

                return (
                    "callers: "
                    + ", ".join(_nm(c) for c in callers)
                    + "\ncallees: "
                    + ", ".join(_nm(c) for c in callees)
                )
            if name == "search":
                q = inp.get("query", "").strip()
                if q.lower().startswith("0x"):
                    hits = find_immediate(img, int(q, 16))[:30]
                else:
                    hits = find_string(img, q)[:30]
                return (
                    "\n".join(f"{h.va:#x}  {h.kind}  {h.detail}" for h in hits)
                    or "no hits"
                )
        # never let a tool crash the loop
        except Exception as e:
            return f"error running {name}: {e}"
        return f"error: unknown tool {name!r}"

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not api_key_present():
            raise AssistantError("ANTHROPIC_API_KEY is not set")
        try:
            import anthropic
        except ModuleNotFoundError as e:
            raise AssistantError(
                "the 'anthropic' package is not installed (pip install anthropic)"
            ) from e
        self._client = anthropic.Anthropic()
        return self._client


# --- hosted (Pro) backend ---------------------------------------------------
# Talks to api.deglyph.dev, which runs the model with the server's key and
# enforces the caller's entitlement. The tool-use loop stays client-side; this
# only proxies one model round-trip. The server is a separate, private repo.


class _HostedBlock:
    """A response content block from the hosted API (Anthropic-shaped)."""

    __slots__ = ("type", "text", "id", "name", "input")

    def __init__(self, d: dict):
        self.type = d.get("type", "")
        self.text = d.get("text", "")
        self.id = d.get("id")
        self.name = d.get("name")
        self.input = d.get("input", {})

    def to_dict(self) -> dict:
        if self.type == "tool_use":
            return {
                "type": "tool_use",
                "id": self.id,
                "name": self.name,
                "input": self.input,
            }
        return {"type": self.type, "text": self.text}


class _HostedResponse:
    def __init__(self, data: dict):
        self.content = [_HostedBlock(b) for b in data.get("content", [])]
        self.stop_reason = data.get("stop_reason", "end_turn")


def _jsonable(messages: list[dict]) -> list[dict]:
    """Make message blocks JSON-serializable (hosted assistant turns are objects)."""
    out = []
    for m in messages:
        content = m["content"]
        if isinstance(content, list):
            content = [
                c.to_dict() if isinstance(c, _HostedBlock) else c for c in content
            ]
        out.append({"role": m["role"], "content": content})
    return out


class HostedBackend:
    """Posts one round-trip to the hosted endpoint; returns an Anthropic-shaped reply."""

    def __init__(self, token: str, url: str | None = None):
        from . import account

        self._token = token
        self._url = (url or account.api_url()).rstrip("/") + "/v1/messages"

    def create(self, **kw: Any) -> _HostedResponse:
        import json
        import urllib.request

        body: dict = {
            "model": kw["model"],
            "max_tokens": kw["max_tokens"],
            "system": kw["system"],
            "messages": _jsonable(kw["messages"]),
            "tools": kw.get("tools"),
        }
        if kw.get("tool_choice") is not None:
            body["tool_choice"] = kw["tool_choice"]
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        )
        try:
            timeout = float(kw.get("timeout") or 120)
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                return _HostedResponse(json.loads(_read_capped(r).decode("utf-8")))
        except Exception as e:
            raise AssistantError(f"hosted AI request failed: {e}") from e


# --- OpenAI-compatible backend ----------------------------------------------
# Speaks the OpenAI Chat Completions API, so one adapter serves OpenAI, Azure,
# Groq, OpenRouter, DeepSeek, and local runners (Ollama, LM Studio). The agentic
# loop builds an Anthropic-shaped request; these helpers translate to OpenAI and
# back, returning the same _HostedResponse the loop already understands.


def _block_to_dict(b: Any) -> dict:
    if isinstance(b, dict):
        return b
    if hasattr(b, "to_dict"):
        return b.to_dict()
    return {"type": getattr(b, "type", "text"), "text": getattr(b, "text", "")}


def _to_openai_messages(system: list[dict], messages: list[dict]) -> list[dict]:
    """Anthropic system block + messages -> OpenAI chat messages."""
    out: list[dict] = []
    sys_text = "\n\n".join(
        b.get("text", "") for b in system if isinstance(b, dict)
    ).strip()
    if sys_text:
        out.append({"role": "system", "content": sys_text})
    for m in messages:
        role, content = m["role"], m["content"]
        if isinstance(content, str):
            out.append({"role": role, "content": content})
        elif role == "assistant":
            texts, calls = [], []
            for blk in content:
                bd = _block_to_dict(blk)
                if bd.get("type") == "text":
                    texts.append(bd.get("text", ""))
                elif bd.get("type") == "tool_use":
                    calls.append(
                        {
                            "id": bd.get("id"),
                            "type": "function",
                            "function": {
                                "name": bd.get("name"),
                                "arguments": json.dumps(bd.get("input") or {}),
                            },
                        }
                    )
            msg: dict = {"role": "assistant", "content": "\n".join(texts) or None}
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
        # a user turn carrying tool_result blocks (and maybe a trailing text nudge)
        else:
            extra_text: list[str] = []
            for blk in content:
                bd = blk if isinstance(blk, dict) else {}
                if bd.get("type") == "tool_result":
                    out.append(
                        {
                            "role": "tool",
                            "tool_call_id": bd.get("tool_use_id"),
                            "content": str(bd.get("content", "")),
                        }
                    )
                elif bd.get("type") == "text":
                    extra_text.append(bd.get("text", ""))
            # a tool message can't hold prose; emit the nudge as its own user turn
            if extra_text:
                out.append({"role": "user", "content": "\n".join(extra_text)})
    return out


def _to_openai_tools(tools: list[dict] | None) -> list[dict] | None:
    if not tools:
        return None
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {}),
            },
        }
        for t in tools
    ]


def _from_openai(data: dict) -> _HostedResponse:
    """OpenAI chat-completion response -> Anthropic-shaped _HostedResponse."""
    choice = (data.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    content: list[dict] = []
    if msg.get("content"):
        content.append({"type": "text", "text": msg["content"]})
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except ValueError:
            args = {}
        content.append(
            {
                "type": "tool_use",
                "id": tc.get("id"),
                "name": fn.get("name"),
                "input": args,
            }
        )
    stop = "tool_use" if choice.get("finish_reason") == "tool_calls" else "end_turn"
    return _HostedResponse({"content": content, "stop_reason": stop})


class OpenAIBackend:
    """One round-trip to an OpenAI-compatible chat-completions endpoint."""

    def __init__(self, base_url: str, model: str, api_key: str = ""):
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._key = api_key

    def create(self, **kw: Any) -> _HostedResponse:
        import urllib.request

        payload: dict = {
            "model": self._model,
            "messages": _to_openai_messages(kw["system"], kw["messages"]),
            "max_tokens": kw.get("max_tokens", MAX_TOKENS),
        }
        tools = _to_openai_tools(kw.get("tools"))
        if tools:
            payload["tools"] = tools
            # Anthropic {"type": "none"} -> OpenAI "none" (forbid new tool calls).
            if isinstance(kw.get("tool_choice"), dict):
                payload["tool_choice"] = kw["tool_choice"].get("type", "auto")
        headers = {"Content-Type": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        req = urllib.request.Request(
            self._url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            timeout = float(kw.get("timeout") or 120)
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                return _from_openai(json.loads(_read_capped(r).decode("utf-8")))
        except Exception as e:
            raise AssistantError(f"OpenAI-compatible request failed: {e}") from e
