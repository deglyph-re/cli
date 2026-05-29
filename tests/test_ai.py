# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Assistant wrapper: request shape, prompt caching, and multi-turn state."""

from __future__ import annotations

import pytest

from deglyph.ai import DEFAULT_MODEL, Assistant, AssistantError


class _Block:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text: str):
        self.content = [_Block(text)]


class _Messages:
    def __init__(self):
        self.calls: list[dict] = []

    def create(self, **kw):
        # Snapshot messages: the caller mutates the list after the call returns.
        self.calls.append({**kw, "messages": list(kw["messages"])})
        return _Resp(f"reply to: {kw['messages'][-1]['content']}")


class FakeClient:
    def __init__(self):
        self.messages = _Messages()


# --- agentic tool-use loop --------------------------------------------------


class _ToolUse:
    def __init__(self, name, inp, id="tu1"):
        self.type, self.name, self.input, self.id = "tool_use", name, inp, id


class _LoopResp:
    def __init__(self, content, stop_reason):
        self.content, self.stop_reason = content, stop_reason


class _AgenticClient:
    """First create() asks for a tool; the second returns the final answer."""

    def __init__(self, tool="find_function", query="enc"):
        self.calls = 0
        self._tool, self._query = tool, query
        # so client.messages.create(...) resolves here
        self.messages = self

    def create(self, **kw):
        self.calls += 1
        if self.calls == 1:
            return _LoopResp([_ToolUse(self._tool, {"query": self._query})], "tool_use")
        return _LoopResp([_Block("done")], "end_turn")


def test_agentic_loop_runs_tools_then_answers(code_image):
    # one func "f" at 0x1000
    img = code_image(bytes.fromhex("c3"))
    a = Assistant(client=_AgenticClient())
    a.bind_image(img)
    a.set_context("f", "0x1000 ret")
    events = []
    reply = a.ask("explain", on_event=lambda n, i: events.append(n))
    assert reply == "done"
    # the loop drove the tool
    assert events == ["find_function"]
    roles = [m["role"] for m in a._messages]
    # tool round-trip
    assert roles == ["user", "assistant", "user", "assistant"]


class _NeverStopsClient:
    """Requests a tool on every normal round; answers in text only on the final
    round, which forbids tools via tool_choice=none."""

    def __init__(self):
        self.calls = 0
        self.tool_choices: list[object] = []
        self.messages = self

    def create(self, **kw):
        self.calls += 1
        self.tool_choices.append(kw.get("tool_choice"))
        # forced-summary round: tools still defined, but new calls forbidden
        if kw.get("tool_choice") == {"type": "none"}:
            return _LoopResp([_Block("forced summary")], "end_turn")
        return _LoopResp([_ToolUse("find_function", {"query": "x"})], "tool_use")


def test_loop_forces_summary_when_budget_exhausted(code_image, monkeypatch):
    monkeypatch.delenv("DEGLYPH_AI_MAX_ITERS", raising=False)
    from deglyph.ai import _max_tool_iters

    img = code_image(bytes.fromhex("c3"))
    a = Assistant(client=_NeverStopsClient())
    a.bind_image(img)
    a.set_context("f", "0x1000 ret")
    events: list[str] = []
    reply = a.ask("map everything", on_event=lambda n, i: events.append(n))
    # the loop never ends empty: the final round produces prose
    assert reply == "forced summary"
    # one tool round per budget unit, then one final tool-less round
    assert a._client.calls == _max_tool_iters() + 1
    # the final round forbids tools; every prior round left tool_choice unset
    assert a._client.tool_choices[-1] == {"type": "none"}
    assert all(tc is None for tc in a._client.tool_choices[:-1])
    assert events[-1] == "summarize"


def test_max_iters_env_override(monkeypatch):
    from deglyph.ai import _max_tool_iters

    monkeypatch.setenv("DEGLYPH_AI_MAX_ITERS", "3")
    assert _max_tool_iters() == 3
    monkeypatch.setenv("DEGLYPH_AI_MAX_ITERS", "garbage")
    assert _max_tool_iters() == 24


def test_tool_find_function(code_image):
    img = code_image(bytes.fromhex("c3"))
    a = Assistant(client=FakeClient())
    a.bind_image(img)
    assert "0x1000" in a._run_tool("find_function", {"query": "f"})


def test_tool_disassemble(code_image):
    # nop ; nop ; ret
    img = code_image(bytes.fromhex("90 90 c3"))
    a = Assistant(client=FakeClient())
    a.bind_image(img)
    out = a._run_tool("disassemble", {"target": "0x1000"})
    assert "nop" in out and "ret" in out


def test_tool_unresolved_target_is_graceful(code_image):
    a = Assistant(client=FakeClient())
    a.bind_image(code_image(bytes.fromhex("c3")))
    assert "could not resolve" in a._run_tool("analyze", {"target": "nope"})


def test_context_is_cached_and_labeled(tmp_path, monkeypatch):
    # Isolate the model config so a real ~/.deglyph/config.json from earlier
    # use of the app does not pin a non-default model.
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_MODEL", raising=False)
    a = Assistant(client=FakeClient())
    a.set_context("encode_frame", "0x1000  mov eax, 1")
    a.ask("what does it do?")
    call = a._client.messages.calls[0]
    # System has frozen instructions + a cached disassembly block.
    assert call["system"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "encode_frame" in call["system"][-1]["text"]
    assert call["model"] == DEFAULT_MODEL


def test_multi_turn_history_accumulates():
    a = Assistant(client=FakeClient())
    a.set_context("f", "code")
    a.ask("first")
    a.ask("second")
    call2 = a._client.messages.calls[1]
    roles = [m["role"] for m in call2["messages"]]
    assert roles == ["user", "assistant", "user"]
    assert call2["messages"][0]["content"] == "first"


def test_ask_without_context_errors():
    a = Assistant(client=FakeClient())
    with pytest.raises(AssistantError):
        a.ask("hi")


def test_failed_turn_is_not_retained():
    class Boom:
        class messages:
            @staticmethod
            def create(**kw):
                raise RuntimeError("network down")

    a = Assistant(client=Boom())
    a.set_context("f", "code")
    with pytest.raises(AssistantError):
        a.ask("q")
    # unanswered turn rolled back
    assert a._messages == []


def test_model_default_and_override(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_MODEL", raising=False)
    assert Assistant().model == DEFAULT_MODEL
    monkeypatch.setenv("DEGLYPH_MODEL", "claude-haiku-4-5")
    assert Assistant().model == "claude-haiku-4-5"


def test_no_api_key_is_a_clean_error(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # no token can leak in
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    # no injected client -> must resolve a real one
    a = Assistant()
    a.set_context("f", "code")
    # The actionable error names whichever gate is hit first: the missing
    # `anthropic` package (CI, no `ai` extra) or the missing key (package present).
    with pytest.raises(AssistantError, match="ANTHROPIC_API_KEY|anthropic"):
        a.ask("q")


def test_unavailable_reason(tmp_path, monkeypatch):
    assert Assistant(client=FakeClient()).unavailable_reason() is None
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    reason = Assistant().unavailable_reason()
    # anthropic may or may not be installed in this env; either way it is a
    # concrete, actionable reason string.
    assert reason and ("anthropic" in reason or "ANTHROPIC_API_KEY" in reason)


def test_logged_in_makes_assistant_available(tmp_path, monkeypatch):
    from deglyph import account

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    # no key, no token -> unavailable
    assert Assistant().unavailable_reason()
    account.save_token("tok-abc")
    # token -> hosted path is viable
    assert Assistant().unavailable_reason() is None


def test_missing_package_when_anthropic_absent(tmp_path, monkeypatch):
    import builtins

    from deglyph import ai

    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "anthropic":
            raise ModuleNotFoundError("no anthropic")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert ai.missing_package() == ai.AI_EXTRA


def test_missing_package_none_when_logged_in(tmp_path, monkeypatch):
    import builtins

    from deglyph import account, ai

    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "anthropic":
            raise ModuleNotFoundError("no anthropic")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # a token makes the hosted path viable, so no package gap to fill
    account.save_token("tok")
    assert ai.missing_package() is None


def test_install_package_success(monkeypatch):
    import subprocess

    from deglyph import ai

    class _Proc:
        returncode = 0
        stdout = "Successfully installed anthropic-0.40.0\n"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc())
    ok, output = ai.install_package(ai.AI_EXTRA)
    assert ok and "Successfully installed" in output


def test_install_package_failure_carries_pip_output(monkeypatch):
    import subprocess

    from deglyph import ai

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "ERROR: Could not find a version that satisfies the requirement\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc())
    ok, output = ai.install_package(ai.AI_EXTRA)
    assert not ok and "Could not find a version" in output


def test_install_package_flags_externally_managed(monkeypatch):
    import subprocess

    from deglyph import ai

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "error: externally-managed-environment\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc())
    ok, output = ai.install_package(ai.AI_EXTRA)
    assert not ok and "virtual environment" in output


def test_hosted_response_parses_text_and_tool_use():
    from deglyph.ai import _HostedResponse, _jsonable

    data = {
        "stop_reason": "tool_use",
        "content": [
            {"type": "text", "text": "looking"},
            {
                "type": "tool_use",
                "id": "t1",
                "name": "find_function",
                "input": {"q": "x"},
            },
        ],
    }
    resp = _HostedResponse(data)
    assert resp.stop_reason == "tool_use"
    text, tool = resp.content
    assert text.type == "text" and text.text == "looking"
    assert (
        tool.type == "tool_use"
        and tool.name == "find_function"
        and tool.input == {"q": "x"}
    )

    # an assistant turn carrying _HostedBlock objects round-trips to plain JSON
    msgs = _jsonable([{"role": "assistant", "content": resp.content}])
    blocks = msgs[0]["content"]
    assert blocks[0] == {"type": "text", "text": "looking"}
    assert blocks[1] == {
        "type": "tool_use",
        "id": "t1",
        "name": "find_function",
        "input": {"q": "x"},
    }


def test_provider_defaults_and_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_AI_PROVIDER", raising=False)
    a = Assistant()
    assert a.provider() == "anthropic"
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "OpenAI")
    # normalized
    assert a.provider() == "openai"


def test_openai_config_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("DEGLYPH_AI_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("DEGLYPH_AI_MODEL", "llama3.1")
    cfg = Assistant().openai_config()
    assert cfg["base_url"].endswith("11434/v1")
    assert cfg["model"] == "llama3.1"


def test_known_providers_registry():
    from deglyph.ai import known_providers, provider_info

    keys = {p.key for p in known_providers()}
    assert {"anthropic", "openai", "groq", "openrouter", "ollama"} <= keys
    assert provider_info("anthropic").family == "anthropic"
    assert provider_info("groq").family == "openai"
    # local runners need no key; an unknown key has no entry
    assert provider_info("ollama").needs_key is False
    assert provider_info("nope") is None


def test_provider_family_routes_known_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_AI_PROVIDER", raising=False)
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "groq")
    a = Assistant()
    assert a.provider() == "groq"
    # groq is OpenAI-shaped, so the request routes through the OpenAI adapter
    assert a.provider_family() == "openai"
    # an unknown custom key is treated as OpenAI-compatible
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "my-proxy")
    assert Assistant().provider_family() == "openai"


def test_openai_config_defaults_to_provider_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    for var in ("DEGLYPH_AI_BASE_URL", "DEGLYPH_AI_MODEL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "groq")
    cfg = Assistant().openai_config()
    # base URL and model fall back to groq's registry entry
    assert "groq.com" in cfg["base_url"]
    assert cfg["model"].startswith("llama")


def test_anthropic_model_from_config(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_MODEL", raising=False)
    monkeypatch.delenv("DEGLYPH_AI_PROVIDER", raising=False)
    from deglyph import config

    a = Assistant()
    assert a.model == DEFAULT_MODEL
    # a configured model applies to the anthropic family
    config.put("ai_model", "claude-haiku-4-5")
    assert a.model == "claude-haiku-4-5"
    # an explicit override (or DEGLYPH_MODEL) still wins
    assert Assistant(model="pinned").model == "pinned"


def test_anthropic_model_config_ignored_for_openai(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_MODEL", raising=False)
    from deglyph import config

    config.put("ai_provider", "openai")
    config.put("ai_model", "gpt-4o")
    # the OpenAI path carries its model via openai_config, not Assistant.model,
    # so .model stays the anthropic default
    assert Assistant().model == DEFAULT_MODEL


def test_unavailable_reason_openai(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "openai")
    monkeypatch.delenv("DEGLYPH_AI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    monkeypatch.setenv("DEGLYPH_AI_BASE_URL", "https://api.openai.com/v1")
    # remote endpoint, no key
    assert Assistant().unavailable_reason()

    monkeypatch.setenv("DEGLYPH_AI_API_KEY", "sk-test")
    # key supplied
    assert Assistant().unavailable_reason() is None

    monkeypatch.delenv("DEGLYPH_AI_API_KEY", raising=False)
    monkeypatch.setenv("DEGLYPH_AI_BASE_URL", "http://localhost:11434/v1")
    # local runner needs no key
    assert Assistant().unavailable_reason() is None


def test_openai_translation_roundtrip():
    from deglyph.ai import _from_openai, _to_openai_messages, _to_openai_tools

    system = [{"type": "text", "text": "sys"}, {"type": "text", "text": "disasm"}]
    msgs = [
        {"role": "user", "content": "what is this?"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "looking"},
                {"type": "tool_use", "id": "t1", "name": "disassemble", "input": {}},
            ],
        },
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ret"}],
        },
    ]
    om = _to_openai_messages(system, msgs)
    assert [m["role"] for m in om] == ["system", "user", "assistant", "tool"]
    assert om[2]["tool_calls"][0]["function"]["name"] == "disassemble"
    assert om[3]["tool_call_id"] == "t1"

    tools = _to_openai_tools(
        [{"name": "x", "description": "d", "input_schema": {"a": 1}}]
    )
    assert tools[0]["type"] == "function" and tools[0]["function"]["parameters"] == {
        "a": 1
    }

    resp = _from_openai(
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "content": "ok",
                        "tool_calls": [
                            {
                                "id": "c1",
                                "function": {
                                    "name": "search",
                                    "arguments": '{"q":"x"}',
                                },
                            }
                        ],
                    },
                }
            ]
        }
    )
    assert resp.stop_reason == "tool_use"
    kinds = [(b.type, getattr(b, "name", None)) for b in resp.content]
    assert ("text", None) in kinds and ("tool_use", "search") in kinds
