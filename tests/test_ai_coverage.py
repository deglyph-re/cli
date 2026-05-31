# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Targeted coverage for the corners of `deglyph.ai` the main suite skips:
the HTTP backends (urlopen mocked), the rest of the tool router, and the
provider-aware branches of `missing_package`.
"""

from __future__ import annotations

import io
import json

import pytest

from deglyph import ai


class _Resp:
    """Minimal urlopen() context manager that yields a JSON body."""

    def __init__(self, body: dict):
        self._buf = io.BytesIO(json.dumps(body).encode("utf-8"))

    def __enter__(self):
        return self._buf

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._buf.read()


def _patch_urlopen(monkeypatch, target: str, fn):
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fn)


# --- _request_timeout -------------------------------------------------------


def test_request_timeout_default_and_bad_env(monkeypatch):
    monkeypatch.delenv("DEGLYPH_AI_TIMEOUT", raising=False)
    assert ai._request_timeout() == 90.0
    monkeypatch.setenv("DEGLYPH_AI_TIMEOUT", "garbage")
    assert ai._request_timeout() == 90.0
    monkeypatch.setenv("DEGLYPH_AI_TIMEOUT", "12.5")
    assert ai._request_timeout() == 12.5


# --- missing_package: provider-aware shortcut --------------------------------


def test_missing_package_skips_for_openai_family(tmp_path, monkeypatch):
    """An OpenAI-family provider needs no anthropic SDK; button must hide."""
    import builtins

    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "openai")
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "anthropic":
            raise ModuleNotFoundError("no anthropic")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert ai.missing_package() is None


def test_missing_package_skips_for_unknown_provider(tmp_path, monkeypatch):
    """A custom provider key is treated as OpenAI-family: still stdlib-only."""
    import builtins

    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "my-proxy")
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "anthropic":
            raise ModuleNotFoundError("no anthropic")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert ai.missing_package() is None


def test_missing_package_none_when_anthropic_present(tmp_path, monkeypatch):
    """With the package importable and Anthropic selected, no spec to install."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "anthropic")
    # the harness has `anthropic` installed via the [ai] extra; trust the import
    assert ai.missing_package() is None


# --- install_package error path ---------------------------------------------


def test_install_package_subprocess_exception(monkeypatch):
    import subprocess

    def boom(*a, **k):
        raise OSError("denied")

    monkeypatch.setattr(subprocess, "run", boom)
    ok, output = ai.install_package(ai.AI_EXTRA)
    assert not ok and "could not launch pip" in output


# --- HostedBackend ----------------------------------------------------------


def test_hosted_backend_posts_and_parses(monkeypatch):
    """Hosted backend serializes the request and returns a _HostedResponse."""
    captured: dict = {}

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp(
            {
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "hi"}],
            }
        )

    _patch_urlopen(monkeypatch, "hosted", fake_urlopen)
    from deglyph import account

    monkeypatch.setattr(account, "api_url", lambda: "https://x")
    backend = ai.HostedBackend("tok-123")
    resp = backend.create(
        model="m",
        max_tokens=10,
        system=[{"type": "text", "text": "sys"}],
        messages=[{"role": "user", "content": "q"}],
        tools=[{"name": "t", "description": "", "input_schema": {}}],
        tool_choice={"type": "none"},
    )
    assert resp.content[0].text == "hi"
    # Authorization carries the token; tool_choice rides on the body
    assert captured["headers"]["Authorization"] == "Bearer tok-123"
    assert captured["body"]["tool_choice"] == {"type": "none"}
    assert captured["body"]["model"] == "m"


def test_hosted_backend_wraps_network_error(monkeypatch):
    def fake_urlopen(req, timeout):
        raise OSError("network down")

    _patch_urlopen(monkeypatch, "hosted", fake_urlopen)
    from deglyph import account

    monkeypatch.setattr(account, "api_url", lambda: "https://x")
    backend = ai.HostedBackend("tok")
    with pytest.raises(ai.AssistantError, match="hosted AI request failed"):
        backend.create(
            model="m",
            max_tokens=1,
            system=[],
            messages=[{"role": "user", "content": "q"}],
            tools=None,
        )


# --- OpenAIBackend ----------------------------------------------------------


def test_openai_backend_translates_request_and_response(monkeypatch):
    captured: dict = {}

    def fake_urlopen(req, timeout):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        captured["headers"] = dict(req.headers)
        return _Resp(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "answer"},
                    }
                ]
            }
        )

    _patch_urlopen(monkeypatch, "openai", fake_urlopen)
    backend = ai.OpenAIBackend(
        base_url="https://api.openai.com/v1",
        model="gpt-4o-mini",
        api_key="sk-test",
    )
    resp = backend.create(
        model="ignored",
        max_tokens=42,
        system=[{"type": "text", "text": "sys"}],
        messages=[{"role": "user", "content": "q"}],
        tools=[{"name": "t", "description": "x", "input_schema": {"type": "object"}}],
        tool_choice={"type": "none"},
    )
    assert resp.content[0].text == "answer"
    # request: model from backend ctor (not kw), tools translated, tool_choice mapped
    assert captured["body"]["model"] == "gpt-4o-mini"
    assert captured["body"]["tool_choice"] == "none"
    assert captured["body"]["tools"][0]["function"]["name"] == "t"
    # Authorization included only when a key is given
    assert captured["headers"]["Authorization"] == "Bearer sk-test"


def test_openai_backend_without_key_omits_auth_header(monkeypatch):
    captured: dict = {}

    def fake_urlopen(req, timeout):
        captured["headers"] = dict(req.headers)
        return _Resp(
            {"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]}
        )

    _patch_urlopen(monkeypatch, "openai", fake_urlopen)
    backend = ai.OpenAIBackend(
        base_url="http://localhost:11434/v1", model="llama", api_key=""
    )
    backend.create(
        model="m",
        max_tokens=1,
        system=[],
        messages=[{"role": "user", "content": "q"}],
        tools=None,
    )
    assert "Authorization" not in captured["headers"]


def test_openai_backend_wraps_network_error(monkeypatch):
    def fake_urlopen(req, timeout):
        raise RuntimeError("dns")

    _patch_urlopen(monkeypatch, "openai", fake_urlopen)
    backend = ai.OpenAIBackend(base_url="https://x/v1", model="m", api_key="k")
    with pytest.raises(ai.AssistantError, match="OpenAI-compatible request failed"):
        backend.create(
            model="m",
            max_tokens=1,
            system=[],
            messages=[{"role": "user", "content": "q"}],
            tools=None,
        )


# --- translation helpers ----------------------------------------------------


def test_from_openai_handles_bad_tool_arguments():
    """A tool_call with non-JSON arguments must not crash translation."""
    resp = ai._from_openai(
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "c1",
                                "function": {
                                    "name": "search",
                                    "arguments": "{not json",
                                },
                            }
                        ],
                    },
                }
            ]
        }
    )
    assert resp.stop_reason == "tool_use"
    [tu] = resp.content
    # bad JSON -> empty input, not a crash
    assert tu.type == "tool_use" and tu.input == {}


def test_to_openai_messages_includes_trailing_user_text():
    """A user turn with both tool_result and a text nudge emits both messages."""
    out = ai._to_openai_messages(
        [],
        [
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
                    {"type": "text", "text": "summarize now"},
                ],
            }
        ],
    )
    roles = [m["role"] for m in out]
    assert roles == ["tool", "user"]
    assert "summarize" in out[1]["content"]


def test_to_openai_tools_returns_none_for_empty():
    assert ai._to_openai_tools(None) is None
    assert ai._to_openai_tools([]) is None


def test_block_to_dict_variants():
    """The translation helper accepts dicts, _HostedBlock-ish objects, and SDK blocks."""

    # dict passes through
    assert ai._block_to_dict({"type": "text", "text": "x"}) == {
        "type": "text",
        "text": "x",
    }

    # an object with to_dict() returns that
    class _With:
        def to_dict(self):
            return {"type": "text", "text": "via"}

    assert ai._block_to_dict(_With()) == {"type": "text", "text": "via"}

    # an SDK-shaped block (type + text attrs, no to_dict)
    class _Bare:
        type = "text"
        text = "y"

    assert ai._block_to_dict(_Bare()) == {"type": "text", "text": "y"}


# --- tool router ------------------------------------------------------------


def _assistant_with_code(code_image, bytes_hex: str):
    img = code_image(bytes.fromhex(bytes_hex))
    a = ai.Assistant(client=object())
    a.bind_image(img)
    return a, img


def test_tool_router_list_functions(code_image):
    a, _ = _assistant_with_code(code_image, "c3")
    out = a._run_tool("list_functions", {"limit": 5})
    assert "0x1000" in out
    # kind filter that matches nothing returns the "no functions" sentinel
    assert a._run_tool("list_functions", {"kind": "import"}) == "no functions"


def test_tool_router_find_function_no_match(code_image):
    a, _ = _assistant_with_code(code_image, "c3")
    assert a._run_tool("find_function", {"query": "_zzz_"}) == "no matching function"


def test_tool_router_pseudo_c_analyze_xrefs(code_image):
    # mov eax, 1 ; ret -> long enough to give the detectors something to chew on
    a, _ = _assistant_with_code(code_image, "b8 01 00 00 00 c3")
    assert "ret" in a._run_tool(
        "pseudo_c", {"target": "0x1000"}
    ).lower() or "(no pseudo-C)" in a._run_tool("pseudo_c", {"target": "0x1000"})
    analyze = a._run_tool("analyze", {"target": "0x1000"})
    assert "impl=0x1000" in analyze
    xrefs = a._run_tool("xrefs", {"target": "0x1000"})
    assert "callers:" in xrefs and "callees:" in xrefs


def test_tool_router_search_immediate_and_string(code_image):
    a, _ = _assistant_with_code(code_image, "b8 ef be ad de c3")
    hits = a._run_tool("search", {"query": "0xdeadbeef"})
    # the immediate appears verbatim somewhere in the listing
    assert "0x" in hits


def test_tool_router_no_image_returns_error():
    a = ai.Assistant(client=object())
    # no bind_image called
    assert a._run_tool("find_function", {"query": "x"}) == "error: no binary is loaded"


def test_tool_router_unknown_tool(code_image):
    a, _ = _assistant_with_code(code_image, "c3")
    assert "unknown tool" in a._run_tool("nope", {})


def test_tool_router_internal_exception(code_image, monkeypatch):
    """A surprising failure inside a tool is caught and surfaced as text."""
    a, _ = _assistant_with_code(code_image, "c3")
    # force the Disassembler import to look fine, but make .func raise

    from deglyph.core import disasm as _d

    def _boom(self, va):
        raise RuntimeError("decode oops")

    monkeypatch.setattr(_d.Disassembler, "func", _boom)
    out = a._run_tool("disassemble", {"target": "0x1000"})
    assert "error running disassemble" in out


def test_resolve_rejects_garbage(code_image):
    a, _ = _assistant_with_code(code_image, "c3")
    # _resolve returns None for an unparseable hex or a non-matching name
    assert a._resolve("0xnothex") is None
    assert a._resolve("definitely_not_present") is None


# --- conversation state accessors -------------------------------------------


def test_context_label_snapshot_restore():
    a = ai.Assistant(client=object())
    assert a.has_context() is False
    a.set_context("encode_frame", "0x1000 ret")
    assert a.has_context() is True
    assert a.context_label == "encode_frame"
    a._messages = [{"role": "user", "content": "q"}]
    snap = a.snapshot()
    # snapshot is a *copy*
    snap.append({"role": "user", "content": "x"})
    assert len(a._messages) == 1
    a.restore([{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}])
    assert len(a._messages) == 2


# --- ask() rollback on AssistantError ---------------------------------------


def test_ask_rolls_back_on_assistant_error():
    """An AssistantError raised inside the loop drops the unanswered turn."""

    class _BoomLoop:
        class messages:
            @staticmethod
            def create(**kw):
                raise ai.AssistantError("simulated upstream")

    a = ai.Assistant(client=_BoomLoop())
    a.set_context("f", "code")
    with pytest.raises(ai.AssistantError, match="simulated"):
        a.ask("q")
    # the unanswered user turn is removed
    assert a._messages == []


# --- _create routing --------------------------------------------------------


def test_create_routes_through_openai_backend(tmp_path, monkeypatch):
    """No injected client + openai-family provider -> OpenAIBackend.create."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("DEGLYPH_AI_PROVIDER", "openai")
    monkeypatch.setenv("DEGLYPH_AI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("DEGLYPH_AI_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("DEGLYPH_AI_API_KEY", "sk-test")
    captured: dict = {}

    def fake_urlopen(req, timeout):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp(
            {"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]}
        )

    _patch_urlopen(monkeypatch, "openai", fake_urlopen)
    a = ai.Assistant()
    resp = a._create(
        model="ignored",
        max_tokens=10,
        system=[{"type": "text", "text": "sys"}],
        messages=[{"role": "user", "content": "q"}],
        tools=None,
    )
    assert resp.content[0].text == "ok"
    # model in the wire request comes from openai_config, not the kw arg
    assert captured["body"]["model"] == "gpt-4o-mini"


def test_create_routes_through_hosted_when_logged_in(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_AI_PROVIDER", raising=False)
    from deglyph import account

    account.save_token("tok-123")
    monkeypatch.setattr(account, "api_url", lambda: "https://x")
    captured: dict = {}

    def fake_urlopen(req, timeout):
        captured["headers"] = dict(req.headers)
        return _Resp(
            {"stop_reason": "end_turn", "content": [{"type": "text", "text": "hi"}]}
        )

    _patch_urlopen(monkeypatch, "hosted", fake_urlopen)
    a = ai.Assistant()
    resp = a._create(
        model="m",
        max_tokens=1,
        system=[{"type": "text", "text": "sys"}],
        messages=[{"role": "user", "content": "q"}],
        tools=None,
    )
    assert resp.content[0].text == "hi"
    assert captured["headers"]["Authorization"] == "Bearer tok-123"


# --- _ensure_client error paths --------------------------------------------


def test_ensure_client_without_key_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    a = ai.Assistant()
    with pytest.raises(ai.AssistantError, match="ANTHROPIC_API_KEY"):
        a._ensure_client()


def test_ensure_client_without_package_raises(tmp_path, monkeypatch):
    import builtins

    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "anthropic":
            raise ModuleNotFoundError("absent")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    a = ai.Assistant()
    with pytest.raises(ai.AssistantError, match="anthropic"):
        a._ensure_client()


# --- _force_summary append-vs-extend branch ---------------------------------


def test_force_summary_appends_user_turn_when_no_tail():
    """When the message tail is an assistant turn, the nudge becomes its own user turn."""
    a = ai.Assistant(client=object())
    a.set_context("f", "code")
    a._messages = [
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": [{"type": "text", "text": "a"}]},
    ]

    class _Stub:
        class messages:
            @staticmethod
            def create(**kw):
                return type(
                    "R",
                    (),
                    {
                        "content": [type("B", (), {"type": "text", "text": "done"})()],
                        "stop_reason": "end_turn",
                    },
                )()

    a._client = _Stub()
    a._force_summary(None)
    # a new user turn carrying the nudge was appended
    assert a._messages[-2]["role"] == "user"
    assert isinstance(a._messages[-2]["content"], list)


# --- xrefs tool fallback ----------------------------------------------------


def test_xrefs_tool_renders_callees(code_image):
    """Exercise the _nm closure when there are callees but no symbol at the address."""
    # call 0x100c (relative); ret. The call target is unmapped, so _nm falls
    # back to either nearest_func or the raw VA — both arms are covered.
    a, _ = _assistant_with_code(code_image, "e8 07 00 00 00 c3")
    out = a._run_tool("xrefs", {"target": "0x1000"})
    assert "callers:" in out and "callees:" in out


def test_read_data_tool_dumps_hex_and_ascii(code_image):
    """read_data returns a tiny hex+ASCII dump for the given VA."""
    # bytes spell "Hello\0"
    a, _ = _assistant_with_code(code_image, "48656c6c6f00")
    out = a._run_tool("read_data", {"va": "0x1000", "size": 6})
    assert "48 65 6c 6c 6f 00" in out
    assert "Hello" in out


def test_read_data_tool_caps_size(code_image):
    """Size is clamped to the per-call max."""
    a, _ = _assistant_with_code(code_image, "00" * 256)
    out = a._run_tool("read_data", {"va": "0x1000", "size": 10000})
    # 256 bytes / 16 per line = 16 dump rows + the header line
    assert out.count("\n") <= 17


def test_read_data_tool_rejects_unmapped(code_image):
    a, _ = _assistant_with_code(code_image, "c3")
    out = a._run_tool("read_data", {"va": "0xdeadbeef", "size": 8})
    assert "no mapped data" in out


def test_string_at_tool_decodes_ascii(code_image):
    # bytes spell "WiFile\0"
    a, _ = _assistant_with_code(code_image, "576946696c6500")
    out = a._run_tool("string_at", {"va": "0x1000"})
    assert "ascii" in out and "WiFile" in out


def test_string_at_tool_decodes_utf16(code_image):
    # UTF-16LE: "Hi\0"
    a, _ = _assistant_with_code(code_image, "4800690000")
    out = a._run_tool("string_at", {"va": "0x1000"})
    assert "utf-16" in out and "Hi" in out


def test_string_at_tool_handles_non_string(code_image):
    a, _ = _assistant_with_code(code_image, "ffff")
    out = a._run_tool("string_at", {"va": "0x1000"})
    assert "no string" in out


def test_list_sections_tool_lists_sections(code_image):
    a, img = _assistant_with_code(code_image, "c3")
    out = a._run_tool("list_sections", {})
    # the synthetic image carries a single .text section
    assert ".text" in out
    assert "RX" in out


def test_xrefs_tool_handles_data_address(code_image):
    """For a data VA, xrefs scans for code that loads it (find_immediate fallback).

    Uses a rip-relative `lea` so the fallback exercises the new path in
    `find_immediate` that resolves rip-relative target VAs.
    """
    from deglyph.core.image import Arch, Image, Section

    img = Image(path="<x>", fmt="PE", arch=Arch.X64, base=0x1000)
    # Layout: a tiny code section, then a data section whose VA is the
    # absolute target of the rip-relative lea at offset 0.
    img.sections = [
        Section(name=".text", va=0x1000, size=8, raw_off=0, raw_size=8, flags="RX"),
        Section(name=".rdata", va=0x1100, size=8, raw_off=8, raw_size=8, flags="R"),
    ]
    # lea rax, [rip + 0xf3] ; ret
    #   instruction at 0x1000, size 7 (lea) — target = 0x1000 + 7 + 0xf9 = 0x1100
    # encoding: 48 8d 05 f9 00 00 00 c3
    code = bytes.fromhex("48 8d 05 f9 00 00 00 c3")
    data = b"hello\x00\x00\x00"
    img._raw_cache = {".text": code, ".rdata": data}
    img.reindex()

    a = ai.Assistant(client=object())
    a.bind_image(img)
    out = a._run_tool("xrefs", {"target": "0x1100"})
    assert "REFERENCES TO 0x1100" in out
    # the lea instruction at the code start is the listed reference
    assert "0x1000" in out


# --- search tool text path --------------------------------------------------


def test_search_tool_string_path(code_image):
    """A non-0x query is treated as a string search (find_string)."""
    a, _ = _assistant_with_code(code_image, "c3")
    # the search shape just shouldn't crash; the demo bytes have no strings,
    # so the sentinel "no hits" comes back
    out = a._run_tool("search", {"query": "DefinitelyNotPresentString"})
    assert out == "no hits"


# --- unavailable_reason: anthropic-family package & key gaps ---------------


def test_unavailable_reason_anthropic_missing_package(tmp_path, monkeypatch):
    import builtins

    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEGLYPH_AI_PROVIDER", raising=False)
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "anthropic":
            raise ModuleNotFoundError("absent")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    reason = ai.Assistant().unavailable_reason()
    assert reason and "anthropic" in reason


def test_unavailable_reason_anthropic_missing_key(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEGLYPH_AI_PROVIDER", raising=False)
    # anthropic is installed in this env; the reason names the missing key
    reason = ai.Assistant().unavailable_reason()
    assert reason and "ANTHROPIC_API_KEY" in reason


# --- _ensure_client cached -------------------------------------------------


def test_ensure_client_returns_injected_client():
    sentinel = object()
    a = ai.Assistant(client=sentinel)
    assert a._ensure_client() is sentinel


def test_unavailable_reason_anthropic_ready(tmp_path, monkeypatch):
    """All gates clear: package present and key present -> no reason."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("DEGLYPH_AI_PROVIDER", raising=False)
    assert ai.Assistant().unavailable_reason() is None


def test_resolve_by_name_substring(code_image):
    """A non-hex target resolves to the VA of the first matching display name."""
    a, _ = _assistant_with_code(code_image, "c3")
    # the seeded image has a Func at 0x1000 named "f" (see code_image fixture)
    assert a._resolve("f") == 0x1000


def test_ensure_client_constructs_anthropic(tmp_path, monkeypatch):
    """The successful _ensure_client path caches the constructed SDK client."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    sentinel = object()

    class _FakeAnthropicModule:
        @staticmethod
        def Anthropic():
            return sentinel

    import sys

    monkeypatch.setitem(sys.modules, "anthropic", _FakeAnthropicModule)
    a = ai.Assistant()
    assert a._ensure_client() is sentinel
    # cached on subsequent calls
    assert a._ensure_client() is sentinel


# --- rename_function tool ---------------------------------------------------


def test_rename_tool_records_rename_and_overrides_display(code_image):
    """Calling rename_function records the new name and influences later tools."""
    a, img = _assistant_with_code(code_image, "c3")
    # a rename is gated on prior inspection of the function this turn
    a._run_tool("disassemble", {"target": "0x1000"})
    out = a._run_tool("rename_function", {"target": "0x1000", "new_name": "WinMain"})
    assert "renamed" in out and "WinMain" in out
    # the override applies to subsequent tool output in the same turn
    listing = a._run_tool("find_function", {"query": "WinMain"})
    assert "WinMain" in listing and "0x1000" in listing
    # consume_renames drains and clears the pending set
    assert a.consume_renames() == {0x1000: "WinMain"}
    assert a.consume_renames() == {}


def test_rename_tool_resolves_by_current_name(code_image):
    """Once renamed, the same target can be referenced by its new name."""
    a, _ = _assistant_with_code(code_image, "c3")
    a._run_tool("disassemble", {"target": "0x1000"})
    a._run_tool("rename_function", {"target": "0x1000", "new_name": "init_codec"})
    # the second rename targets the same function by its new name
    out = a._run_tool(
        "rename_function", {"target": "init_codec", "new_name": "init_codec_v2"}
    )
    assert "renamed" in out
    assert a.consume_renames() == {0x1000: "init_codec_v2"}


def test_rename_tool_rejects_invalid_names(code_image):
    a, _ = _assistant_with_code(code_image, "c3")
    # empty
    assert "empty" in a._run_tool(
        "rename_function", {"target": "0x1000", "new_name": ""}
    )
    # space in the middle
    assert "valid identifier" in a._run_tool(
        "rename_function", {"target": "0x1000", "new_name": "bad name"}
    )
    # leading digit
    assert "valid identifier" in a._run_tool(
        "rename_function", {"target": "0x1000", "new_name": "1nope"}
    )
    # path-separator injection attempt
    assert "valid identifier" in a._run_tool(
        "rename_function", {"target": "0x1000", "new_name": "../escape"}
    )
    # too long
    assert "valid identifier" in a._run_tool(
        "rename_function", {"target": "0x1000", "new_name": "x" * 200}
    )
    # nothing was recorded
    assert a.consume_renames() == {}


def test_rename_tool_rejects_unresolvable_target(code_image):
    a, _ = _assistant_with_code(code_image, "c3")
    out = a._run_tool("rename_function", {"target": "0xdeadbeef", "new_name": "ghost"})
    assert "no function at" in out
    assert a.consume_renames() == {}


def test_create_routes_through_byo_key_path(tmp_path, monkeypatch):
    """No client, no token, anthropic family -> _ensure_client().messages.create."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_AI_PROVIDER", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    captured: list[dict] = []

    class _FakeMessages:
        def create(self, **kw):
            captured.append(kw)
            return type("R", (), {"content": [], "stop_reason": "end_turn"})()

    class _FakeClient:
        messages = _FakeMessages()

    a = ai.Assistant()
    monkeypatch.setattr(a, "_ensure_client", lambda: _FakeClient())
    a._create(
        model="m",
        max_tokens=1,
        system=[{"type": "text", "text": "s"}],
        messages=[{"role": "user", "content": "q"}],
        tools=None,
    )
    assert captured and captured[0]["model"] == "m"
