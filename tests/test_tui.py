# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
TUI smoke test driven by Textual's headless pilot. Loads a host binary, then
switches through the detail tabs and asserts each renders without error.
"""

from __future__ import annotations

import asyncio

import pytest
from rich.style import Style
from textual.widgets import Input, Static, TabbedContent, Tree

from deglyph.re import thunk_chain
from deglyph.store import Annotations
from deglyph.store import load as load_annotations
from deglyph.tui.app import (
    _ITEM_BINARY,
    AboutDialog,
    ContextPrompt,
    DeglyphApp,
    FilePicker,
    WelcomeScreen,
    _group_funcs,
    _group_key,
    _linkify,
    _markdown,
)


class _F:
    """A minimal stand-in for core.image.Func for grouping unit tests."""

    def __init__(self, name, va, kind):
        self.display = name
        self.va = va
        self.kind = kind


def test_linkify_makes_addresses_clickable():
    t = _linkify("look at sub_1400010a0, then 0x4050")
    clicks = [
        s.style.meta["@click"]
        for s in t.spans
        if isinstance(s.style, Style) and s.style.meta.get("@click")
    ]
    assert any(f"goto_addr({0x1400010A0})" in c for c in clicks)
    assert any(f"goto_addr({0x4050})" in c for c in clicks)
    # surrounding prose preserved
    assert "look at" in str(t)


def test_markdown_styles_and_keeps_links():
    t = _markdown(
        "## Heading\nThe **builder** calls `crc16` at sub_140001020.\n- a bullet"
    )
    plain = t.plain
    # heading marker stripped
    assert "Heading" in plain and "# Heading" not in plain
    assert "builder" in plain and "crc16" in plain
    clicks = [
        s.style.meta["@click"]
        for s in t.spans
        if isinstance(s.style, Style) and s.style.meta.get("@click")
    ]
    # links survive
    assert any(f"goto_addr({0x140001020})" in c for c in clicks)


def test_group_key_splits_namespaces_modules_and_imports():
    # C++ namespace: group on the part before the last ::
    assert _group_key("export", "CryptoApi::Init") == "CryptoApi"
    # module-ish prefix: leading token before the first _ or .
    assert _group_key("export", "crypto_init") == "crypto"
    assert _group_key("sub", "av_packet_free") == "av"
    # no usable prefix -> the top-level bucket
    assert _group_key("export", "main") == "(top level)"
    # a 1-char leading stub is not a meaningful group
    assert _group_key("export", "x_y") == "(top level)"
    # imports group by their library when the name carries one
    assert _group_key("import", "KERNEL32.dll!GetProcAddress") == "KERNEL32.dll"
    assert _group_key("import", "MessageBoxA@USER32") == "USER32"
    # an import without an explicit library falls in the top-level bucket
    assert _group_key("import", "bare_import") == "(top level)"


def test_group_funcs_levels_and_collapse():
    # mix of cases: a real namespace folder (2 members), a singleton namespace
    # (collapsed), a name with no prefix (top-level bucket), an import, and subs
    funcs = [
        _F("CryptoApi::Init", 0x1000, "export"),
        _F("CryptoApi::Encrypt", 0x1010, "export"),
        _F("Net::Send", 0x1020, "export"),
        _F("main", 0x1030, "export"),
        _F("GetProcAddress@KERNEL32", 0x2000, "import"),
        _F("sub_401000", 0x401000, "sub"),
        _F("sub_401820", 0x401820, "sub"),
    ]
    grouped = _group_funcs(funcs, {})
    labels = [k for k, _ in grouped]
    # kind order: Exports, then Subs, then Imports
    assert labels == ["Exports", "Subs", "Imports"]
    exports = dict(grouped)["Exports"]
    # CryptoApi is a real folder (2 members)
    folders = {g: [f.display for f in b] for g, b in exports if g is not None}
    assert folders == {"CryptoApi": ["CryptoApi::Init", "CryptoApi::Encrypt"]}
    # Net::Send and main collapse to bare leaves (group None)
    leaves = [b[0].display for g, b in exports if g is None]
    assert "Net::Send" in leaves and "main" in leaves
    # subs are listed flat under their kind, never sub-grouped
    subs = dict(grouped)["Subs"]
    assert subs == [(None, [funcs[5], funcs[6]])]


def test_group_funcs_honors_renames():
    # a rename changes the display name, so it must change the group too
    f = _F("sub_401000", 0x401000, "sub")
    g = _F("Widget::draw", 0x402000, "export")
    grouped = _group_funcs([g], {0x402000: "Gadget::paint"})
    exports = dict(grouped)["Exports"]
    # the single renamed func collapses to a leaf; its group key used the rename
    assert _group_key("export", "Gadget::paint") == "Gadget"
    assert [b[0] for grp, b in exports if grp is None] == [g]
    # sub unaffected by an unrelated rename map
    assert _group_funcs([f], {}) == [("Subs", [(None, [f])])]


def _pane_text(app, pane: str) -> str:
    # Static.update() stores the content in the name-mangled __content attribute.
    widget = app.query_one(pane, Static)
    return str(getattr(widget, "_Static__content", "")).strip()


async def _wait_for(app, pilot, selector: str, tries: int = 10):
    # Settle until a widget is mounted; one pause can race a composed child.
    from textual.css.query import NoMatches

    for _ in range(tries):
        try:
            return app.query_one(selector)
        except NoMatches:
            await pilot.pause()
    # final attempt surfaces a real failure
    return app.query_one(selector)


async def _wait_for_pane(app, pilot, pane: str, tries: int = 20) -> str:
    # A selection renders a detail pane via a queued cursor reapply and the
    # NodeHighlighted message it fires, so the text can land a refresh or two
    # after the move. Pump pauses until it does (slow runners need the slack).
    for _ in range(tries):
        text = _pane_text(app, pane)
        if text:
            return text
        await pilot.pause()
    return _pane_text(app, pane)


def _two_distinct_vas(app):
    # Rows can share a VA (e.g. import thunks at the image base); jump history
    # de-dupes, so pick two genuinely different addresses.
    seen: list[int] = []
    for f in app._rows:
        if f.va not in seen:
            seen.append(f.va)
        if len(seen) >= 2:
            break
    assert len(seen) >= 2, "need two functions with distinct addresses"
    return seen[0], seen[1]


async def _settle_discovery(app, pilot):
    # The function tree is blank while the async sub-discovery worker runs;
    # wait for it so `_rows`/`_va_nodes` are populated before the test reads them.
    await pilot.pause()
    await app.workers.wait_for_complete()
    await pilot.pause()


def _first_code_va(app):
    # `_rows[0]` can be an import stub at VA 0 with no body; pick the first row
    # whose disassembly is non-empty so disasm-dependent assertions hold.
    for f in app._rows:
        if app.dis.func(f.va):
            return f.va
    return None


class _FakeBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeMessages:
    def create(self, **kw):
        return type("R", (), {"content": [_FakeBlock("ANSWER-42")]})()


class _FakeClient:
    def __init__(self):
        self.messages = _FakeMessages()


def test_assistant_chat_echoes_and_replies(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            # avoid any network call
            app._assistant._client = _FakeClient()
            # The tree opens collapsed, so explicitly pick a function before
            # asking the assistant about it.
            assert app._rows, "host binary should expose at least one function"
            app._select_func_node(app._rows[0].va)
            await pilot.pause()
            # open Assistant: sync context + focus input
            await pilot.press("i")
            await pilot.pause()
            assert app._assistant.has_context()
            app.query_one("#ai-input", Input).value = "what is this"
            await pilot.press("enter")
            await pilot.pause()
            # echo is immediate
            assert "what is this" in _pane_text(app, "#ai-log")
            # let the reply worker finish
            await app.workers.wait_for_complete()
            await pilot.pause()
            # reply rendered
            assert "ANSWER-42" in _pane_text(app, "#ai-log")

    asyncio.run(scenario())


def test_assistant_caches_conversation_per_symbol(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # Two functions whose resolved implementations differ.
            reals: dict[int, object] = {}
            for f in app.image.funcs:
                reals.setdefault(thunk_chain(app.image, f.va)[-1], f)
                if len(reals) >= 2:
                    break
            a, b = list(reals.values())[:2]

            app._ai_sync_context(a)
            app._ai_append("you", "QUESTION-ABOUT-A", "green")
            # switch away
            app._ai_sync_context(b)
            # b is fresh
            assert "QUESTION-ABOUT-A" not in _pane_text(app, "#ai-log")
            # switch back
            app._ai_sync_context(a)
            # restored
            assert "QUESTION-ABOUT-A" in _pane_text(app, "#ai-log")

    asyncio.run(scenario())


def test_reply_lands_in_origin_chat_when_browsing_elsewhere(
    host_binary, tmp_path, monkeypatch
):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    from deglyph.tui.render import GOLD

    notes: list[str] = []

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "notify", lambda msg, **k: notes.append(msg))
            reals: dict[int, object] = {}
            for f in app.image.funcs:
                reals.setdefault(thunk_chain(app.image, f.va)[-1], f)
                if len(reals) >= 2:
                    break
            a, b = list(reals.values())[:2]
            va_a = thunk_chain(app.image, a.va)[-1]

            # ask about A, then switch to B before the reply arrives
            app._ai_sync_context(a)
            app._ai_pending.add(va_a)
            app._ai_sync_context(b)
            assert app._ai_va != va_a

            # the reply for A lands while B is displayed
            app._ai_reply(va_a, [], "deglyph", "ANSWER-FOR-A", GOLD, True)
            await pilot.pause()
            # not in the visible (B) pane, and a toast was raised
            assert "ANSWER-FOR-A" not in _pane_text(app, "#ai-log")
            assert notes and "reply ready" in notes[-1]
            # but stored in A's session, so it shows on switch-back
            app._ai_sync_context(a)
            assert "ANSWER-FOR-A" in _pane_text(app, "#ai-log")

    asyncio.run(scenario())


def test_install_button_visibility_tracks_missing_package(
    host_binary, tmp_path, monkeypatch
):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    from textual.widgets import Button

    from deglyph.tui import app as app_mod

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            f = app.image.funcs[0]
            # a package gap -> button shows
            monkeypatch.setattr(app_mod, "missing_package", lambda: "deglyph[ai]")
            app._ai_sync_context(f)
            await pilot.pause()
            assert app.query_one("#ai-install", Button).display is True
            # gap closed -> button hides
            monkeypatch.setattr(app_mod, "missing_package", lambda: None)
            app._ai_refresh_install_btn()
            await pilot.pause()
            assert app.query_one("#ai-install", Button).display is False

    asyncio.run(scenario())


def test_install_button_runs_install_and_reports(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    from deglyph.tui import app as app_mod

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            monkeypatch.setattr(app_mod, "missing_package", lambda: "deglyph[ai]")
            monkeypatch.setattr(
                app_mod,
                "install_package",
                lambda spec: (True, "Successfully installed"),
            )
            app._ai_sync_context(app.image.funcs[0])
            await pilot.pause()
            app._start_ai_install("deglyph[ai]")
            # Wait only on the install worker. The discovery worker now lives
            # in its own group and may still be scanning kernel32 here.
            install_workers = [w for w in app.workers if w.group == "ai-install"]
            await app.workers.wait_for_complete(install_workers)
            await pilot.pause()
            assert "Restart deglyph" in _pane_text(app, "#ai-log")

    asyncio.run(scenario())


def test_about_dialog_opens_and_closes(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(app.screen, AboutDialog)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, AboutDialog)

    asyncio.run(scenario())


def test_context_prompt_loads_saved(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    Annotations(path=host_binary, names={0x1000: "loaded_fn"}).save()

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # prompt appeared
            assert isinstance(app.screen, ContextPrompt)
            # load
            await pilot.press("l")
            await pilot.pause()
            assert app._anno.names.get(0x1000) == "loaded_fn"

    asyncio.run(scenario())


def test_context_prompt_discard_starts_fresh(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    Annotations(path=host_binary, names={0x1000: "loaded_fn"}).save()

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, ContextPrompt)
            # discard
            await pilot.press("d")
            await pilot.pause()
            # started fresh
            assert app._anno.names == {}

    asyncio.run(scenario())


def test_assistant_unavailable_shows_reason(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            # The tree opens collapsed; select a function so the assistant has
            # a context to load before pressing 'i'.
            assert app._rows, "host binary should expose at least one function"
            app._select_func_node(app._rows[0].va)
            await pilot.pause()
            # open Assistant (no client, no key)
            await pilot.press("i")
            await pilot.pause()
            app.query_one("#ai-input", Input).value = "hello?"
            await pilot.press("enter")
            await pilot.pause()
            log = _pane_text(app, "#ai-log")
            # the question still echoes -- never silent
            assert "hello?" in log
            # actionable
            assert "anthropic" in log or "ANTHROPIC_API_KEY" in log

    asyncio.run(scenario())


def test_detail_tabs_render(host_binary, tmp_path, monkeypatch):
    # isolate annotations
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            # The tree opens collapsed; pick a function before exercising the
            # detail tabs, which only make sense for a Func selection.
            assert app._rows, "host binary should expose at least one function"
            # `_rows[0]` may be an import stub at VA 0 with no body; pick a
            # function whose disassembly is non-empty so the pane assertions hold.
            code_va = _first_code_va(app)
            assert (
                code_va is not None
            ), "host binary should expose a function with a body"
            app._select_func_node(code_va)
            assert await _wait_for_pane(app, pilot, "#disasm")
            for key, pane in (
                ("p", "#pseudo"),
                ("c", "#graph"),
                ("x", "#xrefs"),
                ("a", "#analysis"),
                ("d", "#disasm"),
            ):
                await pilot.press(key)
                await pilot.pause()
                assert _pane_text(app, pane), f"{pane} empty after pressing {key!r}"
            # Activating a tab directly (as a mouse click does) must populate it
            # for the current selection, without re-selecting the function.
            tabs = app.query_one("#tabs", TabbedContent)
            tabs.active = "tab-disasm"
            await pilot.pause()
            tabs.active = "tab-graph"
            await pilot.pause()
            assert _pane_text(app, "#graph"), "graph empty after activating its tab"

            # The tree retains its function rows across tab switches.
            assert len(app._rows) > 0
            assert app.query_one("#functions", Tree) is not None
            # Rename the selected function via the 'n' prompt; it persists.
            await pilot.press("n")
            await pilot.pause()
            app.query_one("#search", Input).value = "renamed_by_test"
            await pilot.press("enter")
            await pilot.pause()
            assert "renamed_by_test" in app._anno.names.values()
            # Assistant tab renders its context intro offline (no API call). Press
            # last: it moves focus to the chat input, capturing later keystrokes.
            await pilot.press("i")
            await pilot.pause()
            assert _pane_text(app, "#ai-log"), "assistant log empty after pressing 'i'"

    asyncio.run(scenario())


def test_context_prompt_shows_bracketed_keys(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    Annotations(path=host_binary, names={0x1000: "x"}).save()

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, ContextPrompt)
            # The [L]/[D] hotkeys render literally; markup must not eat the letter.
            label = app.screen.query_one("#ctx-keys", Static)
            keys = str(getattr(label, "_Static__content", ""))
            assert "[L]oad" in keys and "[D]iscard" in keys
            await pilot.press("d")

    asyncio.run(scenario())


def test_nav_history_back_and_forward(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            a, b = _two_distinct_vas(app)
            app._goto_address(a)
            await pilot.pause()
            app._goto_address(b)
            await pilot.pause()
            assert app._nav_history[app._nav_pos] == b
            app.action_nav_back()
            await pilot.pause()
            # back returns to origin
            assert app._nav_history[app._nav_pos] == a
            app.action_nav_fwd()
            await pilot.pause()
            # forward replays
            assert app._nav_history[app._nav_pos] == b
            # nav controls rendered in the header
            assert _pane_text(app, "#hdr-nav")

    asyncio.run(scenario())


def test_tree_includes_sub_functions(host_binary, tmp_path, monkeypatch):
    """Discovered sub_* functions appear in the tree under their own Subs folder.

    A stripped MSVC build typically exports nothing and surfaces every function
    as a synthetic sub_<va> entry; the tree must list them or the user has no
    way to navigate the binary.
    """
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            sub_rows = [f for f in app._rows if f.kind == "sub"]
            # Discovery on a host DLL routinely finds dozens of subs, but a small
            # stub-heavy binary (e.g. macOS /bin/ls) may have none; only the
            # display path is under test, so skip when there is nothing to show.
            if not sub_rows:
                pytest.skip("host binary yields no discovered sub_* functions")
            assert all(f.va in app._va_nodes for f in sub_rows)

    asyncio.run(scenario())


def test_tree_selection_drives_panes_and_reselect(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # Functions section is hidden while discovery runs; wait for the
            # worker so the section (and `_va_nodes`) is populated.
            await app.workers.wait_for_complete()
            await pilot.pause()
            tree = app.query_one("#functions", Tree)
            # a freshly built tree has the root hidden and leaf nodes registered
            assert tree.show_root is False
            assert app._va_nodes, "no leaf nodes registered"
            # selecting a leaf node renders it as the current function
            va = app._rows[0].va
            assert app._select_func_node(va)
            await pilot.pause()
            cur = app._current()
            assert cur is not None and cur.va == va
            # a rebuild (e.g. after rename) re-selects the same function
            app._apply_filter()
            assert app._select_func_node(va)
            await pilot.pause()
            assert app._current().va == va
            # an unknown VA is a no-op, not a crash
            assert app._select_func_node(0xDEADBEEF) is False
            # every Func in the unfiltered view appears as a leaf — a flat
            # bucket (subs, top-level names) must not silently drop entries.
            total_funcs = sum(1 for f in app.image.funcs)
            assert len(app._rows) == total_funcs

    asyncio.run(scenario())


def test_tree_renders_every_func_in_a_flat_bucket(host_binary, tmp_path, monkeypatch):
    """A bucket with many leaves (subs, top-level names) must not drop entries."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    from deglyph.core.image import Func

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # Functions are hidden during discovery; wait so the rebuild below
            # sees the section populated.
            await app.workers.wait_for_complete()
            await pilot.pause()
            base = max(f.va for f in app.image.funcs) + 0x100
            subs = [
                Func(name=f"sub_{base + i * 16:x}", va=base + i * 16, kind="sub")
                for i in range(7)
            ]
            app.image.funcs.extend(subs)
            app._apply_filter()
            await pilot.pause()
            tree_subs = [f for f in app._rows if f.kind == "sub"]
            assert len(tree_subs) >= 7
            for f in subs:
                assert f.va in app._va_nodes, f"sub at {f.va:#x} missing from tree"

    asyncio.run(scenario())


def test_group_node_highlight_does_not_render(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            tree = app.query_one("#functions", Tree)
            # render a leaf first, then move onto a kind folder. Pick a function
            # with a body (`_rows[0]` can be a bodyless import stub) so `before`
            # is non-empty and the no-clobber comparison is meaningful. The render
            # lands a refresh or two after the move (a queued cursor reapply +
            # NodeHighlighted), so wait for it instead of asserting on a race.
            app._select_func_node(_first_code_va(app))
            before = await _wait_for_pane(app, pilot, "#disasm")
            assert before, "disasm must render before the no-clobber comparison"
            kind_node = tree.root.children[0]
            assert kind_node.data is None, "kind folder must carry no Func"
            tree.select_node(kind_node)
            await pilot.pause()
            # cursoring onto a folder neither renders nor clobbers the pane
            assert _pane_text(app, "#disasm") == before

    asyncio.run(scenario())


def test_toolbar_controls_are_not_underlined(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            tb = await _wait_for(app, pilot, "#hdr-nav")
            # Clickable controls read as buttons, not hyperlinks: no underline.
            assert tb.link_style.underline in (None, False)
            assert tb.link_style_hover.underline in (None, False)

    asyncio.run(scenario())


def test_toolbar_fades_until_navigable(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    def _clickable(app):
        content = app.query_one("#hdr-nav", Static)._Static__content
        return {
            s.style.meta["@click"]
            for s in content.spans
            if isinstance(s.style, Style) and s.style.meta.get("@click")
        }

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            await _wait_for(app, pilot, "#hdr-nav")
            # nothing to navigate yet: all faded
            assert not _clickable(app)
            a, b = _two_distinct_vas(app)
            app._goto_address(a)
            await pilot.pause()
            app._goto_address(b)
            await pilot.pause()
            actions = _clickable(app)
            # recent un-fades
            assert any("show_recent" in a for a in actions)
            # back un-fades
            assert any("nav_back" in a for a in actions)

    asyncio.run(scenario())


def test_header_bar_shows_title_and_clock(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _wait_for(app, pilot, "#hdr-clock")
            # The custom one-line header carries the title, a menu glyph, and a clock.
            assert "deglyph" in _pane_text(app, "#hdr-title")
            assert _pane_text(app, "#hdr-menu")
            # HH:MM:SS
            assert ":" in _pane_text(app, "#hdr-clock")

    asyncio.run(scenario())


def test_welcome_with_no_sessions_offers_open(tmp_path, monkeypatch):
    # empty: no sessions
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        # no path -> land on the welcome screen
        app = DeglyphApp(welcome=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, WelcomeScreen)
            # only Open a file
            assert [k for k, _ in app.screen._entries] == ["open"]
            # opens the file navigator
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, FilePicker)

    asyncio.run(scenario())


def test_welcome_lists_and_restores_a_session(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    Annotations(path=host_binary, names={0x1000: "saved_fn"}).save()

    async def scenario():
        app = DeglyphApp(welcome=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, WelcomeScreen)
            assert ("session", host_binary) in app.screen._entries
            # the session is the first entry
            await pilot.press("enter")
            await pilot.pause()
            await _wait_for(app, pilot, "#functions")
            # advanced to main UI
            assert not isinstance(app.screen, WelcomeScreen)
            assert app.image is not None
            # session restored
            assert app._anno.names.get(0x1000) == "saved_fn"

    asyncio.run(scenario())


def test_welcome_with_path_offers_continue(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, WelcomeScreen)
            assert app.screen._entries[0] == ("continue", host_binary)
            # Continue
            await pilot.press("enter")
            await pilot.pause()
            await _wait_for(app, pilot, "#functions")
            assert app.image is not None

    asyncio.run(scenario())


def test_assistant_falls_back_to_binary_chat(host_binary, tmp_path, monkeypatch):
    """With no function selected, 'i' opens a binary-wide chat instead of going silent."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # injected client so no network round-trip
            app._assistant._client = _FakeClient()
            # the tree starts collapsed and nothing is selected
            assert app._current() is None
            await pilot.press("i")
            await pilot.pause()
            # the binary chat is now the active context
            assert app._ai_va is None
            assert app._assistant.has_context()
            # the chat input accepts a question and the worker delivers a reply
            app.query_one("#ai-input", Input).value = "tell me about this binary"
            await pilot.press("enter")
            ask_workers = [w for w in app.workers if w.group == "ai-ask"]
            await app.workers.wait_for_complete(ask_workers)
            await pilot.pause()
            log = _pane_text(app, "#ai-log")
            assert "tell me about this binary" in log
            assert "ANSWER-42" in log

    asyncio.run(scenario())


def test_assistant_tracks_non_func_selection(host_binary, tmp_path, monkeypatch):
    """With the Assistant tab open, selecting a non-Func item syncs the binary chat.

    Covers the passive paths: moving the cursor onto the Binary leaf
    (`_show_for_item`) and switching to the tab from a non-Func selection
    (`_refresh_active_tab`) both leave the binary-wide context in focus, so the
    chat answers regardless of which tree item is selected.
    """
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            app._assistant._client = _FakeClient()
            app.query_one("#tabs", TabbedContent).active = "tab-ai"
            await pilot.pause()
            # point the assistant at a function first
            assert app._rows
            app._ai_sync_context(app._rows[0])
            assert app._ai_va is not None
            # highlight path: selecting the Binary leaf re-syncs the binary chat
            app._show_for_item((_ITEM_BINARY, None))
            assert app._ai_va is None
            assert app._assistant.has_context()
            # tab-activation path: same fallback when the tab is (re)activated
            app._ai_sync_context(app._rows[0])
            assert app._ai_va is not None
            app._refresh_active_tab((_ITEM_BINARY, None))
            assert app._ai_va is None

    asyncio.run(scenario())


def test_binary_chat_caches_across_switch(host_binary, tmp_path, monkeypatch):
    """The binary chat survives switching away to a function and back."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            # leave a marker in the binary chat without going through the worker
            app._ai_sync_binary_context()
            app._ai_append("you", "BINARY-Q", "green")
            # switch to a function chat
            assert app._rows
            app._ai_sync_context(app._rows[0])
            # the binary marker is not in the function chat
            assert "BINARY-Q" not in _pane_text(app, "#ai-log")
            # switch back to the binary chat
            app._ai_sync_binary_context()
            assert "BINARY-Q" in _pane_text(app, "#ai-log")

    asyncio.run(scenario())


def test_copy_action_yanks_active_pane(host_binary, tmp_path, monkeypatch):
    """`y` copies the active right-pane's plain text to the system clipboard."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            va = _first_code_va(app)
            if va is None:
                pytest.skip("host binary exposes no function with a body")
            app._select_func_node(va)
            await pilot.pause()
            # land on Disasm explicitly and copy
            await pilot.press("d")
            await pilot.pause()
            copied: list[str] = []
            monkeypatch.setattr(app, "copy_to_clipboard", lambda t: copied.append(t))
            app.action_copy()
            assert copied, "copy_to_clipboard not called"
            # the copied text should match the disasm pane content
            assert "0x" in copied[0]
            # status surfaces the byte count
            assert "Copied" in _pane_text(app, "#status")

    asyncio.run(scenario())


def test_copy_address_reports_selected_va(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            va = _first_code_va(app)
            app._select_func_node(va)
            await pilot.pause()
            app.action_copy_address()
            await pilot.pause()
            assert f"{va:#x}" in _pane_text(app, "#status")

    asyncio.run(scenario())


def test_function_report_has_sections_and_export(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            va = _first_code_va(app)
            func = app.image.func_at(va)
            report = app._function_report(func)
            assert app._disp(func) in report
            assert f"{va:#x}" in report
            assert "## Disassembly" in report
            assert "## Analysis" in report
            assert "## Cross-references" in report

            import os

            monkeypatch.chdir(tmp_path)
            app._select_func_node(va)
            await pilot.pause()
            app.action_export_report()
            await pilot.pause()
            written = [f for f in os.listdir(tmp_path) if f.endswith(".report.txt")]
            assert written
            body = open(tmp_path / written[0], encoding="utf-8").read()
            assert "## Disassembly" in body

    asyncio.run(scenario())


def test_stop_button_cancels_in_flight_request(host_binary, tmp_path, monkeypatch):
    """Pressing Stop drops the in-flight question and ignores the late reply."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    from textual.widgets import Button as TButton

    from deglyph.tui.render import GOLD

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            assert app._rows
            app._select_func_node(app._rows[0].va)
            await pilot.pause()
            # press 'i' to land on the chat; the stop button starts hidden
            await pilot.press("i")
            await pilot.pause()
            stop = app.query_one("#ai-stop", TButton)
            assert stop.display is False
            # mark a request as in-flight (bypassing the real worker)
            origin = app._ai_va
            app._ai_pending.add(origin)
            app._ai_refresh_stop_btn()
            assert stop.display is True
            # press stop -> origin removed from pending, transcript marked
            app.action_stop_ai()
            await pilot.pause()
            assert origin not in app._ai_pending
            assert stop.display is False
            assert "[stopped]" in _pane_text(app, "#ai-log")
            # a late reply for that origin is now silently dropped
            app._ai_reply(origin, [], "deglyph", "LATE-REPLY", GOLD, True)
            await pilot.pause()
            assert "LATE-REPLY" not in _pane_text(app, "#ai-log")

    asyncio.run(scenario())


def test_goto_data_address_lands_on_section(host_binary, tmp_path, monkeypatch):
    """A click on a data VA (rdata-style) routes to the Section leaf, not a func.

    Waits for background workers (discovery, strings) to finish first so their
    status messages can't race the goto's own status update.
    """
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            # find a non-executable section with mapped bytes
            target = None
            for i, sec in enumerate(app.image.sections):
                if "X" in sec.flags.upper() or sec.raw_size == 0:
                    continue
                target = (i, sec, sec.va)
                break
            assert target is not None, "host binary lacks a data section"
            _, sec, va = target
            app._goto_address(va)
            await pilot.pause()
            # the cursor lands on the Section leaf, not back in a Func
            item = app._current_item()
            assert item is not None and item[0] == "section"
            # status surfaces the data address and the section name
            status = _pane_text(app, "#status")
            assert f"{va:#x}" in status and sec.name in status

    asyncio.run(scenario())


def test_strings_tab_and_referenced_data(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            # 's' navigates to the Binary item and activates the Strings tab.
            await pilot.press("s")
            await pilot.pause()
            strings = _pane_text(app, "#strings")
            assert "STRINGS" in strings and "found" in strings
            # Move back to a Function leaf before checking the Analysis tab:
            # Analysis is hidden when the cursor is on the Binary item.
            assert app._rows, "no functions to inspect"
            assert app._select_func_node(app._rows[0].va)
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            assert "REFERENCED DATA" in _pane_text(app, "#analysis")

    asyncio.run(scenario())


def test_theme_choice_persists_across_runs(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    from deglyph import config

    async def first():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # as the command palette would
            app.theme = "textual-dark"
            await pilot.pause()
        # saved on change
        assert config.get("theme") == "textual-dark"

    asyncio.run(first())

    async def second():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # restored
            assert app.theme == "textual-dark"

    asyncio.run(second())


def test_file_picker_can_browse_up(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    import os

    from deglyph.tui.app import FilePicker

    async def scenario():
        app = DeglyphApp(welcome=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.push_screen(FilePicker())
            await pilot.pause()
            picker = app.screen
            from textual.widgets import DirectoryTree

            start = os.path.normpath(
                str(picker.query_one("#picker-tree", DirectoryTree).path)
            )
            picker.action_up()
            await pilot.pause()
            now = os.path.normpath(
                str(picker.query_one("#picker-tree", DirectoryTree).path)
            )
            # went up one level
            assert now == os.path.dirname(start)

    asyncio.run(scenario())


def test_ai_settings_saves_provider(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    from textual.widgets import Select

    from deglyph import config
    from deglyph.tui.app import AISettingsScreen

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.push_screen(AISettingsScreen())
            await pilot.pause()
            scr = app.screen
            # picking a provider repopulates the model menu and base URL
            scr.query_one("#aiset-provider", Select).value = "openai"
            await pilot.pause()
            assert scr.query_one("#aiset-base", Input).value.endswith("openai.com/v1")
            scr.query_one("#aiset-model", Select).value = "gpt-4o-mini"
            await pilot.pause()
            scr.action_save()
            await pilot.pause()
            assert config.get("ai_provider") == "openai"
            assert config.get("ai_model") == "gpt-4o-mini"
            assert app._assistant.provider() == "openai"

    asyncio.run(scenario())


def test_ai_settings_custom_model(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_MODEL", raising=False)
    from textual.widgets import Select

    from deglyph import config
    from deglyph.tui.app import AISettingsScreen

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.push_screen(AISettingsScreen())
            await pilot.pause()
            scr = app.screen
            # the custom field is hidden until the sentinel is selected
            assert scr.query_one("#aiset-model-custom", Input).display is False
            scr.query_one("#aiset-model", Select).value = AISettingsScreen.CUSTOM
            await pilot.pause()
            custom = scr.query_one("#aiset-model-custom", Input)
            assert custom.display is True
            custom.value = "claude-3-5-sonnet-latest"
            scr.action_save()
            await pilot.pause()
            assert config.get("ai_model") == "claude-3-5-sonnet-latest"
            # an anthropic provider routes the chosen model to the SDK path
            assert app._assistant.model == "claude-3-5-sonnet-latest"

    asyncio.run(scenario())


def test_ai_settings_anthropic_model_select_default(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    monkeypatch.delenv("DEGLYPH_MODEL", raising=False)
    from textual.widgets import Select

    from deglyph import config
    from deglyph.tui.app import AISettingsScreen

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.push_screen(AISettingsScreen())
            await pilot.pause()
            scr = app.screen
            scr.query_one("#aiset-model", Select).value = "claude-haiku-4-5"
            await pilot.pause()
            scr.action_save()
            await pilot.pause()
            assert config.get("ai_provider") == "anthropic"
            assert config.get("ai_model") == "claude-haiku-4-5"
            assert app._assistant.model == "claude-haiku-4-5"

    asyncio.run(scenario())


def test_command_palette_lists_ai_provider(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            titles = [c.title for c in app.get_system_commands(app.screen)]
            assert any("AI provider" in t for t in titles)

    asyncio.run(scenario())


def test_about_dialog_shows_logo(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(app.screen, AboutDialog)
            logo = app.screen.query_one("#about-logo", Static)
            # logo rendered
            assert str(getattr(logo, "_Static__content", "")).strip()

    asyncio.run(scenario())


def test_ai_renames_persist_and_show_in_tree(host_binary, tmp_path, monkeypatch):
    """A rename_function tool call from the agent updates the sidecar and tree."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    class _ToolUse:
        type = "tool_use"

        def __init__(self, name, inp, id="t1"):
            self.name, self.input, self.id = name, inp, id

    class _Block:
        type = "text"

        def __init__(self, text):
            self.text = text

    class _LoopResp:
        def __init__(self, content, stop_reason):
            self.content, self.stop_reason = content, stop_reason

    class _RenameClient:
        """First call: ask for a rename. Second call: answer."""

        def __init__(self, target_va: int, new_name: str):
            self._target_va = target_va
            self._new_name = new_name
            self.calls = 0
            self.messages = self

        def create(self, **kw):
            self.calls += 1
            # Inspect the function first: a rename is gated on prior inspection
            # of that VA this turn, mirroring how the agent actually works.
            if self.calls == 1:
                return _LoopResp(
                    [_ToolUse("disassemble", {"target": f"{self._target_va:#x}"})],
                    "tool_use",
                )
            if self.calls == 2:
                return _LoopResp(
                    [
                        _ToolUse(
                            "rename_function",
                            {
                                "target": f"{self._target_va:#x}",
                                "new_name": self._new_name,
                            },
                        )
                    ],
                    "tool_use",
                )
            return _LoopResp([_Block("renamed.")], "end_turn")

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            target = app._rows[0].va
            new_name = "AgentNamed"
            app._assistant._client = _RenameClient(target, new_name)
            # the tree starts collapsed; pick the target before opening the chat
            app._select_func_node(target)
            await pilot.pause()
            await pilot.press("i")
            await pilot.pause()
            app.query_one("#ai-input", Input).value = "what is this?"
            await pilot.press("enter")
            # wait only on the chat worker; discovery/strings groups are unrelated
            ask_workers = [w for w in app.workers if w.group == "ai-ask"]
            await app.workers.wait_for_complete(ask_workers)
            await pilot.pause()
            # the rename persisted to annotations
            assert app._anno.names.get(target) == new_name
            # and shows up in the tree
            assert any(app._disp(f) == new_name for f in app._rows if f.va == target)

    asyncio.run(scenario())


def test_ai_chat_persists_and_restores(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def first():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            # injected: no network, no prompt
            app._assistant._client = _FakeClient()
            # select a function so the chat has a context
            app._select_func_node(app._rows[0].va)
            await pilot.pause()
            await pilot.press("i")
            await pilot.pause()
            va = app._ai_va
            app.query_one("#ai-input", Input).value = "MARKER-Q"
            await pilot.press("enter")
            await pilot.pause()
            # reply persists chats on success
            await app.workers.wait_for_complete()
            await pilot.pause()
            return va

    va = asyncio.run(first())

    async def second():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # saved chat is offered
            assert isinstance(app.screen, ContextPrompt)
            # load
            await pilot.press("l")
            await pilot.pause()
            # conversation re-hydrated
            assert va in app._ai_sessions
            log = app._ai_sessions[va]["log"].plain
            assert "MARKER-Q" in log and "ANSWER-42" in log

    asyncio.run(second())


def _fat_binary():
    """A real fat Mach-O if one is available on this host, else None."""
    import platform

    if platform.system() != "Darwin":
        return None
    try:
        import lief

        fat = lief.MachO.parse("/bin/pwd")
        if fat is not None and len(fat) > 1:
            return "/bin/pwd"
    except Exception:
        pass
    return None


def test_fat_slice_picker_and_switch(tmp_path, monkeypatch):
    fat = _fat_binary()
    if fat is None:
        pytest.skip("no fat Mach-O available")
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(fat, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            # the picker offers a leaf per slice
            assert len(app.image.slices) >= 2
            assert set(app._slice_nodes) == {s.index for s in app.image.slices}
            start = app.image.slice_index
            other = next(s.index for s in app.image.slices if s.index != start)

            # the Binary item exposes a Map tab that renders the content map
            app._select_item((_ITEM_BINARY, None))
            await pilot.pause()
            app.query_one("#tabs", TabbedContent).active = "tab-map"
            await pilot.pause()
            assert "CONTENT MAP" in _pane_text(app, "#map")

            # selecting another slice reloads the image onto it
            app._switch_slice(other)
            await _settle_discovery(app, pilot)
            assert app.image.slice_index == other

    asyncio.run(scenario())


def test_candidate_sub_flagged_in_tree_and_info(host_binary, tmp_path, monkeypatch):
    """A candidate sub_ shows the candidate glyph in its leaf and its evidence in Info."""
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    from deglyph.core.image import Func
    from deglyph.tui.glyphs import G

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            base = max(f.va for f in app.image.funcs) + 0x100
            cand = Func(
                name=f"sub_{base:x}",
                va=base,
                kind="sub",
                confidence="candidate",
                evidence=("tail jmp at 0x1004",),
            )
            conf = Func(name=f"sub_{base + 0x10:x}", va=base + 0x10, kind="sub")
            app.image.funcs.extend([cand, conf])
            app._apply_filter()
            await pilot.pause()
            assert G["candidate"] in app._va_nodes[cand.va].label.plain
            assert G["candidate"] not in app._va_nodes[conf.va].label.plain
            app._render_func_info(cand)
            info = _pane_text(app, "#info")
            assert "candidate" in info
            assert "tail jmp at 0x1004" in info

    asyncio.run(scenario())


def test_session_view_state_captured_and_restored(host_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))

    async def scenario():
        app = DeglyphApp(host_binary, welcome=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _settle_discovery(app, pilot)
            va = _first_code_va(app)
            assert va is not None
            app._select_func_node(va)
            await pilot.pause()
            app._filter = "a"
            app.query_one("#tabs", TabbedContent).active = "tab-analysis"
            await pilot.pause()
            # capture reflects the live filter / tab / selection
            view = app._capture_view_state()
            assert view == {"filter": "a", "tab": "tab-analysis", "selected_va": va}
            # it round-trips through the sidecar
            app._autosave()
            assert load_annotations(host_binary).view == view

            # restore reapplies a saved view onto the running app. The selection
            # is checked without a filter, so the restored function is visible in
            # the tree (a filter that hides it would defeat the cursor restore).
            app._filter = "zzz-no-match"
            app._anno.view = {"selected_va": va}
            app._restore_view_state()
            await pilot.pause()
            cur = app._current()
            assert cur is not None and cur.va == va
            # a saved filter is reapplied to the search box
            app._anno.view = {"filter": "a"}
            app._restore_view_state()
            await pilot.pause()
            assert app._filter == "a"

    asyncio.run(scenario())
