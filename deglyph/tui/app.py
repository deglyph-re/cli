# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
deglyph TUI — the interactive front end.

Layout: a live-searchable item tree on the left (Binary, Functions, Strings);
a tabbed detail view on the right whose visible tabs track the kind of the
selected item. The Assistant tab is always present; the others (Disasm /
Xrefs / Analysis / Pseudo / Graph / Strings / Info) come and go per kind.
Built on Textual; all heavy work (disasm, xref index, string extraction) is
lazy and cached.
"""

from __future__ import annotations

import json
import os
import re

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.command import DiscoveryHit
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.system_commands import SystemCommandsProvider
from textual.theme import Theme
from textual.widgets import (
    Button,
    DirectoryTree,
    Footer,
    Input,
    Label,
    OptionList,
    Select,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)
from textual.widgets.tree import TreeNode

from .. import __author__, __version__, config
from ..ai import (
    Assistant,
    install_package,
    known_providers,
    missing_package,
    provider_info,
)
from ..core.disasm import Disassembler
from ..core.image import Arch, Image, load_image
from ..re import (
    CallNode,
    add_discovered,
    call_immediate_args,
    call_tree,
    callees_of,
    callers_of,
    data_xrefs_to,
    detect_crc_loops,
    extract_strings,
    function_constants,
    immediate_stores,
    pseudo_c,
    referenced_data,
    scan_targets,
    thunk_chain,
)
from ..store import Annotations, list_sessions
from ..store import load as load_annotations
from . import render
from .glyphs import SPINNER, G
from .logo import TAGLINE, wordmark_text
from .render import ACCENT, BLUE, DIM, GOLD, GREEN, MAUVE

# Default palette as a Textual theme so the built-in switcher (Ctrl+P -> Change
# theme) can recolor the chrome; the stylesheet reads these via $variables.
# Retro "TVA terminal" palette: amber and brass on warm brown-black, the look of
# a 1970s-futurist computer console (the Loki series interfaces).
DEGLYPH_THEME = Theme(
    name="deglyph",
    # burnt orange
    primary="#d97a2e",
    # brass
    secondary="#b38a4f",
    # amber gold
    accent="#e3b04b",
    # warm cream
    foreground="#e7d8b8",
    # dark warm brown-black
    background="#15100b",
    surface="#1e1710",
    panel="#2b2016",
    # olive
    success="#9aa356",
    warning="#e3b04b",
    # rust
    error="#c14a2a",
    dark=True,
)


def _count(n: int, word: str) -> str:
    """`3, 'note'` -> `'3 notes'`; `1, 'note'` -> `'1 note'` (grammatical plurals)."""
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _logo_text() -> Text:
    """The deglyph wordmark as styled Rich Text: "de" amber, "glyph" cream."""
    return wordmark_text()


def _fuzzy(needle: str, hay: str) -> bool:
    """Subsequence fuzzy match (ag/fzf style), case-insensitive."""
    needle = needle.lower()
    hay = hay.lower()
    if not needle:
        return True
    it = iter(hay)
    return all(c in it for c in needle)


# Function-kind -> the label and ordering used inside the Functions section.
# Discovered `sub_*` functions (stripped MSVC builds, etc.) are listed under
# their own Subs subfolder; they are real callable code that the user needs to
# reach, even though their names are synthetic.
_KIND_GROUPS: dict[str, tuple[int, str]] = {
    "export": (0, "Exports"),
    "entry": (1, "Entry"),
    "symbol": (2, "Symbols"),
    "sub": (3, "Subs"),
    "import": (4, "Imports"),
    "func": (5, "Other"),
}

# Tagged item kinds carried in `TreeNode.data`. A function leaf's data is a
# bare int (its index into `self._rows`) so existing call sites and tests stay
# compatible; the other kinds use a `(kind, payload)` tuple.
_ITEM_FUNC = "func"
_ITEM_STRING = "string"
_ITEM_SECTION = "section"
_ITEM_BINARY = "binary"
_ITEM_SLICE = "slice"

# Per-kind set of visible right-pane tabs. The Assistant tab (`tab-ai`) is
# always visible and so does not appear in any list. When the selected item
# changes, every tab not in the kind's set is hidden via TabbedContent.
_TABS_BY_KIND: dict[str, tuple[str, ...]] = {
    _ITEM_FUNC: (
        "tab-disasm",
        "tab-xrefs",
        "tab-analysis",
        "tab-pseudo",
        "tab-graph",
        "tab-info",
    ),
    _ITEM_STRING: ("tab-info",),
    _ITEM_SECTION: ("tab-info",),
    _ITEM_SLICE: ("tab-info",),
    _ITEM_BINARY: ("tab-map", "tab-strings", "tab-data", "tab-compare", "tab-info"),
}

# Default tab the right pane switches to when an item of this kind is selected
# and the still-active tab is not in the kind's visible set.
_DEFAULT_TAB_BY_KIND: dict[str, str] = {
    _ITEM_FUNC: "tab-disasm",
    _ITEM_STRING: "tab-info",
    _ITEM_SECTION: "tab-info",
    _ITEM_SLICE: "tab-info",
    _ITEM_BINARY: "tab-info",
}

# Tab ids that exist in the right pane. Kept here so the visibility helper can
# iterate them without re-querying the layout.
_ALL_TOGGLE_TABS = (
    "tab-disasm",
    "tab-xrefs",
    "tab-analysis",
    "tab-pseudo",
    "tab-graph",
    "tab-map",
    "tab-strings",
    "tab-info",
)

# Imports often read like "KERNEL32.dll!GetProcAddress" or "GetProcAddress@KERNEL32".
# A leading library component, if present, becomes the second-level group.
_IMPORT_LIB = re.compile(r"^(?P<lib>[\w-]+\.(?:dll|so[\w.]*|dylib))[!.](?P<name>.+)$")
_IMPORT_AT = re.compile(r"^(?P<name>[^@]+)@(?P<lib>[\w.-]+)$")

# Bucket for leaves with no meaningful second-level prefix.
_TOP_LEVEL = "(top level)"


def _group_key(kind: str, name: str) -> str:
    """The second-level group a function belongs to, from its display name.

    Named functions group by namespace (C++ `Class::`) or a module-ish leading
    token split on `_` / `.`; imports group by their library when the name
    carries one. A name with no usable prefix falls in `_TOP_LEVEL`. `sub`
    functions are never grouped here (the caller lists them flat).
    """
    if kind == "import":
        m = _IMPORT_LIB.match(name) or _IMPORT_AT.match(name)
        return m.group("lib") if m else _TOP_LEVEL
    # C++ namespace / class: everything before the last `::`
    if "::" in name:
        head = name.rsplit("::", 1)[0]
        return head or _TOP_LEVEL
    # module-ish prefix: the leading token before the first `_` or `.`
    for sep in ("_", "."):
        if sep in name:
            head = name.split(sep, 1)[0]
            # a lone leading separator or a 1-char stub is not a useful group
            if len(head) >= 2:
                return head
    return _TOP_LEVEL


# A grouped tree level: a kind label and its children, where each child is
# either a single Func (a collapsed singleton, group None) or a named group of
# Funcs. Funcs in a group are flat leaves under it.
GroupedKind = tuple[str, list[tuple[str | None, list]]]


def _group_funcs(funcs: list, names: dict[int, str]) -> list[GroupedKind]:
    """Arrange Funcs into the function tree's two levels: kind, then name prefix.

    `funcs` is the already filtered+sorted leaf list (its order is preserved
    within each bucket); `names` supplies user renames so grouping tracks the
    displayed name. Single-Func groups are collapsed to a bare leaf (group key
    None) so the user never expands a folder of one; `sub` functions list flat
    under their kind with no second level.
    """

    def disp(f) -> str:
        return names.get(f.va) or f.display

    by_kind: dict[str, list] = {}
    for f in funcs:
        by_kind.setdefault(f.kind, []).append(f)

    out: list[GroupedKind] = []
    for kind in sorted(by_kind, key=lambda k: _KIND_GROUPS.get(k, (9, k))[0]):
        members = by_kind[kind]
        label = _KIND_GROUPS.get(kind, (9, kind.title()))[1]
        # discovered subs have no useful name prefix: list them flat
        if kind == "sub":
            out.append((label, [(None, members)]))
            continue
        groups: dict[str, list] = {}
        for f in members:
            groups.setdefault(_group_key(kind, disp(f)), []).append(f)
        children: list[tuple[str | None, list]] = []
        # named groups first (alphabetical), the (top level) bucket last
        for key in sorted(groups, key=lambda k: (k == _TOP_LEVEL, k.lower())):
            bucket = groups[key]
            # collapse a one-member group (or the top-level bucket) to bare leaves
            if len(bucket) == 1 or key == _TOP_LEVEL:
                children.extend((None, [f]) for f in bucket)
            else:
                children.append((key, bucket))
        out.append((label, children))
    return out


# Address-like tokens an AI reply might cite, made clickable in the transcript.
_ADDR_TOKEN = re.compile(r"\bsub_[0-9a-fA-F]+\b|\b0x[0-9a-fA-F]+\b")


def _linkify(text: str) -> Text:
    """Render `text`, turning sub_<hex> / 0x<hex> tokens into clickable gotos."""
    out = Text(style="#d9cbac")
    pos = 0
    for m in _ADDR_TOKEN.finditer(text):
        out.append(text[pos : m.start()])
        token = m.group()
        va = int(token[4:], 16) if token.startswith("sub_") else int(token, 16)
        seg = Text(token, style=GOLD)
        seg.apply_meta({"@click": f"app.goto_addr({va})"})
        out.append_text(seg)
        pos = m.end()
    out.append(text[pos:])
    return out


# Inline markdown: `code`, **bold**, *italic*. Underscore forms are intentionally
# omitted so snake_case symbol names (sub_140_a, encode_frame) stay literal.
_MD_INLINE = re.compile(r"`([^`]+)`|\*\*(.+?)\*\*|\*(.+?)\*")
_MD_BULLET = re.compile(r"^(\s*)[-*+]\s+(.*)$")


def _md_inline(text: str) -> Text:
    """Style inline markdown in one line, keeping address tokens clickable."""
    out = Text()
    pos = 0
    for m in _MD_INLINE.finditer(text):
        if m.start() > pos:
            out.append_text(_linkify(text[pos : m.start()]))
        code, bold, italic = m.group(1), m.group(2), m.group(3)
        if code is not None:
            seg = _linkify(code)
            seg.stylize(GREEN)
        elif bold is not None:
            seg = _linkify(bold)
            seg.stylize("bold")
        else:
            seg = _linkify(italic)
            seg.stylize("italic")
        out.append_text(seg)
        pos = m.end()
    if pos < len(text):
        out.append_text(_linkify(text[pos:]))
    return out


def _markdown(text: str) -> Text:
    """Render an assistant reply's markdown to Rich Text with clickable addresses.

    Handles headings, bullet lists, fenced and inline code, bold, and italic --
    enough to make a Claude reply read well in the pane. Not a full parser.
    """
    lines: list[Text] = []
    in_fence = False
    for line in text.split("\n"):
        s = line.strip()
        if s.startswith("```"):
            in_fence = not in_fence
            # drop the fence marker line itself
            continue
        if in_fence:
            seg = _linkify(line)
            seg.stylize(GREEN)
            lines.append(seg)
        elif s.startswith("#"):
            level = len(s) - len(s.lstrip("#"))
            seg = _md_inline(s[level:].strip())
            seg.stylize(f"bold {ACCENT}")
            lines.append(seg)
        elif _MD_BULLET.match(line):
            bm = _MD_BULLET.match(line)
            seg = Text(f"{bm.group(1)}{G['bullet']} ", style=DIM)
            seg.append_text(_md_inline(bm.group(2)))
            lines.append(seg)
        else:
            lines.append(_md_inline(line))
    out = Text()
    for i, seg in enumerate(lines):
        if i:
            out.append("\n")
        out.append_text(seg)
    return out


def _block_dict(b) -> dict:
    """Coerce one response content block (SDK / hosted / dict) to a plain dict."""
    if isinstance(b, dict):
        return b
    # _HostedBlock
    if hasattr(b, "to_dict"):
        return b.to_dict()
    t = getattr(b, "type", "")
    if t == "tool_use":
        return {
            "type": "tool_use",
            "id": getattr(b, "id", None),
            "name": getattr(b, "name", None),
            "input": getattr(b, "input", {}),
        }
    return {"type": t or "text", "text": getattr(b, "text", "")}


def _serialize_messages(messages: list[dict]) -> list[dict]:
    """Convert a conversation to JSON-safe plain dicts for the sidecar."""
    out = []
    for m in messages:
        content = m["content"]
        if isinstance(content, list):
            content = [_block_dict(b) for b in content]
        out.append({"role": m["role"], "content": content})
    # A final round-trip guarantees the result is JSON-clean (tool inputs etc.).
    return json.loads(json.dumps(out, default=str))


def _transcript_from_messages(messages: list[dict]) -> Text:
    """Rebuild the visible chat log from a persisted conversation."""
    log = Text()
    for m in messages:
        content = m["content"]
        if m["role"] == "user":
            # tool_result turns are internal; skip them
            if isinstance(content, str):
                log.append("\nyou\n", style=GREEN)
                log.append(f"{content}\n", style="#d9cbac")
            continue
        texts, tools = [], []
        for b in content if isinstance(content, list) else []:
            if b.get("type") == "text":
                texts.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                tools.append((b.get("name", ""), b.get("input") or {}))
        if isinstance(content, str):
            texts.append(content)
        for name, inp in tools:
            arg = next(iter(inp.values()), "") if inp else ""
            log.append(f"  {G['hint']} {name}({arg})\n", style=DIM)
        joined = "\n".join(t for t in texts if t)
        if joined:
            log.append("\ndeglyph\n", style=GOLD)
            log.append_text(_markdown(joined))
            log.append("\n")
    return log


class _HeaderBar(Horizontal):
    """The title bar: menu glyph, title, navigation controls, and a clock.

    Replaces Textual's `Header` so the nav controls live in the same band and the
    bar can never expand -- there is no tall-toggle to confuse the user.
    """

    def compose(self) -> ComposeResult:
        yield Static(id="hdr-menu")
        yield Static(id="hdr-title")
        yield Static(id="hdr-nav")
        yield Static(id="hdr-clock")

    def on_mount(self) -> None:
        menu = Text(f" {G['menu']} ", style=GOLD)
        # the menu = the palette
        menu.apply_meta({"@click": "app.command_palette"})
        self.query_one("#hdr-menu", Static).update(menu)
        self.set_interval(1, self._tick)
        self._tick()

    def _tick(self) -> None:
        from datetime import datetime

        self.query_one("#hdr-clock", Static).update(
            Text(datetime.now().strftime("%H:%M:%S "), style=DIM)
        )


class ContextPrompt(ModalScreen[bool]):
    """Startup prompt: load the saved annotation context, or discard it (start fresh)."""

    BINDINGS = [
        Binding("l,enter", "choose(True)", "Load"),
        Binding("d,escape", "choose(False)", "Discard"),
    ]

    def __init__(self, summary: str):
        super().__init__()
        self._summary = summary

    def compose(self) -> ComposeResult:
        with Vertical(id="ctx-dialog"):
            yield Label("Restore your previous work?", id="ctx-title")
            yield Label(self._summary, id="ctx-summary")
            # Pass a Text so the [L]/[D] brackets are not parsed as markup tags
            # (which would eat the bracketed letter).
            yield Label(
                Text("[L]oad saved work    ·    [D]iscard and start fresh"),
                id="ctx-keys",
            )

    def action_choose(self, load: bool) -> None:
        self.dismiss(load)


class InstallPrompt(ModalScreen[bool]):
    """Confirm before pip-installing the AI dependencies into this interpreter."""

    BINDINGS = [
        Binding("i,enter", "choose(True)", "Install"),
        Binding("c,escape", "choose(False)", "Cancel"),
    ]

    def __init__(self, spec: str):
        super().__init__()
        self._spec = spec

    def compose(self) -> ComposeResult:
        with Vertical(id="ctx-dialog"):
            yield Label("Install AI dependencies?", id="ctx-title")
            yield Label(
                f"Runs pip install {self._spec} against the current Python and "
                "downloads from PyPI.",
                id="ctx-summary",
            )
            yield Label(
                Text("[I]nstall    ·    [C]ancel"),
                id="ctx-keys",
            )

    def action_choose(self, install: bool) -> None:
        self.dismiss(install)


class AboutDialog(ModalScreen):
    """Modal showing version, author, repository link, and license."""

    REPO = "https://github.com/deglyph-re/cli"
    BINDINGS = [Binding("escape,enter,q", "close", "Close")]

    def compose(self) -> ComposeResult:
        with Vertical(id="about-dialog"):
            yield Static(_logo_text(), id="about-logo")
            yield Label(f"v{__version__}  ·  GPLv3", id="about-sub")
            yield Label(
                "A terminal reverse-engineering tool for native binaries.",
                id="about-desc",
            )
            yield Label(f"Author: {__author__}", id="about-author")
            # Rich "link" style emits an OSC 8 hyperlink (clickable in capable
            # terminals) without going through Textual console markup.
            yield Static(Text(self.REPO, style=f"link {self.REPO}"), id="about-repo")
            yield Label("Press Esc to close", id="about-keys")

    def action_close(self) -> None:
        self.dismiss()


class AISettingsScreen(ModalScreen):
    """Pick the AI provider and model from dropdowns.

    The provider `Select` (Anthropic, OpenAI, Groq, OpenRouter, DeepSeek, Ollama,
    LM Studio) drives the model `Select` and auto-fills the base URL from the
    provider's registry entry. Picking the "Custom model" sentinel reveals a
    free-text field, so a model the menu omits is still reachable; the base URL
    stays editable for a private endpoint.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
    ]

    # sentinel option value: type a model the curated menu does not list
    CUSTOM = "__custom__"

    def compose(self) -> ComposeResult:
        provider = config.get("ai_provider", "anthropic")
        with Vertical(id="aiset-dialog"):
            yield Label("AI provider", id="aiset-title")
            yield Label("provider", classes="aiset-label")
            yield Select(
                [(p.label, p.key) for p in known_providers()],
                value=self._initial_provider(provider),
                allow_blank=False,
                id="aiset-provider",
            )
            yield Label("model", classes="aiset-label")
            yield Select(
                self._model_options(provider),
                value=self._initial_model(provider),
                allow_blank=False,
                id="aiset-model",
            )
            yield Input(
                value=config.get("ai_model", ""),
                placeholder="e.g. gpt-4o-mini, llama3.1",
                id="aiset-model-custom",
            )
            yield Label("base URL (OpenAI-compatible providers)", classes="aiset-label")
            yield Input(
                value=config.get("ai_base_url", "") or self._provider_base(provider),
                placeholder="https://api.openai.com/v1",
                id="aiset-base",
            )
            yield Static(
                "Anthropic uses your key or `deglyph login`; the others speak the "
                "OpenAI API (Ollama / LM Studio run locally, no key).\n"
                "Ctrl+S to save  ·  Esc to cancel",
                id="aiset-hint",
            )

    # -- option builders ---------------------------------------------------
    def _model_options(self, provider: str) -> list[tuple[str, str]]:
        info = provider_info(provider)
        models = list(info.models) if info else []
        return [(m, m) for m in models] + [("Custom model…", self.CUSTOM)]

    def _provider_base(self, provider: str) -> str:
        info = provider_info(provider)
        return info.base_url if info else ""

    def _initial_provider(self, provider: str) -> str:
        return provider if provider_info(provider) else "anthropic"

    def _initial_model(self, provider: str) -> str:
        info = provider_info(provider)
        chosen = config.get("ai_model", "")
        if info and chosen in info.models:
            return chosen
        # an unknown configured model means the custom field carries it
        if chosen:
            return self.CUSTOM
        return info.models[0] if info and info.models else self.CUSTOM

    def on_mount(self) -> None:
        self._sync_custom_visibility()

    # -- reactions ---------------------------------------------------------
    def on_select_changed(self, ev: Select.Changed) -> None:
        if ev.select.id == "aiset-provider":
            self._on_provider_changed(str(ev.value))
        elif ev.select.id == "aiset-model":
            self._sync_custom_visibility()

    def _on_provider_changed(self, provider: str) -> None:
        """Repopulate the model menu and base URL for the newly chosen provider."""
        model_select = self.query_one("#aiset-model", Select)
        model_select.set_options(self._model_options(provider))
        info = provider_info(provider)
        model_select.value = info.models[0] if info and info.models else self.CUSTOM
        self.query_one("#aiset-base", Input).value = self._provider_base(provider)
        self._sync_custom_visibility()

    def _sync_custom_visibility(self) -> None:
        """Show the free-text model field only when the menu is on the sentinel."""
        is_custom = self.query_one("#aiset-model", Select).value == self.CUSTOM
        self.query_one("#aiset-model-custom", Input).display = is_custom

    # -- save --------------------------------------------------------------
    def _chosen_model(self) -> str:
        select = self.query_one("#aiset-model", Select)
        if select.value == self.CUSTOM:
            return self.query_one("#aiset-model-custom", Input).value.strip()
        return str(select.value)

    def action_save(self) -> None:
        provider = str(self.query_one("#aiset-provider", Select).value)
        config.put("ai_provider", provider)
        config.put("ai_base_url", self.query_one("#aiset-base", Input).value.strip())
        config.put("ai_model", self._chosen_model())
        self.dismiss(True)

    def on_input_submitted(self, ev: Input.Submitted) -> None:
        self.action_save()

    def action_cancel(self) -> None:
        self.dismiss(None)


class NavMenu(ModalScreen):
    """A pick-one list (recent functions / saved chats); dismisses with a VA."""

    BINDINGS = [Binding("escape", "cancel", "Close")]

    def __init__(self, title: str, items: list[tuple[str, int]]):
        super().__init__()
        self._title = title
        # (label, va)
        self._items = items

    def compose(self) -> ComposeResult:
        with Vertical(id="menu-dialog"):
            yield Label(self._title, id="menu-title")
            yield OptionList(*[label for label, _ in self._items], id="menu-list")

    def on_mount(self) -> None:
        lst = self.query_one("#menu-list", OptionList)
        if lst.option_count:
            # Enter selects without arrowing first
            lst.highlighted = 0
        lst.focus()

    def on_option_list_option_selected(self, ev: OptionList.OptionSelected) -> None:
        self.dismiss(self._items[ev.option_index][1])

    def action_cancel(self) -> None:
        self.dismiss(None)


class FilePicker(ModalScreen):
    """A small file navigator; dismisses with the chosen path, or None to cancel.

    Browse into folders by selecting them; go up a level with Backspace, or type
    a directory in the path box and press Enter to jump there.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("backspace", "up", "Up"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="picker-dialog"):
            yield Label("Open a Binary", id="picker-title")
            yield Input(value=os.getcwd(), id="picker-path")
            yield DirectoryTree(os.getcwd(), id="picker-tree")
            yield Static(
                "Select a file to open  ·  Backspace up  ·  Esc to cancel",
                id="picker-hint",
            )

    def on_mount(self) -> None:
        self.query_one("#picker-tree", DirectoryTree).focus()

    def _set_root(self, path: str) -> None:
        tree = self.query_one("#picker-tree", DirectoryTree)
        tree.path = path
        tree.reload()
        self.query_one("#picker-path", Input).value = path

    def action_up(self) -> None:
        tree = self.query_one("#picker-tree", DirectoryTree)
        parent = os.path.dirname(os.path.normpath(str(tree.path)))
        if parent:
            self._set_root(parent)

    def on_input_submitted(self, ev: Input.Submitted) -> None:
        if ev.input.id == "picker-path":
            path = os.path.expanduser(ev.value.strip())
            if os.path.isdir(path):
                self._set_root(path)
                self.query_one("#picker-tree", DirectoryTree).focus()

    def on_directory_tree_file_selected(self, ev: DirectoryTree.FileSelected) -> None:
        self.dismiss(str(ev.path))

    def action_cancel(self) -> None:
        self.dismiss(None)


class WelcomeScreen(Screen):
    """Landing screen: the logo, a welcome, and a menu of sessions / Open a file.

    Dismisses with `(path, restore)` -- `restore` adopts that binary's saved
    annotations -- or None if the user quits.
    """

    BINDINGS = [Binding("escape,q", "quit_app", "Quit")]

    def __init__(self, initial_path: str | None, sessions: list[Annotations]):
        super().__init__()
        self._initial = initial_path
        self._sessions = sessions
        # (kind, path)
        self._entries: list[tuple[str, str | None]] = []

    # fixed name column, so the rows line up like a table
    _NAME_W = 28

    def compose(self) -> ComposeResult:
        with Vertical(id="welcome"):
            yield Static(_logo_text(), id="welcome-logo")
            yield Static("Welcome to Deglyph", id="welcome-title")
            yield Static(TAGLINE, id="welcome-tagline")
            yield OptionList(id="welcome-list")
            yield Static("Enter to open  ·  Esc to quit", id="welcome-hint")

    def on_mount(self) -> None:
        rows: list[Text] = []
        if self._initial:
            self._entries.append(("continue", self._initial))
            rows.append(
                self._row(G["nav_fwd"], os.path.basename(self._initial), "continue")
            )
        initial_abs = os.path.abspath(self._initial) if self._initial else None
        for a in self._sessions:
            # The command-line file is already offered above as "Continue".
            if initial_abs and os.path.abspath(a.path) == initial_abs:
                continue
            self._entries.append(("session", a.path))
            rows.append(self._row(" ", os.path.basename(a.path), self._detail(a)))
        self._entries.append(("open", None))
        rows.append(self._row(G["search"], f"Open a file{G['ellipsis']}", ""))
        lst = self.query_one("#welcome-list", OptionList)
        lst.add_options(rows)
        # Highlight the first row so Enter selects without arrowing first.
        lst.highlighted = 0
        lst.focus()

    def _row(self, icon: str, name: str, detail: str) -> Text:
        """One aligned table row: icon, fixed-width name column, dim detail."""
        ell = G["ellipsis"]
        if len(name) > self._NAME_W:
            name = name[: self._NAME_W - len(ell)] + ell
        t = Text()
        t.append(f" {icon}  ", style=GOLD)
        t.append(f"{name:<{self._NAME_W}}")
        if detail:
            t.append(f"  {detail}", style=DIM)
        return t

    def _detail(self, a: Annotations) -> str:
        bits = []
        if a.names:
            bits.append(_count(len(a.names), "rename"))
        if a.comments:
            bits.append(_count(len(a.comments), "note"))
        if a.bookmarks:
            bits.append(_count(len(a.bookmarks), "bookmark"))
        if a.chats:
            bits.append(_count(len(a.chats), "chat"))
        return ", ".join(bits) or "no edits"

    def on_option_list_option_selected(self, ev: OptionList.OptionSelected) -> None:
        kind, path = self._entries[ev.option_index]
        if kind == "open":
            self.app.push_screen(FilePicker(), self._on_pick)
        elif kind == "session":
            self.dismiss((path, True))
        # continue with the file given on the command line
        else:
            self.dismiss((path, False))

    def _on_pick(self, path: str | None) -> None:
        if path:
            self.dismiss((path, False))

    def action_quit_app(self) -> None:
        self.dismiss(None)


class _OrderedSystemCommands(SystemCommandsProvider):
    """System-commands provider that preserves `get_system_commands` yield order.

    Textual's default `SystemCommandsProvider.discover()` sorts commands by title
    before yielding them, which throws away whatever order the app's
    `get_system_commands` produced (so "AI provider…" lands ahead of "About"
    purely on case-sensitive ASCII ordering). This subclass skips the sort; the
    palette then shows commands in the exact order the app yields them. `search`
    is left to the parent, since fuzzy-match score is the right order with a
    query present.
    """

    async def discover(self):
        for name, help_text, callback, discover in self.app.get_system_commands(
            self.screen
        ):
            if discover:
                yield DiscoveryHit(name, callback, help=help_text)


class DeglyphApp(App):
    CSS_PATH = "style.tcss"
    TITLE = "deglyph"
    # Replace Textual's default `SystemCommandsProvider` with one that does not
    # alphabetize the discovery list; `get_system_commands` controls the order.
    COMMANDS = {_OrderedSystemCommands}

    # Ordered like a native menu bar (the footer reads left to right): find,
    # then navigate, view, annotate, help -- and Quit last. Labels are Title Case;
    # an ellipsis marks actions that prompt for more input before completing; view
    # labels match their tab names so a shortcut and its destination read alike.
    BINDINGS = [
        # find
        Binding("/", "focus_search", "Search"),
        Binding("escape", "clear_search", "Clear", show=False),
        # navigate
        Binding("f", "follow", "Follow"),
        Binding("g", "goto", "Go to…"),
        Binding("left_square_bracket", "nav_back", "Back"),
        Binding("right_square_bracket", "nav_fwd", "Forward"),
        # view
        Binding("d", "disasm", "Disasm"),
        Binding("x", "xrefs", "Xrefs"),
        Binding("a", "analysis", "Analysis"),
        Binding("p", "pseudo", "Pseudo"),
        Binding("c", "graph", "Graph"),
        Binding("i", "assistant", "Assistant"),
        Binding("s", "strings", "Strings"),
        Binding("t", "data_view", "Data", show=False),
        Binding("v", "compare", "Compare...", show=False),
        Binding("l", "graph_into", "Graph: into callee", show=False),
        Binding("h", "graph_up", "Graph: up to caller", show=False),
        Binding("m", "graph_more_callees", "Graph: more callees", show=False),
        Binding("u", "graph_more_callers", "Graph: more callers", show=False),
        # annotate
        Binding("n", "rename", "Rename…"),
        Binding("b", "bookmark", "Bookmark"),
        Binding("semicolon", "comment", "Add Note…"),
        Binding("y", "copy", "Copy"),
        Binding("Y", "copy_address", "Copy addr", show=False),
        Binding("e", "export_report", "Export report", show=False),
        # help
        Binding("f1,question_mark", "about", "About"),
        # hidden cursor movement
        Binding("enter", "open", "Open", show=False),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        # quit (last, like a macOS app menu)
        Binding("ctrl+c,ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+x", "cancel_scan", "Cancel scan", show=False),
    ]

    def __init__(
        self,
        path: str | None = None,
        *,
        fmt: str | None = None,
        arch: Arch | None = None,
        slice_index: int | None = None,
        discover: bool = True,
        welcome: bool = True,
    ):
        super().__init__()
        self._path = path
        self._fmt = fmt
        self._arch = arch
        self._slice_index = slice_index
        self._discover = discover
        # show the welcome screen on launch
        self._welcome = welcome
        self.image: Image | None = None
        self.dis: Disassembler | None = None
        # Function leaves: `_rows` is the flat list of displayed Funcs (subs
        # excluded), and a func leaf's `data` is its index here so two Funcs at
        # one VA stay distinct. `_va_nodes` maps a VA to its leaf for fast
        # re-selection after a rebuild.
        self._rows: list = []
        self._va_nodes: dict[int, TreeNode] = {}
        # Tree nodes for the other item kinds, looked up by their payload.
        # Used by `_select_item` to restore the cursor after `_apply_filter`.
        self._string_nodes: dict[int, TreeNode] = {}
        self._section_nodes: dict[int, TreeNode] = {}
        # fat Mach-O slice leaves, keyed by slice index
        self._slice_nodes: dict[int, TreeNode] = {}
        self._binary_node: TreeNode | None = None
        self._filter = ""
        self._pending_highlight: int | None = None
        # The last (kind, payload) the right pane was rendered for; guards the
        # node-highlight handler against a spurious same-item re-render.
        self._last_rendered_item: tuple | None = None
        # Set while the search box is edited programmatically (goto). Queued
        # Input.Changed events then carry a stale value and are ignored until the
        # box settles back to `_filter`.
        self._input_locked = False
        # AI assistant: chat scoped to one function (or to the whole binary
        # when nothing is selected). `_ai_va` carries the VA the context is
        # loaded for, or None for the binary-wide chat.
        self._assistant = Assistant()
        self._ai_va: int | None = None
        self._ai_log = Text()
        # Redacted record of the most recent assistant investigation (question,
        # answer, tool transcript), captured from the worker for export.
        self._last_ai_investigation: dict | None = None
        # animates the "thinking" spinner while a reply loads
        self._ai_timer = None
        self._ai_spin = 0
        # Discovery spinner: animates the status bar and disables the function
        # tree while the background sub_* discovery worker is running.
        # `_discovery_node` is the placeholder leaf shown at the top of the tree
        # so the spinner is visible without the user glancing at the status bar.
        self._discovery_timer = None
        self._discovery_spin = 0
        self._discovery_running = False
        self._discovery_node: TreeNode | None = None
        # Per-symbol chat cache: resolved-impl VA -> {messages, transcript}.
        self._ai_sessions: dict[int, dict] = {}
        # Cached binary-wide session: same shape, kept apart so per-function
        # persistence does not touch it.
        self._ai_binary_session: dict | None = None
        # In-flight question targets. Includes None for an in-flight binary
        # chat. A reply binds to its origin so it still lands in the right
        # chat after the user switches; the spinner only shows for the
        # displayed origin.
        self._ai_pending: set[int | None] = set()
        # Call-graph navigator: the centered function and per-group page offsets.
        self._graph_va: int | None = None
        self._graph_pages = {"callers": 0, "callees": 0}
        # Image-wide string list, extracted lazily and cached per loaded binary.
        self._strings_cache: list | None = None
        # Consolidated data view (sections / imports / exports / strings /
        # findings), rendered once per binary and cached (the scan is slow).
        self._data_view_cache = None
        # Jump history for the toolbar back/forward (browser-style; IDA-like).
        self._nav_history: list[int] = []
        self._nav_pos = -1
        # set while back/forward is replaying, to not record
        self._nav_lock = False
        # Persistent per-binary annotations (renames, comments, bookmarks).
        self._anno = Annotations(path=path or "")
        self._pending_context: Annotations | None = None
        # Active single-line prompt mode for the search box: goto | rename.
        self._prompt: str | None = None

    # -- layout ------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield _HeaderBar(id="header")
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield Input(
                    placeholder=f"  {G['search']} Filter functions…",
                    id="search",
                )
                yield Tree("functions", id="functions")
            with Vertical(id="right"):
                with TabbedContent(id="tabs"):
                    with TabPane("Disasm", id="tab-disasm"):
                        with VerticalScroll(id="disasm-scroll", classes="pane-scroll"):
                            yield Static(id="disasm", classes="pane")
                    with TabPane("Xrefs", id="tab-xrefs"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="xrefs", classes="pane")
                    with TabPane("Analysis", id="tab-analysis"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="analysis", classes="pane")
                    with TabPane("Pseudo", id="tab-pseudo"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="pseudo", classes="pane")
                    with TabPane("Graph", id="tab-graph"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="graph", classes="pane")
                    with TabPane("Map", id="tab-map"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="map", classes="pane")
                    # Info before Strings/Assistant: Textual's hide-tab auto-
                    # switch picks the next visible tab, and Info is the
                    # binary/section default that should win that race.
                    with TabPane("Info", id="tab-info"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="info", classes="pane")
                    with TabPane("Strings", id="tab-strings"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="strings", classes="pane")
                    with TabPane("Data", id="tab-data"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="data", classes="pane")
                    with TabPane("Compare", id="tab-compare"):
                        with VerticalScroll(classes="pane-scroll"):
                            yield Static(id="compare", classes="pane")
                    with TabPane("Assistant", id="tab-ai"):
                        with Vertical(id="ai-box"):
                            with VerticalScroll(id="ai-scroll", classes="pane-scroll"):
                                yield Static(id="ai-log", classes="pane")
                            # Shown only when a needed package is missing; hidden
                            # otherwise. Toggled by _ai_refresh_install_btn.
                            yield Button(
                                "Install AI dependencies",
                                id="ai-install",
                                variant="primary",
                            )
                            # Shown only while an ai-ask worker is in flight;
                            # toggled by _ai_refresh_stop_btn alongside the
                            # thinking spinner.
                            yield Button(
                                "Stop",
                                id="ai-stop",
                                variant="warning",
                            )
                            yield Input(
                                id="ai-input",
                                placeholder="  Ask about this function…",
                            )
        yield Static(id="status")
        yield Footer()

    # -- lifecycle ---------------------------------------------------------
    def on_mount(self) -> None:
        self.register_theme(DEGLYPH_THEME)
        # Restore the theme chosen in a previous run; persist future changes.
        saved = config.get("theme", "deglyph")
        self.theme = saved if self.get_theme(saved) else "deglyph"
        self.theme_changed_signal.subscribe(self, self._on_theme_changed)
        self._set_header_title()
        if self._welcome:
            self._open_welcome()
        elif self._path:
            self._load_binary(restore=False)

    def _open_welcome(self) -> None:
        """Push the landing screen; its result picks the binary to load."""
        self.push_screen(WelcomeScreen(self._path, list_sessions()), self._on_welcome)

    def _on_welcome(self, result: tuple[str, bool] | None) -> None:
        if not result:
            # the user quit from the welcome screen
            self.exit()
            return
        self._path, restore = result
        self._load_binary(restore=restore)

    def _load_binary(self, *, restore: bool) -> None:
        """Load the chosen binary and build the main view.

        `restore` adopts the binary's saved annotations directly (a session the
        user picked from the welcome screen); otherwise the context prompt offers
        to load or discard any saved work.
        """
        try:
            self.image = load_image(
                self._path,
                fmt=self._fmt,
                arch=self._arch,
                slice_index=self._slice_index,
            )
            self.dis = Disassembler(self.image)
            # let the AI tools roam the image
            self._assistant.bind_image(self.image)
        # surface load errors without crashing
        except Exception as e:
            name = os.path.basename(self._path or "")
            self.notify(f"Could not open {name}: {e}", severity="error")
            if self._welcome:
                # let the user pick another file
                self._open_welcome()
            else:
                self.query_one("#status", Static).update(
                    Text(f"Load error: {e}", style="red")
                )
            return
        self._set_header_title()
        self._strings_cache = None
        self._data_view_cache = None
        self._anno = Annotations(path=self._path or "")
        # session picked from the welcome screen: adopt its work now
        if restore:
            self._anno = load_annotations(self._path)
            for va, msgs in self._anno.chats.items():
                self._ai_sessions[va] = {
                    "messages": list(msgs),
                    "log": _transcript_from_messages(msgs),
                }
        # Show the table immediately (exports/imports/entry), then discover the
        # unexported functions on a worker so a large binary never freezes startup.
        self._build_table()
        self._set_status()
        self._refresh_toolbar()
        # Sync the install-button visibility once at load: without a function
        # selected, `_ai_sync_context` never fires and the button can otherwise
        # linger in whatever state the previous binary left it. Same for the
        # Stop button (which should never be visible without a request).
        self._ai_refresh_install_btn()
        self._ai_refresh_stop_btn()
        self.query_one("#functions", Tree).focus()
        # Focus the binary overview leaf so the right pane shows fmt/arch/base/
        # sections as soon as the user lands; the tree still opens collapsed,
        # but with this leaf selected the welcome view is the binary metadata.
        self._select_item((_ITEM_BINARY, None))
        # A restored session reapplies its saved filter / tab / selection.
        if restore:
            self._restore_view_state()
        if self._discover and not getattr(self.image, "_discovered", False):
            self._start_discovery_spinner()
            self._discover_worker()
        # Strings drive a tree section now; extract on a worker so a large
        # binary doesn't stall the welcome -> first-paint path.
        if self._strings_cache is None:
            self._extract_strings_worker()
        if not restore:
            self._maybe_prompt_context()

    def _maybe_prompt_context(self) -> None:
        """Offer to load a saved annotation context, or start fresh (discard)."""
        saved = load_annotations(self._path)
        if saved.is_empty():
            # no prior work for this binary
            return
        self._pending_context = saved
        summary = (
            f"{os.path.basename(self._path)} has "
            f"{_count(len(saved.names), 'rename')}, "
            f"{_count(len(saved.comments), 'note')}, "
            f"{_count(len(saved.bookmarks), 'bookmark')}, and "
            f"{_count(len(saved.chats), 'chat')}."
        )
        self.push_screen(ContextPrompt(summary), self._on_context_choice)

    def _on_context_choice(self, load: bool | None) -> None:
        if load and self._pending_context is not None:
            self._anno = self._pending_context
            # Re-hydrate the per-function AI chats so they resume when opened.
            for va, msgs in self._anno.chats.items():
                self._ai_sessions[va] = {
                    "messages": list(msgs),
                    "log": _transcript_from_messages(msgs),
                }
            keep = self._current_item()
            # re-render with restored renames/bookmarks
            self._apply_filter()
            if keep is not None:
                self._select_item(keep)
            # the adopted context may carry a saved filter / tab / selection
            self._restore_view_state()
            # 'chats' reflects the restored conversations
            self._refresh_toolbar()
        self._pending_context = None

    @work(exclusive=True, thread=True, group="discover")
    def _discover_worker(self) -> None:
        try:
            targets = scan_targets(self.image)
        # never let discovery crash the app
        except Exception:
            targets = []
        self.call_from_thread(self._discovery_done, targets)

    def _discovery_done(self, targets: list) -> None:
        self._stop_discovery_spinner()
        keep = self._current_item()
        # The initial build was skipped while discovery ran (disabled tree), so
        # rebuild unconditionally to populate the named-symbol rows; new sub_*
        # entries are folded in when add_discovered found any.
        add_discovered(self.image, targets)
        self._apply_filter()
        if keep is not None:
            self._select_item(keep)
        self._set_status()

    def _start_discovery_spinner(self) -> None:
        """Animate the status bar and the in-tree spinner row.

        The discovery worker walks every executable byte through Capstone, which
        can take tens of seconds on a large binary. The placeholder leaf at the
        bottom of the tree shows the spinner inside the navigator itself, so the
        user knows the tree is still loading. The tree stays interactive (clicks
        during discovery are safe; `_discovery_done` captures the selection and
        restores it after the rebuild), but the filter input is hidden because
        there is nothing useful to filter until the tree is fully populated.
        """
        self._discovery_running = True
        self._discovery_spin = 0
        tree = self.query_one("#functions", Tree)
        try:
            self.query_one("#search", Input).display = False
        except Exception:
            pass
        self._add_discovery_node(tree)
        if self._discovery_timer is None:
            self._discovery_timer = self.set_interval(0.1, self._tick_discovery)
        self._tick_discovery()

    def _discovery_label(self, frame: str) -> Text:
        """The styled label for the tree's spinner placeholder leaf.

        Bold + accented so the row stands out against the other tree leaves
        while discovery is in flight.
        """
        return Text(f"{frame}  Discovering subs…", style=f"bold {GOLD}")

    def _add_discovery_node(self, tree: Tree) -> None:
        """Append the spinner placeholder leaf at the bottom of the tree.

        Idempotent: if the leaf is already attached, leave it. Bottom placement
        keeps us off Textual's private TreeNode internals (there is no public
        insert-at-index); the unloaded tree is only three rows tall, so the
        spinner is still visible without any scrolling.
        """
        if (
            self._discovery_node is not None
            and self._discovery_node.parent is tree.root
        ):
            return
        frame = SPINNER[self._discovery_spin % len(SPINNER)]
        self._discovery_node = tree.root.add_leaf(
            self._discovery_label(frame), data=None
        )

    def _tick_discovery(self) -> None:
        if not self._discovery_running:
            return
        frame = SPINNER[self._discovery_spin % len(SPINNER)]
        self._discovery_spin += 1
        # The interval timer can fire one last time after the screen is torn
        # down (slow scans on large host binaries outlive the test harness);
        # the status widget is gone by then, so a missing node is not an error.
        try:
            self.query_one("#status", Static).update(
                Text(f" {frame} Discovering functions…", style=GOLD)
            )
        except Exception:
            return
        node = self._discovery_node
        if node is not None and node.parent is not None:
            node.set_label(self._discovery_label(frame))

    def action_cancel_scan(self) -> None:
        """Cancel the background discovery / strings scans and clear the spinner.

        The two worker groups walk every executable byte through Capstone, which
        can run for tens of seconds on a large binary. `cancel_group` is a no-op
        when nothing is in flight, so this is safe to invoke at any time.
        """
        self.workers.cancel_group(self, "discover")
        self.workers.cancel_group(self, "strings")
        self._stop_discovery_spinner()
        self.notify("Background scan cancelled.")

    def _stop_discovery_spinner(self) -> None:
        self._discovery_running = False
        if self._discovery_timer is not None:
            self._discovery_timer.stop()
            self._discovery_timer = None
        node = self._discovery_node
        self._discovery_node = None
        if node is not None and node.parent is not None:
            try:
                node.remove()
            # node may already be gone (a concurrent _apply_filter cleared the tree)
            except Exception:
                pass
        try:
            self.query_one("#search", Input).display = True
        except Exception:
            pass

    @work(exclusive=True, thread=True, group="strings")
    def _extract_strings_worker(self) -> None:
        try:
            strings = extract_strings(self.image)
        # never let string extraction crash the app
        except Exception:
            strings = []
        self.call_from_thread(self._strings_done, strings)

    def _strings_done(self, strings: list) -> None:
        """Adopt the extracted strings and rebuild the tree so they show up."""
        self._strings_cache = strings
        keep = self._current_item()
        self._apply_filter()
        if keep is not None:
            self._select_item(keep)

    # Per-kind leaf color; group folders use the same palette as their kind.
    _KIND_STYLE = {
        "export": GOLD,
        "symbol": BLUE,
        "sub": MAUVE,
        "import": DIM,
        "entry": GREEN,
    }

    def _build_table(self) -> None:
        tree = self.query_one("#functions", Tree)
        tree.show_root = False
        tree.guide_depth = 2
        self._apply_filter()

    # Trailing "(N)" suffix on group folder labels; stripped for the snapshot
    # key so a count change across rebuild does not lose the user's expansion.
    _COUNT_SUFFIX_RE = re.compile(r"\s*\(\d+\)$")

    @classmethod
    def _node_key(cls, node: TreeNode) -> str:
        label = node.label
        text = label.plain if hasattr(label, "plain") else str(label)
        return cls._COUNT_SUFFIX_RE.sub("", text)

    @classmethod
    def _snapshot_expansion(cls, tree: Tree) -> set[tuple[str, ...]]:
        """Return the path-tuples of every expanded non-root node in the tree."""
        out: set[tuple[str, ...]] = set()

        def walk(node: TreeNode, path: tuple[str, ...]) -> None:
            for child in node.children:
                new_path = path + (cls._node_key(child),)
                if child.is_expanded:
                    out.add(new_path)
                walk(child, new_path)

        walk(tree.root, ())
        return out

    @classmethod
    def _restore_expansion(cls, tree: Tree, snapshot: set[tuple[str, ...]]) -> None:
        """Re-expand nodes whose path key is in `snapshot`."""

        def walk(node: TreeNode, path: tuple[str, ...]) -> None:
            for child in node.children:
                new_path = path + (cls._node_key(child),)
                if new_path in snapshot:
                    child.expand()
                walk(child, new_path)

        walk(tree.root, ())

    def _apply_filter(self) -> None:
        """Rebuild the item tree from the current search filter.

        Lays out three top-level sections — Binary, Functions, Strings — and
        binds each leaf's `data` to a tagged item: a bare int for a Func (its
        index in `self._rows`), or `(kind, payload)` for the other kinds.
        `self._va_nodes` / `_string_nodes` / `_section_nodes` / `_binary_node`
        map a payload back to its leaf for re-selection after the rebuild.

        Expansion state is snapshotted before the clear and restored after the
        rebuild so a discovery / rename / bookmark / strings rebuild does not
        visually collapse the folders the user opened. The snapshot key strips
        trailing count suffixes ("Exports (42)" -> "Exports") so a count change
        across rebuild still matches.

        Discovered `sub_*` functions are excluded from the tree (they still
        live in `image.funcs` so disassembly click-throughs and the call graph
        can find them). Strings appear only once `_strings_cache` is populated
        (see `_extract_strings_worker`).
        """
        assert self.image
        tree = self.query_one("#functions", Tree)
        expansion = self._snapshot_expansion(tree)
        # `tree.clear()` invalidates every cached node reference; null the
        # discovery placeholder now so the post-build helper re-creates it.
        self._discovery_node = None
        tree.clear()
        flt = self._filter.strip()

        self._rows = []
        self._va_nodes = {}
        self._string_nodes = {}
        self._section_nodes = {}
        self._slice_nodes = {}
        self._binary_node = None

        self._build_binary_section(tree.root, flt)
        first_func_node = self._build_functions_section(
            tree.root, flt, disabled=self._discovery_running
        )
        self._build_strings_section(tree.root, flt)
        # If discovery is still running across this rebuild (rename / bookmark
        # / strings ingest can fire while the worker is in flight), put the
        # spinner row back at the top.
        if self._discovery_running:
            self._add_discovery_node(tree)
        if expansion:
            self._restore_expansion(tree, expansion)

        self._set_status()
        # Discard the landing reference: the tree opens fully collapsed and the
        # user picks an item; an active search still auto-expands its matches.
        del first_func_node
        self._last_rendered_item = None
        # Tabs depend on the selected item's kind. Default to the Binary set
        # (Info + Strings) so an unselected tree still surfaces an overview of
        # the file; the Assistant tab is always present.
        self._refresh_tabs_for(_ITEM_BINARY)

    def _build_binary_section(self, root: TreeNode, flt: str) -> None:
        """Top-level Binary section: an overview leaf, a Slices subfolder (fat
        Mach-O only), and a Sections subfolder.

        Opens collapsed; an active search expands the folders so matches are
        visible without the user clicking through.
        """
        img = self.image
        match_name = not flt or _fuzzy(flt, os.path.basename(img.path))
        slices = [s for s in img.slices if not flt or _fuzzy(flt, s.cpu)]
        sections = [
            (i, s) for i, s in enumerate(img.sections) if not flt or _fuzzy(flt, s.name)
        ]
        # If a filter excludes everything in this section, drop it entirely.
        if flt and not match_name and not slices and not sections:
            return
        bin_node = root.add("Binary", expand=bool(flt))
        if match_name:
            label = Text(os.path.basename(img.path), style=GOLD)
            leaf = bin_node.add_leaf(label, data=(_ITEM_BINARY, None))
            self._binary_node = leaf
        # Fat (universal) Mach-O: one leaf per architecture slice; the active
        # slice carries a marker. Selecting another reloads the image on it.
        if len(img.slices) > 1 and slices:
            sl_root = bin_node.add(f"Slices ({len(img.slices)})", expand=bool(flt))
            for sl in slices:
                active = sl.index == img.slice_index
                lbl = Text(("* " if active else "  ") + sl.cpu, style=GOLD)
                lbl.append("  active" if active else "", style=DIM)
                leaf = sl_root.add_leaf(lbl, data=(_ITEM_SLICE, sl.index))
                self._slice_nodes[sl.index] = leaf
        if sections:
            sec_root = bin_node.add(f"Sections ({len(sections)})", expand=bool(flt))
            for idx, sec in sections:
                lbl = Text(sec.name, style="#d9cbac")
                lbl.append(f"  {sec.flags}", style=DIM)
                leaf = sec_root.add_leaf(lbl, data=(_ITEM_SECTION, idx))
                self._section_nodes[idx] = leaf

    def _build_functions_section(
        self, root: TreeNode, flt: str, *, disabled: bool = False
    ) -> TreeNode | None:
        """Top-level Functions section. Returns the first func leaf for tests.

        Every kind in `_KIND_GROUPS` is represented, including discovered
        `sub_*` entries (stripped MSVC builds have nothing but these, and the
        user needs to be able to navigate to them from the tree).

        Opens collapsed; an active search expands matching folders so the user
        can see what matched without clicking through. `disabled=True` skips
        the build entirely (no node added) and leaves `_rows` / `_va_nodes`
        empty for this rebuild, so the user does not see a partial function
        list while the sub_* discovery worker is still running.
        """
        if disabled:
            return None
        funcs = [f for f in self.image.funcs if not flt or _fuzzy(flt, self._disp(f))]
        if not funcs:
            return None
        funcs.sort(
            key=lambda f: (_KIND_GROUPS.get(f.kind, (9, ""))[0], self._disp(f).lower())
        )
        func_root = root.add(f"Functions ({len(funcs)})", expand=bool(flt))
        grouped = _group_funcs(funcs, self._anno.names)
        first_leaf: TreeNode | None = None
        for kind_label, children in grouped:
            count = sum(len(b) for _, b in children)
            kind_node = func_root.add(f"{kind_label} ({count})", expand=bool(flt))
            for group, bucket in children:
                if group is None:
                    for f in bucket:
                        leaf = self._add_func_leaf(kind_node, f)
                        if first_leaf is None:
                            first_leaf = leaf
                else:
                    grp_node = kind_node.add(
                        f"{group} ({len(bucket)})", expand=bool(flt)
                    )
                    for f in bucket:
                        leaf = self._add_func_leaf(grp_node, f)
                        if first_leaf is None:
                            first_leaf = leaf
        return first_leaf

    # Cap the strings the tree can show per section. The Strings tab still
    # renders the full image-wide list; the tree is for navigation, not bulk.
    _MAX_TREE_STRINGS_PER_SECTION = 1000

    def _build_strings_section(self, root: TreeNode, flt: str) -> None:
        """Top-level Strings section, grouped by the section the string lives in.

        Renders only once `_strings_cache` is populated by the background
        worker. A search filters by the string's text content.
        """
        strings = self._strings_cache
        if not strings:
            return
        if flt:
            entries = [(i, s) for i, s in enumerate(strings) if _fuzzy(flt, s.text)]
        else:
            entries = list(enumerate(strings))
        if not entries:
            return
        # group by section so the user can scan a section's strings together
        by_section: dict[str, list[tuple[int, object]]] = {}
        for idx, s in entries:
            by_section.setdefault(s.section or "?", []).append((idx, s))
        str_root = root.add(f"Strings ({len(entries)})", expand=bool(flt))
        for sec_name in sorted(by_section):
            group = by_section[sec_name]
            cap = self._MAX_TREE_STRINGS_PER_SECTION
            shown = group[:cap]
            label = f"{sec_name} ({len(group)})"
            sec_node = str_root.add(label, expand=bool(flt))
            for idx, s in shown:
                short = s.text if len(s.text) <= 60 else s.text[:57] + G["ellipsis"]
                lbl = Text(f'"{short}"', style=GREEN)
                if s.encoding != "ascii":
                    lbl.append(" w", style=DIM)
                leaf = sec_node.add_leaf(lbl, data=(_ITEM_STRING, idx))
                self._string_nodes[idx] = leaf
            if len(group) > cap:
                sec_node.add_leaf(
                    Text(f"{G['ellipsis']} {len(group) - cap} more", style=DIM),
                    data=None,
                )

    def _add_func_leaf(self, parent: TreeNode, func) -> TreeNode:
        """Append `func` as a tree leaf carrying its `self._rows` index as data."""
        idx = len(self._rows)
        self._rows.append(func)
        booked = func.va in self._anno.bookmarks
        name = ("* " if booked else "") + self._disp(func)
        style = GOLD if booked else self._KIND_STYLE.get(func.kind, "#d9cbac")
        label = Text(name, style=style)
        # A recovered start with weak evidence (tail-jmp only) is flagged so a
        # candidate boundary is never read as a confirmed one.
        if getattr(func, "is_candidate", False):
            label.append(f" {G['candidate']}", style="yellow")
        # A user-renamed function carries a marker so a hand-given name reads
        # apart from a container-provided symbol (a user annotation vs a fact).
        if func.va in self._anno.names:
            label.append(f" {G['user']}", style=ACCENT)
        leaf = parent.add_leaf(label, data=idx)
        # last writer wins, matching func_at when two Funcs share a VA
        self._va_nodes[func.va] = leaf
        return leaf

    def _disp(self, func) -> str:
        """Display name for a Func: a user rename if set, else its own label."""
        return self._anno.names.get(func.va) or func.display

    @staticmethod
    def _item_from_node(node: TreeNode) -> tuple | None:
        """The tagged item for a leaf node, or None on a group folder.

        Func leaves carry a bare int (an index into `_rows`); the other kinds
        carry `(kind, payload)` directly. A folder's data is None.
        """
        d = node.data
        if d is None:
            return None
        if isinstance(d, int):
            return (_ITEM_FUNC, d)
        if isinstance(d, tuple):
            return d
        return None

    def _current(self) -> object | None:
        """The Func for the highlighted leaf, or None on any other item / folder."""
        item = self._current_item()
        if item is None or item[0] != _ITEM_FUNC:
            return None
        try:
            return self._rows[item[1]]
        except (IndexError, TypeError):
            return None

    def _current_item(self) -> tuple | None:
        """The tagged item under the cursor: `(kind, payload)` or None."""
        node = self.query_one("#functions", Tree).cursor_node
        if node is None:
            return None
        return self._item_from_node(node)

    def _select_node(self, node: TreeNode) -> None:
        """Expand ancestors, move the cursor to `node`, scroll it into view.

        `move_cursor` is silently dropped during the initial mount when the
        tree has not laid out yet, so the cursor placement is also queued via
        `call_after_refresh` to land once layout settles. The expand+move pair
        runs synchronously too so callers that act on `cursor_node` straight
        away still see the new node when layout is already done.
        """
        parent = node.parent
        while parent is not None:
            parent.expand()
            parent = parent.parent
        tree = self.query_one("#functions", Tree)
        tree.move_cursor(node)
        tree.scroll_to_node(node, animate=False)
        self.call_after_refresh(self._reapply_cursor, node)

    def _reapply_cursor(self, node: TreeNode) -> None:
        """Second cursor placement after a refresh; covers the initial-mount case."""
        tree = self.query_one("#functions", Tree)
        if tree.cursor_node is not node:
            tree.move_cursor(node)
            tree.scroll_to_node(node, animate=False)

    def _select_func_node(self, va: int) -> bool:
        """Move the cursor to the leaf for `va`; True if a leaf exists for it.

        The single cursor primitive after a rebuild for function navigation:
        the goto/follow/rename/bookmark paths all rebuild the tree, then call
        this to restore or move the selection.
        """
        node = self._va_nodes.get(va)
        if node is None:
            return False
        self._select_node(node)
        return True

    def _select_item(self, item: tuple) -> bool:
        """Move the cursor to the leaf for a tagged item; True if found."""
        kind, payload = item
        if kind == _ITEM_FUNC:
            try:
                f = self._rows[payload]
            except (IndexError, TypeError):
                return False
            return self._select_func_node(f.va)
        if kind == _ITEM_STRING:
            node = self._string_nodes.get(payload)
        elif kind == _ITEM_SECTION:
            node = self._section_nodes.get(payload)
        elif kind == _ITEM_SLICE:
            node = self._slice_nodes.get(payload)
        elif kind == _ITEM_BINARY:
            node = self._binary_node
        else:
            node = None
        if node is None:
            return False
        self._select_node(node)
        return True

    # -- detail panes ------------------------------------------------------
    # Cap the instructions rendered into the (single) disassembly Static. A large
    # function would otherwise build thousands of styled lines and stall the UI.
    _DISASM_WINDOW = 800

    def _show_for_item(self, item: tuple) -> None:
        """Render the right pane for `item` and update tab visibility per kind."""
        kind, payload = item
        self._refresh_tabs_for(kind)
        if kind == _ITEM_FUNC:
            try:
                func = self._rows[payload]
            except (IndexError, TypeError):
                return
            self._show_for(func)
            return
        # Non-Func selection on the Assistant tab: keep the binary-wide chat in
        # focus so moving the cursor onto a string/section/binary still answers.
        if self.query_one("#tabs", TabbedContent).active == "tab-ai":
            self._ai_sync_binary_context()
            return
        if kind == _ITEM_STRING:
            self._show_for_string(payload)
        elif kind == _ITEM_SECTION:
            self._show_for_section(payload)
        elif kind == _ITEM_SLICE:
            self._show_for_slice(payload)
        elif kind == _ITEM_BINARY:
            self._show_for_binary()

    def _show_for(self, func) -> None:
        hl = self._pending_highlight
        self._pending_highlight = None
        self._render_disasm(func.va, highlight=hl)
        self._render_func_info(func)
        self._refresh_active_tab_func(func)

    def _show_for_string(self, idx: int) -> None:
        s = self._string_at(idx)
        if s is None:
            return
        self._render_string_info(s)

    def _show_for_section(self, idx: int) -> None:
        if not (0 <= idx < len(self.image.sections)):
            return
        self._render_section_info(self.image.sections[idx])

    def _show_for_slice(self, idx: int) -> None:
        sl = next((s for s in self.image.slices if s.index == idx), None)
        if sl is None:
            return
        # The active slice shows its own info; selecting another reloads onto it.
        if idx == self.image.slice_index:
            self._render_slice_info(sl)
        else:
            self._switch_slice(idx)

    def _show_for_binary(self) -> None:
        self._render_binary_info()
        active = self.query_one("#tabs", TabbedContent).active
        if active == "tab-strings":
            self._render_strings()
        elif active == "tab-map":
            self._render_map()

    def _refresh_tabs_for(self, kind: str) -> None:
        """Show/hide right-pane tabs for the selected item kind.

        Assistant (`tab-ai`) is always visible. When the active tab is not
        in the kind's visible set, switch to the kind's default tab so the
        pane has something to render.
        """
        tabs = self.query_one("#tabs", TabbedContent)
        visible = set(_TABS_BY_KIND.get(kind, ()))
        for tid in _ALL_TOGGLE_TABS:
            if tid in visible:
                tabs.show_tab(tid)
            else:
                tabs.hide_tab(tid)
        active = tabs.active
        if active not in visible and active != "tab-ai":
            tabs.active = _DEFAULT_TAB_BY_KIND.get(kind, "tab-info")

    def _string_at(self, idx: int):
        if not self._strings_cache:
            return None
        if not (0 <= idx < len(self._strings_cache)):
            return None
        return self._strings_cache[idx]

    def _render_disasm(self, va: int, highlight: int | None = None) -> None:
        insns = self.dis.func(va)
        if not insns:
            self.query_one("#disasm", Static).update(
                Text("No code at this address.", style=DIM)
            )
            self.query_one("#disasm-scroll", VerticalScroll).scroll_home(animate=False)
            return

        # Window the listing around the highlight (or the start) when it is large.
        total = len(insns)
        start = 0
        if total > self._DISASM_WINDOW:
            if highlight is not None:
                idx = next(
                    (i for i, ins in enumerate(insns) if ins.addr == highlight), 0
                )
                start = max(0, idx - self._DISASM_WINDOW // 2)
            shown = insns[start : start + self._DISASM_WINDOW]
        else:
            shown = insns

        body, mark_line = render.disasm_text(
            self.image, shown, highlight=highlight, names=self._anno.names
        )
        if total > len(shown):
            end = start + len(shown)
            body.append(
                f"\n{G['ellipsis']} showing {start}{G['ndash']}{end} of {total} "
                f"instructions (go to an address to move the window)\n",
                style=DIM,
            )
        self.query_one("#disasm", Static).update(body)
        scroll = self.query_one("#disasm-scroll", VerticalScroll)
        if mark_line is None:
            scroll.scroll_home(animate=False)
        else:
            # Center the marked instruction once layout has settled and the
            # viewport height is known.
            self.call_after_refresh(self._center_disasm, mark_line)

    def _refresh_active_tab_func(self, func) -> None:
        """Render whichever detail tab is active for a Func selection.

        Driven by both cursor movement and tab activation, so a tab populates
        whether the user moves the selection or just switches to the tab.
        """
        active = self.query_one("#tabs", TabbedContent).active
        if active == "tab-xrefs":
            self._render_xrefs(func)
        elif active == "tab-analysis":
            self._render_analysis(func)
        elif active == "tab-pseudo":
            self._render_pseudo(func)
        elif active == "tab-graph":
            self._graph_recenter(func.va)
        elif active == "tab-ai":
            self._ai_sync_context(func)

    def _refresh_active_tab(self, item: tuple) -> None:
        """Re-render the active tab for `item` (any kind)."""
        kind, payload = item
        if kind == _ITEM_FUNC:
            try:
                func = self._rows[payload]
            except (IndexError, TypeError):
                return
            self._refresh_active_tab_func(func)
            return
        active = self.query_one("#tabs", TabbedContent).active
        # Non-Func selection on the Assistant tab: the chat is binary-wide, so
        # the user can ask questions from any item without first picking a func.
        if active == "tab-ai":
            self._ai_sync_binary_context()
            return
        if kind == _ITEM_STRING and active == "tab-info":
            s = self._string_at(payload)
            if s is not None:
                self._render_string_info(s)
        elif kind == _ITEM_SECTION and active == "tab-info":
            if 0 <= payload < len(self.image.sections):
                self._render_section_info(self.image.sections[payload])
        elif kind == _ITEM_SLICE and active == "tab-info":
            sl = next((s for s in self.image.slices if s.index == payload), None)
            if sl is not None:
                self._render_slice_info(sl)
        elif kind == _ITEM_BINARY:
            if active == "tab-strings":
                self._render_strings()
            elif active == "tab-map":
                self._render_map()
            elif active == "tab-data":
                self._render_data_view()
            elif active == "tab-info":
                self._render_binary_info()

    def _center_disasm(self, line: int) -> None:
        scroll = self.query_one("#disasm-scroll", VerticalScroll)
        y = max(0, line - scroll.scrollable_content_region.height // 2)
        scroll.scroll_to(y=y, animate=False)

    def _goto_address(self, addr: int) -> None:
        """Navigate to `addr`. Code addresses jump to disassembly; data
        addresses select the enclosing section and preview what is there.

        Routes by section flags: an executable section is treated as code (the
        previous behavior), anything else as data so a clickable string VA from
        an AI reply doesn't dive into an unrelated nearby function.
        """
        if self.image is None:
            return
        sec = self.image.section_at(addr)
        if sec is None or "X" in sec.flags.upper():
            self._goto_code(addr)
        else:
            self._goto_data(addr, sec)

    def _goto_code(self, addr: int) -> None:
        """Disassembly jump: select the enclosing function and mark the insn."""
        exact = self.image.func_at(addr)
        f = self.image.nearest_func(addr)
        # Record the jump before the cursor moves, so back returns to the origin.
        self._record_nav((exact or f).va if (exact or f) else addr)
        # The previous item may have been Binary/String/Section, so the Disasm
        # tab can be hidden right now: switch the visibility set to a function.
        self._refresh_tabs_for(_ITEM_FUNC)
        self.query_one("#tabs", TabbedContent).active = "tab-disasm"
        if exact is not None:
            # the highlight handler renders the marked instruction on select
            self._pending_highlight = addr
            self._select_func_node(exact.va)
        self._render_disasm(f.va if f else addr, highlight=addr)
        loc = f"{f.display}+{addr - f.va:#x}" if f else ""
        self.query_one("#status", Static).update(
            Text(f" Go to {addr:#x}  {loc}", style=GOLD)
        )

    def _goto_data(self, addr: int, sec) -> None:
        """Data jump: select the section leaf and surface a string preview.

        Disassembly doesn't apply to a `.rdata`-style VA, so the right pane
        switches to the Section's Info view and the status bar carries the
        printable bytes at the address (truncated) so a click from an AI reply
        gives the user something useful to read.
        """
        self._record_nav(addr)
        idx = self.image.sections.index(sec)
        node = self._section_nodes.get(idx)
        if node is not None:
            self._select_node(node)
        else:
            # the Section leaf isn't in the tree (filter active, etc.): drive
            # the panes directly so the user still gets the Info content
            self._refresh_tabs_for(_ITEM_SECTION)
            self.query_one("#tabs", TabbedContent).active = "tab-info"
            self._render_section_info(sec)
        preview = self._data_preview(addr)
        self.query_one("#status", Static).update(
            Text(f" Data {addr:#x} in {sec.name}{preview}", style=GOLD)
        )

    @staticmethod
    def _printable_prefix(raw: bytes) -> str:
        out = []
        for b in raw:
            if 0x20 <= b <= 0x7E:
                out.append(chr(b))
            else:
                break
        return "".join(out)

    def _data_preview(self, addr: int) -> str:
        """Best-effort string preview at `addr`, or empty if not printable."""
        raw = self.image.read_va(addr, 64)
        if not raw:
            return ""
        ascii_run = self._printable_prefix(raw)
        if len(ascii_run) >= 4:
            short = (
                ascii_run if len(ascii_run) <= 48 else ascii_run[:45] + G["ellipsis"]
            )
            return f'  "{short}"'
        # UTF-16LE: ASCII byte then NUL, repeated
        if len(raw) >= 6 and raw[1] == 0 and 0x20 <= raw[0] <= 0x7E:
            chars = []
            i = 0
            while i + 1 < len(raw) and raw[i + 1] == 0 and 0x20 <= raw[i] <= 0x7E:
                chars.append(chr(raw[i]))
                i += 2
            if len(chars) >= 3:
                text = "".join(chars)
                short = text if len(text) <= 48 else text[:45] + G["ellipsis"]
                return f'  L"{short}"'
        return ""

    def _render_func_info(self, func) -> None:
        """Info pane content for a Function leaf."""
        img = self.image
        t = Text()
        t.append("FUNCTION\n", style=GOLD)
        t.append(f"  {self._disp(func)}\n", style=GREEN)
        if func.va in self._anno.bookmarks:
            t.append(f"  {'bookmark':<12}yes\n", style=GOLD)
        if func.va in self._anno.names:
            t.append(f"  {'name from':<12}", style="#d9cbac")
            t.append("user\n", style=ACCENT)
            t.append(f"  {'original':<12}{func.display}\n", style=DIM)
        t.append(f"  {'va':<12}{func.va:#x}\n", style=DIM)
        t.append(f"  {'kind':<12}{func.kind}\n", style=DIM)
        # Recovered subs carry a confidence and the evidence that named them;
        # container-provided functions are confirmed with nothing to explain.
        if func.kind == "sub":
            conf_style = "yellow" if func.is_candidate else GREEN
            t.append(f"  {'confidence':<12}{func.confidence}\n", style=conf_style)
            for ev in func.evidence:
                t.append(f"  {'why':<12}{ev}\n", style=DIM)
        sec = img.section_at(func.va)
        if sec:
            t.append(f"  {'section':<12}{sec.name}\n", style=DIM)
        insns = self.dis.func(func.va)
        if insns:
            last = insns[-1]
            span = (last.addr + len(last.bytes)) - func.va
            t.append(f"  {'span':<12}{span:#x} bytes\n", style=DIM)
            t.append(f"  {'instrs':<12}{len(insns)}\n", style=DIM)
        if func.demangled and func.demangled != func.name:
            t.append(f"  {'mangled':<12}{func.name}\n", style=DIM)
        comment = self._anno.comments.get(func.va)
        if comment:
            t.append("\nNOTE\n", style=GOLD)
            t.append(f"  {comment}\n", style="#d9cbac")
        self.query_one("#info", Static).update(t)

    def _render_binary_info(self) -> None:
        """Info pane content for the Binary overview leaf: file + sections summary."""
        img = self.image
        t = Text()
        t.append("FILE\n", style=GOLD)
        t.append(f"  {img.path}\n", style="#d9cbac")
        t.append(
            f"  {img.fmt}  {img.arch.value}  base={img.base:#x}\n",
            style=DIM,
        )
        funcs = img.funcs
        by_kind: dict[str, int] = {}
        for f in funcs:
            by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        t.append(f"\nFUNCTIONS  ({len(funcs)} total)\n", style=GOLD)
        for kind in ("export", "entry", "symbol", "import", "sub", "func"):
            n = by_kind.get(kind, 0)
            if n:
                label = _KIND_GROUPS.get(kind, (9, kind.title()))[1]
                t.append(f"  {label:<12}{n}\n", style="#d9cbac")
        if self._strings_cache is not None:
            t.append(f"\nSTRINGS  ({len(self._strings_cache)} total)\n", style=GOLD)
        t.append(f"\nSECTIONS  ({len(img.sections)} total)\n", style=GOLD)
        for s in img.sections:
            t.append(
                f"  {s.name:<10} {s.va:#012x}  {s.size:#8x}  {s.flags}\n",
                style="#d9cbac",
            )
        self.query_one("#info", Static).update(t)

    def _render_section_info(self, sec) -> None:
        """Info pane content for a Section leaf."""
        img = self.image
        t = Text()
        t.append(f"SECTION  {sec.name}\n", style=GOLD)
        t.append(f"  {'va':<12}{sec.va:#x}\n", style=DIM)
        t.append(f"  {'end':<12}{sec.end:#x}\n", style=DIM)
        t.append(f"  {'size':<12}{sec.size:#x}  ({sec.size} bytes)\n", style=DIM)
        t.append(f"  {'raw off':<12}{sec.raw_off:#x}\n", style=DIM)
        t.append(f"  {'raw size':<12}{sec.raw_size:#x}\n", style=DIM)
        t.append(f"  {'flags':<12}{sec.flags}\n", style=DIM)
        funcs_in = [f for f in img.funcs if sec.contains(f.va)]
        if funcs_in:
            t.append(
                f"\nfunctions in section: {len(funcs_in)}\n",
                style="#d9cbac",
            )
        self.query_one("#info", Static).update(t)

    def _render_slice_info(self, sl) -> None:
        """Info pane content for a fat-Mach-O slice leaf."""
        img = self.image
        active = sl.index == img.slice_index
        t = Text()
        t.append(f"SLICE  {sl.cpu}\n", style=GOLD)
        t.append(f"  {'arch':<12}{sl.arch.value}\n", style=DIM)
        t.append(f"  {'index':<12}{sl.index}\n", style=DIM)
        t.append(f"  {'fat off':<12}{sl.fat_offset:#x}\n", style=DIM)
        t.append(
            f"  {'state':<12}{'active' if active else 'inactive'}\n",
            style=GOLD if active else DIM,
        )
        if not active:
            t.append("\nSelect this slice in the tree to load it.\n", style="#d9cbac")
        self.query_one("#info", Static).update(t)

    def _switch_slice(self, idx: int) -> None:
        """Reload the binary on fat slice `idx` and rebuild the whole view.

        Annotations are keyed per file path, shared across slices; renames ride
        on VAs, which differ per slice (different code), so a switch starts the
        slice's own view fresh while the saved sidecar stays intact.
        """
        if self.image is None or idx == self.image.slice_index:
            return
        cpu = next((s.cpu for s in self.image.slices if s.index == idx), str(idx))
        # an explicit slice pick overrides any arch default for this session
        self._arch = None
        self._slice_index = idx
        try:
            self.image = load_image(self._path, fmt=self._fmt, slice_index=idx)
            self.dis = Disassembler(self.image)
            self._assistant.bind_image(self.image)
        except Exception as e:
            self.notify(f"Could not load slice {cpu}: {e}", severity="error")
            return
        # The new slice has its own functions / strings / nav; reset the
        # per-slice view state so nothing from the prior slice leaks across.
        self._strings_cache = None
        self._data_view_cache = None
        self._nav_history = []
        self._nav_pos = -1
        self._set_header_title()
        self._build_table()
        self._set_status()
        self._refresh_toolbar()
        self._select_item((_ITEM_BINARY, None))
        if self._discover and not getattr(self.image, "_discovered", False):
            self._start_discovery_spinner()
            self._discover_worker()
        if self._strings_cache is None:
            self._extract_strings_worker()
        self.query_one("#status", Static).update(
            Text(f" Loaded {cpu} slice", style=GOLD)
        )

    def _render_string_info(self, s) -> None:
        """Info pane content for a String leaf: text, location, and xrefs."""
        t = Text()
        t.append("STRING\n", style=GOLD)
        t.append(f"  {'va':<12}{s.va:#x}\n", style=DIM)
        t.append(f"  {'section':<12}{s.section}\n", style=DIM)
        enc = {"utf-16le": "UTF-16LE", "utf-8": "UTF-8"}.get(s.encoding, "ASCII")
        t.append(f"  {'encoding':<12}{enc}\n", style=DIM)
        if getattr(s, "category", "literal") != "literal":
            t.append(f"  {'category':<12}{s.category}\n", style=DIM)
        t.append(f"  {'length':<12}{len(s.text)}\n", style=DIM)
        t.append("\nTEXT\n", style=GOLD)
        t.append(f'  "{s.text}"\n', style=GREEN)
        # Every site that references this address (whole-image, cached), not just
        # nearby linear hits, so the string's full use set is visible.
        refs = data_xrefs_to(self.image, s.va) if s.va else []
        t.append(f"\nXREFS ({len(refs)})\n", style=GOLD)
        if not refs:
            t.append("  (none recorded)\n", style=DIM)
        for addr in refs[:40]:
            origin = self.image.nearest_func(addr)
            label = self._disp(origin) if origin else ""
            seg = Text(f"  {addr:#012x}", style=GREEN)
            seg.apply_meta({"@click": f"app.goto_addr({addr})"})
            t.append_text(seg)
            t.append(f"  {label}\n", style="#d9cbac")
        self.query_one("#info", Static).update(t)

    def _render_xrefs(self, func) -> None:
        img = self.image
        t = Text()
        chain = thunk_chain(img, func.va)
        t.append("THUNK / IMPLEMENTATION CHAIN\n", style=GOLD)
        for i, va in enumerate(chain):
            f = img.func_at(va)
            arrow = "    " if i == 0 else f" {G['arrow']}  "
            label = self._disp(f) if f else "(sub)"
            t.append(
                f"{arrow}{va:#012x}  {label}\n",
                style=GREEN if i == len(chain) - 1 else "#d9cbac",
            )
        t.append("\nCALLS  ", style=GOLD)
        t.append("(callees, recursive)\n", style=DIM)
        calls = call_tree(img, func.va, callers=False, depth=3)
        if not calls.children:
            t.append("  (calls nothing in .text)\n", style=DIM)
        else:
            self._append_call_tree(t, calls)
        t.append("\nCALLED BY  ", style=GOLD)
        t.append("(callers, recursive)\n", style=DIM)
        called_by = call_tree(img, func.va, callers=True, depth=2)
        if not called_by.children:
            t.append("  (no callers found in .text)\n", style=DIM)
        else:
            self._append_call_tree(t, called_by)
        self.query_one("#xrefs", Static).update(t)

    def _append_call_tree(
        self,
        t: Text,
        node: CallNode,
        *,
        prefix: str = "",
        is_last: bool = True,
        is_root: bool = True,
    ) -> None:
        """Render a `CallNode` as an ASCII tree into `t` (depth-first)."""
        img = self.image
        f = img.func_at(node.va) or img.nearest_func(node.va)
        if f and f.va == node.va:
            label, style = self._disp(f), GREEN if is_root else "#d9cbac"
        elif f:
            label, style = f"{self._disp(f)}+{node.va - f.va:#x}", DIM
        else:
            label, style = f"sub_{node.va:#x}", DIM
        connector = "" if is_root else (G["t_end"] if is_last else G["t_mid"])
        t.append(f"  {prefix}{connector}", style=DIM)
        t.append(f"{node.va:#012x}  ", style=DIM)
        t.append(label, style=style)
        t.append(f"  {G['ellipsis']}\n" if node.elided else "\n", style=DIM)
        child_prefix = prefix + (
            "" if is_root else (G["t_gap"] if is_last else G["t_bar"])
        )
        for i, c in enumerate(node.children):
            self._append_call_tree(
                t,
                c,
                prefix=child_prefix,
                is_last=(i == len(node.children) - 1),
                is_root=False,
            )

    def _render_analysis(self, func) -> None:
        img = self.image
        chain = thunk_chain(img, func.va)
        real = chain[-1]
        t = Text()
        t.append(f"ANALYSIS  {self._disp(func)}\n", style=GOLD)
        if real != func.va:
            t.append(f"resolved implementation {G['arrow']} {real:#x}\n", style=DIM)
        t.append("\n")

        # Structured-buffer immediate stores (opcodes, lengths, magic bytes)
        stores = immediate_stores(img, real)
        t.append("IMMEDIATE STORES  ", style=GOLD)
        t.append("(structured-buffer field writes)\n", style=DIM)
        if not stores:
            t.append("  (none)\n", style=DIM)
        for s in stores[:24]:
            where = "abs" if s.is_absolute else f"{s.base}{_signed_disp(s.signed_disp)}"
            t.append(f"  {s.addr:#012x}  [{where}]  ", style="#d9cbac")
            t.append(f".{s.size}  = {s.value:#04x}", style=GREEN)
            t.append(_conf_text(s.evidence), style=DIM)
            t.append("\n")

        # Register-passed call arguments (opcodes handed to a shared sender, etc.)
        args = call_immediate_args(img, real)
        if args:
            t.append("\nCALL-ARGUMENT IMMEDIATES  ", style=GOLD)
            t.append("(values in registers at a call)\n", style=DIM)
            for a in args[:16]:
                tgt = ""
                if a.target is not None:
                    tf = img.func_at(
                        a.target
                        # exact match only; avoid misleading nearest
                    )
                    name = self._disp(tf) if tf else f"sub_{a.target:#x}"
                    tgt = f" {G['arrow']} {name}"
                t.append(f"  {a.call_addr:#012x}  {a.reg:<4} = ", style="#d9cbac")
                t.append(f"{a.value:#04x}", style=GREEN)
                t.append(tgt, style=GOLD)
                t.append(_conf_text(a.evidence), style=DIM)
                t.append("\n")

        # Strings, tables, and pointer constants the function points at
        refs = referenced_data(img, real)
        t.append("\nREFERENCED DATA  ", style=GOLD)
        t.append("(strings / tables / pointers it reads)\n", style=DIM)
        if not refs:
            t.append("  (none on this target)\n", style=DIM)
        for r in refs[:24]:
            t.append(f"  {r.addr:#012x}  {G['arrow']} ", style="#d9cbac")
            t.append(f"{r.target:#x}", style=GOLD)
            if r.kind == "str":
                t.append(f'  "{r.text}"\n', style=GREEN)
            else:
                t.append(f"  [{r.text}]\n", style=DIM)

        # CRC / checksum loops
        t.append("\nCRC / CHECKSUM LOOPS\n", style=GOLD)
        crcs = detect_crc_loops(img, real)
        if not crcs:
            t.append("  (no bit-twiddling loop detected here)\n", style=DIM)
        for c in crcs:
            polys = ", ".join(f"{p:#x}" for p in c.polys) or G["mdash"]
            init = f"{c.init:#x}" if c.init is not None else G["mdash"]
            t.append(
                f"  {c.kind} loop {c.start:#x}{G['ndash']}{c.end:#x}  poly={polys}  "
                f"init={init}  ({c.insn_count}i)",
                style="#d9cbac",
            )
            t.append(_conf_text(c.evidence), style=DIM)
            t.append("\n")
            for cv in c.evidence.caveats:
                t.append(f"      {G['hint']} {cv}\n", style=DIM)
            for p in c.polys:
                hint = _poly_hint(p)
                if hint:
                    t.append(f"      {G['hint']} {hint}\n", style=GREEN)

        # Top immediate constants
        t.append("\nFREQUENT CONSTANTS\n", style=GOLD)
        consts = function_constants(img, real)
        for val, n in consts.most_common(8):
            t.append(f"  {val:#x}  {G['times']}{n}\n", style="#d9cbac")
        self.query_one("#analysis", Static).update(t)

    def _render_strings(self) -> None:
        """Image-wide string list (ASCII + UTF-16), extracted lazily and cached."""
        img = self.image
        if img is None:
            return
        if self._strings_cache is None:
            self._strings_cache = extract_strings(img)
        strings = self._strings_cache
        t = Text()
        t.append("STRINGS  ", style=GOLD)
        t.append(f"({len(strings)} ASCII / UTF-16 found)\n\n", style=DIM)
        if not strings:
            t.append("  (none)\n", style=DIM)
        for s in strings[:2000]:
            t.append(f"  {s.va:#012x}  ", style=DIM)
            t.append(f"{s.section:<8}", style=BLUE)
            t.append(" w " if s.encoding == "utf16" else "   ", style=DIM)
            val = s.text if len(s.text) <= 80 else s.text[:77] + G["ellipsis"]
            t.append(f'"{val}"\n', style=GREEN)
        if len(strings) > 2000:
            t.append(f"\n  {G['ellipsis']} {len(strings) - 2000} more\n", style=DIM)
        self.query_one("#strings", Static).update(t)

    def _render_map(self) -> None:
        """Whole-file content map: sections to scale, each with a byte-class strip."""
        img = self.image
        if img is None:
            return
        self.query_one("#map", Static).update(render.binary_map(img))

    _DATA_VIEW_CAP = 200

    def _render_data_view(self) -> None:
        """Sections, imports, exports, strings, and scan findings in one pane.

        Rendered once per binary and cached, since the scan is the slow step.
        Each list is capped (`_DATA_VIEW_CAP`) with a truncation note so a large
        binary stays responsive. Findings are the scanner's, run without the
        network (no CVE), and stay labeled facts / heuristics, never proven.
        """
        widget = self.query_one("#data", Static)
        if self._data_view_cache is not None:
            widget.update(self._data_view_cache)
            return
        img = self.image
        t = Text()

        def _head(title: str, count: int) -> None:
            t.append(f"{title}  ", style=GOLD)
            t.append(f"({count})\n", style=DIM)

        def _capped(rows: list, render_row) -> None:
            for r in rows[: self._DATA_VIEW_CAP]:
                render_row(r)
            extra = len(rows) - self._DATA_VIEW_CAP
            if extra > 0:
                t.append(f"  {G['ellipsis']} {extra} more not shown\n", style=DIM)

        _head("SECTIONS", len(img.sections))
        for s in img.sections:
            t.append(
                f"  {s.name:<16}  {s.va:#012x}  {s.size:#10x}  {s.flags}\n",
                style="#d9cbac",
            )
        imports = [f for f in img.funcs if f.kind == "import"]
        exports = [f for f in img.funcs if f.kind == "export"]
        t.append("\n")
        _head("IMPORTS", len(imports))
        _capped(
            imports,
            lambda f: t.append(f"  {self._disp(f):<32}  {f.va:#x}\n", style=BLUE),
        )
        t.append("\n")
        _head("EXPORTS", len(exports))
        _capped(
            exports,
            lambda f: t.append(f"  {self._disp(f):<32}  {f.va:#x}\n", style=GOLD),
        )
        strings = self._strings_cache or []
        t.append("\n")
        _head("STRINGS", len(strings))
        _capped(
            strings,
            lambda s: t.append(f'  {s.va:#012x}  "{s.text}"\n', style=GREEN),
        )
        findings = self._data_view_findings()
        t.append("\n")
        _head("SCAN FINDINGS", len(findings))
        t.append("(facts / heuristics; confirm before acting)\n", style=DIM)
        if not findings:
            t.append("  (none)\n", style=DIM)
        _capped(
            findings,
            lambda f: t.append(
                f"  [{f.level:<7}] {f.rule}  {f.message}\n", style="#d9cbac"
            ),
        )
        self._data_view_cache = t
        widget.update(t)

    def _data_view_findings(self) -> list:
        """Scanner findings for the data view, without the network (no CVE)."""
        try:
            from ..scan import scan_image

            return scan_image(self.image, cve=False)
        except Exception:
            return []

    def _render_pseudo(self, func) -> None:
        img = self.image
        real = thunk_chain(img, func.va)[-1]
        t = Text()
        t.append(f"PSEUDO-C  {func.display}", style=GOLD)
        if real != func.va:
            t.append(f"  (impl {real:#x})", style=DIM)
        t.append(
            "\nheuristic; registers shown as variables -- confirm in Disasm\n\n",
            style=DIM,
        )
        lines = pseudo_c(img, real)
        if not lines:
            t.append("  (no pseudo-C: non-x86 target or no code here)\n", style=DIM)
        for ln in lines:
            if ln.is_label:
                t.append(f"{ln.code}\n", style=BLUE)
                continue
            t.append(f"  {ln.addr:#012x}    ", style=DIM)
            muted = ln.code.startswith(("//", "asm("))
            t.append(f"{ln.code}\n", style=DIM if muted else "#d9cbac")
        self.query_one("#pseudo", Static).update(t)

    # -- call-graph navigator ---------------------------------------------
    # nodes shown per group; center + 2 groups = <= 7 visible
    _GRAPH_SLOTS = 3

    def _node_label(self, va: int) -> str:
        f = self.image.func_at(va) or self.image.nearest_func(va)
        if f and f.va == va:
            return self._disp(f)
        if f:
            return f"{self._disp(f)}+{va - f.va:#x}"
        return f"sub_{va:x}"

    def _graph_callers(self, va: int) -> list[int]:
        out: list[int] = []
        for c in callers_of(self.image, va):
            f = self.image.nearest_func(c)
            fva = f.va if f else c
            if fva != va and fva not in out:
                out.append(fva)
        return out

    def _graph_callees(self, va: int) -> list[int]:
        out: list[int] = []
        for c in self.dis.callees(va):
            f = self.image.func_at(c) or self.image.nearest_func(c)
            fva = f.va if f else c
            if fva != va and fva not in out:
                out.append(fva)
        return out

    def _graph_section(self, t: Text, group: str, arrow: str, vas: list[int]) -> None:
        n = len(vas)
        t.append(f"\n{arrow} {group} ({n})\n", style=BLUE)
        if n == 0:
            t.append("    (none)\n", style=DIM)
            return
        slots = self._GRAPH_SLOTS
        pager = n > slots
        if pager:
            # reserve a slot for the pager node
            per = slots - 1
            pages = (n + per - 1) // per
            page = self._graph_pages[group] % pages
            window = vas[page * per : page * per + per]
        else:
            window = vas
            pages = page = 1
        for va in window:
            node = Text(f"    {G['bullet']} {self._node_label(va)}", style="#d9cbac")
            node.append(f"  {va:#x}", style=DIM)
            node.apply_meta({"@click": f"app.graph_center({va})"})
            t.append_text(node)
            t.append("\n")
        if pager:
            pg = Text(
                f"    + more  (page {page + 1}/{pages})  {G['recycle']}", style=GOLD
            )
            pg.apply_meta({"@click": f"app.graph_page('{group}', 1)"})
            t.append_text(pg)
            t.append("\n")

    def _render_graph(self) -> None:
        va = self._graph_va
        if va is None:
            return
        t = Text()
        t.append("CALL GRAPH", style=GOLD)
        t.append(f"  {G['mdash']} click a node to recenter\n", style=DIM)
        self._graph_section(t, "callers", G["up"], self._graph_callers(va))
        t.append(f"\n    {G['node']} ", style=GOLD)
        t.append(self._node_label(va), style=f"bold {GOLD}")
        t.append(f"   {va:#x}\n", style=DIM)
        self._graph_section(t, "callees", G["down"], self._graph_callees(va))
        self.query_one("#graph", Static).update(t)

    def _graph_recenter(self, va: int) -> None:
        self._graph_va = va
        self._graph_pages = {"callers": 0, "callees": 0}
        self._render_graph()

    # -- assistant ---------------------------------------------------------
    def _ai_disasm_text(self, va: int) -> str:
        """Plain-text disassembly of the function at `va`, symbolized, for context."""
        img = self.image
        lines = []
        for ins in self.dis.func(va):
            sym = ""
            tgt = ins.imm_target()
            if tgt is not None:
                f = img.func_at(tgt) or img.nearest_func(tgt)
                if f and f.va == tgt:
                    sym = f"  ; -> {f.display}"
                elif f:
                    sym = f"  ; -> {f.display}+{tgt - f.va:#x}"
            lines.append(f"{ins.addr:#012x}  {ins.text}{sym}")
        return "\n".join(lines)

    def _ai_sync_context(self, func) -> None:
        """Point the assistant at `func` (resolved impl), restoring its chat.

        Each function keeps its own conversation and transcript, cached by the
        resolved-implementation VA, so switching away and back resumes it.
        """
        real = thunk_chain(self.image, func.va)[-1]
        if self._ai_va == real and self._assistant.has_context():
            return
        self._stash_active_session()
        label = func.display if real == func.va else f"{func.display} (impl {real:#x})"
        self._assistant.set_context(label, self._ai_disasm_text(real))
        self._ai_va = real
        cached = self._ai_sessions.get(real)
        # resume a prior conversation for this function
        if cached is not None:
            self._assistant.restore(cached["messages"])
            self._ai_log = cached["log"]
        else:
            self._ai_log = Text()
            reason = self._assistant.unavailable_reason()
            intro = (
                f"AI unavailable: {reason}. " if reason else "Ask about this function. "
            )
            self._ai_log.append(f"{intro}Context: {label}.\n", style=DIM)
        self._ai_refresh()
        self._ai_refresh_install_btn()
        self._sync_thinking_spinner()

    def _ai_sync_binary_context(self) -> None:
        """Point the assistant at the whole binary; resume any prior session.

        Fallback when no Function is selected: seeds the Assistant with file
        properties, sections, and counts so the agent has whole-binary context
        for the user's question and can use its tools to roam from there.
        """
        if self._ai_va is None and self._assistant.has_context():
            return
        self._stash_active_session()
        label = f"binary {os.path.basename(self.image.path)}"
        self._assistant.set_context(label, self._ai_binary_summary())
        self._ai_va = None
        cached = self._ai_binary_session
        if cached is not None:
            self._assistant.restore(cached["messages"])
            self._ai_log = cached["log"]
        else:
            self._ai_log = Text()
            reason = self._assistant.unavailable_reason()
            intro = (
                f"AI unavailable: {reason}. " if reason else "Ask about the binary. "
            )
            self._ai_log.append(f"{intro}Context: {label}.\n", style=DIM)
        self._ai_refresh()
        self._ai_refresh_install_btn()
        self._sync_thinking_spinner()

    def _stash_active_session(self) -> None:
        """Save the in-memory chat for whichever context is currently active.

        Per-function chats land in `_ai_sessions`; the binary chat lives in
        `_ai_binary_session`. Called before switching contexts so a later
        switch-back finds the transcript intact.
        """
        if not self._assistant.has_context():
            return
        snap = {"messages": self._assistant.snapshot(), "log": self._ai_log}
        if self._ai_va is None:
            self._ai_binary_session = snap
        else:
            self._ai_sessions[self._ai_va] = snap

    def _sync_thinking_spinner(self) -> None:
        """Run the spinner only when the displayed origin has a reply in flight.

        Also re-syncs the Stop button visibility so it appears/disappears with
        the spinner instead of after a tab refresh.
        """
        if self._ai_va in self._ai_pending:
            self._ai_start_thinking()
        else:
            self._ai_stop_thinking()
        self._ai_refresh_stop_btn()

    def _ai_binary_summary(self) -> str:
        """Compact binary description for the Assistant's seeded context."""
        img = self.image
        lines = [
            f"File: {img.path}",
            f"Format: {img.fmt}  Arch: {img.arch.value}  Base: {img.base:#x}",
            "",
            "Sections:",
        ]
        for s in img.sections:
            lines.append(f"  {s.name:<12} {s.va:#012x}  size {s.size:#x}  {s.flags}")
        by_kind: dict[str, int] = {}
        for f in img.funcs:
            by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        kinds = ", ".join(f"{n} {k}" for k, n in sorted(by_kind.items()))
        lines.append("")
        lines.append(f"Functions: {len(img.funcs)} total ({kinds})")
        if self._strings_cache is not None:
            lines.append(f"Strings: {len(self._strings_cache)}")
        lines.append("")
        lines.append(
            "No single function is in focus. Use find_function, list_functions, "
            "search, xrefs, and disassemble to investigate."
        )
        return "\n".join(lines)

    def _ai_log_for(self, va: int | None) -> Text:
        """The transcript Text for `va`: the live log if displayed, else its session.

        Materializes a session log for a backgrounded origin so an in-flight
        reply has a stable place to land even when the user has switched away.
        `va is None` refers to the binary-wide chat.
        """
        if va == self._ai_va:
            return self._ai_log
        if va is None:
            if self._ai_binary_session is None:
                self._ai_binary_session = {"messages": [], "log": Text()}
            return self._ai_binary_session["log"]
        sess = self._ai_sessions.get(va)
        if sess is None:
            sess = {"messages": [], "log": Text()}
            self._ai_sessions[va] = sess
        return sess["log"]

    def _assistant_for(self, origin: int | None) -> Assistant:
        """A dedicated Assistant seeded with `origin`'s context and history.

        Runs one request in isolation so the user switching contexts (which
        re-points `self._assistant`) cannot corrupt the in-flight conversation.
        `origin is None` seeds the binary-wide chat. Reuses the same client
        (so an injected test client and the configured backend carry over).
        """
        worker = Assistant(model=self._assistant.model, client=self._assistant._client)
        worker.bind_image(self.image)
        if origin is None:
            label = f"binary {os.path.basename(self.image.path)}"
            worker.set_context(label, self._ai_binary_summary())
        else:
            label = self._ai_label_for(origin)
            worker.set_context(label, self._ai_disasm_text(origin))
        if origin == self._ai_va:
            worker.restore(self._assistant.snapshot())
        elif origin is None:
            sess = self._ai_binary_session
            if sess and sess.get("messages"):
                worker.restore(list(sess["messages"]))
        else:
            sess = self._ai_sessions.get(origin)
            if sess and sess.get("messages"):
                worker.restore(list(sess["messages"]))
        return worker

    def _ai_refresh_install_btn(self) -> None:
        """Show the install button only when a needed package is absent."""
        try:
            btn = self.query_one("#ai-install", Button)
        except Exception:
            return
        btn.display = missing_package() is not None

    def _ai_refresh_stop_btn(self) -> None:
        """Show the Stop button only while a request is in flight for this origin."""
        try:
            btn = self.query_one("#ai-stop", Button)
        except Exception:
            return
        btn.display = self._ai_va in self._ai_pending

    def _ai_append(
        self, who: str, text: str, style: str, *, link: bool = False
    ) -> None:
        self._ai_append_to(self._ai_log, who, text, style, link=link)

    def _ai_append_to(
        self, log: Text, who: str, text: str, style: str, *, link: bool = False
    ) -> None:
        """Append a turn to `log`; refresh the pane only if `log` is displayed."""
        log.append(f"\n{who}\n", style=style)
        # an assistant reply: render markdown, keep addresses clickable
        if link:
            log.append_text(_markdown(text))
            log.append("\n")
        else:
            log.append(f"{text}\n", style="#d9cbac")
        if log is self._ai_log:
            self._ai_refresh()

    def _ai_refresh(self) -> None:
        self.query_one("#ai-log", Static).update(self._ai_log)
        self.query_one("#ai-scroll", VerticalScroll).scroll_end(animate=False)

    def _ai_start_thinking(self) -> None:
        """Show an animated 'thinking' line beneath the transcript while waiting."""
        self._ai_stop_thinking()
        self._ai_spin = 0
        self._ai_timer = self.set_interval(0.12, self._ai_tick)
        self._ai_tick()

    def _ai_tick(self) -> None:
        frame = SPINNER[self._ai_spin % len(SPINNER)]
        self._ai_spin += 1
        # Render the committed transcript plus a transient spinner line.
        pending = self._ai_log.copy()
        pending.append(f"\n{frame} deglyph is thinking…\n", style=GOLD)
        self.query_one("#ai-log", Static).update(pending)
        self.query_one("#ai-scroll", VerticalScroll).scroll_end(animate=False)

    def _ai_stop_thinking(self) -> None:
        if self._ai_timer is not None:
            self._ai_timer.stop()
            self._ai_timer = None

    def _ai_reply(
        self,
        origin: int | None,
        messages: list,
        who: str,
        text: str,
        style: str,
        link: bool,
        renames: dict[int, str] | None = None,
    ) -> None:
        """Reply/error sink (UI thread): write to the originating chat by origin.

        The reply lands in the chat it was asked from, even if the user has
        since switched contexts; it appends to that origin's transcript and,
        when the origin is no longer displayed, raises a toast instead of
        writing to the visible pane. `origin is None` is the binary-wide chat.

        `renames` carries the agent's `rename_function` calls drained from the
        worker; applying them here (on the UI thread) keeps the sidecar write
        and tree rebuild off the worker.

        If `origin` is no longer pending (the user clicked Stop, or this is a
        stale double-reply), the reply is dropped — even the renames, since
        applying them silently after a Stop would surprise the user.
        """
        if origin not in self._ai_pending:
            return
        self._ai_pending.discard(origin)
        self._ai_refresh_stop_btn()
        if renames:
            self._apply_ai_renames(renames)
        # the worker ran on its own assistant; fold its turns back into the origin
        if messages:
            if origin == self._ai_va:
                self._assistant.restore(messages)
            elif origin is None:
                if self._ai_binary_session is None:
                    self._ai_binary_session = {"messages": [], "log": Text()}
                self._ai_binary_session["messages"] = messages
            else:
                self._ai_sessions.setdefault(origin, {"messages": [], "log": Text()})
                self._ai_sessions[origin]["messages"] = messages
        log = self._ai_log_for(origin)
        self._ai_append_to(log, who, text, style, link=link)
        if origin == self._ai_va:
            self._ai_stop_thinking()
            self._ai_refresh()
        else:
            # finished while browsing elsewhere
            label = "the binary" if origin is None else self._ai_label_for(origin)
            verb = "reply ready" if link else "request failed"
            self.notify(
                f"AI {verb} for {label}.",
                severity="information" if link else "error",
            )
        # a real answer (not an error): persist per-function chats
        if link and origin is not None:
            self._persist_chats()

    def _apply_ai_renames(self, renames: dict[int, str]) -> None:
        """Adopt agent renames into the persistent annotations, rebuild the tree.

        Each pair lands in `Annotations.names` keyed by VA; the sidecar saves
        once, the tree is rebuilt so the new labels show in every pane, and the
        cursor is restored to whatever item was selected before.
        """
        if not renames:
            return
        applied = 0
        for va, name in renames.items():
            if not self.image or self.image.func_at(va) is None:
                # an outdated or invalid VA — silently skip rather than poison
                continue
            self._anno.names[va] = name
            applied += 1
        if applied == 0:
            return
        self._anno.save()
        keep = self._current_item()
        self._apply_filter()
        if keep is not None:
            self._select_item(keep)
        # surface what happened so the user has a paper trail in the status bar
        suffix = "" if applied == 1 else "s"
        self.query_one("#status", Static).update(
            Text(f" AI renamed {applied} function{suffix}", style=GOLD)
        )

    def _ai_label_for(self, va: int) -> str:
        if not self.image:
            return f"{va:#x}"
        f = self.image.func_at(va) or self.image.nearest_func(va)
        return f.display if f else f"{va:#x}"

    def _ai_tool_note(self, origin: int | None, name: str, inp: dict) -> None:
        """Show a tool call the agent made, as a dim line in the origin transcript."""
        arg = next(iter(inp.values()), "") if inp else ""
        log = self._ai_log_for(origin)
        log.append(f"  {G['hint']} {name}({arg})\n", style=DIM)
        if log is self._ai_log:
            self._ai_refresh()

    @work(thread=True, group="ai-ask")
    def _ask_ai(self, origin: int | None, question: str) -> None:
        """Answer `question` about `origin` on a dedicated, isolated assistant.

        Switching functions mid-flight re-points `self._assistant`; the worker
        holds its own seeded copy so the in-flight conversation is unaffected.
        """
        worker = self._assistant_for(origin)

        def on_tool(name: str, inp: dict) -> None:
            self.call_from_thread(self._ai_tool_note, origin, name, inp)

        try:
            reply = worker.ask(question, on_event=on_tool)
        # AssistantError and any SDK surprise
        except Exception as e:
            renames = worker.consume_renames()
            self.call_from_thread(
                self._ai_reply,
                origin,
                worker.snapshot(),
                "deglyph (error)",
                str(e),
                "red",
                False,
                renames,
            )
            return
        renames = worker.consume_renames()
        # Capture the worker's investigation (question, answer, redacted
        # transcript) so `action_export_ai` can save the last one.
        try:
            self._last_ai_investigation = worker.export_investigation()
        except Exception:
            self._last_ai_investigation = None
        self.call_from_thread(
            self._ai_reply,
            origin,
            worker.snapshot(),
            "deglyph",
            reply,
            GOLD,
            True,
            renames,
        )

    def on_button_pressed(self, ev: Button.Pressed) -> None:
        if ev.button.id == "ai-stop":
            self.action_stop_ai()
            return
        if ev.button.id != "ai-install":
            return
        spec = missing_package()
        if spec is None:
            self._ai_refresh_install_btn()
            return

        def go(ok: bool) -> None:
            if ok:
                self._start_ai_install(spec)

        self.push_screen(InstallPrompt(spec), go)

    def action_stop_ai(self) -> None:
        """Cancel any in-flight AI request for the displayed origin.

        Marks the origin as no-longer-pending so the late reply (if it slips
        through after the thread finishes) is dropped by `_ai_reply`. The
        worker thread itself can't be killed in-flight (a network request may
        still be running), so this only suppresses the UI side.
        """
        origin = self._ai_va
        if origin not in self._ai_pending:
            return
        self._ai_pending.discard(origin)
        try:
            self.workers.cancel_group(self, "ai-ask")
        # Worker cancellation is best-effort; clean up the UI side regardless.
        except Exception:
            pass
        self._ai_append("deglyph", "[stopped]", DIM)
        self._ai_stop_thinking()
        self._ai_refresh_stop_btn()

    def action_export_ai(self) -> None:
        """Write the last assistant investigation (redacted) to the CWD as JSON."""
        inv = self._last_ai_investigation
        if not inv:
            self.query_one("#status", Static).update(
                Text(" No AI investigation to export yet", style=DIM)
            )
            return
        ctx = inv.get("context") or os.path.basename(
            self.image.path if self.image else ""
        )
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", ctx)[:60] or "investigation"
        out = os.path.abspath(f"ai_investigation_{safe}.json")
        try:
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(inv, fh, indent=2)
        except OSError as e:
            self.query_one("#status", Static).update(
                Text(f" Could not write investigation: {e}", style="red")
            )
            return
        self.query_one("#status", Static).update(
            Text(f" Wrote {os.path.basename(out)}", style=GOLD)
        )

    def _start_ai_install(self, spec: str) -> None:
        """Disable the button, show progress, and run pip on a worker."""
        btn = self.query_one("#ai-install", Button)
        btn.disabled = True
        btn.label = "Installing…"
        self._ai_append("deglyph", f"Installing {spec}…", DIM)
        self._install_ai_worker(spec)

    @work(exclusive=True, thread=True, group="ai-install")
    def _install_ai_worker(self, spec: str) -> None:
        ok, output = install_package(spec)
        self.call_from_thread(self._ai_install_done, spec, ok, output)

    def _ai_install_done(self, spec: str, ok: bool, output: str) -> None:
        """Report the pip result (runs on the UI thread)."""
        btn = self.query_one("#ai-install", Button)
        btn.disabled = False
        btn.label = "Install AI dependencies"
        if ok:
            self._ai_append(
                "deglyph",
                f"Installed {spec}. Restart deglyph to use the assistant.",
                GREEN,
            )
        else:
            self._ai_append("deglyph (install failed)", output or "pip failed", "red")
        self._ai_refresh_install_btn()

    def _set_status(self) -> None:
        img = self.image
        if not img:
            return
        shown = len(self._rows)
        total = len(img.funcs)
        flt = f"  filter='{self._filter}'" if self._filter else ""
        msg = Text()
        msg.append(f" {os.path.basename(img.path)} ", style=f"bold {GOLD}")
        msg.append(f" {img.fmt}/{img.arch.value} ", style=DIM)
        msg.append(f" {shown}/{total} functions{flt} ", style="#d9cbac")
        msg.append(
            " │ / search · f follow · g go to · i assistant · q quit",
            style=DIM,
        )
        self.query_one("#status", Static).update(msg)

    # -- events ------------------------------------------------------------
    def on_input_changed(self, ev: Input.Changed) -> None:
        if ev.input.id != "search":
            return
        # Ignore queued events from programmatic edits (goto). The box is locked
        # until its value settles back to the active filter text.
        if self._input_locked:
            if ev.value == self._filter:
                self._input_locked = False
            return
        if self._prompt is None and ev.value != self._filter:
            self._filter = ev.value
            self._apply_filter()

    def on_input_submitted(self, ev: Input.Submitted) -> None:
        if ev.input.id == "ai-input":
            question = ev.value.strip()
            if not question or not self._assistant.has_context():
                return
            self.query_one("#ai-input", Input).value = ""
            self._ai_append("you", question, GREEN)
            # Always give immediate feedback: a setup reason if the assistant
            # can't run, otherwise the reply lands from the worker.
            reason = self._assistant.unavailable_reason()
            if reason:
                self._ai_append("deglyph (unavailable)", reason, "red")
            else:
                # `_ai_va` is None for the binary chat; the worker accepts None
                # and routes its reply back to the binary session.
                self._ai_pending.add(self._ai_va)
                self._ai_start_thinking()
                self._ai_refresh_stop_btn()
                self._ask_ai(self._ai_va, question)
            return
        if ev.input.id != "search":
            return
        if self._prompt is not None:
            self._handle_prompt(ev.value)
            return
        self.query_one("#functions", Tree).focus()

    def _handle_prompt(self, value: str) -> None:
        """Dispatch a one-shot search-box prompt (goto / rename), then restore it."""
        mode = self._prompt
        self._prompt = None
        inp = self.query_one("#search", Input)
        inp.placeholder = f"  {G['search']} Filter functions…"
        # Restore the box to the active filter; lock so the queued Changed events
        # (this assignment + the prompt text) don't re-filter the table.
        self._input_locked = True
        inp.value = self._filter
        if mode == "goto":
            self._do_goto(value)
        elif mode == "compare":
            self._run_compare(value)
        elif mode == "rename":
            self._do_rename(value)
        elif mode == "comment":
            self._do_comment(value)
        # Return focus to the table so key bindings work again (not typed as text).
        self.query_one("#functions", Tree).focus()

    def _do_goto(self, value: str) -> None:
        try:
            addr = int(value.strip(), 0)
        except ValueError:
            self.query_one("#status", Static).update(
                Text(f" not a valid address: {value!r}", style="red")
            )
            return
        self._goto_address(addr)

    def _do_rename(self, value: str) -> None:
        cur = self._current()
        if cur is None:
            return
        name = value.strip()
        if name:
            self._anno.names[cur.va] = name
        else:
            # empty input clears the rename
            self._anno.names.pop(cur.va, None)
        self._anno.save()
        self._apply_filter()
        self._select_func_node(cur.va)
        self._set_status()

    def _do_comment(self, value: str) -> None:
        cur = self._current()
        if cur is None:
            return
        text = value.strip()
        if text:
            self._anno.comments[cur.va] = text
        else:
            # empty input clears the note
            self._anno.comments.pop(cur.va, None)
        self._anno.save()
        self._render_info(cur)
        self.query_one("#tabs", TabbedContent).active = "tab-info"

    def on_tree_node_highlighted(self, ev: Tree.NodeHighlighted) -> None:
        # NodeHighlighted is also fired by DirectoryTree (the file picker), whose
        # node.data is a DirEntry. Scope this handler to the function tree.
        tree = getattr(ev.node, "tree", None)
        if tree is None or tree.id != "functions":
            return
        # A NodeHighlighted can arrive while the app is tearing down, after the
        # detail widgets are unmounted; rendering then raises NoMatches. Ignore it.
        if not self.is_running:
            return
        # Group folders carry no item (data is None): expanding/collapsing or
        # cursoring onto one must not render or clobber an explicit goto/follow.
        item = self._item_from_node(ev.node)
        if item is None:
            return
        # Ignore a spurious re-highlight of the already-rendered item (Textual
        # can emit one on first paint or on expand), which would otherwise
        # overwrite a pending goto/follow view.
        if item == self._last_rendered_item:
            return
        self._last_rendered_item = item
        self._show_for_item(item)

    def on_tabbed_content_tab_activated(self, ev: TabbedContent.TabActivated) -> None:
        # Populate the newly-active tab for the current item, so switching tabs
        # by click or arrow shows data without re-selecting the item.
        # A TabActivated can arrive while the app is tearing down, after the
        # function tree is unmounted; _current_item's query then raises NoMatches.
        if not self.is_running:
            return
        item = self._current_item()
        if item is not None:
            self._refresh_active_tab(item)

    # -- actions -----------------------------------------------------------
    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_clear_search(self) -> None:
        inp = self.query_one("#search", Input)
        inp.value = ""
        self._filter = ""
        self._apply_filter()
        self.query_one("#functions", Tree).focus()

    def action_cursor_down(self) -> None:
        self.query_one("#functions", Tree).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#functions", Tree).action_cursor_up()

    def action_disasm(self) -> None:
        cur = self._current()
        if cur is None:
            return
        self.query_one("#tabs", TabbedContent).active = "tab-disasm"
        self._render_disasm(cur.va)

    def action_xrefs(self) -> None:
        # Switching the tab fires TabActivated, which renders it for the selection.
        if self._current() is None:
            return
        self.query_one("#tabs", TabbedContent).active = "tab-xrefs"

    def action_analysis(self) -> None:
        if self._current() is None:
            return
        self.query_one("#tabs", TabbedContent).active = "tab-analysis"

    def action_follow(self) -> None:
        """Jump the table+disasm to the resolved implementation of the selection."""
        cur = self._current()
        if not cur:
            return
        chain = thunk_chain(self.image, cur.va)
        real = chain[-1]
        # the origin (cur) is captured inside _record_nav
        self._record_nav(real)
        self._refresh_tabs_for(_ITEM_FUNC)
        self._render_disasm(real)
        self.query_one("#tabs", TabbedContent).active = "tab-disasm"
        f = self.image.func_at(real)
        name = f.display if f else f"{real:#x}"
        self.query_one("#status", Static).update(
            Text(f" Followed {cur.display} → {name} ({real:#x})", style=GOLD)
        )

    def action_pseudo(self) -> None:
        if self._current() is None:
            return
        self.query_one("#tabs", TabbedContent).active = "tab-pseudo"

    def action_graph(self) -> None:
        if self._current() is None:
            return
        self.query_one("#tabs", TabbedContent).active = "tab-graph"

    def action_strings(self) -> None:
        """Jump to the Binary item and show the full image-wide strings list."""
        if self._binary_node is None:
            return
        self._select_node(self._binary_node)
        self.query_one("#tabs", TabbedContent).active = "tab-strings"

    def action_data_view(self) -> None:
        """Jump to the Binary item and show the consolidated data view."""
        if self._binary_node is None:
            return
        self._select_node(self._binary_node)
        self.query_one("#tabs", TabbedContent).active = "tab-data"

    def action_compare(self) -> None:
        """Prompt for a second binary to diff against the current build."""
        self._prompt = "compare"
        box = self.query_one("#search", Input)
        box.placeholder = "compare with build (path), Enter to diff"
        box.focus()

    def _compare_report(self, other) -> Text:
        """A two-build diff: functions and imports added / removed.

        `diff_baseline(current, other)` reports what the current build has that
        `other` does not (added) and what `other` had that the current build
        dropped (removed), keyed by a relocation-immune identity so a moved but
        identical function is not double counted. A self-compare is empty.
        """
        from ..scan import diff_baseline

        t = Text()
        t.append(f"COMPARE  {os.path.basename(self.image.path)}\n", style=GOLD)
        t.append(f"  against  {os.path.basename(other.path)}\n\n", style=DIM)
        findings = diff_baseline(self.image, other)
        if not findings:
            t.append("No function or import differences.\n", style=GREEN)
            return t
        for rule, title in (
            ("diff/added-function", "FUNCTIONS ADDED"),
            ("diff/removed-function", "FUNCTIONS REMOVED"),
            ("diff/added-import", "IMPORTS ADDED"),
        ):
            group = [f for f in findings if f.rule == rule]
            t.append(f"{title}  ", style=GOLD)
            t.append(f"({len(group)})\n", style=DIM)
            for f in group[:200]:
                t.append(f"  {f.message}\n", style="#d9cbac")
            if len(group) > 200:
                t.append(f"  {G['ellipsis']} {len(group) - 200} more\n", style=DIM)
            t.append("\n")
        return t

    def _run_compare(self, path: str) -> None:
        """Load `path` as a second build and render the diff in the Compare tab."""
        path = (path or "").strip()
        if not path:
            return
        try:
            other = load_image(path)
        except Exception as e:
            self.notify(
                f"Could not open {os.path.basename(path)}: {e}", severity="error"
            )
            return
        self.query_one("#compare", Static).update(self._compare_report(other))
        if self._binary_node is not None:
            self._select_node(self._binary_node)
            self.query_one("#tabs", TabbedContent).active = "tab-compare"

    # Active tab id -> the Static widget whose content the copy action yanks.
    _COPY_PANE_BY_TAB = {
        "tab-disasm": "#disasm",
        "tab-xrefs": "#xrefs",
        "tab-analysis": "#analysis",
        "tab-pseudo": "#pseudo",
        "tab-graph": "#graph",
        "tab-map": "#map",
        "tab-strings": "#strings",
        "tab-data": "#data",
        "tab-compare": "#compare",
        "tab-info": "#info",
        "tab-ai": "#ai-log",
    }

    def action_copy(self) -> None:
        """Copy the active right-pane content to the system clipboard.

        Uses Textual's `copy_to_clipboard`, which writes an OSC52 escape that
        most modern terminals honor (the clipboard ends up on the host the
        terminal is attached to, even over SSH).
        """
        tab = self.query_one("#tabs", TabbedContent).active
        sel = self._COPY_PANE_BY_TAB.get(tab)
        if sel is None:
            return
        try:
            widget = self.query_one(sel, Static)
        except Exception:
            return
        content = getattr(widget, "_Static__content", "")
        text = content.plain if hasattr(content, "plain") else str(content)
        if not text:
            self.query_one("#status", Static).update(
                Text(" Nothing to copy", style=DIM)
            )
            return
        self.copy_to_clipboard(text)
        self.query_one("#status", Static).update(
            Text(f" Copied {len(text)} chars to clipboard ({tab[4:]})", style=GOLD)
        )

    def action_copy_address(self) -> None:
        """Copy the selected function's virtual address to the clipboard."""
        cur = self._current()
        if cur is None:
            self.query_one("#status", Static).update(
                Text(" Select a function to copy its address", style=DIM)
            )
            return
        text = f"{cur.va:#x}"
        self.copy_to_clipboard(text)
        self.query_one("#status", Static).update(
            Text(f" Copied {text} to clipboard", style=GOLD)
        )

    def _function_report(self, func) -> str:
        """A plain-text report for `func`: header, disassembly, analysis, xrefs.

        Pure text (no Rich styling) so it can be written to a file or piped into
        another tool. The disassembly and detector lines are the same the panes
        show, flattened; detector hits stay labeled as heuristics.
        """
        img = self.image
        real = thunk_chain(img, func.va)[-1]
        name = self._disp(func)
        user_named = " (user-named)" if func.va in self._anno.names else ""
        lines = [
            f"# {name}  {func.va:#x}  ({func.kind}){user_named}",
            f"confidence: {func.confidence}",
        ]
        if real != func.va:
            lines.append(f"resolved implementation: {real:#x}")
        lines.append("")
        lines.append("## Disassembly")
        lines.append(self._ai_disasm_text(func.va) or "(none)")

        lines.append("")
        lines.append("## Analysis (heuristic; confirm in the disassembly)")
        stores = immediate_stores(img, real)
        lines.append("immediate stores:")
        if not stores:
            lines.append("  (none)")
        for s in stores[:24]:
            where = "abs" if s.is_absolute else f"{s.base}{_signed_disp(s.signed_disp)}"
            lines.append(
                f"  {s.addr:#012x}  [{where}] .{s.size} = {s.value:#04x} "
                f"({s.evidence.confidence})"
            )
        args = call_immediate_args(img, real)
        lines.append("call-argument immediates:")
        if not args:
            lines.append("  (none)")
        for a in args[:16]:
            lines.append(
                f"  {a.call_addr:#012x}  {a.reg} = {a.value:#04x} "
                f"({a.evidence.confidence})"
            )
        crcs = detect_crc_loops(img, real)
        lines.append("crc / checksum loops:")
        if not crcs:
            lines.append("  (none)")
        for c in crcs:
            polys = ", ".join(f"{p:#x}" for p in c.polys) or "none"
            lines.append(f"  {c.kind}: polys [{polys}]")
        consts = function_constants(img, real)
        top = ", ".join(f"{v:#x}" for v, _ in consts.most_common(8))
        lines.append(f"constants: {top or '(none)'}")

        lines.append("")
        lines.append("## Cross-references")
        callers = [self._report_name(c) for c in callers_of(img, func.va)[:30]]
        callees = [self._report_name(c) for c in callees_of(img, func.va)[:30]]
        lines.append("callers: " + (", ".join(callers) or "(none)"))
        lines.append("callees: " + (", ".join(callees) or "(none)"))
        return "\n".join(lines)

    def _report_name(self, va: int) -> str:
        """A display name for an address in a report, or the bare VA."""
        f = self.image.func_at(va) or self.image.nearest_func(va)
        return self._disp(f) if f else f"{va:#x}"

    def action_export_report(self) -> None:
        """Write a plain-text report for the selected function to the CWD."""
        cur = self._current()
        if cur is None:
            self.query_one("#status", Static).update(
                Text(" Select a function to export a report", style=DIM)
            )
            return
        report = self._function_report(cur)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", self._disp(cur))[:60] or "func"
        out = os.path.abspath(f"{safe}_{cur.va:#x}.report.txt")
        try:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as e:
            self.query_one("#status", Static).update(
                Text(f" Could not write report: {e}", style="red")
            )
            return
        self.query_one("#status", Static).update(
            Text(f" Wrote {os.path.basename(out)}", style=GOLD)
        )

    def action_graph_center(self, va: int) -> None:
        """Click handler for a graph node: recenter the call graph on it."""
        self._graph_recenter(va)

    def action_graph_page(self, group: str, delta: int) -> None:
        """Click handler for a group pager: advance the visible window."""
        if group in self._graph_pages:
            self._graph_pages[group] += delta
            self._render_graph()

    def _on_graph_tab(self) -> bool:
        """True when the call-graph tab is active and centered on a function."""
        try:
            active = self.query_one("#tabs", TabbedContent).active
        except Exception:
            return False
        return active == "tab-graph" and self._graph_va is not None

    def action_graph_into(self) -> None:
        """Keyboard: recenter the graph on the centered function's first callee."""
        if not self._on_graph_tab():
            return
        callees = self._graph_callees(self._graph_va)
        if callees:
            self._graph_recenter(callees[0])

    def action_graph_up(self) -> None:
        """Keyboard: recenter the graph on the centered function's first caller."""
        if not self._on_graph_tab():
            return
        callers = self._graph_callers(self._graph_va)
        if callers:
            self._graph_recenter(callers[0])

    def action_graph_more_callees(self) -> None:
        """Keyboard: page the callees group forward (graph tab only)."""
        if self._on_graph_tab():
            self.action_graph_page("callees", 1)

    def action_graph_more_callers(self) -> None:
        """Keyboard: page the callers group forward (graph tab only)."""
        if self._on_graph_tab():
            self.action_graph_page("callers", 1)

    def _on_theme_changed(self, theme) -> None:
        """Persist the theme so the next run starts with the same one."""
        config.put("theme", getattr(theme, "name", str(theme)))

    def get_system_commands(self, screen):
        """Order the command palette like a macOS app menu, with Quit last.

        Sequence: About, Keys, AI provider, Theme, Maximize, Screenshot, Quit.
        Textual's built-ins arrive in its own order, so collect them by title
        and re-emit deterministically, independent of framework changes.
        """
        builtin = {c.title: c for c in super().get_system_commands(screen)}
        quit_cmd = builtin.pop("Quit", None)

        yield SystemCommand("About", "Version, author, and license", self.action_about)
        keys_cmd = builtin.pop("Keys", None)
        if keys_cmd is not None:
            yield keys_cmd
        yield SystemCommand(
            "Copy address",
            "Copy the selected function's address to the clipboard",
            self.action_copy_address,
        )
        yield SystemCommand(
            "Copy current pane",
            "Copy the active detail pane to the clipboard",
            self.action_copy,
        )
        yield SystemCommand(
            "Export function report",
            "Write a plain-text report (disassembly, analysis, xrefs) to the CWD",
            self.action_export_report,
        )
        yield SystemCommand(
            "Disassemble",
            "Show the selected function's disassembly",
            self.action_disasm,
        )
        yield SystemCommand(
            "Cross-references",
            "Show callers and callees of the selection",
            self.action_xrefs,
        )
        yield SystemCommand(
            "Analysis",
            "Run the structure detectors on the selection",
            self.action_analysis,
        )
        yield SystemCommand(
            "Pseudo-C", "Show heuristic pseudo-C for the selection", self.action_pseudo
        )
        yield SystemCommand(
            "Call graph", "Show the call graph around the selection", self.action_graph
        )
        yield SystemCommand(
            "Strings", "Show the image-wide strings list", self.action_strings
        )
        yield SystemCommand(
            "Go to address…", "Jump to a virtual address", self.action_goto
        )
        yield SystemCommand(
            "Data view",
            "Sections, imports, exports, strings, and scan findings",
            self.action_data_view,
        )
        yield SystemCommand(
            "Compare with build…",
            "Diff functions and imports against a second binary",
            self.action_compare,
        )
        yield SystemCommand(
            "Export AI investigation",
            "Save the last assistant investigation (redacted) to the CWD",
            self.action_export_ai,
        )
        yield SystemCommand(
            "AI provider…",
            "Choose the LLM provider and model (Anthropic / OpenAI-compatible)",
            self._open_ai_settings,
        )
        for title in ("Theme", "Maximize", "Screenshot"):
            cmd = builtin.pop(title, None)
            if cmd is not None:
                yield cmd
        # any built-in not named above keeps its place, still ahead of Quit
        yield from builtin.values()
        if quit_cmd is not None:
            yield quit_cmd

    def _open_ai_settings(self) -> None:
        self.push_screen(AISettingsScreen(), self._on_ai_settings)

    def _on_ai_settings(self, saved: bool | None) -> None:
        if saved:
            self.notify("AI provider updated; it applies to your next question.")

    # -- navigation history / toolbar --------------------------------------
    def _set_header_title(self) -> None:
        """Render the title in the header bar: the app name and the file."""
        t = Text()
        t.append(" deglyph ", style=f"bold {ACCENT}")
        if self._path:
            t.append(f"{G['mdash']} ", style=DIM)
            t.append(os.path.basename(self._path), style=GOLD)
        self.query_one("#hdr-title", Static).update(t)

    def _record_nav(self, dest_va: int) -> None:
        """Push a deliberate jump onto the history (browser back/forward model)."""
        if self._nav_lock:
            return
        # drop any forward entries
        seq = self._nav_history[: self._nav_pos + 1]
        # the place being left; keep it so 'back' returns here
        cur = self._current()
        if cur is not None and (not seq or seq[-1] != cur.va):
            seq.append(cur.va)
        if not seq or seq[-1] != dest_va:
            seq.append(dest_va)
        self._nav_history = seq
        self._nav_pos = len(seq) - 1
        self._refresh_toolbar()

    def _nav_to(self, va: int) -> None:
        """Replay a history entry without recording it as a new jump."""
        self._nav_lock = True
        try:
            self._goto_address(va)
        finally:
            self._nav_lock = False
        self._refresh_toolbar()

    def _func_label(self, va: int) -> str:
        f = self.image.func_at(va) or self.image.nearest_func(va)
        return self._disp(f) if f else f"{va:#x}"

    def _refresh_toolbar(self) -> None:
        """Render the clickable back / forward / recent / chats controls."""
        if self.image is None:
            return
        can_back = self._nav_pos > 0
        can_fwd = 0 <= self._nav_pos < len(self._nav_history) - 1
        bar = Text("  ")

        def control(glyph: str, label: str, action: str, enabled: bool) -> None:
            seg = Text(f" {glyph}{label} ", style=GOLD if enabled else DIM)
            if enabled:
                seg.apply_meta({"@click": action})
            bar.append_text(seg)
            bar.append("  ")

        control(G["nav_back"], "", "app.nav_back", can_back)
        control(G["nav_fwd"], "", "app.nav_fwd", can_fwd)
        control(
            f"{G['recent']} ",
            f"recent {G['caret']}",
            "app.show_recent",
            # faded until there is somewhere to go
            bool(self._nav_history),
        )
        control(
            G["chat"],
            f"chats {G['caret']}",
            "app.show_chats",
            # faded until a conversation exists
            bool(self._chat_vas()),
        )
        self.query_one("#hdr-nav", Static).update(bar)

    def _chat_vas(self) -> list[int]:
        """VAs that have a conversation: cached sessions plus the live one."""
        vas = list(self._ai_sessions)
        if (
            self._ai_va is not None
            and self._ai_va not in self._ai_sessions
            and self._assistant.has_context()
            and self._assistant.snapshot()
        ):
            vas.append(self._ai_va)
        return vas

    def action_nav_back(self) -> None:
        if self._nav_pos > 0:
            self._nav_pos -= 1
            self._nav_to(self._nav_history[self._nav_pos])

    def action_nav_fwd(self) -> None:
        if 0 <= self._nav_pos < len(self._nav_history) - 1:
            self._nav_pos += 1
            self._nav_to(self._nav_history[self._nav_pos])

    def action_show_recent(self) -> None:
        """Open a menu of recently visited functions (most recent first)."""
        seen: set[int] = set()
        items: list[tuple[str, int]] = []
        for va in reversed(self._nav_history):
            if va in seen:
                continue
            seen.add(va)
            items.append((self._func_label(va), va))
        if not items:
            self.query_one("#status", Static).update(
                Text(" No navigation history yet.", style=DIM)
            )
            return
        self.push_screen(NavMenu("Recent Functions", items), self._on_recent_pick)

    def action_show_chats(self) -> None:
        """Open a menu of functions that have a saved conversation."""
        items = [(self._func_label(va), va) for va in self._chat_vas()]
        if not items:
            self.query_one("#status", Static).update(
                Text(" No saved chats yet.", style=DIM)
            )
            return
        self.push_screen(NavMenu("Chats", items), self._on_chat_pick)

    def _on_recent_pick(self, va: int | None) -> None:
        if va is not None:
            self._goto_address(va)

    def _on_chat_pick(self, va: int | None) -> None:
        if va is None:
            return
        self._goto_address(va)
        f = self.image.func_at(va) or self.image.nearest_func(va)
        if f is not None:
            self._ai_sync_context(f)
            self.query_one("#tabs", TabbedContent).active = "tab-ai"

    def action_assistant(self) -> None:
        """Switch to the Assistant tab; sync the right context for the selection.

        A Func selection gets its per-function chat; anything else (no
        selection, a String, a Section, or the Binary overview) falls back to
        the binary-wide chat so the user can ask questions without first
        clicking on a function.
        """
        cur = self._current()
        if cur is not None:
            self._ai_sync_context(cur)
        else:
            self._ai_sync_binary_context()
        self.query_one("#tabs", TabbedContent).active = "tab-ai"
        self.query_one("#ai-input", Input).focus()

    def action_goto(self) -> None:
        """Prompt for an address in the search box and disassemble there."""
        inp = self.query_one("#search", Input)
        inp.placeholder = "  Go to address (hex), e.g. 0x180001000…"
        self._prompt = "goto"
        inp.value = ""
        inp.focus()

    def action_goto_addr(self, addr: int) -> None:
        """Click handler for a branch/call target in the disassembly view."""
        self._goto_address(addr)

    def action_rename(self) -> None:
        """Prompt to rename the selected function; persists to the sidecar."""
        cur = self._current()
        if cur is None:
            return
        inp = self.query_one("#search", Input)
        inp.placeholder = f"  New name for {self._disp(cur)}…"
        self._prompt = "rename"
        inp.value = self._anno.names.get(cur.va, "")
        inp.focus()

    def action_comment(self) -> None:
        """Prompt to set a note on the selected function; persists to the sidecar."""
        cur = self._current()
        if cur is None:
            return
        inp = self.query_one("#search", Input)
        inp.placeholder = f"  Note for {self._disp(cur)}…"
        self._prompt = "comment"
        inp.value = self._anno.comments.get(cur.va, "")
        inp.focus()

    def action_bookmark(self) -> None:
        """Toggle a bookmark on the selected function; persists to the sidecar."""
        cur = self._current()
        if cur is None:
            return
        if cur.va in self._anno.bookmarks:
            self._anno.bookmarks.discard(cur.va)
        else:
            self._anno.bookmarks.add(cur.va)
        self._anno.save()
        keep = cur.va
        self._apply_filter()
        self._select_func_node(keep)

    def action_open(self) -> None:
        cur = self._current()
        if cur:
            self.action_disasm()

    def action_about(self) -> None:
        self.push_screen(AboutDialog())

    def _collect_chats(self) -> dict[int, list]:
        """Serialize every per-function conversation (cached + the live one)."""
        chats: dict[int, list] = {}
        for va, sess in self._ai_sessions.items():
            msgs = sess.get("messages") or []
            if msgs:
                chats[va] = _serialize_messages(msgs)
        if self._ai_va is not None and self._assistant.has_context():
            live = self._assistant.snapshot()
            if live:
                chats[self._ai_va] = _serialize_messages(live)
        return chats

    def _persist_chats(self) -> None:
        """Save chats immediately after a reply, so a conversation is crash-safe."""
        self._anno.chats = self._collect_chats()
        self._anno.save()
        # the 'chats' control may have just become active
        self._refresh_toolbar()

    def _capture_view_state(self) -> dict:
        """The current session UI state: filter, active tab, selected function VA.

        Stored in the sidecar so reopening a binary lands on the same search,
        tab, and function the user left. Only a function selection is recorded
        (the binary / section / string leaves rebuild deterministically).
        """
        view: dict = {}
        flt = self._filter.strip()
        if flt:
            view["filter"] = flt
        try:
            active = self.query_one("#tabs", TabbedContent).active
        except Exception:
            active = ""
        if active:
            view["tab"] = active
        cur = self._current()
        if cur is not None:
            view["selected_va"] = cur.va
        return view

    def _restore_view_state(self) -> None:
        """Reapply a saved session view (filter, tab, selection) after a load."""
        view = self._anno.view or {}
        if not view:
            return
        flt = view.get("filter")
        if isinstance(flt, str) and flt:
            self._filter = flt
            try:
                box = self.query_one("#search", Input)
                self._input_locked = True
                box.value = flt
                self._input_locked = False
            except Exception:
                pass
            self._apply_filter()
        va = view.get("selected_va")
        if isinstance(va, int):
            self._select_func_node(va)
        # The tab is set last: selecting a function re-runs the per-kind tab
        # gate, which would otherwise override a restored tab. Reapply it both
        # now and after the next refresh so it wins over the selection handler.
        tab = view.get("tab")
        if isinstance(tab, str) and tab:
            self._apply_restored_tab(tab)
            self.call_after_refresh(self._apply_restored_tab, tab)

    def _apply_restored_tab(self, tab: str) -> None:
        """Activate a restored tab if it is currently a valid choice."""
        try:
            self.query_one("#tabs", TabbedContent).active = tab
        except Exception:
            pass

    def _autosave(self) -> None:
        """Persist the annotation context on the way out (only if it has content)."""
        a = self._anno
        a.chats = self._collect_chats()
        a.view = self._capture_view_state()
        if not a.is_empty():
            a.save()

    async def action_quit(self) -> None:
        self._autosave()
        await super().action_quit()


def run(
    path: str | None = None,
    *,
    fmt: str | None = None,
    arch: Arch | None = None,
    slice_index: int | None = None,
    discover: bool = True,
    welcome: bool = True,
) -> None:
    DeglyphApp(
        path,
        fmt=fmt,
        arch=arch,
        slice_index=slice_index,
        discover=discover,
        welcome=welcome,
    ).run()


def _signed_disp(signed: int) -> str:
    """Signed-displacement suffix for a memory operand (`+0x4` / `-0x8` / '')."""
    if signed == 0:
        return ""
    return f"+{signed:#x}" if signed > 0 else f"-{-signed:#x}"


def _conf_text(ev) -> str:
    """A short confidence/caveat suffix for a detector hit, or '' for plain high."""
    if ev.confidence == "high" and not ev.caveats:
        return ""
    note = f": {ev.caveats[0]}" if ev.caveats else ""
    return f"  ({ev.confidence}{note})"


def _signed_disp(signed: int) -> str:
    """Signed-displacement suffix for a memory operand (`+0x4` / `-0x8` / '')."""
    if signed == 0:
        return ""
    return f"+{signed:#x}" if signed > 0 else f"-{-signed:#x}"


def _conf_text(ev) -> str:
    """A short confidence/caveat suffix for a detector hit, or '' for plain high."""
    if ev.confidence == "high" and not ev.caveats:
        return ""
    note = f": {ev.caveats[0]}" if ev.caveats else ""
    return f"  ({ev.confidence}{note})"


def _poly_hint(poly: int) -> str | None:
    """Name well-known CRC polynomials (incl. the >>1 pre-shift encodings)."""
    table = {
        0x8408: "CRC-16/X.25·MCRF4XX (reflected 0x1021)",
        0x10810: "CRC-16 reflected, pre-shift form of 0x8408",
        0x1021: "CRC-16/CCITT (0x1021)",
        0xA001: "CRC-16/MODBUS·ARC (reflected 0x8005)",
        0x8005: "CRC-16/IBM (0x8005)",
        0xEDB88320: "CRC-32 (reflected 0x04C11DB7)",
        0x04C11DB7: "CRC-32 (0x04C11DB7)",
    }
    return table.get(poly)
