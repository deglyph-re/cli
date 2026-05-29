# Keyboard Shortcuts

Each detail view and each common action has a single-key binding. The bindings
work whenever the function navigator or a detail pane has focus; the filter box
captures typing while it is focused.

## Detail views

| Key | View |
| --- | --- |
| <kbd>d</kbd> | [Disassembly](Disassembly.md), with clickable branch and call targets |
| <kbd>x</kbd> | Cross-references: wrapper chain, caller and callee trees |
| <kbd>a</kbd> | [Analysis](Pattern-Detectors.md): immediate stores, call args, CRC loops |
| <kbd>p</kbd> | Pseudo-C, a heuristic C-like view |
| <kbd>c</kbd> | Call graph, a clickable node navigator |
| <kbd>s</kbd> | Strings: browse every string in the binary |

## Navigation

| Key | Action |
| --- | --- |
| <kbd>/</kbd> | Focus the filter (subsequence match) |
| <kbd>t</kbd> | Cycle the kind filter (all, code, export, sub, import) |
| <kbd>f</kbd> | Follow the selection to its implementation |
| <kbd>[</kbd> <kbd>]</kbd> | Jump history back and forward |

## Annotations and the assistant

| Key | Action |
| --- | --- |
| <kbd>n</kbd> | Rename the selected function (persists) |
| <kbd>;</kbd> | Add a note to the selection (persists) |
| <kbd>b</kbd> | Bookmark the selection (persists) |
| <kbd>i</kbd> | Ask the [AI assistant](AI-Assistant.md) about the selection |

Renames, notes, bookmarks, and AI chats persist to a sidecar file keyed to the
binary, so they are restored when you reopen it.

## The command palette

The command palette (opened from the header menu glyph) holds the actions
without a dedicated key: About, the key map, the AI provider settings, the theme
switcher, screenshot, and quit. Its entries are searchable by fuzzy match.

## See also

- [The Interface](The-Interface.md): the panes the keys act on.
- [Disassembly View](Disassembly.md): goto, follow, and jump history.
- [Command-Line Reference](CLI-Reference.md): the `--ascii` and `--nerd` glyph flags.
