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
| <kbd>t</kbd> | Data: the whole-file content map and referenced data |

## Navigation

| Key | Action |
| --- | --- |
| <kbd>/</kbd> | Focus the filter (subsequence match) |
| <kbd>esc</kbd> | Clear the filter |
| <kbd>j</kbd> <kbd>k</kbd> / arrows | Move in the function tree |
| <kbd>f</kbd> | Follow the selection to its implementation |
| <kbd>g</kbd> | Go to an address |
| <kbd>[</kbd> <kbd>]</kbd> | Jump history back and forward |

Functions are grouped into expandable folders by kind and name prefix; the filter
is a plain subsequence match, with no separate kind toggle.

## Annotations and the assistant

| Key | Action |
| --- | --- |
| <kbd>n</kbd> | Rename the selected function (persists) |
| <kbd>;</kbd> | Add a note to the selection (persists) |
| <kbd>b</kbd> | Bookmark the selection (persists) |
| <kbd>i</kbd> | Ask the [AI assistant](AI-Assistant.md) about the selection |
| <kbd>y</kbd> | Copy the active pane's text |
| <kbd>v</kbd> | Compare the build against a second binary |
| <kbd>e</kbd> | Export an [analysis report](Output-Formats.md) for the binary |

Renames, notes, bookmarks, and AI chats persist to a sidecar file keyed to the
binary, so they are restored when you reopen it.

## The command palette

Press <kbd>ctrl-p</kbd> (or use the header menu glyph) to open the command
palette: About, the key map, the AI provider settings, the theme switcher,
screenshot, and quit. Its entries are searchable by fuzzy match. <kbd>f1</kbd> or
<kbd>?</kbd> opens About directly; <kbd>ctrl-c</kbd> / <kbd>ctrl-q</kbd> quits.

## See also

- [The Interface](The-Interface.md): the panes the keys act on.
- [Disassembly View](Disassembly.md): goto, follow, and jump history.
- [Command-Line Reference](CLI-Reference.md): the `--ascii` and `--nerd` glyph flags.
