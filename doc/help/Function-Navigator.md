# The Function Navigator

The left pane is a tree of every function `deglyph` found in the binary, grouped so
a large symbol table stays navigable. It is the primary way to move around a
binary.

## Two levels of grouping

Functions are arranged first by **kind**, then by a **name prefix**:

- **Kind** is one of Exports, Entry, Symbols, Subs, Imports, or Other, shown in
  that order. The kind reflects where the function came from: an export table
  entry, the image entry point, a symbol, a discovered `sub_*`, or an import.
- **Name prefix** groups leaves within a kind by a shared prefix: a C++
  `Class::` qualifier, a leading `_` or `.` token, or, for imports, the library
  the symbol comes from.

A group folder shows the count of members. A group with a single member collapses
to a bare leaf, so you never expand a folder of one. Discovered `sub_*` functions
list flat under their kind.

## Filtering

Two filters narrow the tree:

- Press <kbd>/</kbd> to focus the filter box. Matching is **subsequence**:
  typing `frd` matches `frame_read` and `FrameDecoder`. Filtering rebuilds the
  tree against the displayed names, so it tracks any renames you have made.
- Press <kbd>t</kbd> to cycle the kind filter (all, code, export, sub, import).

## Selection and rendering

Highlighting a leaf renders that function in the active detail tab. Highlighting
a group folder renders nothing; folders are organizational only.

Function identity rides on the row, not the address: two exports can legitimately
share one virtual address (for example an MSVC constructor and its `operator=`,
or aliased commands). `deglyph` handles this correctly when you select, rename, or
bookmark a function.

## Renames flow everywhere

When you rename a function (<kbd>n</kbd>), the new name appears in the tree, in
the disassembly labels, and in cross-references. Renames, notes, and bookmarks
persist to a sidecar file keyed to the binary, so they survive across sessions.

## Stripped binaries

A release executable often exports nothing and is symbol-stripped. `deglyph` still
populates the tree by discovering functions from direct call targets in the
executable sections. While that scan runs, the tree shows a spinner and fills in
when discovery completes. See [Function Discovery](Function-Discovery.md).

## See also

- [Disassembly View](Disassembly.md): what a selected function shows.
- [Function Discovery](Function-Discovery.md): the `sub_*` recovery pass.
- [Keyboard Shortcuts](Keyboard-Shortcuts.md): filter, rename, and jump keys.
