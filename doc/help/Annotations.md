# Renames, Notes & Bookmarks

As you work through a binary you build understanding: this `sub_*` is the frame
encoder, that constant is the protocol version, this function is worth returning
to. `deglyph` records that understanding as renames, notes, and bookmarks that
persist across sessions.

## The three annotations

- **Rename** (<kbd>n</kbd>) gives a function a meaningful name. The new name
  appears everywhere the function is shown: the tree, the disassembly labels, and
  cross-references.
- **Note** (<kbd>;</kbd>) attaches free text to a function, for an observation
  that is not a name.
- **Bookmark** (<kbd>b</kbd>) flags a function so you can find it again quickly.

Renames flow through one display resolver, so a renamed function reads
consistently in every view, including as a call target in another function's
disassembly.

## Where they are stored

Annotations are an overlay on top of the binary, kept in a sidecar JSON file
keyed to the binary's path. The default location is under your home directory
(`~/.deglyph/annotations/`), and it honors `DEGLYPH_STORE_DIR` if you set it. The
binary itself is never modified.

Edits are written immediately, so a crash does not lose your work. Loading and
saving are best-effort: a malformed sidecar degrades to an empty set rather than
failing to open the binary.

## AI chats persist too

Each function's [AI assistant](AI-Assistant.md) conversation is saved into the
same sidecar, so reopening a binary restores both your annotations and the
questions you asked about it.

## Restoring on open

When you open a binary that has a saved sidecar, `deglyph` offers to load it. A
session opened from the welcome screen's recent list restores its annotations and
chats directly. Discarding leaves you with an empty context, and quitting after a
discard does not overwrite the saved file.

## See also

- [The Function Navigator](Function-Navigator.md): where renames and bookmarks appear.
- [The AI Assistant](AI-Assistant.md): conversations saved alongside annotations.
- [Configuration & Environment](Configuration.md): `DEGLYPH_STORE_DIR` and paths.
