# Project Files

Your renames, notes, bookmarks, and saved view live in a per-binary
[sidecar](Annotations.md) keyed to the binary's absolute path, so they do not
follow the file to another machine. `deglyph project` moves that work in a
path-independent file you reattach on the other end.

```bash
deglyph project export ./app.exe -f app.work.json   # write a portable file
deglyph project import ./app.exe -f app.work.json    # reattach it to a binary
```

## What travels

The portable file carries only the edits, not the binary or its path:

- function renames,
- notes,
- bookmarks,
- the saved view (filter, active tab, selected address).

AI chats are deliberately left out: they can be large and may carry private
conversation. To move chats too, copy the sidecar from
`~/.deglyph/annotations/` directly.

## Reattaching

`import` binds the edits to whatever binary you point it at by address, so the
target should be the same build (or close to it) the edits were made against.
A malformed or hand-edited entry, a non-hex address or a wrong-typed field, is
dropped rather than raised, so a partial file still imports cleanly. The command
prints how many renames, notes, and bookmarks it attached.

## See also

- [Renames, Notes & Bookmarks](Annotations.md): the per-binary sidecar these come from.
- [Command-Line Reference](CLI-Reference.md): the `project` flags.
- [Configuration & Environment](Configuration.md): where the sidecar lives.
