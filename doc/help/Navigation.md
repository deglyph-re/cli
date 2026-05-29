# Navigation & History

Moving through a binary in `deglyph` works like a web browser: deliberate jumps are
recorded on a history stack, and you can step back and forward through where you
have been. Scrolling the cursor does not record a jump, so the history stays a
record of intent rather than of every keypress.

## Jumping to an address

Two actions move you to a specific place:

- **Goto** an address. The disassembly recenters on it; if the address falls
  inside a known function, that function is selected in the tree.
- **Follow** (<kbd>f</kbd>) resolves the selected exported wrapper to the
  function that does the real work and jumps there. See the wrapper chain on the
  [Cross-References](Cross-References.md) tab.

Clicking a branch or call target in the [disassembly](Disassembly.md) is also a
jump, and is recorded like any other.

## Back and forward

Press <kbd>[</kbd> to go back and <kbd>]</kbd> to go forward through the jump
history. A deliberate jump captures the place you left, so back returns you
there. Replaying history does not itself record a new entry, so back and forward
stay symmetric.

## The header controls

The header bar carries the navigation controls:

- **Back / forward** arrows over the jump stack.
- A **recent** picker listing places you have been, faded until there is
  history.
- A **chats** picker listing functions that have a saved
  [AI conversation](AI-Assistant.md), faded until at least one exists.

## How selection stays correct

The function tree is rebuilt whenever the displayed names change (a rename, a
bookmark, discovery completing). Every jump entry point resolves to a single
selection primitive that expands the ancestors of the target, selects it, and
scrolls it into view, so a jump lands precisely even after a rebuild. Function
identity rides on the tree row, not the address, so a jump is unambiguous even
when two functions share an address. See
[The Function Navigator](Function-Navigator.md).

## See also

- [Disassembly View](Disassembly.md): clickable targets and goto.
- [Cross-References](Cross-References.md): the wrapper chain that follow uses.
- [Keyboard Shortcuts](Keyboard-Shortcuts.md): the navigation keys.
