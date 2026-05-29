# Cross-References & Call Graph

The Xrefs tab (<kbd>x</kbd>) answers two questions about the selected function:
what calls it, and what it calls. The Graph tab (<kbd>c</kbd>) shows the same
relationships as a clickable node navigator. Together they let you trace a path
through a binary without reading every function in full.

## The wrapper chain

An exported symbol is often a thin wrapper: it marshals arguments and tail-calls,
or jumps to, the function that does the real work. The Xrefs tab shows the
**wrapper chain**, resolving an export to its implementation.

The chain follows tail-call thunks and the last in-image call of an
argument-marshalling wrapper, but it **stops at the first function with a body**:
one that writes an immediate into memory, or loads an immediate into a register
before a call. Without that stop, the chain would descend past the
implementation into shared checksum and transport helpers, and the function you
were looking for would be lost. The Follow action (<kbd>f</kbd>) jumps to the end
of this chain.

## Callers and callees

- **Callers** are every function that calls the selected one, computed from a
  cached whole-image cross-reference index.
- **Callees** are the functions the selected one calls.

Each entry is a jump: selecting it navigates there and records the jump in your
[history](Navigation.md).

## The call graph

The Graph tab centers on the current function, with callers above and callees
below. It shows up to three of each around the center (seven nodes total); a
group with more shows a pager node you can click to page through. Clicking any
node recenters the graph on it without moving the tree cursor, so you can explore
the neighborhood freely.

The underlying call tree is cycle-safe and bounded by depth, child count, and an
overall budget. A branch that is stopped by a bound is marked **elided** rather
than dropped, so you can see that more exists beyond what is shown.

## Limits

Cross-references are built from direct calls in the disassembly. A call made
indirectly through a register or a vtable slot does not appear as an edge, the
same blind spot that affects [function discovery](Function-Discovery.md). Treat
the graph as the set of statically resolvable calls, not a proof of every
possible control flow.

## See also

- [Navigation & History](Navigation.md): following and jumping between functions.
- [Function Discovery](Function-Discovery.md): the direct-call assumption.
- [Disassembly View](Disassembly.md): confirm an edge in the code.
