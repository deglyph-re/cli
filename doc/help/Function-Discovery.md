# Function Discovery

A release executable often exports nothing and is stripped of symbols. Loaded as
is, it would show only its entry point and a handful of import thunks. Function
discovery fills the gap by recovering unexported functions so the tree, cross
references, and the call graph are populated.

## How it works

`deglyph` scans the executable sections once for direct `call` instructions and
collects their targets. Each distinct target that is not already a known function
becomes a new function named `sub_<va>`, with the kind `sub`. The result is the
set of functions that are actually called somewhere in the binary.

This is what makes clicks land, cross-references resolve, and the call graph fill
in on binaries like a stripped system DLL.

## Go binaries get real names

A Go program keeps a function table (the pclntab) even when it is stripped, and
that table names every function it contains. `deglyph` reads it first, so a Go
binary shows real names like `main.main` and `net/http.(*Server).Serve` instead
of `sub_*`. The call-target scan then only adds whatever the table did not name.
Go builds from version 1.2 through the current layout are recognized; a table
that fails validation is ignored rather than trusted.

## When it runs

Discovery runs automatically after load, in both the interface and the headless
modes. In the interface it runs off the UI thread because decoding every byte of
a large `.text` section can take tens of seconds; the function tree shows a
spinner while it works and fills in when it completes. The scan only reads the
image; nothing is executed.

To skip discovery, pass `--no-discover`:

```bash
deglyph ./app.exe --no-discover
```

## Limits

Discovery is a heuristic and finds functions reached by a direct `call`. It
misses:

- functions reached only through an indirect call (a call through a register or
  a vtable slot),
- tail-call-only functions entered by `jmp` rather than `call`,
- functions reached only through a jump table whose base is computed in a
  register (a simple memory-operand table has its arms resolved; a
  register-computed one does not).

A function that is never the target of a direct call will not appear as a
`sub_*`. You can still navigate to it with goto if you know its address, and
analysis works once you are there.

## See also

- [The Function Navigator](Function-Navigator.md): where `sub_*` functions appear.
- [Loading Binaries](Loading-Binaries.md): what happens at load.
- [How deglyph Works](How-It-Works.md): the pipeline around discovery.
