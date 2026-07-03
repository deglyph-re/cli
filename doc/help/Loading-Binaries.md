# Loading Binaries

`deglyph` reads three container formats through the LIEF parsing library: PE
(Windows `.exe` / `.dll` / `.sys`), ELF (Linux / BSD executables and shared
objects), and Mach-O (macOS executables, dylibs, and fat binaries). It loads the
container, applies the image base, and presents one uniform model regardless of
format.

## Supported formats and architectures

| Container | Typical extensions | Architectures |
| --- | --- | --- |
| PE | `.exe` `.dll` `.sys` | x86, x86-64 |
| ELF | (none) `.so` `.elf` | x86, x86-64, ARM, AArch64, RISC-V (RV32 / RV64) |
| Mach-O | (none) `.dylib` | x86-64, ARM, AArch64 |

The disassembler is driven by the detected architecture. A 32-bit image decoded
in 64-bit mode produces plausible-looking garbage, so the architecture must be
correct. The pattern detectors run on x86, x86-64, AArch64, and 32-bit ARM; on
RISC-V the disassembly renders but the detectors are off. Managed formats (.NET,
JVM bytecode) are out of scope: they hold intermediate language, not native code.

## Opening a file

From the command line, pass a path:

```bash
deglyph ./libexample.so
```

A bare name is resolved against your `PATH`, and on Windows against System32, so
`deglyph notepad.exe` works without a full path.

## Forcing format or architecture

Detection is automatic, but you can override it when a file is mislabeled or
`deglyph` cannot infer the architecture:

```bash
deglyph ./driver.dll --arch x86      # decode as 32-bit
deglyph ./blob --fmt ELF --arch arm64
```

Accepted architecture names include `x86` / `x32`, `x64` / `amd64`, `arm`,
`arm64` / `aarch64`, and `riscv64` / `rv64` / `riscv32` / `rv32`. Accepted
formats are `PE`, `ELF`, and `MachO`.

## The address model

`deglyph` works entirely in **virtual addresses** with the image base already
applied. Every address you see in the disassembly, the goto box, and the
analysis output is a VA. PE export addresses, which LIEF reports as relative
virtual addresses, have the base added at load time.

## What happens at load

1. The container is parsed and its sections, base, and entry point are read.
2. Functions are listed from the export and symbol tables; C++ and Rust symbols
   are demangled to readable names.
3. For stripped binaries, a Go program's functions are named from its pclntab,
   then executable sections are scanned for call targets to recover the rest.
   See [Function Discovery](Function-Discovery.md).
4. The interface opens on the binary overview, with the function tree populated.

Section bytes are read lazily from disk and cached, so loading a large binary is
fast and memory stays bounded.

## See also

- [Function Discovery](Function-Discovery.md): recovering functions in stripped builds.
- [How deglyph Works](How-It-Works.md): the full pipeline.
- [Command-Line Reference](CLI-Reference.md): `--fmt`, `--arch`, and friends.
