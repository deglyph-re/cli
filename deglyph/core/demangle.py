# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Symbol demangling for C++ and Rust.

`demangle(name)` returns a readable form of a mangled linker symbol, or None
when the name is not mangled or cannot be decoded with certainty. Three schemes
are handled:

  * MSVC (`?...`) and Itanium C++ (`_Z...`) via the optional `cxxfilt` package.
  * Rust legacy mangling (Itanium `_ZN...E` with a trailing `17h<16-hex>` hash):
    demangled by cxxfilt, then the compiler-added hash suffix is stripped.
  * Rust v0 (`_R...`), which cxxfilt does not handle: a self-contained decoder
    that covers paths, the builtin types, generic arguments, references, tuples,
    and backreferences. Any production it does not recognize aborts the decode
    and returns None, so a partial or wrong name is never emitted (the caller
    then shows the raw symbol). It never guesses.

Public: `demangle`.
"""

from __future__ import annotations

import re

# A rustc-appended instance hash on a legacy-mangled symbol: `::h` followed by
# 16 hex digits, at the very end. Stripped for readability.
_LEGACY_HASH = re.compile(r"::h[0-9a-f]{16}$")

# v0 builtin types, keyed by their single-letter tag.
_BASIC_TYPES = {
    "a": "i8",
    "b": "bool",
    "c": "char",
    "d": "f64",
    "e": "str",
    "f": "f32",
    "h": "u8",
    "i": "isize",
    "j": "usize",
    "l": "i32",
    "m": "u32",
    "n": "i128",
    "o": "u128",
    "s": "i16",
    "t": "u16",
    "u": "()",
    "v": "...",
    "x": "i64",
    "y": "u64",
    "z": "!",
    "p": "_",
}

_BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def demangle(name: str) -> str | None:
    """Readable form of a mangled symbol, or None if not mangled / undecodable."""
    if not name:
        return None
    if name.startswith("_R"):
        return _demangle_rust_v0(name)
    if name.startswith("?") or name.startswith("_Z") or name.startswith("__Z"):
        out = _cxxfilt(name)
        if out is None or out == name:
            return None
        # A legacy-mangled Rust symbol demangles as C++ but keeps the hash tail.
        return _LEGACY_HASH.sub("", out)
    return None


def _cxxfilt(name: str) -> str | None:
    try:
        import cxxfilt

        return cxxfilt.demangle(name)
    except Exception:
        return None


class _Abort(Exception):
    """Raised on any v0 production the decoder does not handle with certainty."""


class _V0:
    """A single-pass Rust v0 decoder with backreference support.

    Positions are byte offsets into the whole mangled string (including the
    `_R`), matching how v0 encodes backreferences. A recursion depth cap and a
    strictly-backward backref check bound the work on a hostile input.
    """

    __slots__ = ("s", "pos", "depth")

    def __init__(self, s: str, pos: int) -> None:
        self.s = s
        self.pos = pos
        self.depth = 0

    def _peek(self) -> str:
        if self.pos >= len(self.s):
            raise _Abort
        return self.s[self.pos]

    def _take(self) -> str:
        c = self._peek()
        self.pos += 1
        return c

    def _base62(self) -> int:
        # "_" alone is 0; otherwise the digits form n and the value is n + 1.
        if self._peek() == "_":
            self.pos += 1
            return 0
        val = 0
        while self._peek() != "_":
            d = _BASE62.find(self._take())
            if d < 0:
                raise _Abort
            val = val * 62 + d
        self.pos += 1
        return val + 1

    def _decimal(self) -> int:
        start = self.pos
        while self.pos < len(self.s) and self.s[self.pos].isdigit():
            self.pos += 1
        if self.pos == start:
            raise _Abort
        return int(self.s[start : self.pos])

    def _backref_target(self) -> int:
        # "B" <base62>: an absolute offset that must point strictly backward.
        target = self._base62()
        if target >= self.pos:
            raise _Abort
        return target

    def _at(self, pos: int, kind: str) -> str:
        sub = _V0(self.s, pos)
        sub.depth = self.depth + 1
        if kind == "path":
            return sub.path()
        return sub.type()

    def _identifier(self) -> str:
        # optional disambiguator (dropped in output), then a length-prefixed run
        if self._peek() == "s":
            self.pos += 1
            self._base62()
        punycode = False
        if self._peek() == "u":
            self.pos += 1
            punycode = True
        length = self._decimal()
        if self._peek() == "_":
            self.pos += 1
        if self.pos + length > len(self.s):
            raise _Abort
        ident = self.s[self.pos : self.pos + length]
        self.pos += length
        if punycode:
            # Punycode idents are rare and non-trivial to decode; refuse rather
            # than emit an approximation.
            raise _Abort
        return ident

    def path(self) -> str:
        self.depth += 1
        if self.depth > 64:
            raise _Abort
        tag = self._take()
        if tag == "C":
            return self._identifier()
        if tag == "N":
            ns = self._take()
            parent = self.path()
            ident = self._identifier()
            if ns.isupper():
                # A compiler-internal namespace (closure, shim, ...): tag it so
                # the output does not read like a real function name.
                return f"{parent}::{{{ident or ns}}}"
            return f"{parent}::{ident}"
        if tag == "I":
            base = self.path()
            args = self._generic_args()
            return f"{base}::<{', '.join(args)}>" if args else base
        if tag in ("M", "X"):
            # inherent / trait impl: <type> or <type as Trait>
            self._disambiguator_impl()
            ty = self.type()
            if tag == "X":
                tr = self.path()
                return f"<{ty} as {tr}>"
            return f"<{ty}>"
        if tag == "Y":
            ty = self.type()
            tr = self.path()
            return f"<{ty} as {tr}>"
        if tag == "B":
            return self._at(self._backref_target(), "path")
        raise _Abort

    def _disambiguator_impl(self) -> None:
        # M/X carry <impl-path> = optional disambiguator then a skipped path.
        if self._peek() == "s":
            self.pos += 1
            self._base62()

    def _generic_args(self) -> list[str]:
        args: list[str] = []
        while self._peek() != "E":
            args.append(self._generic_arg())
        self.pos += 1
        return args

    def _generic_arg(self) -> str:
        c = self._peek()
        if c == "L":
            self.pos += 1
            n = self._base62()
            return f"'_{n}" if n else "'_"
        if c == "K":
            self.pos += 1
            return self._const()
        return self.type()

    def _const(self) -> str:
        c = self._peek()
        if c == "p":
            self.pos += 1
            return "_"
        if c == "B":
            self.pos += 1
            return self._at(self._backref_target(), "type")
        # A typed const value (e.g. an integer literal): decode the type, then
        # its hex-encoded data. Only the common integer form is handled.
        self.type()
        neg = False
        if self._peek() == "n":
            self.pos += 1
            neg = True
        start = self.pos
        while self.pos < len(self.s) and self.s[self.pos] in "0123456789abcdef":
            self.pos += 1
        if self.pos == start or self._peek() != "_":
            raise _Abort
        digits = self.s[start : self.pos]
        self.pos += 1
        try:
            val = int(digits, 16)
        except ValueError as exc:
            raise _Abort from exc
        return f"-{val}" if neg else str(val)

    def type(self) -> str:
        self.depth += 1
        if self.depth > 64:
            raise _Abort
        c = self._peek()
        # A builtin tag is a lowercase letter; a path or composite-type tag is
        # uppercase, so the two never collide.
        if c in _BASIC_TYPES:
            self.pos += 1
            return _BASIC_TYPES[c]
        if c in ("C", "N", "I", "M", "X", "Y"):
            return self.path()
        if c == "A":
            self.pos += 1
            inner = self.type()
            n = self._const()
            return f"[{inner}; {n}]"
        if c == "S":
            self.pos += 1
            return f"[{self.type()}]"
        if c == "T":
            self.pos += 1
            parts: list[str] = []
            while self._peek() != "E":
                parts.append(self.type())
            self.pos += 1
            if len(parts) == 1:
                return f"({parts[0]},)"
            return f"({', '.join(parts)})"
        if c in ("R", "Q"):
            self.pos += 1
            mut = "mut " if c == "Q" else ""
            if self._peek() == "L":
                self.pos += 1
                self._base62()
            return f"&{mut}{self.type()}"
        if c == "P":
            self.pos += 1
            return f"*const {self.type()}"
        if c == "O":
            self.pos += 1
            return f"*mut {self.type()}"
        if c == "B":
            self.pos += 1
            return self._at(self._backref_target(), "type")
        raise _Abort


def _demangle_rust_v0(name: str) -> str | None:
    """Decode a Rust v0 (`_R`) symbol, or None if any part is unsupported."""
    # Strip a vendor suffix (`.` onwards) the linker may append (e.g. `.llvm.*`).
    core = name.split(".", 1)[0]
    dec = _V0(core, 2)
    # An optional leading decimal is the encoding version; only absent (v0) is
    # defined today, so its presence means a scheme this decoder predates.
    if dec.pos < len(core) and core[dec.pos].isdigit():
        return None
    try:
        out = dec.path()
    except _Abort:
        return None
    except Exception:
        return None
    if not out:
        return None
    return out
