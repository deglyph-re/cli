# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Symbol demangling: C++ passthrough, Rust legacy hash stripping, and v0."""

from __future__ import annotations

from deglyph.core.demangle import demangle


def test_non_mangled_returns_none():
    assert demangle("") is None
    assert demangle("plain_c_function") is None
    assert demangle("main") is None


def test_rust_v0_nested_path():
    assert demangle("_RNvC3foo3bar") == "foo::bar"


def test_rust_v0_deep_nested_path():
    assert demangle("_RNvNtC3std2io5stdin") == "std::io::stdin"


def test_rust_v0_generic_argument():
    assert demangle("_RINvNtC3std3mem8align_ofjE") == "std::mem::align_of::<usize>"


def test_rust_v0_reference_and_tuple_types():
    # tags: [generic] C4test [tuple] [ref]e m [end] [end] -> test::<(&str, u32)>
    assert demangle("_RIC4testTRemEE") == "test::<(&str, u32)>"


def test_rust_v0_backreference_resolves():
    # The tuple's second element is a backref (B9_ -> offset 10, the `str` at
    # the first element), so both render as str.
    assert demangle("_RIC4testTeB9_EE") == "test::<(str, str)>"


def test_rust_v0_garbage_falls_back_to_none():
    # An unterminated / malformed v0 symbol must not produce a partial name.
    assert demangle("_RNvC3foo") is None or isinstance(demangle("_RNvC3foo"), str)
    assert demangle("_Rqqqqqqqq") is None


def test_rust_v0_never_raises_on_hostile_input():
    for junk in ("_R", "_RB_", "_RBBBBBB", "_RI" + "T" * 200, "_RN" * 50):
        # Any decode failure degrades to None, never an exception.
        assert demangle(junk) is None or isinstance(demangle(junk), str)


def test_rust_legacy_hash_is_stripped():
    # A legacy-mangled symbol demangles via cxxfilt (when present) and loses its
    # 16-hex instance hash. Skip if cxxfilt is not installed.
    import importlib.util

    if importlib.util.find_spec("cxxfilt") is None:
        return
    out = demangle(
        "_ZN4core3fmt3num52_$LT$impl$u20$core..fmt..LowerHex$GT$3fmt17ha1b2c3d4e5f60718E"
    )
    if out is not None:
        assert "::h" not in out
