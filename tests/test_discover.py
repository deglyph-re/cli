# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Function discovery from call targets (for stripped binaries)."""

from __future__ import annotations

from deglyph.core.image import Func
from deglyph.re import discover_functions

# call 0x100a ; ret ; nop*4 ; ret   -- the call target 0x100a is unnamed code.
CALLER = bytes.fromhex("e8 05 00 00 00  c3  90 90 90 90  c3")


def test_discovers_call_target(code_image):
    img = code_image(CALLER)
    added = discover_functions(img)
    assert added >= 1
    f = img.func_at(0x100A)
    assert f is not None and f.kind == "sub" and f.name == "sub_100a"


def test_discovery_is_idempotent(code_image):
    img = code_image(CALLER)
    assert discover_functions(img) >= 1
    # second pass is a no-op
    assert discover_functions(img) == 0


def test_existing_function_is_not_renamed(code_image):
    img = code_image(CALLER)
    img.funcs.append(Func(name="real_target", va=0x100A, kind="export"))
    img.reindex()
    discover_functions(img)
    # The call target already had a name; discovery must not add a sub_ alias.
    assert img.func_at(0x100A).name == "real_target"


def test_no_calls_discovers_nothing(code_image):
    # nop ; nop ; ret
    img = code_image(bytes.fromhex("90 90 c3"))
    assert discover_functions(img) == 0
