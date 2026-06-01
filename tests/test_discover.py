# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Function discovery from call targets (for stripped binaries)."""

from __future__ import annotations

from deglyph import cache
from deglyph.core.image import Func
from deglyph.re import discover_functions
from deglyph.re.discover import scan_targets

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


def test_call_target_is_confirmed_with_evidence(code_image):
    img = code_image(CALLER)
    discover_functions(img)
    f = img.func_at(0x100A)
    assert f.confidence == "confirmed"
    assert f.evidence and "call" in f.evidence[0]


# At va 0x1000:
#   call 0x100b ; jmp 0x101a ; ret ; ret(@100b) ; pad ; ret(@101a)
# The call names 0x100b (confirmed); the tail jmp leaves that function and names
# 0x101a (candidate).
def _tail_jmp_code() -> bytes:
    code = bytearray(b"\x90" * 0x30)
    code[0x00:0x05] = bytes.fromhex("e8 06 00 00 00")
    code[0x05:0x0A] = bytes.fromhex("e9 10 00 00 00")
    code[0x0A] = 0xC3
    code[0x0B] = 0xC3
    code[0x1A] = 0xC3
    return bytes(code)


def test_tail_jmp_target_is_a_candidate(code_image):
    img = code_image(_tail_jmp_code())
    discover_functions(img)
    called = img.func_at(0x100B)
    jumped = img.func_at(0x101A)
    assert called is not None and called.confidence == "confirmed"
    assert jumped is not None and jumped.confidence == "candidate"
    assert jumped.evidence and "tail jmp" in jumped.evidence[0]


# call 0x100b names sub_100b; a backward jmp inside that body must not become a
# start (its target shares the enclosing function / falls in a bounded body).
def _intra_branch_code() -> bytes:
    code = bytearray(b"\x90" * 0x20)
    code[0x00:0x05] = bytes.fromhex("e8 06 00 00 00")
    code[0x05] = 0xC3
    code[0x0B] = 0x90
    code[0x0C:0x11] = bytes.fromhex("e9 f6 ff ff ff")
    return bytes(code)


def test_intra_function_branch_is_not_a_start(code_image):
    img = code_image(_intra_branch_code())
    vas = {h.va for h in scan_targets(img)}
    assert 0x100B in vas
    assert 0x100C not in vas
    assert 0x1007 not in vas


def test_scan_targets_is_cached_by_file_hash(code_image, tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    img = code_image(CALLER)
    digest = cache.file_sha256(img.path)
    assert cache.cache_get(digest, "discover") is None
    first = scan_targets(img)
    assert any(h.va == 0x100A for h in first)
    # the .text scan is now persisted under the file's content hash
    assert cache.cache_get(digest, "discover") is not None
    # a fresh image with identical bytes is served from disk, identically
    img2 = code_image(CALLER)
    second = scan_targets(img2)
    assert [(h.va, h.confirmed, h.evidence) for h in second] == [
        (h.va, h.confirmed, h.evidence) for h in first
    ]
