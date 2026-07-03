# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""32-bit ARM detector coverage: immediate stores, call args, and CRC loops.

Encodings are hand-assembled ARM (little-endian) and decoded by capstone in the
loader, so the tests exercise the real operand walk, not a mock.
"""

from __future__ import annotations

from deglyph.core.image import Arch
from deglyph.re.patterns import (
    call_immediate_args,
    detect_crc_loops,
    immediate_stores,
)


def _arm(code_image, blob: bytes):
    return code_image(blob, arch=Arch.ARM)


def test_immediate_store_recovered(code_image):
    # mov r0, #0xaa ; str r0, [r1, #4] ; bx lr
    blob = bytes.fromhex("aa00a0e3" + "040081e5" + "1eff2fe1")
    img = _arm(code_image, blob)
    stores = immediate_stores(img, 0x1000)
    assert stores, "no store recovered on ARM"
    s = stores[0]
    assert s.value == 0xAA
    assert (s.base or "").lower() == "r1"
    assert s.signed_disp == 4


def test_call_immediate_arg_high_confidence(code_image):
    # mov r0, #0x2a ; bl 0x1008 ; bx lr  (r0 is an AAPCS argument register)
    blob = bytes.fromhex("2a00a0e3" + "000000eb" + "1eff2fe1")
    img = _arm(code_image, blob)
    args = call_immediate_args(img, 0x1000)
    assert args, "no call argument recovered on ARM"
    hit = next(a for a in args if a.reg == "r0")
    assert hit.value == 0x2A
    assert hit.evidence.confidence == "high"


def test_crc_style_loop_detected(code_image):
    # eor/lsr body closed by a backward `bne`, the shape of a bit-twiddling
    # checksum loop.
    blob = bytes.fromhex(
        "043023e0" + "a330a0e1" + "043023e0" + "a330a0e1" + "012052e2" + "f9ffff1a"
    )
    img = _arm(code_image, blob)
    loops = detect_crc_loops(img, 0x1000)
    assert loops, "no CRC/checksum loop detected on ARM"
    assert loops[0].kind in ("crc", "checksum")


def test_analysis_support_lists_arm():
    from deglyph.cli import _analysis_support

    support = _analysis_support(Arch.ARM)
    assert support["immediate_stores"] is True
    assert support["call_immediate_args"] is True
    assert support["detect_crc_loops"] is True
    assert support["pseudo_c"] is False
