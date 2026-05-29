# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Disassembly rendering: branch/call targets inside the image carry a clickable
`@click` action so the TUI can navigate to them.
"""

from __future__ import annotations

from rich.style import Style

from deglyph.core import Disassembler
from deglyph.tui.render import binary_map, disasm_text


def _click_actions(text):
    return [
        s.style.meta["@click"]
        for s in text.spans
        if isinstance(s.style, Style) and s.style.meta.get("@click")
    ]


def test_in_image_call_target_is_clickable(code_image):
    # call $+5 ; ret  — target 0x1005 is inside the .text section.
    img = code_image(bytes.fromhex("e8 00 00 00 00 c3"))
    insns = Disassembler(img).func(0x1000)
    text, _ = disasm_text(img, insns)
    assert any(f"goto_addr({0x1005})" in a for a in _click_actions(text))


def test_target_outside_image_is_not_clickable(code_image):
    # jmp far backward to 0x0 (outside the section): not navigable, no @click.
    # jmp -0x1000 ; ret
    img = code_image(bytes.fromhex("e9 00 f0 ff ff c3"))
    insns = Disassembler(img).func(0x1000)
    text, _ = disasm_text(img, insns)
    assert _click_actions(text) == []


def test_highlight_marks_line(code_image):
    # nop ; nop ; ret
    img = code_image(bytes.fromhex("90 90 c3"))
    insns = Disassembler(img).func(0x1000)
    _, mark = disasm_text(img, insns, highlight=0x1001)
    assert mark == 1


def test_binary_map_lists_sections(code_image):
    # A mostly-printable blob: the map names the section and renders a strip.
    img = code_image(b"hello world, this is plain ascii text " * 4)
    out = binary_map(img, width=20).plain
    assert "CONTENT MAP" in out
    assert ".text" in out
    # the byte-class strip uses shade glyphs from the section's content
    from deglyph.tui.glyphs import G

    assert any(G[k] in out for k in ("shade_low", "shade_mid", "shade_full"))


def test_binary_map_handles_unreadable_path(code_image):
    img = code_image(b"\x90\x90\xc3")
    img.path = "/no/such/file/at/all.bin"
    out = binary_map(img).plain
    assert "Cannot read file" in out
