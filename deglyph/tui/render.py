# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Rich renderers: colorized disassembly, hexdump, and analysis tables."""

from __future__ import annotations

from rich.text import Text

from ..core.disasm import Insn
from ..core.image import Image
from .glyphs import G

# Retro "TVA terminal" palette: warm amber / brass / cream (matches DEGLYPH_THEME).
# burnt orange
ACCENT = "#d97a2e"
# amber gold
GOLD = "#e3b04b"
# warm taupe
DIM = "#9b8a6c"
# olive
GREEN = "#9aa356"
# muted teal
BLUE = "#6fa39b"
# terracotta rose
MAUVE = "#c08a6f"

_FLOW = {
    "call",
    "jmp",
    "ret",
    "retn",
    "bl",
    "blr",
    "br",
    "je",
    "jne",
    "jz",
    "jnz",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jg",
    "jge",
    "jl",
    "jle",
    "js",
    "jns",
    "jo",
    "jno",
    "jp",
    "jnp",
    "loop",
}
_ARITH = {
    "xor",
    "and",
    "or",
    "shl",
    "shr",
    "sar",
    "rol",
    "ror",
    "add",
    "sub",
    "inc",
    "dec",
    "imul",
    "mul",
    "neg",
    "not",
}


def _mnem_style(m: str) -> str:
    if m in ("call", "bl", "blr"):
        return GOLD
    if m in ("ret", "retn", "iret"):
        return MAUVE
    if m in _FLOW:
        return BLUE
    if m in _ARITH:
        return GREEN
    if m.startswith("mov") or m in ("lea", "push", "pop"):
        return "#d9cbac"
    return DIM


def disasm_text(
    image: Image,
    insns: list[Insn],
    *,
    highlight: int | None = None,
    names: dict[int, str] | None = None,
) -> tuple[Text, int | None]:
    """Colorized disassembly listing; symbolizes branch/call targets when known.

    `names` maps a VA to a user rename, applied to symbolized targets. Returns the
    rendered text and the 0-based line index of the highlighted instruction (or
    None), so the caller can scroll it into view.
    """
    names = names or {}
    out = Text()
    mark_line: int | None = None
    for i, ins in enumerate(insns):
        line = Text()
        is_mark = highlight == ins.addr
        if is_mark:
            mark_line = i
        marker = G["mark"] if is_mark else "  "
        line.append(marker, style=ACCENT if is_mark else "")
        line.append(f"{ins.addr:#012x}  ", style=DIM)
        line.append(f"{ins.bytes.hex():<20.20} ", style="#5f5a54")
        line.append(f"{ins.mnemonic:<7} ", style=_mnem_style(ins.mnemonic))

        ops = Text(ins.op_str, style="#d9cbac")
        tgt = ins.imm_target()
        if tgt is not None:
            f = image.func_at(tgt) or image.nearest_func(tgt)
            if f and f.va == tgt:
                ops.append(f"  {G['arrow']} {names.get(f.va) or f.display}", style=GOLD)
            elif f:
                label = names.get(f.va) or f.display
                ops.append(f"  {G['arrow']} {label}+{tgt - f.va:#x}", style=DIM)
            # A target inside executable space is a navigable jump/call: clicking
            # the operand dispatches a goto. Textual adds the hover link style.
            if image.text and image.text.contains(tgt):
                ops.apply_meta({"@click": f"app.goto_addr({tgt})"})
        line.append(ops)
        out.append_text(line)
        out.append("\n")
    return out, mark_line


# Byte-class colors for the binary map strip (warm-palette consistent).
# zero-pad: faint; ASCII text: olive; code: gold; dense/other: terracotta.
_MAP_ZERO = "#5f5a54"
_MAP_TEXT = GREEN
_MAP_CODE = GOLD
_MAP_DENSE = MAUVE


def _classify_block(block: bytes) -> tuple[str, str]:
    """Coarse content class for a byte block: (glyph_key, style).

    Looks at the byte mix, not a full entropy calc: mostly-NUL reads as
    padding, mostly-printable as text, a wide spread of distinct values as
    dense (packed / compressed / high-entropy), else generic code/data.
    """
    if not block:
        return "shade_min", _MAP_ZERO
    n = len(block)
    zeros = block.count(0)
    if zeros >= n * 0.9:
        return "shade_min", _MAP_ZERO
    printable = sum(1 for b in block if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    if printable >= n * 0.85:
        return "shade_low", _MAP_TEXT
    distinct = len(set(block))
    if distinct >= 200:
        return "shade_full", _MAP_DENSE
    return "shade_mid", _MAP_CODE


def binary_map(image: Image, *, width: int = 48, max_rows: int = 200) -> Text:
    """Whole-file content map: sections laid out to scale with a content strip.

    Each section gets a header line (name, VA, size, flags) and one or more
    rows of a byte-class strip whose length is proportional to the section's
    file extent. The strip is colored by content class (padding, text, code,
    or dense/high-entropy) so the shape of the file is readable at a glance.
    A fat Mach-O notes the active slice at the top.
    """
    try:
        with open(image.path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return Text(f"Cannot read file: {e}", style=DIM)

    total = len(data) or 1
    out = Text()
    out.append("CONTENT MAP", style=GOLD)
    out.append(f"  {G['mdash']} {total:#x} bytes on disk\n", style=DIM)
    if len(image.slices) > 1:
        active = next((s for s in image.slices if s.index == image.slice_index), None)
        cpu = active.cpu if active else "?"
        names = ", ".join(s.cpu for s in image.slices)
        out.append(f"  fat: {names}  (active: {cpu})\n", style=DIM)
    out.append("\n")

    # One legend line so the colors are decodable.
    legend = Text("  ", style=DIM)
    for label, style in (
        ("pad", _MAP_ZERO),
        ("text", _MAP_TEXT),
        ("code", _MAP_CODE),
        ("dense", _MAP_DENSE),
    ):
        legend.append(G["block"], style=style)
        legend.append(f" {label}  ", style=DIM)
    out.append_text(legend)
    out.append("\n\n")

    # Sections in file order; skip ones with no on-disk bytes (bss-like).
    secs = sorted(
        (s for s in image.sections if s.raw_size > 0), key=lambda s: s.raw_off
    )
    if not secs:
        out.append("  (no on-disk sections to map)\n", style=DIM)
        return out

    rows_left = max_rows
    for s in secs:
        head = Text()
        head.append(f"{s.name:<14}", style="#d9cbac")
        head.append(f"{s.va:#012x}  ", style=DIM)
        head.append(f"{s.raw_size:#x}  ", style=DIM)
        head.append(f"{s.flags}\n", style=BLUE)
        out.append_text(head)

        chunk = data[s.raw_off : s.raw_off + s.raw_size]
        # Cells proportional to the section's share of the file, at least one
        # full row so a tiny section is still visible, capped so a huge section
        # cannot flood the pane.
        share = len(chunk) / total
        cells = max(width, min(width * 8, round(share * width * 24)))
        if rows_left <= 0:
            out.append(f"  {G['ellipsis']} (map truncated)\n", style=DIM)
            break
        step = max(1, len(chunk) // cells) if chunk else 1
        strip = Text("  ")
        col = 0
        for off in range(0, len(chunk), step):
            key, style = _classify_block(chunk[off : off + step])
            strip.append(G[key], style=style)
            col += 1
            if col >= width:
                strip.append("\n  ")
                col = 0
                rows_left -= 1
                if rows_left <= 0:
                    break
        out.append_text(strip)
        out.append("\n\n")
        rows_left -= 1
    return out


def hexdump(data: bytes, base: int = 0, width: int = 16) -> Text:
    out = Text()
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        out.append(f"{base + i:#012x}  ", style=DIM)
        hexs = " ".join(f"{b:02x}" for b in chunk)
        out.append(f"{hexs:<{width*3}}", style="#d9cbac")
        out.append("  ")
        out.append(
            "".join(chr(b) if 32 <= b < 127 else "." for b in chunk), style=GREEN
        )
        out.append("\n")
    return out
