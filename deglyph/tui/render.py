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
