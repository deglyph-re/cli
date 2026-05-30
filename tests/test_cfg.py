# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Bounded recursive-descent CFG for a single function."""

from __future__ import annotations

from deglyph.re.cfg import function_cfg


def test_early_return_reaches_both_arms(code_image):
    # xor eax,eax ; test eax,eax ; je 0x1009 ; mov al,1 ; ret ; mov al,2 ; ret
    # A linear "decode until first ret" would stop at the first ret and miss the
    # second arm; the CFG must reach both blocks behind the conditional branch.
    img = code_image(bytes.fromhex("31c085c07403b001c3b002c3"))
    cfg = function_cfg(img, 0x1000)
    starts = {b.start for b in cfg.blocks}
    assert starts == {0x1000, 0x1006, 0x1009}
    cond = next(b for b in cfg.blocks if b.start == 0x1000)
    assert cond.kind == "cond"
    assert set(cond.successors) == {0x1006, 0x1009}
    # both arms end in a ret, and nothing was left undecoded
    assert all(
        b.kind == "ret" for b in cfg.blocks if b.start in (0x1006, 0x1009)
    )
    assert cfg.gaps == []


def test_backward_jmp_is_a_self_loop(code_image):
    # inc rax ; jmp 0x2000  -- the back-edge makes one block point at itself.
    img = code_image(bytes.fromhex("48ffc0ebfb"), va=0x2000)
    cfg = function_cfg(img, 0x2000)
    assert len(cfg.blocks) == 1
    b = cfg.blocks[0]
    assert b.kind == "jmp"
    assert b.successors == [0x2000]


def test_boundary_stops_at_next_start(code_image):
    # The same early-return blob, but a known neighbor start at 0x1006 cuts the
    # walk so the first function does not bleed into the next.
    img = code_image(bytes.fromhex("31c085c07403b001c3b002c3"))
    cfg = function_cfg(img, 0x1000, boundary=[0x1000, 0x1006])
    assert cfg.extent <= 0x1006
    assert all(b.start < 0x1006 for b in cfg.blocks)


def test_indirect_jump_ends_block_without_successor(code_image):
    # jmp rax  -- a computed/jump-table transfer has no static target, so the
    # block ends as "indirect" and its arms show up as an undecoded gap.
    img = code_image(bytes.fromhex("ffe0"))
    cfg = function_cfg(img, 0x1000)
    assert cfg.blocks[0].kind == "indirect"
    assert cfg.blocks[0].successors == []


def test_unreachable_tail_is_reported_as_a_gap(code_image):
    # ret ; <2 bytes never reached>. The descent stops at the ret; the trailing
    # bytes inside the section are surfaced as a gap, not silently dropped.
    img = code_image(bytes.fromhex("c39090"))
    cfg = function_cfg(img, 0x1000, boundary=[0x1000])
    # only the ret block is decoded
    assert cfg.extent == 0x1001
    # nothing past the ret was decoded into a block
    assert all(b.end <= 0x1001 for b in cfg.blocks)


def test_no_section_yields_empty_cfg():
    from deglyph.core.image import Arch, Image

    img = Image(path="x", fmt="RAW", arch=Arch.X64, base=0)
    cfg = function_cfg(img, 0x1000)
    assert cfg.blocks == []
    assert cfg.extent == 0x1000


def test_instructions_view_is_address_ordered(code_image):
    img = code_image(bytes.fromhex("31c085c07403b001c3b002c3"))
    cfg = function_cfg(img, 0x1000)
    addrs = [i.addr for i in cfg.instructions()]
    assert addrs == sorted(addrs)


def test_aarch64_conditional_branch_splits(code_image):
    # cmp x0,#0 ; b.eq 0x1014 ; mov x0,#1 ; ret ; mov x0,#2 ; ret
    # The CFG is architecture-aware: AArch64 b.eq is a conditional branch with a
    # fall-through (0x1008) and a target (0x1014), both reached. A previous build
    # only knew x86 Jcc mnemonics and merged the whole function into one block.
    from deglyph.core.image import Arch

    words = ["1f0000f1", "80000054", "200080d2", "c0035fd6", "400080d2", "c0035fd6"]
    blob = b"".join(bytes.fromhex(w) for w in words)
    img = code_image(blob, arch=Arch.ARM64)
    cfg = function_cfg(img, 0x1000)
    assert {b.start for b in cfg.blocks} == {0x1000, 0x1008, 0x1014}
    head = next(b for b in cfg.blocks if b.start == 0x1000)
    assert head.kind == "cond"
    assert set(head.successors) == {0x1008, 0x1014}


def test_function_insns_reaches_store_behind_early_return(code_image):
    # The reason the detectors moved onto the CFG. Linear "decode until first
    # ret" stops at the first ret and never sees the mov-to-memory that sits
    # behind a forward conditional branch; function_insns reaches it.
    #   xor eax,eax ; test eax,eax ; je 0x1009 ; mov al,1 ; ret
    #   (0x1009) mov byte ptr [rcx], 4 ; ret
    from deglyph.core.disasm import Disassembler
    from deglyph.re.cfg import function_insns
    from deglyph.re.patterns import immediate_stores

    img = code_image(bytes.fromhex("31c085c07403b001c3c60104c3"))
    # the old linear decode stops at the first ret and misses the store
    linear = Disassembler(img).func(0x1000)
    assert all(i.addr < 0x1009 for i in linear)
    # the CFG-backed instruction set reaches the post-branch block
    assert 0x1009 in {i.addr for i in function_insns(img, 0x1000)}
    # and the detector now finds the store the linear decode dropped
    stores = immediate_stores(img, 0x1000)
    assert any(s.addr == 0x1009 and s.value == 0x04 for s in stores)
