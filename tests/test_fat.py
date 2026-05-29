# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Fat (universal) Mach-O handling.

A fat binary carries several architecture slices. `lief.parse` would hand back
only the first; deglyph resolves all slices, picks one (host arch by default),
and adds the slice's fat offset to each section so a file read lands in the
chosen slice instead of the fat header's zero padding. The regression that
motivated this: `/bin/pwd` on Apple Silicon disassembled to a wall of
`add byte ptr [rax], al` (decoded zeros) because the offset was slice-relative.
"""

from __future__ import annotations

import platform

import pytest

from deglyph.core.disasm import Disassembler
from deglyph.core.image import Arch, Slice, _build_sections, _pick_slice, load_image

# A real fat binary ships with macOS; skip cleanly elsewhere.
FAT = "/bin/pwd"


def _have_fat() -> bool:
    if platform.system() != "Darwin":
        return False
    try:
        import lief

        fat = lief.MachO.parse(FAT)
        return fat is not None and len(fat) > 1
    except Exception:
        return False


needs_fat = pytest.mark.skipif(not _have_fat(), reason="no fat Mach-O available")


@needs_fat
def test_fat_lists_all_slices():
    img = load_image(FAT)
    archs = {s.arch for s in img.slices}
    # /bin/pwd is x86_64 + arm64(e)
    assert len(img.slices) >= 2
    assert Arch.X64 in archs
    assert Arch.ARM64 in archs


@needs_fat
def test_fat_text_is_not_zero_padding():
    # The bug read slice-relative offsets against the whole fat file, landing
    # in the fat header's NULs. Real code is never an all-zero run.
    for arch in (Arch.X64, Arch.ARM64):
        img = load_image(FAT, arch=arch)
        head = img.read_va(img.text.va, 16)
        assert head and any(head), f"{arch} __text read back as zeros"


@needs_fat
def test_fat_slices_disassemble_to_real_code():
    # x86_64 entry begins push rbp / mov rbp, rsp; the all-zeros bug decoded
    # every byte as `add byte ptr [rax], al`. arm64 begins with a frame setup.
    x86 = load_image(FAT, arch=Arch.X64)
    ins = Disassembler(x86).func(x86.funcs[-1].va)
    assert ins, "no x86_64 instructions decoded"
    assert not all(i.mnemonic == "add" for i in ins[:8])

    arm = load_image(FAT, arch=Arch.ARM64)
    assert arm.arch == Arch.ARM64
    ins = Disassembler(arm).func(arm.funcs[-1].va)
    assert ins, "no arm64 instructions decoded"
    assert not all(i.mnemonic == "add" for i in ins[:8])


@needs_fat
def test_fat_default_prefers_host_arch():
    img = load_image(FAT)
    host = platform.machine().lower()
    if host in ("arm64", "aarch64"):
        assert img.arch == Arch.ARM64
    elif host in ("x86_64", "amd64"):
        assert img.arch == Arch.X64


@needs_fat
def test_fat_slice_index_override():
    img0 = load_image(FAT, slice_index=0)
    img1 = load_image(FAT, slice_index=1)
    assert img0.slice_index == 0
    assert img1.slice_index == 1
    # different slices are different architectures, hence different first bytes
    assert img0.read_va(img0.text.va, 16) != img1.read_va(img1.text.va, 16)


def test_build_sections_adds_fat_offset():
    # A slice-relative section offset plus the fat base is the absolute file
    # offset; _build_sections must fold the base in so a later seek is correct.
    class _Sec:
        name = "__text"
        virtual_address = 0x1000
        size = 0x40
        offset = 0x4C0

    class _Bin:
        sections = [_Sec()]

    secs = _build_sections(_Bin(), base=0, fat_offset=0x4000)
    assert secs[0].raw_off == 0x4000 + 0x4C0


def test_pick_slice_prefers_arch():
    slices = [
        Slice(index=0, arch=Arch.X64, cpu="X86_64", fat_offset=0),
        Slice(index=1, arch=Arch.ARM64, cpu="ARM64", fat_offset=0x4000),
    ]
    # an explicit arch wins, regardless of host
    assert _pick_slice(slices, Arch.X64) == 0
    assert _pick_slice(slices, Arch.ARM64) == 1


def test_pick_slice_falls_back_to_first_when_nothing_matches():
    # No slice matches the requested arch and none matches the host arch, so
    # the first slice is the floor. Use arches absent from any real host so the
    # assertion is independent of the machine the suite runs on.
    slices = [
        Slice(index=0, arch=Arch.ARM, cpu="ARM", fat_offset=0),
        Slice(index=1, arch=Arch.UNKNOWN, cpu="?", fat_offset=0x4000),
    ]
    assert _pick_slice(slices, Arch.X86) == 0


def test_thin_binary_has_no_slices():
    # The demo fixture is a thin PE; fat handling must not invent slices.
    img = load_image("samples/demo.exe")
    assert img.slices == []
    assert img.slice_index == 0
