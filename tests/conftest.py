# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Shared test fixtures.

`code_image` builds an in-memory `Image` over a raw machine-code blob, so the
disassembler and detectors can be exercised on known byte sequences without a
real container file or a host toolchain.
"""

from __future__ import annotations

import os
import platform

import pytest

from deglyph.core.image import Arch, Func, Image, Section


@pytest.fixture
def host_binary():
    """Path to a real OS binary for integration tests; skip if none is present."""
    system = platform.system()
    if system in ("Darwin", "Linux"):
        cands = ["/bin/ls", "/usr/bin/true", "/bin/cat"]
    elif system == "Windows":
        sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        cands = [os.path.join(sys32, n) for n in ("kernel32.dll", "user32.dll")]
    else:
        cands = []
    for c in cands:
        if os.path.isfile(c):
            return c
    pytest.skip("no host binary available")


@pytest.fixture
def code_image(tmp_path):
    """Factory: wrap `code` bytes in a one-section `Image` at virtual address `va`."""

    def _make(code: bytes, *, va: int = 0x1000, arch: Arch = Arch.X64) -> Image:
        blob = bytes(code)
        p = tmp_path / "synthetic.bin"
        p.write_bytes(blob)
        img = Image(path=str(p), fmt="RAW", arch=arch, base=0)
        img.sections.append(
            Section(
                name=".text",
                va=va,
                size=len(blob),
                raw_off=0,
                raw_size=len(blob),
                flags="RX",
            )
        )
        img.funcs.append(Func(name="f", va=va, kind="func"))
        img.reindex()
        return img

    return _make
