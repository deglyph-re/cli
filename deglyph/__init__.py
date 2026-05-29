"""
deglyph — a terminal reverse-engineering tool for native binaries.

Loads a PE / ELF / Mach-O (or fat) object, lists its functions in a searchable
table, follows exported-wrapper -> real-function chains, shows annotated
disassembly, walks the call graph, and searches for byte / string / immediate
patterns. Backed by LIEF (container parsing) and Capstone (disassembly).

Author: Alex Spataru
"""

__version__ = "1.2.0"
__author__ = "Alex Spataru"
__all__ = ["__version__", "__author__"]
