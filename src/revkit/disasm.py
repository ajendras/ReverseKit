"""Capstone-based disassembler with function abstraction.

Provides fast disassembly of ranges and a lightweight Function wrapper
that supports .to_asm() for easy integration with the report and AI modules.
"""

from __future__ import annotations

from typing import Any

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_MIPS,
    CS_ARCH_RISCV,
    CS_ARCH_WASM,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_MIPS32,
    CS_MODE_RISCV32,
    Cs,
    CsInsn,
)

from .core import Binary
from .utils import map_arch_to_capstone


class Function:
    """Lightweight representation of a disassembled function.

    Holds Capstone instructions and can be extended by AIAnnotator with
    names, variable names and comments.
    """

    def __init__(self, name: str, address: int, instructions: list[CsInsn]) -> None:
        self.name = name
        self.address = address
        self.instructions = instructions
        self.comment: str = ""
        self.variables: dict[str, str] = {}

    def to_asm(self) -> str:
        """Return formatted assembly listing."""
        lines = [f"{self.name}() {{"]  # type: list[str]
        for insn in self.instructions:
            addr = f"{insn.address:08x}"
            bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
            lines.append(f"  {addr}: {bytes_str:<20} {insn.mnemonic} {insn.op_str}")
        lines.append("}")
        if self.comment:
            lines.insert(0, f"; {self.comment}")
        return "\n".join(lines)


def get_function(binary: Binary, name_or_addr: str | int, length: int = 256) -> Function:
    """Get Function object by symbol name or address."""
    addr = 0
    name = "unknown"
    if isinstance(name_or_addr, str):
        name = name_or_addr
        for sym in binary.symbols():
            if getattr(sym, "name", "") == name_or_addr or getattr(sym, "name", "") == f"_{name_or_addr}":
                addr = int(getattr(sym, "value", 0)) or int(getattr(sym, "address", 0))
                break
        if addr == 0:
            addr = binary.entry_point()
    else:
        addr = name_or_addr
        name = f"func_{addr:x}"
    return _disassemble_range_to_function(binary, addr, length, name)


def _disassemble_range_to_function(
    binary: Binary, start: int, length: int, name: str
) -> Function:
    """Disassemble bytes into Function (internal helper)."""
    code = binary.read_bytes(start, length)
    arch, mode = map_arch_to_capstone(binary.architecture or "auto")
    md = Cs(arch, mode)
    md.detail = True
    instructions = list(md.disasm(code, start))
    return Function(name, start, instructions)


def disassemble_range(
    binary: Binary, start: int, length: int = 64, arch: str = "auto"
) -> str:
    """Disassemble a raw byte range."""
    code = binary.read_bytes(start, length)
    if not code:
        return ""
    use_arch = arch if arch != "auto" else (binary.architecture or "auto")
    arch_const, mode = map_arch_to_capstone(use_arch)
    md = Cs(arch_const, mode)
    md.detail = False
    lines = []
    for insn in md.disasm(code, start):
        bytes_str = " ".join(f"{b:02x}" for b in insn.bytes[:6])
        lines.append(f"{insn.address:08x}: {bytes_str:<20} {insn.mnemonic} {insn.op_str}")
    return "\n".join(lines)
