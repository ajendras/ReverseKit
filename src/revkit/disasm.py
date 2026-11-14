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
        self.var_names: dict[int, str] = {}  # offset -> name

    def to_asm(self) -> str:
        """Return a pretty-printed assembly listing with address, bytes, mnemonic.

        Respects any AI-added comments or variable renames (future).
        """
        lines = [f"{self.name}:  # @ {hex(self.address)}"]
        if self.comment:
            lines.append(f"    ; {self.comment}")

        for insn in self.instructions:
            addr = insn.address
            byte_str = " ".join(f"{b:02x}" for b in insn.bytes).ljust(20)
            asm_line = f"  {addr:0>8x}:  {byte_str}{insn.mnemonic} {insn.op_str}"

            # Could insert variable names here if implemented
            lines.append(asm_line)

        return "\n".join(lines)

    def __str__(self) -> str:
        return self.to_asm()


def disassemble_range(
    binary: Binary,
    start: int,
    length: int = 64,
    arch: str = "auto",
) -> str:
    """Disassemble a memory range into a human-readable assembly string.

    Args:
        binary: RevKit Binary instance.
        start: Virtual address to start disassembling from.
        length: Maximum number of bytes to decode.
        arch: Architecture (auto uses binary.architecture).

    Returns:
        Formatted disassembly text.

    Raises:
        ValueError: Unsupported architecture.
        RuntimeError: Failed to read memory at address.
    """
    if arch == "auto" or arch == "unknown":
        arch = binary.architecture or "x86"

    try:
        cs_arch, cs_mode = map_arch_to_capstone(arch)
    except ValueError as exc:
        raise ValueError(f"Architecture '{arch}' is not supported by Capstone") from exc

    md = Cs(cs_arch, cs_mode)
    md.detail = True
    md.skipdata = True

    try:
        code = binary.read_bytes(start, length)
    except Exception as exc:
        raise RuntimeError(f"Cannot read {length} bytes at {hex(start)}") from exc

    if not code:
        return f"; No data at virtual address {hex(start)}"

    disassembly: list[str] = []
    for insn in md.disasm(code, start):
        bytes_hex = " ".join(f"{b:02x}" for b in insn.bytes)
        disassembly.append(
            f"{insn.address:08x}  {bytes_hex:<24} {insn.mnemonic:8} {insn.op_str}"
        )

    return "\n".join(disassembly)


def get_function(
    binary: Binary, name_or_addr: str | int, length: int = 192
) -> Function:
    """Return a Function object for the given symbol name or virtual address.

    Uses symbol table lookup when a name is provided. Falls back to entry point
    for common names like 'main'. Disassembles a fixed window of bytes.

    Args:
        binary: The loaded binary.
        name_or_addr: Function name or start address.
        length: How many bytes to disassemble for the function body.

    Returns:
        Function wrapper with .to_asm() capability.
    """
    if isinstance(name_or_addr, int):
        addr = name_or_addr
        name = f"sub_{addr:x}"
    else:
        name = str(name_or_addr)
        addr = _resolve_symbol(binary, name)
        if addr is None:
            if name.lower() in ("main", "start", "_start"):
                addr = binary.entry_point()
            else:
                # Fallback: use entry point
                addr = binary.entry_point()
                name = "entry"

    instructions = _disassemble_to_instructions(binary, addr, length, arch="auto")

    return Function(name, addr, instructions)


def _resolve_symbol(binary: Binary, name: str) -> int | None:
    """Helper to find virtual address of a symbol by name."""
    for sym in binary.symbols():
        if hasattr(sym, "name") and getattr(sym, "name", None) == name:
            # LIEF symbols usually have .value for address
            if hasattr(sym, "value") and sym.value != 0:
                return sym.value
            if hasattr(sym, "address"):
                return sym.address
    return None


def _disassemble_to_instructions(
    binary: Binary, start: int, length: int = 192, arch: str = "auto"
) -> list[CsInsn]:
    """Internal helper returning raw Capstone instruction objects."""
    if arch == "auto" or arch == "unknown":
        arch = binary.architecture or "x86"

    cs_arch, cs_mode = map_arch_to_capstone(arch)

    md = Cs(cs_arch, cs_mode)
    md.detail = True
    md.skipdata = True

    code = binary.read_bytes(start, length)
    return list(md.disasm(code, start))


if __name__ == "__main__":
    # Demo / test with a tiny x86 binary
    import tempfile
    from pathlib import Path

    shellcode = b"\x55\x48\x89\xe5\x48\x83\xec\x10\xb8\x01\x00\x00\x00\xc3"
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name

    try:
        bin_obj = Binary(tmp)
        print("Disassembly:")
        print(disassemble_range(bin_obj, 0, 20))
        func = get_function(bin_obj, 0)
        print("\nFunction:")
        print(func.to_asm())
    finally:
        Path(tmp).unlink()
