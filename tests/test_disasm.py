"""Unit tests for the disassembly module.

Verifies Capstone-based disassembly produces accurate output for known
x86-64 and ARM snippets, that the Function abstraction behaves correctly,
architecture auto-detection works, and errors are raised with clear messages.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from revkit.core import Binary
from revkit.disasm import (
    Function,
    disassemble_range,
    get_function,
)


def test_disassemble_range_x86_known_snippet() -> None:
    """Test disassembly of a known x86-64 function against expected output."""
    # push rbp; mov rbp,rsp; sub rsp,0x20; mov eax,0x2a; leave; ret
    code = b"\x55\x48\x89\xe5\x48\x83\xec\x20\xb8\x2a\x00\x00\x00\xc9\xc3"

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(code)
        path = tmp.name

    try:
        binary = Binary(path)
        asm = disassemble_range(binary, 0, len(code), arch="x86_64")

        assert "55 48 89 e5" in asm
        assert "48 83 ec 20" in asm
        assert "b8 2a 00 00 00" in asm
        assert "c9" in asm
        assert "c3" in asm
        assert "push" in asm.lower()
        assert "mov" in asm.lower()
        assert "sub" in asm.lower()
        assert "ret" in asm.lower()
        # Address should be shown
        assert "00000000" in asm or "00000000" in asm.lower()
    finally:
        Path(path).unlink(missing_ok=True)


def test_disassemble_range_arm_known_snippet() -> None:
    """Test ARM disassembly against a known sequence."""
    # mov r0, #42; bx lr
    code = b"\x2a\x00\xa0\xe1\x1e\xff\x2f\xe1"

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(code)
        path = tmp.name

    try:
        binary = Binary(path)
        asm = disassemble_range(binary, 0, len(code), arch="arm")

        assert "2a 00 a0 e1" in asm
        assert "1e ff 2f e1" in asm
        assert "mov" in asm.lower()
        assert "bx" in asm.lower()
        assert "r0" in asm.lower()
    finally:
        Path(path).unlink(missing_ok=True)


def test_disassemble_range_auto_architecture(sample_elf: Path) -> None:
    """Test that 'auto' architecture uses the Binary's detected architecture."""
    binary = Binary(str(sample_elf))
    asm = disassemble_range(binary, binary.entry_point(), 48, arch="auto")
    assert isinstance(asm, str)
    assert len(asm.strip()) > 0


def test_function_wrapper() -> None:
    """Test the Function class directly with mock instructions."""
    # Minimal mock that matches what Capstone produces
    class MockInsn:
        def __init__(self, address: int, mnemonic: str, op_str: str, byte_data: bytes) -> None:
            self.address = address
            self.mnemonic = mnemonic
            self.op_str = op_str
            self.bytes = byte_data

    instructions = [
        MockInsn(0x1000, "push", "rbp", b"\x55"),
        MockInsn(0x1001, "mov", "rbp, rsp", b"\x48\x89\xe5"),
        MockInsn(0x1004, "ret", "", b"\xc3"),
    ]

    func = Function("calculate_flag", 0x1000, instructions)
    func.comment = "Computes CTF flag"

    assert func.name == "calculate_flag"
    assert func.address == 0x1000
    assert len(func.instructions) == 3
    assert func.comment == "Computes CTF flag"

    asm = func.to_asm()
    assert "calculate_flag:" in asm
    assert "; Computes CTF flag" in asm
    assert "1000:" in asm
    assert "1001:" in asm
    assert "1004:" in asm
    assert "push rbp" in asm
    assert "mov rbp, rsp" in asm
    assert "ret" in asm


def test_get_function_by_name_and_address(sample_elf: Path) -> None:
    """Test get_function with both name and address lookup."""
    binary = Binary(str(sample_elf))

    # By common name (falls back to entry point)
    func1 = get_function(binary, "main", length=64)
    assert isinstance(func1, Function)
    assert func1.name in ("main", "entry", "sub_0")
    assert len(func1.instructions) >= 0

    # By address
    ep = binary.entry_point()
    func2 = get_function(binary, ep, length=32)
    assert isinstance(func2, Function)
    assert func2.address == ep


def test_disassemble_range_empty_or_no_data() -> None:
    """Test graceful handling when no bytes are present at an address."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"\x90\x90")  # only two nops
        path = tmp.name

    try:
        binary = Binary(path)
        # Ask for more bytes than available - should not crash
        asm = disassemble_range(binary, 0, 128)
        assert isinstance(asm, str)
        # Should contain at least the nops
        assert "90" in asm
    finally:
        Path(path).unlink(missing_ok=True)


def test_disassemble_range_unsupported_architecture(sample_elf: Path) -> None:
    """Unsupported architecture must raise ValueError."""
    binary = Binary(str(sample_elf))

    with pytest.raises(ValueError, match="Architecture 'invalidarch' is not supported"):
        disassemble_range(binary, 0, 16, arch="invalidarch")


def test_disassemble_range_read_failure() -> None:
    """Reading from an invalid address should raise RuntimeError."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"")
        path = tmp.name

    try:
        binary = Binary(path)
        with pytest.raises(RuntimeError, match="Cannot read"):
            disassemble_range(binary, 0xFFFFFFFF, 16)
    finally:
        Path(path).unlink(missing_ok=True)


def test_function_str_and_to_asm_consistency() -> None:
    """__str__ must delegate to to_asm()."""
    class MockInsn:
        def __init__(self, address: int, mnemonic: str, op_str: str, byte_data: bytes) -> None:
            self.address = address
            self.mnemonic = mnemonic
            self.op_str = op_str
            self.bytes = byte_data

    func = Function(
        "test_func",
        0x400000,
        [MockInsn(0x400000, "xor", "eax, eax", b"\x31\xc0")],
    )
    func.comment = "Clear return value"

    text = str(func)
    assert text == func.to_asm()
    assert "test_func:" in text
    assert "xor eax, eax" in text
    assert "Clear return value" in text


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
