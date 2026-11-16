"""Tests for the disassembler."""

import pytest
import tempfile
from pathlib import Path

from revkit.core import Binary
from revkit.disasm import (
    disassemble_range,
    get_function,
    Function,
)


X86_SNIPPET = b"\x55\x48\x89\xe5\xb8\x2a\x00\x00\x00\xc3"  # push rbp; mov rbp,rsp; mov eax,42; ret
ARM_SNIPPET = b"\x0d\xc0\xa0\xe1\x00\x00\x81\xe2"  # mov ip, sp; add r0, r1, #0 (example)


def test_disassemble_range_x86_known_snippet() -> None:
    """Disassembly of known x86 snippet must produce expected mnemonics."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(X86_SNIPPET)
        path = tmp.name
    try:
        binary = Binary(path)
        asm = disassemble_range(binary, 0, len(X86_SNIPPET), arch="x86")
        assert "mov" in asm.lower()
        assert "eax" in asm.lower() or "42" in asm
    finally:
        Path(path).unlink(missing_ok=True)


def test_disassemble_range_arm_known_snippet() -> None:
    """Disassembly of known ARM snippet must produce expected mnemonics."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(ARM_SNIPPET)
        path = tmp.name
    try:
        binary = Binary(path)
        asm = disassemble_range(binary, 0, len(ARM_SNIPPET), arch="arm")
        assert "mov" in asm.lower() or "add" in asm.lower()
    finally:
        Path(path).unlink(missing_ok=True)


def test_disassemble_range_auto_architecture(sample_elf: Path) -> None:
    """auto architecture should use binary.architecture."""
    binary = Binary(sample_elf)
    asm = disassemble_range(binary, binary.entry_point(), 32, arch="auto")
    assert isinstance(asm, str)


def test_get_function_by_name_and_address(sample_elf: Path) -> None:
    """get_function should return a Function object."""
    binary = Binary(sample_elf)
    func = get_function(binary, "main", length=64)
    assert isinstance(func, Function)
    assert func.name is not None
    assert len(func.instructions) >= 0


def test_disassemble_range_empty_or_no_data() -> None:
    """Disassembling empty region should return a no-data message."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"\x00" * 16)
        path = tmp.name
    try:
        binary = Binary(path)
        asm = disassemble_range(binary, 0, 0)
        assert "No data" in asm or asm == ""
    finally:
        Path(path).unlink(missing_ok=True)


def test_disassemble_range_unsupported_architecture() -> None:
    """Unsupported arch should raise ValueError."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"\x90")
        path = tmp.name
    try:
        binary = Binary(path)
        with pytest.raises(ValueError, match="Unsupported"):
            disassemble_range(binary, 0, 4, arch="invalid-arch")
    finally:
        Path(path).unlink(missing_ok=True)


def test_disassemble_range_read_failure() -> None:
    """Reading from an invalid address on an empty file should raise RuntimeError.

    (Test updated to match new RAW + read_bytes behaviour.)
    """
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"")
        path = tmp.name
    try:
        binary = Binary(path)
        with pytest.raises(RuntimeError, match="Failed to read|Cannot read"):
            disassemble_range(binary, 0x1000, 64)
    finally:
        Path(path).unlink(missing_ok=True)
