"""Tests for the disassembler.

Covers Capstone accuracy on known snippets, Function wrapper and
graceful handling of empty/RAW binaries.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from revkit.core import Binary
from revkit.disasm import disassemble_range, get_function


def test_disassemble_x86() -> None:
    """Basic x86_64 disassembly produces expected mnemonics."""
    shellcode = b"\x55\x48\x89\xe5\xb8\x2a\x00\x00\x00\xc3"  # push rbp; mov rbp,rsp; mov eax,42; ret
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name
    try:
        binary = Binary(tmp)
        asm = disassemble_range(binary, 0, len(shellcode), arch="x86_64")
        assert "push" in asm.lower()
        assert "mov" in asm.lower()
        assert "eax" in asm.lower()
        assert "ret" in asm.lower()
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_disassemble_arm() -> None:
    """ARM disassembly works (thumb mode)."""
    shellcode = b"\x00\x00\xa0\xe1\x01\x00\xa0\xe1"  # mov r0,r0; mov r0,r1 (ARM)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name
    try:
        binary = Binary(tmp)
        asm = disassemble_range(binary, 0, len(shellcode), arch="arm")
        assert "mov" in asm.lower()
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_get_function() -> None:
    """get_function returns a Function object with instructions."""
    shellcode = b"\x90\xc3"  # nop; ret
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name
    try:
        binary = Binary(tmp)
        func = get_function(binary, "entry", length=8)
        assert func.name == "entry"
        assert len(func.instructions) > 0
        assert "nop" in func.to_asm().lower()
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_disassemble_range_read_failure() -> None:
    """Reading from an invalid address on an empty file gracefully returns
    an empty or placeholder disassembly string.

    (Test updated to match new RAW + read_bytes behaviour that no longer
    raises RuntimeError for flat/empty binaries.)
    """
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"")
        path = tmp.name
    try:
        binary = Binary(path)
        asm = disassemble_range(binary, 0x1000, 32)
        assert isinstance(asm, str)
        # Current implementation returns empty or a comment for no data
        assert asm.strip() == "" or any(
            kw in asm.lower() for kw in ("no data", "empty", "could not read", ";")
        )
    finally:
        Path(path).unlink(missing_ok=True)


def test_function_to_asm() -> None:
    """Function.to_asm() produces a readable multi-line string."""
    shellcode = b"\x48\x31\xc0\xc3"  # xor rax,rax; ret
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name
    try:
        binary = Binary(tmp)
        func = get_function(binary, 0, length=8)
        asm = func.to_asm()
        assert "xor" in asm.lower()
        assert "ret" in asm.lower()
        assert hex(func.address) in asm
    finally:
        Path(tmp).unlink(missing_ok=True)
