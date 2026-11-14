"""Tests for revkit.core.Binary.

Covers loader behavior, string extraction, symbol table access,
entropy calculation and error handling. Uses fixtures from conftest.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from revkit.core import Binary
from revkit.utils import calculate_entropy, detect_format


def test_binary_loads_valid_file(sample_elf: Path) -> None:
    """Binary can be instantiated from a realistic ELF."""
    b = Binary(sample_elf)
    assert b.path == sample_elf.resolve()
    assert b.format == "ELF"
    assert b.architecture in ("x86_64", "unknown")
    assert isinstance(b.entry_point(), int)
    assert isinstance(b.sections(), list)
    assert isinstance(b.symbols(), list)


def test_binary_strings(sample_elf: Path) -> None:
    """String extraction finds both ASCII and embedded strings."""
    b = Binary(sample_elf)
    strings = b.strings(min_length=4)
    assert any("REVKIT_TEST" in s for s in strings)
    assert any("hello_from_elf" in s for s in strings)
    assert len(strings) >= 3


def test_binary_strings_min_length(temp_binary: Path) -> None:
    """min_length parameter is respected."""
    b = Binary(temp_binary)
    short = b.strings(min_length=4)
    assert any("TEST_STRING_123" in s for s in short)
    very_short = b.strings(min_length=15)
    assert not any(len(s) < 15 for s in very_short)


def test_binary_symbols(sample_elf: Path) -> None:
    """symbols() returns a list even when the binary is stripped."""
    b = Binary(sample_elf)
    syms = b.symbols()
    assert isinstance(syms, list)
    # We do not require any particular symbol count for the minimal ELF


def test_binary_entropy(sample_elf: Path) -> None:
    """entropy() returns a float in the expected range."""
    b = Binary(sample_elf)
    ent = b.entropy()
    assert isinstance(ent, float)
    assert 0.0 <= ent <= 8.0


def test_entropy_helper() -> None:
    """Standalone calculate_entropy produces correct values."""
    assert calculate_entropy(b"") == 0.0
    assert calculate_entropy(b"\x00" * 256) == 0.0
    randomish = bytes(range(256)) * 4
    assert 7.0 < calculate_entropy(randomish) < 8.0


def test_detect_format_helper(sample_elf: Path) -> None:
    """detect_format returns expected string for ELF."""
    fmt = detect_format(sample_elf)
    assert fmt == "ELF"


def test_binary_read_bytes(sample_elf: Path) -> None:
    """read_bytes can retrieve content at a virtual address."""
    b = Binary(sample_elf)
    # Read the function prologue we placed at a known offset
    data = b.read_bytes(0x4000, 6)
    assert data[:3] == b"\x55\x48\x89"


def test_binary_nonexistent_file() -> None:
    """Clear error when file is missing."""
    with pytest.raises(FileNotFoundError, match="Binary not found"):
        Binary("/nonexistent/file/that/does/not/exist.bin")


def test_binary_invalid_format(tmp_path: Path) -> None:
    """Invalid or empty file raises a helpful ValueError."""
    bad = tmp_path / "not_a_binary.bin"
    bad.write_text("this is not a binary")
    with pytest.raises(ValueError, match="Failed to parse"):
        Binary(bad)


def test_binary_ai_annotations_not_present_by_default(sample_elf: Path) -> None:
    """Fresh Binary does not have AI annotation attributes."""
    b = Binary(sample_elf)
    assert not hasattr(b, "ai_annotations")
    assert not hasattr(b, "_annotated_functions")


def test_entropy_on_empty_file(tmp_path: Path) -> None:
    """Entropy of a zero-byte file is defined as 0.0."""
    empty = tmp_path / "empty.bin"
    empty.touch()
    b = Binary(empty)
    assert b.entropy() == 0.0
