"""Tests for the core Binary class and utilities."""

from pathlib import Path
import tempfile

import pytest

from revkit.core import Binary
from revkit.utils import calculate_entropy, detect_format


def test_binary_loads_valid_file(sample_elf: Path) -> None:
    """Binary should load a valid ELF without error and set format/arch."""
    binary = Binary(sample_elf)
    assert binary.format in ("ELF", "PE", "Mach-O", "DEX", "RAW", "Unknown")
    assert isinstance(binary.architecture, str)
    assert binary.path == sample_elf.resolve()


def test_binary_strings(sample_elf: Path) -> None:
    """Should extract strings from binary."""
    binary = Binary(sample_elf)
    strings = binary.strings()
    assert isinstance(strings, list)
    assert len(strings) >= 0


def test_binary_strings_min_length(sample_elf: Path) -> None:
    """min_length param should filter short strings."""
    binary = Binary(sample_elf)
    long_strings = binary.strings(min_length=10)
    short_strings = binary.strings(min_length=4)
    assert len(long_strings) <= len(short_strings)


def test_binary_symbols(sample_elf: Path) -> None:
    """Should return list of symbols."""
    binary = Binary(sample_elf)
    syms = binary.symbols()
    assert isinstance(syms, list)


def test_binary_entropy(sample_elf: Path) -> None:
    """Entropy should be between 0 and 8."""
    binary = Binary(sample_elf)
    ent = binary.entropy()
    assert isinstance(ent, float)
    assert 0.0 <= ent <= 8.0


def test_entropy_helper() -> None:
    """Uniform distribution over 0-255 must yield exactly 8.0 entropy.

    (The original test used a faulty < comparison.)
    """
    data = bytes(range(256))
    assert calculate_entropy(data) == 8.0


def test_binary_read_bytes(sample_elf: Path) -> None:
    """Should read bytes at given virtual address (falls back for any VA)."""
    binary = Binary(sample_elf)
    data = binary.read_bytes(0, 16)
    assert isinstance(data, bytes)
    assert len(data) == 16


def test_binary_ai_annotations_not_present_by_default(sample_elf: Path) -> None:
    """Binary should not have ai_annotations until annotated."""
    binary = Binary(sample_elf)
    assert not hasattr(binary, "ai_annotations")
    assert not hasattr(binary, "_annotated_functions")


def test_entropy_on_empty_file() -> None:
    """Empty file should load as RAW with 0 entropy (no longer raises)."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        path = tmp.name
    try:
        binary = Binary(path)
        assert binary.format == "RAW"
        assert binary.entropy() == 0.0
        assert binary.entry_point() == 0
        assert len(binary.sections()) == 0
        assert len(binary.symbols()) == 0
    finally:
        Path(path).unlink(missing_ok=True)


def test_raw_binary_support() -> None:
    """RAW format support for shellcode .bin files (new behaviour)."""
    shellcode = b"\x90\x90\xc3"  # NOP; NOP; RET
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(shellcode)
        path = tmp.name
    try:
        binary = Binary(path)
        assert binary.format == "RAW"
        assert binary.architecture == "unknown"
        code = binary.read_bytes(0, 3)
        assert code == shellcode
        # read beyond EOF raises
        with pytest.raises(RuntimeError):
            binary.read_bytes(10, 10)
    finally:
        Path(path).unlink(missing_ok=True)


def test_detect_format_raw() -> None:
    """detect_format falls back to RAW for non-LIEF files."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"\x00\x01\x02")
        path = tmp.name
    try:
        assert detect_format(path) == "RAW"
    finally:
        Path(path).unlink(missing_ok=True)
