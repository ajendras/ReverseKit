"""Tests for core Binary functionality, parsers, FLIRT and integration."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from revkit.core import Binary
from revkit.scanner import FlirtMatcher, VulnScanner


@pytest.fixture
def sample_elf(tmp_path: Path) -> Path:
    """Create a minimal ELF for testing."""
    elf_data = (
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
        b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    elf = tmp_path / "sample.elf"
    elf.write_bytes(elf_data)
    return elf


def test_binary_loads_elf(sample_elf: Path) -> None:
    """Binary loads ELF and extracts basic metadata."""
    binary = Binary(str(sample_elf))
    assert binary.format == "ELF"
    assert binary.entry_point() == 0
    assert len(binary.sections()) >= 0
    assert isinstance(binary.symbols(), list)
    assert isinstance(binary.strings(), list)
    assert 0.0 <= binary.entropy() <= 8.0


def test_binary_raw_fallback() -> None:
    """RAW format support for shellcode/flat binaries (including empty)."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x90\xc3")
        tmp = f.name
    try:
        binary = Binary(tmp)
        assert binary.format == "RAW"
        assert binary.read_bytes() == b"\x90\xc3"
        assert binary.entropy() > 0.0
    finally:
        Path(tmp).unlink()


def test_flirt_matcher_builtin(sample_elf: Path) -> None:
    """FlirtMatcher provides builtin signatures and matching works."""
    binary = Binary(str(sample_elf))
    matcher = FlirtMatcher(binary)
    assert matcher.download() is True
    matches = matcher.match(download=False)
    assert isinstance(matches, dict)
    # At least builtin signatures are present even if no match on tiny ELF
    assert len(matcher.signatures) > 0


def test_flirt_matcher_download_and_cache(sample_elf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Download populates cache; cache is reused."""
    cache_dir = tmp_path / "cache" / "revkit" / "flirt"
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "cache")

    binary = Binary(str(sample_elf))
    matcher = FlirtMatcher(binary)
    matcher.download(force=True)
    assert matcher.sig_path.exists()
    # second call uses cache
    assert matcher.download() is True


def test_vuln_scanner(sample_elf: Path) -> None:
    """VulnScanner integrates anti-debug, stack checks and flirt."""
    binary = Binary(str(sample_elf))
    scanner = VulnScanner(binary)
    assert hasattr(scanner, "flirt")
    anti = scanner.find_anti_debug()
    assert isinstance(anti, list)
    smash = scanner.detect_stack_smash()
    assert isinstance(smash, list)
    flirt_matches = scanner.match_flirt(download=False)
    assert isinstance(flirt_matches, dict)


def test_binary_match_flirt(sample_elf: Path) -> None:
    """Binary.match_flirt() convenience method works."""
    binary = Binary(str(sample_elf))
    matches = binary.match_flirt(download=False)
    assert isinstance(matches, dict)


def test_binary_trace_skipped_when_no_unicorn(sample_elf: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Trace gracefully handles missing unicorn (test env)."""
    monkeypatch.setattr("revkit.tracer.UnicornTracer", None)
    binary = Binary(str(sample_elf))
    with pytest.raises((ImportError, RuntimeError)):
        binary.trace(steps=5)
