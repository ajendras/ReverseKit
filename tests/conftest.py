"""Pytest fixtures for the RevKit test suite.

Provides reusable sample binaries, temporary files and mocked Ollama
responses so that test_core, test_disasm and future test modules stay
fast and deterministic.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure src is importable (works with pyproject pytest config)
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from revkit.core import Binary


@pytest.fixture(scope="session")
def sample_elf(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Return path to a minimal but LIEF-parseable ELF64 binary.

    Contains a few printable strings and a classic function prologue so
    that string extraction, symbol and disassembly tests have realistic
    data to work with.
    """
    elf_bytes = (
        b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00"
        b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"
        b"\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # code + strings
        b"\x55\x48\x89\xe5\x48\x83\xec\x10\xb8\x2a\x00\x00\x00\xc3"
        b"__REVKIT_TEST__"
        b"\x00hello_from_elf\x00"
        b"strcpy\x00IsDebuggerPresent\x00"
    )

    elf_path = tmp_path_factory.mktemp("data") / "sample.elf"
    elf_path.write_bytes(elf_bytes)
    return elf_path


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Return a generic temporary binary (flat shellcode style).

    Useful for tests that do not require a full ELF header.
    """
    content = (
        b"\x90\x90\xc3"  # NOP NOP RET
        b"TEST_STRING_123\x00"
        b"another_string\x00"
        b"\x55\x48\x89\xe5\xc3"
    )
    bin_path = tmp_path / "temp.bin"
    bin_path.write_bytes(content)
    return bin_path


@pytest.fixture
def mocked_ollama_response(mocker: pytest.MockFixture) -> MagicMock:
    """Patch both ollama.generate and ollama.chat with deterministic responses.

    Used by tests that exercise AIAnnotator without requiring a live Ollama
    instance.
    """
    generate_mock = mocker.patch("ollama.generate")
    chat_mock = mocker.patch("ollama.chat")

    generate_mock.return_value = {"response": "calculate_checksum"}
    chat_mock.return_value = {
        "message": {
            "content": "This function appears to compute a checksum over a buffer."
        }
    }

    return generate_mock


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent accidental network calls during tests."""

    def _raise(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("Network calls disabled in tests")

    monkeypatch.setattr("urllib.request.urlopen", _raise)
