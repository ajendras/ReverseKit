"""Tests for RevKit core functionality.

Covers Binary loading for all formats (including the new WASM and DOTNET),
string/symbol extraction, entropy, parsers, and integration points.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from revkit.core import Binary, WasmParser, DotNetParser
from revkit.utils import calculate_entropy, detect_format


@pytest.fixture
def sample_wasm():
    with tempfile.NamedTemporaryFile(suffix=".wasm", delete=False) as f:
        # Minimal valid WASM header + simple function
        f.write(b"\x00asm\x01\x00\x00\x00\x01\x05\x01\x60\x00\x01\x7f\x03\x02\x01\x00\x07\x08\x01\x04main\x00\x00\x0a\x06\x01\x04\x00\x41\x2a\x0b")
        tmp = f.name
    yield tmp
    Path(tmp).unlink(missing_ok=True)


@pytest.fixture
def sample_dotnet():
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        # Minimal PE + .NET CLR hint
        f.write(b"MZ\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00CLR")
        tmp = f.name
    yield tmp
    Path(tmp).unlink(missing_ok=True)


@pytest.fixture
def sample_raw():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x90\xc3\x55\x48\x89\xe5")
        tmp = f.name
    yield tmp
    Path(tmp).unlink(missing_ok=True)


def test_detect_format_wasm(sample_wasm):
    assert detect_format(sample_wasm) == "WASM"


def test_detect_format_dotnet(sample_dotnet):
    assert detect_format(sample_dotnet) == "DOTNET"


def test_detect_format_raw(sample_raw):
    assert detect_format(sample_raw) == "RAW"


def test_wasm_parser():
    mock_binary = MagicMock()
    mock_binary.sections = [MagicMock(), MagicMock()]
    mock_binary.exported_functions = [MagicMock(name="main")]
    parser = WasmParser(mock_binary)
    assert parser.entry_point() == 0
    assert len(parser.sections()) == 2
    assert len(parser.symbols()) == 1
    assert parser.symbols()[0].name == "main"


def test_dotnet_parser():
    mock_binary = MagicMock()
    mock_dotnet = MagicMock()
    mock_method = MagicMock()
    mock_method.name = "Main"
    mock_dotnet.methods = [mock_method]
    mock_dotnet.entrypoint_token = 0x6000001
    mock_binary.dotnet = mock_dotnet
    mock_binary.entrypoint = 0x1000
    parser = DotNetParser(mock_binary)
    assert parser.entry_point() == 0x1000
    assert len(parser.symbols()) == 1
    assert len(parser.methods()) == 1
    assert parser.methods()[0] == "Main"


def test_binary_wasm_support(sample_wasm):
    b = Binary(sample_wasm)
    assert b.format == "WASM"
    assert b.architecture == "wasm"
    assert b.entry_point() == 0
    assert len(b.sections()) >= 0
    assert len(b.symbols()) >= 0
    assert len(b.strings()) >= 0
    assert b.entropy() > 0.0
    # test read_bytes
    assert len(b.read_bytes(0, 8)) == 8


def test_binary_dotnet_support(sample_dotnet):
    b = Binary(sample_dotnet)
    assert b.format == "DOTNET"
    assert b.architecture == "x86_64"
    assert len(b.symbols()) >= 0
    assert len(b.strings()) >= 0
    assert b.entropy() > 0.0


def test_binary_raw_support(sample_raw):
    b = Binary(sample_raw)
    assert b.format == "RAW"
    assert b.architecture == "x86_64"
    assert b.entry_point() == 0
    assert len(b.read_bytes()) == 6


def test_calculate_entropy():
    assert calculate_entropy(b"") == 0.0
    assert calculate_entropy(b"aaaa") == 0.0
    assert 1.5 < calculate_entropy(b"abcde12345") < 3.0


@patch("revkit.core.lief.parse")
def test_binary_load_fallback(mock_parse):
    mock_parse.side_effect = Exception("parse failed")
    with tempfile.NamedTemporaryFile(suffix=".unknown", delete=False) as f:
        f.write(b"\x00\x00")
        tmp = f.name
    try:
        b = Binary(tmp)
        assert b.format == "RAW"
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_binary_symbols_and_strings(sample_wasm):
    b = Binary(sample_wasm)
    symbols = b.symbols()
    strings = b.strings()
    assert isinstance(symbols, list)
    assert isinstance(strings, list)


# Integration smoke test for analyze with new formats (mocked)
@patch("revkit.core.Binary")
def test_analyze_with_wasm(mock_binary_cls):
    mock_binary = MagicMock()
    mock_binary.format = "WASM"
    mock_binary.architecture = "wasm"
    mock_binary.entry_point.return_value = 0
    mock_binary.sections.return_value = []
    mock_binary.symbols.return_value = []
    mock_binary.strings.return_value = []
    mock_binary.entropy.return_value = 1.23
    mock_binary.match_flirt.return_value = {}
    mock_binary_cls.return_value = mock_binary

    from revkit import analyze

    result = analyze("test.wasm", report="json")
    assert result["format"] == "WASM"
    assert result["architecture"] == "wasm"
