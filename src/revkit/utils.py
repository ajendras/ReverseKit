"""Utility functions for RevKit."""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Any

import lief

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
)


def calculate_entropy(data: bytes) -> float:
    """Compute Shannon entropy of the given bytes.

    Returns 0.0 for empty input. Maximum is exactly 8.0 for uniform
    distribution over all 256 byte values.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def detect_format(path: str | Path) -> str:
    """Detect the format of a binary file.

    Uses LIEF for structured formats, falls back to RAW for flat files
    and files that LIEF cannot parse. Safe handling for DEX to avoid
    AttributeError on some LIEF builds.
    """
    path = Path(path)
    if not path.is_file():
        return "unknown"
    try:
        parsed = lief.parse(str(path))
        if parsed is None:
            return "RAW"
        if isinstance(parsed, lief.ELF.Binary):
            return "ELF"
        if isinstance(parsed, lief.PE.Binary):
            return "PE"
        if isinstance(parsed, lief.MachO.Binary):
            return "Mach-O"
        try:
            if isinstance(parsed, lief.DEX.Binary):
                return "DEX"
        except AttributeError:
            if "DEX" in str(type(parsed)) or hasattr(parsed, "dex_header"):
                return "DEX"
        return "RAW"
    except Exception:
        return "RAW"


def map_arch_to_capstone(arch: str) -> tuple[Any, Any]:
    """Map architecture string to Capstone constants.

    Raises:
        ValueError: For unsupported architectures.
    """
    arch = arch.lower().strip()
    if arch in ("auto", "unknown"):
        arch = "x86"
    arch_map: dict[str, tuple[Any, Any]] = {
        "x86": (CS_ARCH_X86, CS_MODE_32),
        "x86_64": (CS_ARCH_X86, CS_MODE_64),
        "arm": (CS_ARCH_ARM, CS_MODE_ARM),
        "arm64": (CS_ARCH_ARM64, CS_MODE_64),
        "mips": (CS_ARCH_MIPS, CS_MODE_MIPS32),
        "riscv": (CS_ARCH_RISCV, CS_MODE_RISCV32),
        "wasm": (CS_ARCH_WASM, 0),
    }
    if arch not in arch_map:
        raise ValueError(f"Unsupported architecture: {arch}")
    return arch_map[arch]
