"""Utility functions for RevKit.

Includes format detection (now with WASM and DOTNET), architecture mapping
for Capstone (including wasm and dotnet fallback) and entropy calculation.
"""

from __future__ import annotations

import math
from pathlib import Path
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
)


def detect_format(path: str | Path) -> str:
    """Detect binary format from magic bytes and extension.

    Supports all formats handled by Binary (including the new WASM and DOTNET).
    """
    p = Path(path)
    if not p.exists():
        return "UNKNOWN"
    data = p.read_bytes()[:512]
    suffix = p.suffix.lower()
    if data.startswith(b"\x00asm"):
        return "WASM"
    if data.startswith(b"MZ") and (b"CLR" in data or b"BSJB" in data):
        return "DOTNET"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"MZ"):
        return "PE"
    if data[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    ):
        return "MachO"
    if data.startswith(b"dex\n"):
        return "DEX"
    return "RAW"


def map_arch_to_capstone(arch: str) -> tuple[int, int]:
    """Map architecture string to Capstone constants.

    Now includes wasm (CS_ARCH_WASM) and dotnet (falls back to x86_64 for
    mixed-mode or native parts; pure CIL is not directly supported by Capstone).
    """
    arch = (arch or "auto").lower()
    if arch in ("x86", "i386", "x86_64", "amd64", "auto", "dotnet", "cil", ".net"):
        return CS_ARCH_X86, CS_MODE_64 if arch in ("x86_64", "amd64", "auto", "dotnet", "cil", ".net") else CS_MODE_32
    if arch in ("arm", "armv7"):
        return CS_ARCH_ARM, CS_MODE_ARM
    if arch in ("aarch64", "arm64"):
        return CS_ARCH_ARM64, 0
    if arch in ("mips", "mips32"):
        return CS_ARCH_MIPS, CS_MODE_MIPS32
    if arch in ("riscv", "riscv32"):
        return CS_ARCH_RISCV, CS_MODE_RISCV32
    if arch in ("wasm", "webassembly"):
        return CS_ARCH_WASM, 0
    return CS_ARCH_X86, CS_MODE_64


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0.0:
            entropy -= p_x * math.log2(p_x)
    return entropy
