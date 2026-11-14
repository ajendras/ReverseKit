"""Utility functions for RevKit.

Contains architecture mapping for Capstone, entropy calculation,
binary format detection via LIEF, and Rich-compatible color helpers.
All functions include strict input validation and production-grade error
messages. Used by core, disasm, cli and report modules.
"""

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


def detect_format(path: str | Path) -> str:
    """Detect binary format using LIEF.

    Args:
        path: Filesystem path to the binary.

    Returns:
        Normalized uppercase format name (ELF, PE, Mach-O, DEX, Unknown).

    Raises:
        FileNotFoundError: If the path does not exist or is not a file.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Binary not found or not a file: {p}")

    try:
        parsed = lief.parse(str(p))
        if isinstance(parsed, lief.ELF.Binary):
            return "ELF"
        if isinstance(parsed, lief.PE.Binary):
            return "PE"
        if isinstance(parsed, lief.MachO.Binary):
            return "Mach-O"
        if isinstance(parsed, lief.DEX.Binary):
            return "DEX"
        return "Unknown"
    except Exception as exc:  # noqa: BLE001
        # LIEF may raise on corrupted or unsupported files
        return "Unknown"


def map_arch_to_capstone(arch: str) -> tuple[int, int]:
    """Map architecture string to Capstone (CS_ARCH_*, CS_MODE_*) constants.

    Supports the architectures advertised in the project: x86, x86_64, ARM,
    ARM64, MIPS, RISC-V and WASM. Raises a clear error for anything else.

    Args:
        arch: Architecture name (case-insensitive). "auto" is rejected here;
              callers must resolve it first.

    Returns:
        Tuple of Capstone architecture and mode constants.

    Raises:
        ValueError: Unsupported architecture.
    """
    if not isinstance(arch, str) or not arch.strip():
        raise ValueError("arch must be a non-empty string")

    a = arch.lower().strip()
    if a in ("x86", "i386", "ia32"):
        return CS_ARCH_X86, CS_MODE_32
    if a in ("x86_64", "amd64", "x64"):
        return CS_ARCH_X86, CS_MODE_64
    if a in ("arm", "armv7", "arm32"):
        return CS_ARCH_ARM, CS_MODE_ARM
    if a in ("arm64", "aarch64"):
        return CS_ARCH_ARM64, CS_MODE_64
    if a in ("mips", "mips32", "mipsel"):
        return CS_ARCH_MIPS, CS_MODE_MIPS32
    if a in ("riscv", "riscv32", "riscv64"):
        return CS_ARCH_RISCV, CS_MODE_RISCV32
    if a in ("wasm", "webassembly"):
        return CS_ARCH_WASM, 0

    raise ValueError(
        f"Unsupported architecture '{arch}'. "
        "Supported: x86, x86_64, arm, arm64, mips, riscv, wasm"
    )


def calculate_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte string.

    Args:
        data: Raw bytes to measure.

    Returns:
        Entropy value in [0.0, 8.0], rounded to 6 decimal places.

    Raises:
        TypeError: If data is not bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 6)


def colorize_output(text: str, accent: str = "#ff0044") -> str:
    """Return Rich markup string using the project visual direction.

    Bold monochrome palette with a single hot accent (#ff0044). Used by
    CLI commands and report generation for consistent high-contrast output.

    Args:
        text: Text to style.
        accent: Accent color (project default is #ff0044).

    Returns:
        String containing Rich markup tags.
    """
    if not isinstance(text, str):
        text = str(text)

    # For disassembly we highlight addresses and mnemonics; otherwise generic bold
    if any(kw in text.lower() for kw in (":", "0x", "jmp", "mov", "call", "ret")):
        return f"[bold {accent}]{text}[/bold {accent}]"

    return f"[bold white]{text}[/bold white]"


if __name__ == "__main__":
    # Self-demo / smoke test
    print("RevKit utils self-test")
    print("detect_format(__file__):", detect_format(__file__))
    print("map_arch_to_capstone('x86_64'):", map_arch_to_capstone("x86_64"))
    print(
        "calculate_entropy(b'\\x00'*128):",
        calculate_entropy(b"\x00" * 128),
    )
    print(
        "calculate_entropy(bytes(range(256))):",
        calculate_entropy(bytes(range(256))),
    )
    print("colorize_output('mov eax, 1'):", colorize_output("mov eax, 1"))
