"""Core module providing the Binary abstraction using LIEF.

This is the foundation of RevKit. Handles loading of multiple binary formats
(ELF, PE, Mach-O, DEX), metadata extraction, string scanning, entropy calculation
and memory access for disassembly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import lief

from .utils import calculate_entropy


class Binary:
    """Loaded binary with high-level analysis interface.

    Wraps a LIEF parsed binary and augments it with common reverse engineering
    operations. Designed to be passed between analysis modules (disasm, graph,
    annotator, report).
    """

    def __init__(self, path: str | Path) -> None:
        """Load a binary from disk using LIEF.

        Args:
            path: Path to the binary file.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If LIEF cannot parse the file.
        """
        self.path = Path(path).resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"Binary not found or not a file: {self.path}")

        try:
            self._binary: Any = lief.parse(str(self.path))
            if self._binary is None:
                raise ValueError("LIEF returned None")
        except Exception as exc:
            raise ValueError(
                f"Failed to parse {self.path.name} with LIEF. "
                f"Format may be unsupported or file corrupted: {exc}"
            ) from exc

        self.format = self._detect_format()
        self.architecture = self._detect_architecture()
        self._strings: list[str] | None = None

    def _detect_format(self) -> str:
        """Return normalized format name based on LIEF type."""
        if isinstance(self._binary, lief.ELF.Binary):
            return "ELF"
        if isinstance(self._binary, lief.PE.Binary):
            return "PE"
        if isinstance(self._binary, lief.MachO.Binary):
            return "Mach-O"
        if isinstance(self._binary, lief.DEX.Binary):
            return "DEX"
        return "Unknown"

    def _detect_architecture(self) -> str:
        """Map LIEF architecture to Capstone-compatible name."""
        arch_map = {
            lief.ARCHITECTURES.X86_64: "x86_64",
            lief.ARCHITECTURES.X86: "x86",
            lief.ARCHITECTURES.ARM: "arm",
            lief.ARCHITECTURES.ARM64: "arm64",
            lief.ARCHITECTURES.MIPS: "mips",
            lief.ARCHITECTURES.RISCV: "riscv",
            lief.ARCHITECTURES.WASM: "wasm",
        }

        # LIEF v0.14+ uses .header.architecture for some
        if hasattr(self._binary, "header") and hasattr(
            self._binary.header, "architecture"
        ):
            arch = self._binary.header.architecture
            return arch_map.get(arch, "unknown")

        # Fallback for ELF
        if self.format == "ELF" and hasattr(self._binary, "header"):
            machine = self._binary.header.machine_type
            if machine in (lief.ELF.ARCH.x86_64, lief.ELF.ARCH.i386):
                return "x86_64" if machine == lief.ELF.ARCH.x86_64 else "x86"
            if "ARM" in str(machine):
                return "arm"
        return "unknown"

    def entry_point(self) -> int:
        """Return the program entry point virtual address."""
        return getattr(self._binary, "entrypoint", 0)

    def sections(self) -> list[Any]:
        """Return all sections as LIEF section objects."""
        return list(self._binary.sections)

    def symbols(self) -> list[Any]:
        """Return symbols from the binary (dynamic, static, exports)."""
        symbols: list[Any] = []
        if hasattr(self._binary, "symbols"):
            symbols.extend(self._binary.symbols)
        if hasattr(self._binary, "dynamic_symbols"):
            symbols.extend(self._binary.dynamic_symbols)
        if hasattr(self._binary, "imported_functions"):
            symbols.extend(self._binary.imported_functions)
        if hasattr(self._binary, "exports"):
            symbols.extend(self._binary.exports)
        return symbols

    def strings(self, min_length: int = 4) -> list[str]:
        """Extract ASCII and wide strings from the raw binary content.

        Args:
            min_length: Minimum string length to report.

        Returns:
            List of decoded strings.
        """
        if self._strings is None:
            self._strings = self._extract_strings(min_length)
        return self._strings

    def _extract_strings(self, min_length: int = 4) -> list[str]:
        """Low-level string scanner."""
        strings: list[str] = []
        try:
            with self.path.open("rb") as f:
                data = f.read()
            i = 0
            n = len(data)
            while i < n:
                # ASCII strings
                if 32 <= data[i] <= 126 or data[i] in (9, 10, 13):
                    start = i
                    while i < n and (32 <= data[i] <= 126 or data[i] in (9, 10, 13)):
                        i += 1
                    s = data[start:i].decode("ascii", errors="replace").strip()
                    if len(s) >= min_length:
                        strings.append(s)
                    continue
                # Basic UTF-16LE check (simple)
                if i + 1 < n and data[i + 1] == 0 and 32 <= data[i] <= 126:
                    start = i
                    while (
                        i + 1 < n
                        and data[i + 1] == 0
                        and 32 <= data[i] <= 126
                    ):
                        i += 2
                    s = data[start:i:2].decode("ascii", errors="replace").strip()
                    if len(s) >= min_length:
                        strings.append(s)
                    continue
                i += 1
        except OSError:
            pass  # ignore file read errors
        return strings

    def read_bytes(self, virtual_address: int, size: int) -> bytes:
        """Read bytes from a virtual address.

        Uses LIEF's virtual_address_to_offset when possible, falls back to
        raw read for flat binaries.
        """
        try:
            # Prefer LIEF offset mapping
            if hasattr(self._binary, "virtual_address_to_offset"):
                offset = self._binary.virtual_address_to_offset(virtual_address)
                with self.path.open("rb") as f:
                    f.seek(offset)
                    return f.read(size)
            # Alternative using section content if available
            for section in self.sections():
                if (
                    hasattr(section, "virtual_address")
                    and section.virtual_address
                    <= virtual_address
                    < getattr(section, "virtual_size", getattr(section, "size", 0))
                ):
                    offset_in_section = virtual_address - section.virtual_address
                    content = bytes(section.content)
                    if offset_in_section + size <= len(content):
                        return content[
                            offset_in_section : offset_in_section + size
                        ]
        except Exception:  # noqa: BLE001
            # Fallback for raw binaries or when offset mapping fails
            pass

        # Last resort: treat VA as file offset (common for shellcode)
        with self.path.open("rb") as f:
            f.seek(virtual_address)
            return f.read(size)

    def entropy(self) -> float:
        """Compute Shannon entropy of the full binary file."""
        try:
            with self.path.open("rb") as f:
                data = f.read()
            return calculate_entropy(data)
        except Exception:  # noqa: BLE001
            return 0.0


if __name__ == "__main__":
    # Simple smoke test
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"\x90\x90\xC3")  # NOP NOP RET
        tmp_path = tmp.name
    try:
        b = Binary(tmp_path)
        print(f"Format: {b.format}, Arch: {b.architecture}, EP: {hex(b.entry_point())}")
        print(f"Strings: {len(b.strings())}, Entropy: {b.entropy():.3f}")
    finally:
        Path(tmp_path).unlink()
