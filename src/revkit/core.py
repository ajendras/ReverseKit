"""Core module providing the Binary abstraction using LIEF.

This is the foundation of RevKit. Handles loading of multiple binary formats
(ELF, PE, Mach-O, DEX), metadata extraction, string scanning, entropy calculation
and memory access for disassembly.

Dedicated native parsers (MachOParser, DEXParser) provide format-specific
handling while reusing LIEF where possible.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import lief

from .utils import calculate_entropy


class MachOParser:
    """Native parser for Mach-O binaries.

    Exposes segments, load commands and handles Mach-O specific quirks
    (fat binaries, thread state for entrypoint, etc.).
    """

    def __init__(self, lief_binary: Any) -> None:
        self.binary = lief_binary
        self.segments: list[Any] = list(lief_binary.segments) if hasattr(lief_binary, "segments") else []
        self.load_commands: list[Any] = list(lief_binary.commands) if hasattr(lief_binary, "commands") else []

    def entry_point(self) -> int:
        """Return entry point, preferring thread state from LC_MAIN/LC_UNIXTHREAD."""
        for cmd in self.load_commands:
            if hasattr(cmd, "pc") and cmd.pc != 0:
                return cmd.pc
            if isinstance(cmd, lief.MachO.ThreadCommand) and hasattr(cmd, "state"):
                # Simplified extraction; real impl would parse register state
                if hasattr(cmd.state, "rip"):
                    return cmd.state.rip
                if hasattr(cmd.state, "pc"):
                    return cmd.state.pc
        return getattr(self.binary, "entrypoint", 0)

    def sections(self) -> list[Any]:
        """Return sections (Mach-O uses segments + sections)."""
        if hasattr(self.binary, "sections"):
            return list(self.binary.sections)
        return []

    def symbols(self) -> list[Any]:
        """Return symbols (exported, imported, etc.)."""
        symbols: list[Any] = []
        if hasattr(self.binary, "symbols"):
            symbols.extend(self.binary.symbols)
        if hasattr(self.binary, "exports"):
            symbols.extend(self.binary.exports)
        return symbols


class DEXParser:
    """Native parser for Android DEX files.

    Extracts classes, methods, types and provides symbol-like view over
    the Dalvik/ART structures. DEX has no traditional virtual memory layout.
    """

    def __init__(self, lief_binary: Any) -> None:
        self.binary = lief_binary
        self.classes: list[Any] = list(lief_binary.classes) if hasattr(lief_binary, "classes") else []

    def entry_point(self) -> int:
        """DEX files have no single native entrypoint. Return 0 or first 'main' offset."""
        for cls in self.classes:
            for method in getattr(cls, "methods", []):
                if getattr(method, "name", "") in ("main", "<clinit>"):
                    # Could map to code_item offset but we keep simple for now
                    return 0
        return 0

    def sections(self) -> list[Any]:
        """DEX does not have classic sections; return empty or synthetic list."""
        return []

    def symbols(self) -> list[Any]:
        """Synthesize symbol list from classes and methods (common in DEX)."""
        symbols: list[Any] = []
        for cls in self.classes:
            cls_name = getattr(cls, "name", "UnknownClass")
            for method in getattr(cls, "methods", []):
                meth_name = getattr(method, "name", "unknown")
                sym = type(
                    "Symbol",
                    (),
                    {
                        "name": f"{cls_name}.{meth_name}",
                        "value": 0,
                        "is_method": True,
                    },
                )()
                symbols.append(sym)
        return symbols


class Binary:
    """Loaded binary with high-level analysis interface.

    Wraps a LIEF parsed binary and augments it with common reverse engineering
    operations. Uses dedicated native parsers for Mach-O and DEX formats.
    Designed to be passed between analysis modules (disasm, graph,
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
        self.parser: MachOParser | DEXParser | None = None
        if self.format == "Mach-O":
            self.parser = MachOParser(self._binary)
        elif self.format == "DEX":
            self.parser = DEXParser(self._binary)
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
        """Map LIEF architecture to Capstone-compatible name.

        Extended with native handling for Mach-O CPU types and DEX.
        """
        if isinstance(self._binary, lief.MachO.Binary):
            cpu = getattr(self._binary.header, "cpu_type", None)
            if cpu == lief.MachO.CPU_TYPE.X86_64:
                return "x86_64"
            if cpu == lief.MachO.CPU_TYPE.X86:
                return "x86"
            if cpu == lief.MachO.CPU_TYPE.ARM64:
                return "arm64"
            if cpu == lief.MachO.CPU_TYPE.ARM:
                return "arm"
            return "unknown"

        if isinstance(self._binary, lief.DEX.Binary):
            # DEX is bytecode; many Android DEXes target ARM devices.
            # We default to arm but disassembly may need a dedicated DEX
            # backend in a future version.
            return "arm"

        arch_map = {
            lief.ARCHITECTURES.X86_64: "x86_64",
            lief.ARCHITECTURES.X86: "x86",
            lief.ARCHITECTURES.ARM: "arm",
            lief.ARCHITECTURES.ARM64: "arm64",
            lief.ARCHITECTURES.MIPS: "mips",
            lief.ARCHITECTURES.RISCV: "riscv",
            lief.ARCHITECTURES.WASM: "wasm",
        }

        if hasattr(self._binary, "header") and hasattr(
            self._binary.header, "architecture"
        ):
            arch = self._binary.header.architecture
            return arch_map.get(arch, "unknown")

        if self.format == "ELF" and hasattr(self._binary, "header"):
            machine = self._binary.header.machine_type
            if machine in (lief.ELF.ARCH.x86_64, lief.ELF.ARCH.i386):
                return "x86_64" if machine == lief.ELF.ARCH.x86_64 else "x86"
            if "ARM" in str(machine):
                return "arm"
        return "unknown"

    def entry_point(self) -> int:
        """Return the program entry point virtual address.

        Delegates to native parser when available.
        """
        if self.parser is not None and hasattr(self.parser, "entry_point"):
            return self.parser.entry_point()
        return getattr(self._binary, "entrypoint", 0)

    def sections(self) -> list[Any]:
        """Return all sections as LIEF section objects.

        Uses native parser for Mach-O/DEX when present.
        """
        if self.parser is not None and hasattr(self.parser, "sections"):
            return self.parser.sections()
        if hasattr(self._binary, "sections"):
            return list(self._binary.sections)
        return []

    def symbols(self) -> list[Any]:
        """Return symbols from the binary (dynamic, static, exports).

        Uses native parser for Mach-O/DEX when present.
        """
        if self.parser is not None and hasattr(self.parser, "symbols"):
            return self.parser.symbols()
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
        raw read for flat binaries. DEX uses file offset directly.
        """
        if self.format == "DEX":
            # DEX uses file offsets for code items; treat VA as file offset
            with self.path.open("rb") as f:
                f.seek(virtual_address)
                return f.read(size)

        try:
            # Prefer LIEF offset mapping (works for ELF, PE, Mach-O)
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
