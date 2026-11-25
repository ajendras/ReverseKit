"""Core module providing the Binary abstraction using LIEF.

This is the foundation of RevKit. Handles loading of multiple binary formats
(ELF, PE, Mach-O, DEX, WASM, DOTNET, RAW), metadata extraction, string scanning, entropy calculation
and memory access for disassembly.

Dedicated native parsers (MachOParser, DEXParser, WasmParser, DotNetParser) provide format-specific
handling while reusing LIEF where possible. RAW format is used for flat
binaries, shellcode and files that LIEF cannot parse (e.g. empty files).
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
                state = getattr(cmd, "state", {})
                if isinstance(state, dict) and "pc" in state:
                    return state["pc"]
        return int(getattr(self.binary, "entrypoint", 0))

    def sections(self) -> list[Any]:
        """Return segments as sections for compatibility."""
        return self.segments


class DEXParser:
    """Native parser for Android DEX files.

    Extracts classes, methods and basic metadata.
    """

    def __init__(self, lief_binary: Any) -> None:
        self.binary = lief_binary
        self.classes: list[Any] = list(getattr(lief_binary, "classes", []))

    def entry_point(self) -> int:
        """DEX entrypoint is usually the first method."""
        return 0x0  # DEX does not have a classic entry point

    def methods(self) -> list[str]:
        """Return list of method names."""
        return [m.name for cls in self.classes for m in getattr(cls, "methods", []) if hasattr(m, "name")]


class WasmParser:
    """Native parser for WebAssembly (WASM) modules.

    Uses LIEF WASM support for sections, exports (functions) and metadata.
    """

    def __init__(self, lief_binary: Any) -> None:
        self.binary = lief_binary
        self.functions: list[Any] = list(getattr(lief_binary, "exported_functions", []))

    def entry_point(self) -> int:
        """WASM modules have no traditional entrypoint; return 0 or first export."""
        for f in self.functions:
            if getattr(f, "name", "") in ("_start", "main", "start"):
                return 0
        return 0

    def sections(self) -> list[Any]:
        return list(getattr(self.binary, "sections", []))

    def symbols(self) -> list[Any]:
        return self.functions


class DotNetParser:
    """Parser for .NET managed assemblies (PE with .NET metadata).

    Leverages LIEF .NET metadata for methods, entrypoint token and classes.
    """

    def __init__(self, lief_binary: Any) -> None:
        self.binary = lief_binary
        self._dotnet = getattr(lief_binary, "dotnet", None)
        self.methods: list[Any] = list(getattr(self._dotnet, "methods", [])) if self._dotnet else []

    def entry_point(self) -> int:
        """Return entry point from .NET metadata or fall back to PE entrypoint."""
        if self._dotnet and hasattr(self._dotnet, "entrypoint_token") and self._dotnet.entrypoint_token:
            return int(getattr(self.binary, "entrypoint", 0))
        return int(getattr(self.binary, "entrypoint", 0))

    def sections(self) -> list[Any]:
        return list(getattr(self.binary, "sections", []))

    def symbols(self) -> list[Any]:
        return self.methods

    def methods(self) -> list[str]:
        """Return list of .NET method names."""
        return [getattr(m, "name", "unknown") for m in self.methods if hasattr(m, "name")]


class Binary:
    """Universal binary loader with format-specific parsers and analysis helpers.

    Supports ELF, PE, Mach-O, DEX, WASM, DOTNET, and RAW (flat/shellcode) binaries via LIEF
    with native fallback parsers. Provides lazy access to disassembly, strings,
    symbols, CFG, tracing and FLIRT matching.
    """

    def __init__(self, path: str | Path) -> None:
        """Load binary from disk.

        Args:
            path: Path to binary file.

        Raises:
            FileNotFoundError: If path does not exist.
            ValueError: If format cannot be handled.
        """
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"Binary not found: {path}")

        self.format = self._detect_format()
        self._binary: Any = None
        self._parser: Any = None
        self.r2bridge: Any = None
        self.ai_annotations: dict[int, dict[str, str]] = {}
        self._annotated_functions: dict[int, Any] = {}
        self.base_address = 0x0
        self._strings: list[str] = []
        self._symbols: list[Any] = []
        self._sections: list[Any] = []
        self._entry_point: int = 0
        self._architecture: str | None = None

        self._load()

    def _detect_format(self) -> str:
        """Return normalized format string."""
        data = self.path.read_bytes()[:512]
        suffix = self.path.suffix.lower()
        if data.startswith(b"\x00asm"):
            return "WASM"
        if data.startswith(b"MZ") and (b"CLR" in data or b"BSJB" in data):
            return "DOTNET"
        if suffix in (".elf", ".so", "") and data.startswith(b"\x7fELF"):
            return "ELF"
        if suffix in (".exe", ".dll", ".pe") and data.startswith(b"MZ"):
            return "PE"
        if suffix in (".mach-o", ".dylib", "") and (
            b"\xcf\xfa\xed\xfe" in data[:16]
            or b"\xce\xfa\xed\xfe" in data[:16]
            or b"\xfe\xed\xfa\xce" in data[:16]
            or b"\xfe\xed\xfa\xcf" in data[:16]
        ):
            return "MachO"
        if suffix == ".dex" or b"dex\n" in data:
            return "DEX"
        return "RAW"

    def _load(self) -> None:
        """Load via LIEF or native parser, with RAW fallback."""
        try:
            if self.format == "RAW":
                self._binary = self.path.read_bytes()
                self.base_address = 0x0
                self._entry_point = 0x0
                self._architecture = "x86_64"
                return

            self._binary = lief.parse(str(self.path))
            if self._binary is None:
                raise ValueError("LIEF could not parse binary")

            if self.format == "WASM":
                self._parser = WasmParser(self._binary)
                self.base_address = 0x0
                self._entry_point = self._parser.entry_point()
                self._architecture = "wasm"
                self._sections = self._parser.sections()
            elif self.format == "DOTNET":
                self._parser = DotNetParser(self._binary)
                self.base_address = int(getattr(self._binary, "imagebase", 0x400000))
                self._entry_point = self._parser.entry_point()
                self._architecture = "x86_64"
                self._sections = self._parser.sections()
            elif self.format == "MachO":
                self._parser = MachOParser(self._binary)
                self.base_address = int(getattr(self._binary, "imagebase", 0x100000000))
                self._entry_point = self._parser.entry_point()
                self._architecture = "x86_64"
                self._sections = self._parser.sections()
            elif self.format == "DEX":
                self._parser = DEXParser(self._binary)
                self.base_address = 0x0
                self._entry_point = 0x0
                self._architecture = "dalvik"
                self._sections = []
            else:
                self.base_address = int(getattr(self._binary, "imagebase", 0x400000))
                self._entry_point = int(getattr(self._binary, "entrypoint", 0))
                self._architecture = (
                    self._binary.header.architecture.name
                    if hasattr(self._binary.header, "architecture")
                    else None
                )
                self._sections = list(self._binary.sections) if hasattr(self._binary, "sections") else []

        except Exception as exc:  # fallback to RAW for malformed/flat files
            self.format = "RAW"
            self._binary = self.path.read_bytes()
            self.base_address = 0x0
            self._entry_point = 0x0
            self._architecture = "x86_64"

    def entry_point(self) -> int:
        """Return virtual address of entry point."""
        if self._parser and hasattr(self._parser, "entry_point"):
            return self._parser.entry_point()
        return self._entry_point

    def sections(self) -> list[Any]:
        """Return list of sections/segments."""
        if self._parser and hasattr(self._parser, "sections"):
            return self._parser.sections()
        return self._sections

    def symbols(self) -> list[Any]:
        """Return exported/imported symbols."""
        if not self._symbols:
            if self._parser and hasattr(self._parser, "symbols"):
                self._symbols = self._parser.symbols()
            elif hasattr(self._binary, "symbols"):
                self._symbols = list(self._binary.symbols)
            elif hasattr(self._binary, "exported_functions"):
                self._symbols = list(self._binary.exported_functions)
            elif self.format == "DOTNET" and self._parser and hasattr(self._parser, "methods"):
                self._symbols = self._parser.methods()
        return self._symbols

    def strings(self) -> list[str]:
        """Extract printable strings (minimum 4 chars)."""
        if not self._strings:
            try:
                content = self.read_bytes()
                self._strings = [
                    s.decode("ascii", errors="ignore")
                    for s in content.split(b"\x00")
                    if len(s) >= 4 and s.decode("ascii", errors="ignore").isprintable()
                ]
            except Exception:
                self._strings = []
        return self._strings

    def entropy(self) -> float:
        """Compute Shannon entropy of the binary content."""
        try:
            content = self.read_bytes()
            return calculate_entropy(content)
        except Exception:
            return 0.0

    def read_bytes(self, start: int = 0, length: int | None = None) -> bytes:
        """Read raw bytes from the binary (virtual or file offset).

        For RAW binaries returns the full content.
        """
        if self.format == "RAW" or isinstance(self._binary, bytes):
            data = self._binary if isinstance(self._binary, bytes) else self.path.read_bytes()
            if length is None:
                return data[start:]
            return data[start : start + length]

        # LIEF virtual read
        try:
            if length is None:
                length = 0
            return bytes(
                self._binary.get_content_from_virtual_address(
                    start or self.base_address, length or len(self.path.read_bytes())
                )
            )
        except Exception:
            # fallback to full file
            return self.path.read_bytes()

    def enable_r2(self) -> None:
        """Enable Radare2 bridge for advanced analysis."""
        from .r2bridge import R2Bridge

        self.r2bridge = R2Bridge(self)

    def match_flirt(self, download: bool = True) -> dict[int, str]:
        """Run FLIRT signature matching via scanner.

        Args:
            download: Whether to download/refresh signature database.

        Returns:
            Dict of VA to matched library function name (guaranteed to be str).
        """
        from .scanner import FlirtMatcher

        matcher = FlirtMatcher(self)
        matches = matcher.match(download=download)
        # Normalize names to str for JSON compatibility in reports/tests.
        # FLIRT signature databases can return bytes for symbol names.
        normalized: dict[int, str] = {}
        for addr, name in matches.items():
            if isinstance(name, bytes):
                normalized[addr] = name.decode("utf-8", errors="replace")
            elif isinstance(name, str):
                normalized[addr] = name
            else:
                normalized[addr] = str(name)
        return normalized

    def trace(self, start: int | None = None, steps: int = 10000, trace_regs: bool = False) -> list[dict[str, Any]]:
        """Run Unicorn-based dynamic tracing.

        Delegates to UnicornTracer. Raises a clear RuntimeError if the
        Unicorn engine is not available (supports test environments that
        simulate missing dependencies).

        Args:
            start: Virtual address to start emulation (default: entry point).
            steps: Maximum number of instructions to emulate.
            trace_regs: Whether to record CPU registers after each instruction.

        Returns:
            List of trace entries (address, instruction, optional registers).

        Raises:
            RuntimeError: If Unicorn is unavailable or emulation fails.
        """
        try:
            from .tracer import UnicornTracer
        except ImportError as exc:
            raise RuntimeError(
                "Unicorn engine is required for dynamic tracing. "
                "Install with: pip install unicorn>=2.0.1"
            ) from exc
        if UnicornTracer is None:
            raise RuntimeError("UnicornTracer is not available.")
        tracer = UnicornTracer()
        return tracer.trace(self, start=start, steps=steps, trace_regs=trace_regs)

    @property
    def architecture(self) -> str | None:
        """Return detected architecture string."""
        return self._architecture


if __name__ == "__main__":
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x90\x90\xc3")
        tmp = f.name
    try:
        b = Binary(tmp)
        print(f"Loaded {b.format} binary, EP=0x{b.entry_point():x}, entropy={b.entropy():.2f}")
    finally:
        Path(tmp).unlink(missing_ok=True)
