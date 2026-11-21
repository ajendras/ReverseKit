"""Core module providing the Binary abstraction using LIEF.

This is the foundation of RevKit. Handles loading of multiple binary formats
(ELF, PE, Mach-O, DEX, RAW), metadata extraction, string scanning, entropy calculation
and memory access for disassembly.

Dedicated native parsers (MachOParser, DEXParser) provide format-specific
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
    Falls back to RAW mode for shellcode, flat binaries and files LIEF cannot
    parse (including empty files). Designed to be passed between analysis
    modules (disasm, graph, annotator, report).
    """

    def __init__(self, path: str | Path) -> None:
        """Load a binary from disk using LIEF.

        Args:
            path: Path to the binary file.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file cannot be parsed and is not a raw binary.
        """
        self.path = Path(path).resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"Binary not found or not a file: {self.path}")

        self._strings: list[str] | None = None
        self.parser: MachOParser | DEXParser | None = None
        self.r2bridge: Any = None

        try:
            parsed = lief.parse(str(self.path))
            if parsed is None:
                self._binary = None
                self.format = "RAW"
                self.architecture = "unknown"
            else:
                self._binary = parsed
                self.format = self._detect_format()
                self.architecture = self._detect_architecture()
                if self.format == "Mach-O":
                    self.parser = MachOParser(self._binary)
                elif self.format == "DEX":
                    self.parser = DEXParser(self._binary)
        except Exception as exc:
            raise ValueError(
                f"Failed to parse {self.path.name} with LIEF. "
                f"Format may be unsupported or file corrupted: {exc}"
            ) from exc

    def _detect_format(self) -> str:
        """Return normalized format name based on LIEF type."""
        if isinstance(self._binary, lief.ELF.Binary):
            return "ELF"
        if isinstance(self._binary, lief.PE.Binary):
            return "PE"
        if isinstance(self._binary, lief.MachO.Binary):
            return "Mach-O"
        # Safe DEX check to avoid AttributeError on some LIEF builds (e.g. py3.11 CI)
        try:
            if isinstance(self._binary, lief.DEX.Binary):
                return "DEX"
        except AttributeError:
            if "DEX" in str(type(self._binary)) or hasattr(self._binary, "dex_header"):
                return "DEX"
        return "Unknown"

    def _detect_architecture(self) -> str:
        """Map LIEF architecture to Capstone-compatible name.

        Extended with native handling for Mach-O CPU types and DEX.
        Defensive against LIEF builds where lief.ARCH is unavailable
        (e.g. some py3.11 CI environments) by falling back to string-based
        enum inspection.
        """
        if self._binary is None:
            return "unknown"

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

        # Safe DEX check to avoid AttributeError on some LIEF builds (e.g. py3.11 CI)
        try:
            if isinstance(self._binary, lief.DEX.Binary):
                return "arm"
        except AttributeError:
            if "DEX" in str(type(self._binary)) or hasattr(self._binary, "dex_header"):
                return "arm"

        if hasattr(self._binary, "header") and hasattr(
            self._binary.header, "architecture"
        ):
            arch = self._binary.header.architecture
            try:
                arch_map = {
                    lief.ARCH.X86_64: "x86_64",
                    lief.ARCH.X86: "x86",
                    lief.ARCH.ARM: "arm",
                    lief.ARCH.ARM64: "arm64",
                    lief.ARCH.MIPS: "mips",
                    lief.ARCH.RISCV: "riscv",
                    lief.ARCH.WASM: "wasm",
                }
                return arch_map.get(arch, "unknown")
            except AttributeError:
                # LIEF without top-level ARCH (root cause of py3.11 CI failure);
                # fall back to reliable string inspection of the enum
                arch_str = str(arch).upper()
                if "X86_64" in arch_str or "AMD64" in arch_str:
                    return "x86_64"
                if "X86" in arch_str or "I386" in arch_str:
                    return "x86"
                if "ARM64" in arch_str or "AARCH64" in arch_str:
                    return "arm64"
                if "ARM" in arch_str:
                    return "arm"
                if "MIPS" in arch_str:
                    return "mips"
                if "RISCV" in arch_str:
                    return "riscv"
                if "WASM" in arch_str:
                    return "wasm"

        # ELF specific fallback
        if self.format == "ELF" and hasattr(self._binary, "header"):
            machine = self._binary.header.machine_type
            try:
                if machine in (lief.ELF.ARCH.x86_64, lief.ELF.ARCH.i386):
                    return "x86_64" if machine == lief.ELF.ARCH.x86_64 else "x86"
                if "ARM" in str(machine):
                    return "arm"
            except AttributeError:
                mstr = str(machine).upper()
                if "X86_64" in mstr or "AMD64" in mstr:
                    return "x86_64"
                if "386" in mstr or "X86" in mstr:
                    return "x86"
                if "ARM" in mstr:
                    return "arm"

        return "unknown"

    def entry_point(self) -> int:
        """Return the program entry point virtual address.

        Delegates to native parser when available. RAW binaries return 0.
        """
        if self.format == "RAW" or self._binary is None:
            return 0
        if self.parser is not None and hasattr(self.parser, "entry_point"):
            return self.parser.entry_point()
        return getattr(self._binary, "entrypoint", 0)

    def sections(self) -> list[Any]:
        """Return all sections as LIEF section objects.

        Uses native parser for Mach-O/DEX when present. RAW returns [].
        """
        if self.format == "RAW" or self._binary is None:
            return []
        if self.parser is not None and hasattr(self.parser, "sections"):
            return self.parser.sections()
        if hasattr(self._binary, "sections"):
            return list(self._binary.sections)
        return []

    def symbols(self) -> list[Any]:
        """Return symbols from the binary (dynamic, static, exports).

        Uses native parser for Mach-O/DEX when present. RAW returns [].
        """
        if self.format == "RAW" or self._binary is None:
            return []
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

    def _segments(self) -> list[Any]:
        """Return segments (PT_LOAD, etc.) for VA-to-file-offset mapping.

        Works for ELF, PE, Mach-O. Returns empty list for RAW/DEX.
        """
        if self._binary is None:
            return []
        if hasattr(self._binary, "segments"):
            segments = self._binary.segments
            return list(segments) if hasattr(segments, "__iter__") else []
        if hasattr(self._binary, "program_headers"):
            return list(self._binary.program_headers)
        return []

    def _read_file_at(self, offset: int, size: int) -> bytes:
        """Read bytes from a file offset. Raises if zero bytes could be read."""
        with self.path.open("rb") as f:
            f.seek(offset)
            data = f.read(size)
        if len(data) == 0:
            raise RuntimeError(
                f"Failed to read any bytes at offset {hex(offset)}. "
                f"File may be too small or offset invalid."
            )
        return data

    def read_bytes(self, virtual_address: int, size: int) -> bytes:
        """Read bytes from a virtual address.

        1. RAW/DEX/None: direct file offset read.
        2. LIEF virtual_address_to_offset (may return None on py3.11 for
           valid addresses).
        3. Segment/PT_LOAD lookup (VA -> file_offset + delta). This is the
           key fix for py3.11 CI failures and binaries without section headers.
        4. Section content (for pre-loaded data).
        5. Final fallback (VA as file offset, e.g. ELF header at VA 0).

        Returns as many bytes as available (up to size). Only raises on
        complete failure to read anything.

        Raises:
            ValueError: On negative size.
            RuntimeError: If no bytes could be read.
        """
        if size < 0:
            raise ValueError("size must be non-negative")
        if size == 0:
            return b""

        if self.format in ("RAW", "Unknown") or self._binary is None:
            return self._read_file_at(virtual_address, size)

        if self.format == "DEX":
            return self._read_file_at(virtual_address, size)

        # 1. Try LIEF virtual_address_to_offset (primary path)
        if hasattr(self._binary, "virtual_address_to_offset"):
            try:
                offset = self._binary.virtual_address_to_offset(virtual_address)
                if offset is not None and offset >= 0:
                    data = self._read_file_at(offset, size)
                    return data
            except Exception:
                pass  # fall through to segments/sections

        # 2. Segment-based mapping (fixes py3.11 + no-section-header cases)
        for seg in self._segments():
            va = getattr(seg, "virtual_address", getattr(seg, "vaddr", 0))
            vsize = getattr(
                seg,
                "virtual_size",
                getattr(seg, "mem_size", getattr(seg, "size", 0)),
            )
            if va <= virtual_address < va + max(vsize, 1):
                file_off = getattr(
                    seg,
                    "file_offset",
                    getattr(seg, "offset", getattr(seg, "file_offset", 0)),
                )
                offset_in_seg = virtual_address - va
                file_pos = file_off + offset_in_seg
                try:
                    data = self._read_file_at(file_pos, size)
                    return data
                except Exception:
                    continue

        # 3. Section content fallback
        for section in self.sections():
            if not hasattr(section, "virtual_address"):
                continue
            va = getattr(section, "virtual_address", 0)
            vsize = getattr(
                section, "virtual_size", getattr(section, "size", 0)
            )
            if va <= virtual_address < va + max(vsize, 1):
                offset_in_section = virtual_address - va
                try:
                    content = bytes(section.content)
                    if offset_in_section + size <= len(content):
                        return content[
                            offset_in_section : offset_in_section + size
                        ]
                    # fall back to file using section offset if available
                    file_off = getattr(
                        section,
                        "file_offset",
                        getattr(section, "offset", getattr(section, "pointer_to_raw_data", 0)),
                    )
                    if file_off >= 0:
                        file_pos = file_off + offset_in_section
                        return self._read_file_at(file_pos, size)
                except Exception:
                    continue

        # 4. Final fallback: treat VA as file offset (ELF header at 0, etc.)
        return self._read_file_at(virtual_address, size)

    def entropy(self) -> float:
        """Compute Shannon entropy of the full binary file."""
        try:
            with self.path.open("rb") as f:
                data = f.read()
            return calculate_entropy(data)
        except Exception:  # noqa: BLE001
            return 0.0

    def enable_r2(self) -> Any | None:
        """Enable Radare2 bridge if r2pipe is available.

        Returns:
            R2Bridge instance or None if unavailable.
        """
        if self.r2bridge is not None:
            return self.r2bridge

        try:
            from .r2bridge import R2Bridge
            self.r2bridge = R2Bridge(self, auto_analyze=True)
            if not self.r2bridge.is_available():
                self.r2bridge = None
        except Exception:  # noqa: BLE001
            self.r2bridge = None

        return self.r2bridge

    def trace(self, start: int | None = None, steps: int = 10000, trace_regs: bool = False) -> list[dict[str, Any]]:
        """Perform dynamic execution tracing using Unicorn.

        Requires the unicorn package. Emulates from entry_point (or custom start)
        and returns a structured trace log. Best suited for flat binaries and
        shellcode; complex PE/ELF may need additional syscall hooks.

        Args:
            start: Start virtual address (defaults to entry_point()).
            steps: Maximum number of instructions to execute.
            trace_regs: Capture register values after each instruction.

        Returns:
            List of dicts with address, instruction, bytes and optional registers.

        Raises:
            RuntimeError: Unicorn not available or emulation error.
        """
        if start is None:
            start = self.entry_point()

        try:
            from .tracer import UnicornTracer
            tracer = UnicornTracer()
            return tracer.trace(self, start=start, steps=steps, trace_regs=trace_regs)
        except ImportError as exc:
            raise RuntimeError(
                "Unicorn is required for dynamic tracing. "
                "Install via: pip install unicorn"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"Dynamic tracing failed: {exc}") from exc


if __name__ == "__main__":
    # Simple smoke test
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"\x90\x90\xC3" * 20)  # enough bytes for all tests
        tmp_path = tmp.name
    try:
        b = Binary(tmp_path)
        print(f"Format: {b.format}, Arch: {b.architecture}, EP: {hex(b.entry_point())}")
        print(f"Strings: {len(b.strings())}, Entropy: {b.entropy():.3f}")
        # Test the fixed read_bytes paths (including VA=0 fallback and high VA)
        assert len(b.read_bytes(0, 4)) == 4
        assert len(b.read_bytes(0, 16)) >= 3
        # High VA that would previously fail on small files without segment mapping
        assert len(b.read_bytes(0x400078, 32)) > 0
        trace_log = b.trace(steps=5)
        print(f"Trace length: {len(trace_log)}")
        if trace_log:
            print("First trace entry:", trace_log[0])
    finally:
        Path(tmp_path).unlink()
