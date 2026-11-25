"""RevKit — All-in-one binary analysis toolkit with local LLM support.

Provides a clean public API for loading binaries, disassembly, AI annotation,
CFG generation and report creation. Designed for both interactive CLI use
and as an importable library for automation pipelines.

The Binary class now includes dedicated native parsers for Mach-O
(segments, load commands), Android DEX (classes, methods), WebAssembly
(exports, sections) and .NET (metadata, methods). Dynamic tracing via
Unicorn is also available through trace() and Binary.trace(). The new
plugin system (revkit.plugin.Analyzer) lets third-party packages register
custom analyzers via the "revkit.analyzers" entry point group; they are
executed by analyze(plugins=[...]) and their results are merged into the
returned dictionary.

FLIRT support via FlirtMatcher (downloader + byte-pattern matcher for
common library functions) is available through Binary.match_flirt(),
VulnScanner, analyze(flirt=True) and the new match_flirt() helper.

Headless Ghidra support via GhidraDecompiler (analyzeHeadless + embedded
postScript) is available through Binary.enable_ghidra(), Binary.decompile(),
analyze(ghidra=True) and the new decompile() helper.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

from .core import Binary
from .disasm import disassemble_range
from .annotator import AIAnnotator
from .report import ReportGenerator
from .graph import CFGBuilder
from .r2bridge import R2Bridge
from .plugin import Analyzer, run_plugins
from .scanner import FlirtMatcher, VulnScanner
from .ghidra import GhidraDecompiler

# UnicornTracer is conditional to support test environments that simulate
# a missing unicorn dependency without breaking module import.
try:
    from .tracer import UnicornTracer
except ImportError:
    UnicornTracer = None  # type: ignore[assignment]

try:
    __version__ = importlib.metadata.version("revkit")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = [
    "__version__",
    "Binary",
    "AIAnnotator",
    "CFGBuilder",
    "ReportGenerator",
    "R2Bridge",
    "UnicornTracer",
    "Analyzer",
    "FlirtMatcher",
    "VulnScanner",
    "GhidraDecompiler",
    "analyze",
    "disassemble",
    "annotate",
    "generate_report",
    "trace",
    "match_flirt",
    "decompile",
]


def analyze(
    path: str,
    *,
    arch: str = "auto",
    ai: bool = False,
    r2: bool = False,
    flirt: bool = False,
    ghidra: bool = False,
    report: str = "html",
    output: str | None = None,
    plugins: list[str] | None = None,
) -> dict[str, Any]:
    """Run a complete analysis pipeline on a binary.

    Loads the binary via LIEF, performs disassembly, optionally annotates
    functions and variables using a local Ollama model, optionally enables
    the Radare2 bridge for advanced graphs and emulation, optionally runs
    FLIRT signature matching for library function identification, optionally
    runs registered third-party Analyzer plugins, optionally enables headless
    Ghidra decompilation, then produces a rich report.

    Args:
        path: Filesystem path to the binary (ELF, PE, Mach-O, DEX, WASM,
              .NET, etc.).
        arch: Architecture hint. "auto" uses LIEF detection mapped to Capstone.
        ai: Enable local LLM annotation (requires Ollama running with a model).
        r2: Enable Radare2 bridge for advanced CFG and ESIL emulation
            (requires r2pipe and radare2).
        flirt: Enable FLIRT signature database download + matching for
            library function identification.
        ghidra: Enable headless Ghidra decompilation (requires GHIDRA_HOME).
        report: Report format — one of "html", "markdown", "json".
        output: If provided, report is also written to this path.
        plugins: Optional list of analyzer names to run (discovered via the
            "revkit.analyzers" entry point group). If omitted, no plugins run.

    Returns:
        Dictionary with analysis summary, statistics, plugin results, FLIRT
        matches, decompiled functions and report content.

    Raises:
        FileNotFoundError: Binary does not exist.
        ValueError: Unsupported format or architecture.
        RuntimeError: AI annotation requested but Ollama unavailable.
    """
    if not Path(path).exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    binary = Binary(path)

    if r2:
        binary.enable_r2()

    if ai:
        annotator = AIAnnotator()
        binary = annotator.batch_annotate(binary)

    plugin_results: list[dict[str, Any]] = []
    if plugins:
        plugin_results = run_plugins(binary, plugins)

    flirt_results: dict[int, str] = {}
    if flirt:
        flirt_results = binary.match_flirt()

    ghidra_enabled = False
    decompiled: dict[str, str] = {}
    if ghidra:
        binary.enable_ghidra()
        ghidra_enabled = True
        try:
            decompiled["main"] = binary.decompile("main")
        except Exception:  # noqa: BLE001
            decompiled["main"] = "// decompilation failed"

    generator = ReportGenerator(binary)

    report_content: str | dict[str, Any]
    if report == "json":
        report_content = generator.to_json()
    elif report == "markdown":
        report_content = generator.to_markdown()
    else:
        report_content = generator.to_html()

    if output is not None:
        out_path = Path(output)
        if report == "json":
            out_path.write_text(str(report_content))
        else:
            out_path.write_text(report_content)

    return {
        "path": path,
        "format": binary.format,
        "architecture": binary.architecture or arch,
        "entry_point": hex(binary.entry_point()),
        "sections": len(binary.sections()),
        "symbols": len(binary.symbols()),
        "strings": len(binary.strings()),
        "entropy": round(binary.entropy(), 4),
        "ai_annotated": ai,
        "r2_enabled": bool(getattr(binary, "r2bridge", None)),
        "flirt_enabled": flirt,
        "flirt_matches": len(flirt_results),
        "flirt": flirt_results,
        "ghidra_enabled": ghidra_enabled,
        "decompiled_functions": len(decompiled),
        "decompiled": decompiled,
        "plugin_count": len(plugin_results),
        "plugins": plugin_results,
        "report_format": report,
        "report": report_content,
    }


def disassemble(
    path: str,
    start: int | None = None,
    length: int = 64,
    arch: str = "auto",
) -> str:
    """Disassemble a region of the binary to readable assembly.

    Args:
        path: Path to binary file.
        start: Virtual address to begin disassembly. Defaults to entry point.
        length: Number of bytes to disassemble.
        arch: Architecture (x86, arm, riscv, wasm, dotnet, etc.).

    Returns:
        Multi-line string containing disassembly with addresses and bytes.
    """
    binary = Binary(path)
    if start is None:
        start = binary.entry_point()
    return disassemble_range(binary, start, length, arch=arch)


def annotate(path: str) -> Binary:
    """Annotate a binary with AI-suggested names and comments.

    Requires Ollama running locally with a capable model (e.g. codellama).

    Args:
        path: Path to the binary.

    Returns:
        Binary instance with added annotations (functions, variables, comments).
    """
    binary = Binary(path)
    annotator = AIAnnotator()
    return annotator.batch_annotate(binary)


def generate_report(
    binary: Binary, fmt: str = "html", output: str | None = None
) -> str | dict[str, Any]:
    """Generate a formatted analysis report.

    Args:
        binary: Binary instance (may be AI-annotated).
        fmt: One of "html", "markdown", "json".
        output: Optional path to write the report to disk.

    Returns:
        Report content as string (HTML/Markdown) or dict (JSON).
    """
    generator = ReportGenerator(binary)
    content: str | dict[str, Any]

    if fmt == "json":
        content = generator.to_json()
    elif fmt == "markdown":
        content = generator.to_markdown()
    else:
        content = generator.to_html()

    if output is not None:
        Path(output).write_text(str(content) if isinstance(content, dict) else content)

    return content


def trace(
    path: str,
    start: int | None = None,
    steps: int = 10000,
    trace_regs: bool = False,
) -> list[dict[str, Any]]:
    """Run dynamic tracing with the Unicorn emulator.

    Emulates code from the entry point (or a custom start address) and
    returns a list of executed instructions. Optionally captures register
    state at each step. Works best on flat binaries and shellcode.

    Args:
        path: Path to the binary or shellcode.
        start: Virtual address to start emulation (default: entry point).
        steps: Maximum number of instructions to emulate.
        trace_regs: Whether to record CPU registers after each instruction.

    Returns:
        List of trace entries (address, instruction, optional registers).

    Raises:
        RuntimeError: If Unicorn is unavailable or emulation fails catastrophically.
    """
    if not Path(path).exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    if UnicornTracer is None:
        raise RuntimeError(
            "Unicorn is not installed. Dynamic tracing is unavailable. "
            "Install with: pip install unicorn>=2.0.1"
        )

    binary = Binary(path)
    tracer = UnicornTracer()
    return tracer.trace(binary, start=start, steps=steps, trace_regs=trace_regs)


def match_flirt(path: str, download: bool = True) -> dict[int, str]:
    """Run FLIRT signature matching on a binary.

    Downloads the signature database (if requested) and returns a mapping
    of addresses to identified library function names.

    Args:
        path: Path to the binary.
        download: Whether to (re)download the FLIRT signature database.

    Returns:
        Dict mapping virtual addresses to matched library function names.
    """
    if not Path(path).exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    binary = Binary(path)
    return binary.match_flirt(download=download)


def decompile(path: str, function: str = "main") -> str:
    """Decompile a function to C using headless Ghidra.

    Requires Ghidra installed with GHIDRA_HOME set.

    Args:
        path: Path to the binary.
        function: Function name or symbol to decompile.

    Returns:
        C pseudocode (or explanatory message if Ghidra unavailable).
    """
    if not Path(path).exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    binary = Binary(path)
    binary.enable_ghidra()
    return binary.decompile(function)
