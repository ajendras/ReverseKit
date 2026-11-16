"""RevKit — All-in-one binary analysis toolkit with local LLM support.

Provides a clean public API for loading binaries, disassembly, AI annotation,
CFG generation and report creation. Designed for both interactive CLI use
and as an importable library for automation pipelines.

The Binary class now includes dedicated native parsers for Mach-O
(segments, load commands) and Android DEX (classes, methods).
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
    "analyze",
    "disassemble",
    "annotate",
    "generate_report",
]


def analyze(
    path: str,
    *,
    arch: str = "auto",
    ai: bool = False,
    report: str = "html",
    output: str | None = None,
) -> dict[str, Any]:
    """Run a complete analysis pipeline on a binary.

    Loads the binary via LIEF, performs disassembly, optionally annotates
    functions and variables using a local Ollama model, then produces
    a rich report.

    Args:
        path: Filesystem path to the binary (ELF, PE, Mach-O, DEX, etc.).
        arch: Architecture hint. "auto" uses LIEF detection mapped to Capstone.
        ai: Enable local LLM annotation (requires Ollama running with a model).
        report: Report format — one of "html", "markdown", "json".
        output: If provided, report is also written to this path.

    Returns:
        Dictionary with analysis summary, statistics and report content.

    Raises:
        FileNotFoundError: Binary does not exist.
        ValueError: Unsupported format or architecture.
        RuntimeError: AI annotation requested but Ollama unavailable.
    """
    if not Path(path).exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    binary = Binary(path)

    if ai:
        annotator = AIAnnotator()
        binary = annotator.batch_annotate(binary)

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
        arch: Architecture (x86, arm, riscv, etc.).

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
