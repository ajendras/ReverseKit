"""Command-line interface for RevKit.

Implements all documented commands using Typer + Rich with the exact
visual direction: bold monochrome, #111111 background with #ff0044 accents,
oversized headings, high contrast, generous spacing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from revkit import (
    Binary,
    analyze,
    annotate,
    disassemble,
    generate_report,
)
from revkit.annotator import AIAnnotator
from revkit.core import Binary as CoreBinary
from revkit.disasm import disassemble_range, get_function
from revkit.graph import CFGBuilder
from revkit.report import ReportGenerator
from revkit.utils import detect_format, map_arch_to_capstone

app = typer.Typer(
    name="revkit",
    help=Text.from_markup(
        "[bold #ff0044]REVKIT[/bold #ff0044] — binary analysis + local AI",
        style="bold",
    ),
    rich_markup_mode="rich",
    add_completion=True,
    no_args_is_help=True,
)

console = Console(highlight=False, color_system="auto")


def _print_header(title: str) -> None:
    """Print consistent oversized header using project accent color."""
    console.print()
    console.print(
        Panel(
            Text(title, style="bold #ff0044", justify="center"),
            title="revkit",
            title_align="left",
            border_style="#ff0044",
            padding=(1, 2),
            expand=False,
        )
    )
    console.print()


def _validate_binary_path(path: Path) -> Path:
    """Shared validation for binary arguments."""
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {path}")
        raise typer.Exit(1)
    if not path.is_file():
        console.print(f"[bold red]Error:[/bold red] Not a file: {path}")
        raise typer.Exit(1)
    return path


@app.callback()
def callback(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", "-V", help="Show version and exit"),
    ] = False,
) -> None:
    """RevKit CLI entrypoint."""
    if version:
        from revkit import __version__

        console.print(f"RevKit v[bold]{__version__}[/bold]")
        raise typer.Exit()


@app.command("info")
def cmd_info(
    binary: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            help="Path to binary file",
        ),
    ],
    arch: Annotated[str, typer.Option("--arch", "-a", help="Architecture override")] = "auto",
) -> None:
    """Display high-level information about a binary."""
    _print_header("BINARY INFORMATION")
    _validate_binary_path(binary)

    try:
        bin_obj: CoreBinary = Binary(str(binary))
        fmt = detect_format(str(binary))

        table = Table(
            title=f"[bold]{binary.name}[/bold]",
            title_justify="left",
            border_style="#111111",
            show_header=False,
            padding=(0, 2),
        )
        table.add_column("Property", style="bold", width=18)
        table.add_column("Value", style="dim")

        table.add_row("Format", fmt.upper())
        table.add_row("Architecture", bin_obj.architecture or arch)
        table.add_row("Entry point", hex(bin_obj.entry_point()))
        table.add_row("Sections", str(len(bin_obj.sections())))
        table.add_row("Symbols", str(len(bin_obj.symbols())))
        table.add_row("Strings", str(len(bin_obj.strings())))
        table.add_row("Entropy", f"{bin_obj.entropy():.3f}")
        table.add_row("Size", f"{binary.stat().st_size:,} bytes")

        console.print(table)
        console.print()

    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Failed to parse binary:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command("analyze")
def cmd_analyze(
    binary: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    arch: Annotated[str, typer.Option("--arch", "-a")] = "auto",
    ai: Annotated[bool, typer.Option("--ai", help="Enable local Ollama annotation")] = False,
    r2: Annotated[
        bool, typer.Option("--r2", help="Enable Radare2 bridge for advanced graph/emulation")
    ] = False,
    report: Annotated[
        str, typer.Option("--report", "-r", help="Report format")
    ] = "html",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output report path"),
    ] = None,
) -> None:
    """Full analysis pipeline with optional AI and report generation."""
    _print_header("ANALYZING BINARY")
    _validate_binary_path(binary)

    out_path = output or Path(f"revkit_report.{report}")

    try:
        result = analyze(
            str(binary),
            arch=arch,
            ai=ai,
            r2=r2,
            report=report,
            output=str(out_path),
        )

        console.print("[bold green]✓ Analysis completed successfully[/bold green]")
        console.print(f"   Format      : {result['format']}")
        console.print(f"   Architecture: {result['architecture']}")
        console.print(f"   Entry point : {result['entry_point']}")
        console.print(f"   Entropy     : {result['entropy']}")
        console.print(f"   AI annotated: {'yes' if result['ai_annotated'] else 'no'}")
        console.print(f"   R2 enabled  : {'yes' if result.get('r2_enabled', False) else 'no'}")
        console.print(f"   Report      : [bold]{out_path}[/bold]")
        console.print()

    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Analysis failed:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command("disassemble")
def cmd_disassemble(
    binary: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    start: Annotated[
        int | None,
        typer.Option("--start", "-s", help="Start virtual address (default = entry point)"),
    ] = None,
    length: Annotated[int, typer.Option("--length", "-l", help="Bytes to disassemble")] = 128,
    function: Annotated[
        str | None,
        typer.Option("--function", "-f", help="Disassemble specific function by name or address"),
    ] = None,
    arch: Annotated[str, typer.Option("--arch", "-a")] = "auto",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Disassemble code at an address or inside a function."""
    _print_header("DISASSEMBLY")
    _validate_binary_path(binary)

    bin_obj = Binary(str(binary))

    try:
        if function:
            func = get_function(bin_obj, function)
            asm = func.to_asm() if hasattr(func, "to_asm") else str(func)
            console.print(f"Function [bold]{function}[/bold]:\n")
        else:
            if start is None:
                start = bin_obj.entry_point()
            asm = disassemble_range(bin_obj, start, length, arch=arch)
            console.print(
                f"Disassembly from [bold]{hex(start)}[/bold] "
                f"({length} bytes):\n"
            )

        console.print(asm)

        if output:
            output.write_text(asm)
            console.print(f"\n[bold]Written to[/bold] {output}")

    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Disassembly error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command("annotate")
def cmd_annotate(
    binary: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Annotate functions/variables using a local Ollama model."""
    _print_header("AI ANNOTATION")
    _validate_binary_path(binary)

    try:
        console.print("Querying local Ollama for naming and comments...\n")
        bin_obj = annotate(str(binary))

        console.print("[bold green]✓ Annotation complete[/bold green]")
        console.print(f"   Annotated functions : {len(bin_obj.symbols())}")
        console.print(f"   AI model used       : codellama (default)")

        if output:
            # Report with annotations
            report_path = output.with_suffix(".md")
            generate_report(bin_obj, fmt="markdown", output=str(report_path))
            console.print(f"   Annotated report    : {report_path}")

    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Annotation failed:[/bold red] {exc}")
        console.print("Make sure Ollama is running with a model pulled.")
        raise typer.Exit(1) from exc


@app.command("visualize")
def cmd_visualize(
    binary: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    function: Annotated[
        str | None, typer.Option("--function", "-f", help="Function to graph")
    ] = None,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output image path")
    ] = Path("cfg.png"),
    fmt: Annotated[
        str, typer.Option("--format", help="Export format (png, svg, dot)")
    ] = "png",
    r2: Annotated[bool, typer.Option("--r2", help="Use Radare2 for advanced CFG")] = False,
) -> None:
    """Build and export a control-flow graph using NetworkX."""
    _print_header("CONTROL FLOW GRAPH")
    _validate_binary_path(binary)

    bin_obj = Binary(str(binary))
    if r2:
        bin_obj.enable_r2()
        if getattr(bin_obj, "r2bridge", None) and getattr(bin_obj.r2bridge, "is_available", lambda: False)():
            console.print("   [dim]Radare2 bridge activated for advanced CFG[/dim]")

    builder = CFGBuilder(bin_obj)

    try:
        target = function or "main"
        console.print(f"Building CFG for [bold]{target}[/bold]...")
        cfg = builder.build_cfg(target)

        if fmt == "png":
            builder.export_png(output)
        elif fmt == "svg":
            builder.export_svg(str(output.with_suffix(".svg")))
        else:
            builder.export_dot(str(output.with_suffix(".dot")))

        console.print(f"[bold green]✓ Graph exported[/bold green] → [bold]{output}[/bold]")
        console.print(f"   Nodes: {cfg.number_of_nodes()}")
        console.print(f"   Edges: {cfg.number_of_edges()}")

    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Visualization failed:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command("report")
def cmd_report(
    binary: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="html | markdown | json")
    ] = "html",
    output: Annotated[
        Path | None, typer.Option("--output", "-o")
    ] = None,
    ai: Annotated[bool, typer.Option("--ai", help="Include AI annotations")] = False,
) -> None:
    """Generate Markdown, JSON or interactive HTML report with embedded visuals."""
    _print_header("REPORT GENERATION")
    _validate_binary_path(binary)

    bin_obj = Binary(str(binary))

    if ai:
        console.print("Running AI annotation first...")
        annotator = AIAnnotator()
        bin_obj = annotator.batch_annotate(bin_obj)

    generator = ReportGenerator(bin_obj)
    out_path = output or Path(f"revkit.{fmt}")

    try:
        if fmt == "html":
            generator.to_html(str(out_path))
        elif fmt == "json":
            generator.to_json(str(out_path))
        else:
            generator.to_markdown(str(out_path))

        console.print(f"[bold green]Report written[/bold green] → [bold]{out_path}[/bold]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Report generation failed:[/bold red] {exc}")
        raise typer.Exit(1) from exc


if __name__ == "__main__":
    app()
