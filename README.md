<!-- header:start -->
<div align="center">

<img src="./assets/banner.svg" alt="RevKit" width="100%">

<a href="#-quick-start"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=1000&color=ff0044&center=true&vCenter=true&width=640&lines=Raw+bytes+to+insights+instantly;ELF%2C+PE%2C+Mach-O+in+one+command;Local+AI+explains+every+function" alt="Raw bytes to insights instantly · ELF, PE, Mach-O in one command · Local AI explains every function"></a>

<a href="LICENSE"><img src="https://img.shields.io/github/license/ajendras/ReverseKit?style=for-the-badge&color=111111" alt="License"></a>
<img src="https://img.shields.io/badge/Python-111111?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<a href="https://github.com/ajendras/ReverseKit/stargazers"><img src="https://img.shields.io/github/stars/ajendras/ReverseKit?style=for-the-badge&logo=github&color=ff0044" alt="Stars"></a>
<a href="https://github.com/ajendras/ReverseKit/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ajendras/ReverseKit/ci.yml?style=for-the-badge&label=CI" alt="CI"></a>
<img src="https://img.shields.io/github/last-commit/ajendras/ReverseKit?style=for-the-badge&color=111111" alt="Last commit">
<a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-22c55e?style=for-the-badge" alt="PRs welcome"></a>

**All-in-one CLI toolkit for binary disassembly, analysis, visualization and local-AI annotation**

[✨ Features](#-features) • [⚡ Quick start](#-quick-start) • [🧰 Usage](#-usage) • [🧩 Architecture](#-architecture) • [📍 Roadmap](#-roadmap) • [🤝 Contributing](#-contributing)

</div>
<!-- header:end -->

## ✨ Why RevKit?

Reverse engineering workflows are fragmented across Ghidra, radare2, custom scripts and steep learning curves. RevKit unifies the most-used capabilities into a single fast CLI augmented by local LLMs for naming and semantic understanding. Perfect for security researchers, CTF players, firmware analysts and maintainers who need speed without context switching.

- **One-command pipeline** — load, disassemble, annotate and report with `revkit analyze`
- **Local AI only** — function renaming, variable suggestions and comments via Ollama (no cloud, no telemetry)
- **Rich visuals** — CFG graphs, embedded SVGs, interactive HTML reports with zero external dependencies
- **Python first** — import `Binary`, `analyze()`, `CFGBuilder` or `AIAnnotator` for custom automation pipelines

## 🎬 Demo

<p align="center"><img src="./assets/demo.svg" alt="RevKit demo" width="760"></p>

## 🚀 Features

<table>
<tr>
<td align="center" valign="top" width="33%">
🔄<br>
<b>Universal Loader</b><br>
Auto-detects and parses ELF, PE, Mach-O, DEX using LIEF with one command
</td>
<td align="center" valign="top" width="33%">
⚡<br>
<b>Capstone Disasm</b><br>
Lightning-fast disassembly for x86, ARM, MIPS, RISC-V and WebAssembly
</td>
<td align="center" valign="top" width="33%">
📈<br>
<b>CFG Builder</b><br>
Generates control-flow graphs with NetworkX and exports to PNG, DOT or SVG
</td>
</tr>
<tr>
<td align="center" valign="top">
🧠<br>
<b>Local AI Helper</b><br>
Ollama integration renames functions, suggests variable names and adds comments
</td>
<td align="center" valign="top">
🔎<br>
<b>Pattern Scanner</b><br>
Detects common vulnerabilities, anti-debug tricks and library function signatures
</td>
<td align="center" valign="top">
📋<br>
<b>Rich Reports</b><br>
Creates Markdown, JSON and interactive HTML reports with embedded visuals
</td>
</tr>
<tr>
<td align="center" valign="top">
🐍<br>
<b>Python Library</b><br>
Importable API for scripting custom analysis pipelines and automation
</td>
<td align="center" valign="top">
🔤<br>
<b>String Explorer</b><br>
Advanced string extraction, decoding and cross-reference mapping
</td>
<td align="center" valign="top">
🧩<br>
<b>Symbol Recovery</b><br>
Reconstructs stripped symbols and imports with FLIRT-style matching
</td>
</tr>
</table>

## 📦 Installation

Requires Python 3.9+ and (optionally) an Ollama instance with a code model for AI features.

```bash
pip install revkit
```

For AI support:

```bash
ollama pull codellama
ollama serve
```

## ⚡ Quick start

```bash
revkit analyze firmware.bin --ai --report html --output report.html
```

Or via the Python API:

```python
from revkit import analyze

result = analyze(
    "firmware.bin",
    arch="auto",
    ai=True,
    report="html",
    output="report.html"
)

print(f"Entropy: {result['entropy']}, AI annotated: {result['ai_annotated']}")
```

## 🧰 Usage

Display binary metadata:

```bash
revkit info sample.elf --arch x86_64
```

Disassemble a function:

```bash
revkit disassemble sample.elf --function main --length 128
```

Generate a control-flow graph:

```bash
revkit visualize sample.elf --function main --output cfg.png --format png
```

<details>
<summary>AI annotation + report pipeline</summary>

```python
from revkit import annotate, generate_report, CFGBuilder
from revkit.core import Binary

binary = annotate("crackme.bin")                    # runs AIAnnotator.batch_annotate
report = generate_report(binary, fmt="markdown", output="annotated.md")

builder = CFGBuilder(binary)
builder.build_cfg("main")
builder.export_svg("main_cfg.svg")
```
</details>

<details>
<summary>Custom scanner + library usage (CTF example)</summary>

```python
from revkit.core import Binary
from revkit.scanner import VulnScanner
from revkit import disassemble

binary = Binary("ctf_crackme.bin")
scanner = VulnScanner(binary)

print("Anti-debug tricks:", len(scanner.find_anti_debug()))
print("Stack smash candidates:", len(scanner.detect_stack_smash()))

asm = disassemble("ctf_crackme.bin", start=0x401000, length=64)
print(asm)
```
</details>

## 🔧 Configuration

| Option     | Default   | Description                                      |
|------------|-----------|--------------------------------------------------|
| `arch`     | `auto`    | Architecture hint passed to Capstone (x86, arm, riscv, auto) |
| `ai`       | `False`   | Enable local Ollama annotation via AIAnnotator |
| `report`   | `html`    | Report format — one of "html", "markdown", "json" |
| `output`   | `None`    | Path to write report (CLI uses revkit_report.{fmt} by default) |
| `model`    | `codellama` | Ollama model used by AIAnnotator.__init__ |

## 🧩 Architecture

```mermaid
flowchart TD
    CLI[cli.py — Typer commands] --> API[__init__.py — analyze / disassemble / annotate]
    API --> Binary[core.Binary — LIEF loader]
    Binary --> Disasm[disasm.py — Capstone + Function]
    Binary --> Scanner[scanner.py — VulnScanner]
    Binary --> Annotator[annotator.py — AIAnnotator + Ollama]
    Annotator --> Binary
    Binary --> Graph[graph.py — CFGBuilder + NetworkX]
    Binary --> Report[report.py — ReportGenerator]
    Graph --> Report
    Scanner --> Report
    Report --> Outputs[HTML / Markdown / JSON + embedded SVGs]
```

The central `Binary` class (powered by LIEF) is passed between modules. Disassembly, AI annotation and CFG generation are lazily executed only when needed. The public API and CLI both call the same underlying functions, guaranteeing identical results whether used interactively or in scripts.

## 📁 Project structure

```text
src/revkit/
├── __init__.py          # Public API: Binary, analyze(), disassemble(), annotate(), generate_report()
├── cli.py               # Typer CLI: info, analyze, disassemble, annotate, visualize, report
├── core.py              # Binary class — LIEF parsing, strings(), symbols(), entropy(), read_bytes()
├── disasm.py            # Capstone wrapper, disassemble_range(), get_function(), Function.to_asm()
├── graph.py             # CFGBuilder — build_cfg(), export_png(), export_svg(), export_dot()
├── annotator.py         # AIAnnotator — suggest_name(), explain_function(), batch_annotate()
├── scanner.py           # VulnScanner — detect_stack_smash(), find_anti_debug(), match_signatures()
├── report.py            # ReportGenerator — to_html(), to_markdown(), to_json()
├── utils.py             # detect_format(), map_arch_to_capstone(), calculate_entropy()
└── __version__          # dynamic via importlib.metadata

tests/
├── conftest.py          # fixtures: sample_elf, mocked_ollama_response, temp_binary
├── test_core.py         # Binary loader, strings, symbols, entropy
└── test_disasm.py       # Capstone accuracy on x86/ARM snippets

examples/
└── ctf_crackme.py       # Full AI annotation → solve-script generation example
```

## 🧪 Testing

```bash
pytest
```

The test suite covers Binary loading, string extraction, symbol table parsing, entropy calculation, Capstone disassembly accuracy on known x86/ARM snippets, and mocked Ollama responses for annotation tests.

## 📍 Roadmap

<!-- roadmap:start -->
- [x] **v0.1.0** — first release: Universal Loader, Capstone Disasm, CFG Builder, Local AI Helper
- [ ] Add Mach-O and Android DEX native parsers
- [ ] Radare2 bridge for advanced graph and emulation
- [ ] Unicorn-based dynamic tracing command
- [ ] Plugin system for third-party analyzers
- [ ] FLIRT signature database downloader and matcher
- [ ] Headless Ghidra integration for decompilation
- [ ] WebAssembly and .NET binary support
- [ ] Parallel processing for large firmware images
- [ ] Interactive terminal explorer (REPL mode)
- [ ] Export to IDA .idb and Binary Ninja .bndb
- [ ] HTML dashboard with zoomable CFGs
- [ ] YARA rule integration for malware family detection

> 🤖 This roadmap is worked through continuously — ideas and PRs welcome!
<!-- roadmap:end -->

## 🤝 Contributing

Contributions are welcome and appreciated! Whether it's a bug fix, new scanner pattern, improved CFG layout or documentation tweak, please read our [CONTRIBUTING.md](https://github.com/ajendras/ReverseKit/blob/main/CONTRIBUTING.md) and adhere to the [CODE_OF_CONDUCT.md](https://github.com/ajendras/ReverseKit/blob/main/CODE_OF_CONDUCT.md). Good-first-issue PRs are especially encouraged — just open a PR against `main`.

## 📄 License

MIT © RevKit Contributors — see [LICENSE](LICENSE) for details.

<!-- footer:start -->
<div align="center">

### ⭐ Star history

<a href="https://star-history.com/#ajendras/ReverseKit&Date"><img src="https://api.star-history.com/svg?repos=ajendras/ReverseKit&type=Date" alt="Star history" width="600"></a>

If **RevKit** saves you time, a ⭐ helps others find it.

Made with ❤️ by [Ajendra](https://ajendra.info)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:111111,100:ff0044&height=120&section=footer" width="100%" alt="">

</div>
<!-- footer:end -->
