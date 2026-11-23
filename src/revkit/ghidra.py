"""Headless Ghidra integration for decompilation.

Uses analyzeHeadless with a custom Jython postScript to decompile functions
to C and capture the output. Falls back gracefully if Ghidra is not installed.
Requires GHIDRA_HOME pointing to the Ghidra installation directory.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .core import Binary


class GhidraDecompiler:
    """Provides decompilation of functions to C via Ghidra's headless mode."""

    def __init__(self) -> None:
        self.available = self._is_available()

    def _is_available(self) -> bool:
        """Detect if analyzeHeadless binary exists."""
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if ghidra_home:
            support = Path(ghidra_home) / "support" / "analyzeHeadless"
            if support.is_file():
                return True
        # Common install locations
        for base in [
            Path("/opt/ghidra"),
            Path("/usr/local/ghidra"),
            Path.home() / "ghidra",
            Path.home() / "ghidra_11.0.1_PUBLIC",
            Path.home() / "ghidra_11.1_PUBLIC",
        ]:
            support = base / "support" / "analyzeHeadless"
            if support.is_file():
                os.environ["GHIDRA_HOME"] = str(base)
                return True
        return False

    def decompile_function(self, binary: Binary, function_name: str = "main") -> str:
        """Decompile function to C.

        Runs Ghidra headless if available, otherwise returns explanatory message.
        """
        if not self.available:
            return (
                f"// Ghidra decompilation unavailable for {function_name}.\n"
                "// Set GHIDRA_HOME environment variable to the Ghidra install dir."
            )

        script_content = '''from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
target = args[0] if args else "main"
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()
funcs = list(fm.getFunctions(True))
for func in funcs:
    name = func.getName()
    if name == target or target.lower() in name.lower():
        res = decomp.decompileFunction(func, 30, monitor)
        if res.decompileCompleted():
            c = res.getDecompiledFunction().getC()
            print("===DECOMPILED " + name + "===")
            print(c)
            break
else:
    print("// Function " + target + " not found")
'''

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            script_file = tmp_path / "revkit_decomp.py"
            script_file.write_text(script_content)

            project_path = tmp_path / "ghidra_project"
            analyze_headless = Path(os.environ["GHIDRA_HOME"]) / "support" / "analyzeHeadless"

            cmd = [
                str(analyze_headless),
                str(project_path),
                "revkit_tmp",
                "-import",
                str(binary.path.absolute()),
                "-nonInteractive",
                "-analysis",
                "-postScript",
                str(script_file),
                function_name,
                "-deleteProject",
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                out = proc.stdout + "\n" + proc.stderr
                if "===DECOMPILED" in out:
                    parts = out.split("===DECOMPILED ", 1)[1]
                    if "===" in parts:
                        code = parts.split("===", 1)[1].strip()
                        return code
                if "// Function" in out:
                    return out.split("// Function", 1)[1].strip()
                if "int " in out or "void " in out or "#include" in out:
                    return out.strip()
                return "// Ghidra ran successfully but no C output parsed:\n" + out[:300]
            except subprocess.TimeoutExpired:
                return "// Ghidra analysis timed out (60s limit)."
            except Exception as exc:  # noqa: BLE001
                return f"// Failed to run headless Ghidra: {exc}"


if __name__ == "__main__":
    # Demo (uses any file as binary for testing availability)
    from .core import Binary
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x55\x48\x89\xe5\xc3")
        tmp = f.name
    try:
        b = Binary(tmp)
        d = GhidraDecompiler()
        print("Available:", d.available)
        print(d.decompile_function(b, "main")[:200])
    finally:
        Path(tmp).unlink(missing_ok=True)
