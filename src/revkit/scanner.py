"""Vulnerability and signature scanner.

Implements lightweight static analysis for common anti-debug tricks,
dangerous function usage and YARA-style byte/assembly signatures.
No external YARA dependency — uses Python stdlib and binary content.
"""

from __future__ import annotations

import re
from typing import Any

from .core import Binary


class VulnScanner:
    """Performs pattern-based scanning for vulnerabilities and anti-debug patterns.

    Uses a mix of imported-symbol inspection, string scanning and simple
    byte-pattern matching (YARA-like). All methods are safe to call on
    any supported binary format.
    """

    def __init__(self, binary: Binary) -> None:
        """Initialize scanner with a loaded binary.

        Args:
            binary: RevKit Binary instance.

        Raises:
            TypeError: If binary is not a revkit.Binary.
        """
        if not isinstance(binary, Binary):
            raise TypeError("binary must be a revkit.Binary instance")
        self.binary = binary
        self._data: bytes | None = None

    def _get_data(self) -> bytes:
        """Return raw file bytes (cached)."""
        if self._data is None:
            try:
                with self.binary.path.open("rb") as f:
                    self._data = f.read()
            except OSError:
                self._data = b""
        return self._data

    def detect_stack_smash(self) -> list[dict[str, Any]]:
        """Detect potential stack-based buffer overflows.

        Looks for:
          * Imports of known dangerous libc functions
          * Large stack allocations via common instruction patterns
        """
        findings: list[dict[str, Any]] = []
        data = self._get_data()

        dangerous = {"strcpy", "strcat", "gets", "sprintf", "scanf", "memcpy"}

        for sym in self.binary.symbols():
            name = getattr(sym, "name", "") or str(sym)
            if any(d in name.lower() for d in dangerous):
                addr = getattr(sym, "value", 0) or getattr(sym, "address", 0)
                findings.append(
                    {
                        "type": "dangerous_function",
                        "name": name,
                        "address": hex(addr) if addr else "dynamic",
                        "description": f"Use of '{name}' without bounds checking can lead to stack smashing.",
                        "severity": "high",
                    }
                )

        # Look for large stack frame allocations (x86/amd64)
        if re.search(rb"\x81\xec.{2,3}\x00", data):  # sub esp/ rsp, large immediate
            findings.append(
                {
                    "type": "large_stack_alloc",
                    "address": "dynamic",
                    "description": "Large stack allocation detected (may indicate vulnerable buffer).",
                    "severity": "medium",
                }
            )

        return findings

    def find_anti_debug(self) -> list[dict[str, Any]]:
        """Detect common anti-debugging techniques.

        Scans for strings and byte patterns associated with debugger detection.
        """
        findings: list[dict[str, Any]] = []
        strings = self.binary.strings(min_length=5)
        data = self._get_data()

        anti_strings = {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "BeingDebugged",
            "ptrace",
            "PTRACE_TRACEME",
        }

        for s in strings:
            if any(anti in s for anti in anti_strings):
                findings.append(
                    {
                        "type": "anti_debug_string",
                        "value": s,
                        "description": "String indicates debugger detection logic.",
                        "severity": "info",
                    }
                )

        # Common byte patterns
        patterns = [
            (rb"\x64\xa1\x18\x00\x00\x00", "PEB BeingDebugged access (fs:[0x18])"),
            (rb"CheckRemoteDebuggerPresent", "Windows anti-debug API"),
            (rb"\x0f\x31", "RDTSC timing check (common in VM/anti-debug)"),
        ]

        for pattern, description in patterns:
            if pattern in data:
                findings.append(
                    {
                        "type": "anti_debug_pattern",
                        "description": description,
                        "severity": "info",
                    }
                )

        return findings

    def match_signatures(self) -> list[dict[str, Any]]:
        """Match binary against a small built-in set of YARA-style signatures.

        Signatures target common shellcode, crypto loops and library patterns.
        """
        data = self._get_data()
        signatures = [
            {
                "name": "simple_xor_decode",
                "pattern": rb"\x31\xc0[\x00-\xff]{0,8}?\x30",
                "description": "XOR decoding loop (common in shellcode)",
            },
            {
                "name": "linux_syscall",
                "pattern": rb"\xb0\x0f\xcd\x80",  # mov al, 15; int 0x80 (old syscalls)
                "description": "Linux syscall stub",
            },
            {
                "name": "function_prologue_x64",
                "pattern": rb"\x55\x48\x89\xe5",
                "description": "Standard x86-64 function prologue",
            },
            {
                "name": "tls_callback",
                "pattern": rb"tls_callback",
                "description": "TLS callback string (anti-analysis)",
            },
        ]

        findings: list[dict[str, Any]] = []
        for sig in signatures:
            pat = sig["pattern"]
            for match in re.finditer(pat, data, re.DOTALL):
                findings.append(
                    {
                        "name": sig["name"],
                        "address": hex(match.start()),
                        "description": sig["description"],
                        "matched_bytes": match.group(0)[:12].hex() + ("..." if len(match.group(0)) > 12 else ""),
                        "severity": "info",
                    }
                )
        return findings

    def scan(self) -> dict[str, Any]:
        """Convenience method that runs all scanners and returns aggregated results.

        Used by ReportGenerator.
        """
        return {
            "stack_smash": self.detect_stack_smash(),
            "anti_debug": self.find_anti_debug(),
            "signatures": self.match_signatures(),
            "total_findings": len(self.detect_stack_smash())
            + len(self.find_anti_debug())
            + len(self.match_signatures()),
        }


if __name__ == "__main__":
    # Quick self-test with a tiny binary
    import tempfile
    from pathlib import Path

    shellcode = (
        b"\x55\x48\x89\xe5\x48\x83\xec\x20"
        b"strcpy\x00IsDebuggerPresent\x00"
    )
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name

    try:
        b = Binary(tmp)
        scanner = VulnScanner(b)
        results = scanner.scan()
        print(f"Total findings: {results['total_findings']}")
        for cat, items in results.items():
            if cat != "total_findings" and items:
                print(f"  {cat}: {len(items)} item(s)")
    finally:
        Path(tmp).unlink(missing_ok=True)
