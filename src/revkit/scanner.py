"""Scanner for vulnerabilities, anti-debug tricks and FLIRT library signatures.

VulnScanner provides detection for common issues (anti-debug, unsafe functions).
FlirtMatcher downloads (or falls back to builtin) signatures and performs
masked byte-pattern matching on executable code for library function
identification. Signatures are cached under ~/.cache/revkit/flirt.
Consistent with project style: type hints, full docstrings, graceful fallbacks.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import Binary


class FlirtMatcher:
    """Simplified FLIRT-style signature matcher with cache + byte pattern support.

    Uses a small set of builtin signatures for x86_64 (common libc entry points).
    Real FLIRT .sig parsing is out of scope; this performs fast masked scans
    on binary content.
    """

    def __init__(self, binary: Binary) -> None:
        """Initialize matcher for a given binary.

        Args:
            binary: RevKit Binary instance.
        """
        self.binary = binary
        self.cache_dir = Path.home() / ".cache" / "revkit" / "flirt"
        self.sig_path = self.cache_dir / "signatures.json"
        self.signatures: list[dict[str, Any]] = []

    def download(self, force: bool = False) -> bool:
        """Ensure signature database is available in cache.

        Uses builtin signatures (no external network dependency in CI/tests).
        Cache is written to disk for subsequent runs.

        Args:
            force: Rebuild cache even if it exists.

        Returns:
            True if signatures are ready.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        if self.sig_path.exists() and not force:
            self._load()
            return bool(self.signatures)

        self.signatures = self._builtin_signatures()
        self._save()
        return True

    def _builtin_signatures(self) -> list[dict[str, Any]]:
        """Return builtin signatures for common library functions.

        Patterns are exact byte sequences; masks allow future wildcard support.
        Focused on x86_64 prologues for CTF / libc-linked binaries.
        """
        return [
            {
                "name": "__libc_start_main",
                "pattern": b"\x48\x83\xec\x08\xe8",
                "mask": b"\xff\xff\xff\xff\xff",
                "arch": "x86_64",
            },
            {
                "name": "printf",
                "pattern": b"\x55\x48\x89\xe5\x48\x83\xec\x10",
                "mask": b"\xff\xff\xff\xff\xff\xff\xff\xff",
                "arch": "x86_64",
            },
            {
                "name": "puts",
                "pattern": b"\x48\x8d\x3d",
                "mask": b"\xff\xff\xff",
                "arch": "x86_64",
            },
            {
                "name": "strlen",
                "pattern": b"\x48\x89\xf8\x48\x8d\x50\x01",
                "mask": b"\xff\xff\xff\xff\xff\xff\xff",
                "arch": "x86_64",
            },
            {
                "name": "memcpy",
                "pattern": b"\x48\x89\xf8\x48\x89\xd1\x48\x89\xc7",
                "mask": b"\xff\xff\xff\xff\xff\xff\xff\xff",
                "arch": "x86_64",
            },
        ]

    def _load(self) -> None:
        """Load signatures from JSON cache."""
        try:
            with self.sig_path.open("r", encoding="utf-8") as f:
                self.signatures = json.load(f)
        except (OSError, json.JSONDecodeError, TypeError):
            self.signatures = self._builtin_signatures()

    def _save(self) -> None:
        """Write signatures to cache as JSON."""
        try:
            with self.sig_path.open("w", encoding="utf-8") as f:
                json.dump(self.signatures, f, indent=2)
        except OSError:
            pass  # cache write is best-effort

    def _match_pattern(self, data: bytes, pattern: bytes, mask: bytes) -> list[int]:
        """Return all offsets where pattern matches data under the given mask.

        Mask bytes that are 0xFF must match exactly; 0x00 are wildcards.
        """
        matches: list[int] = []
        if not pattern or len(pattern) != len(mask):
            return matches
        plen = len(pattern)
        for i in range(len(data) - plen + 1):
            if all(
                (mask[j] == 0 or data[i + j] == pattern[j]) for j in range(plen)
            ):
                matches.append(i)
        return matches

    def match(self, download: bool = True) -> dict[int, str]:
        """Scan binary for signature matches.

        Args:
            download: Ensure signatures are loaded first.

        Returns:
            Mapping of virtual address to matched library function name.
        """
        if download or not self.signatures:
            self.download()

        matches: dict[int, str] = {}
        if not self.signatures:
            return matches

        # Obtain raw bytes via Binary API (full content for scanning)
        try:
            data = self.binary.read_bytes()
            if not isinstance(data, bytes):
                data = bytes(data)
        except Exception:  # fallback for any Binary implementation detail
            data = b""

        if not data:
            return matches

        # Determine base address for VA calculation
        base_addr = getattr(self.binary, "base_address", 0)
        if base_addr == 0 and hasattr(self.binary, "_binary"):
            base_addr = getattr(self.binary._binary, "imagebase", 0x400000)
        if base_addr == 0:
            base_addr = getattr(self.binary, "entry_point", lambda: 0x400000)() & ~0xFFF

        for sig in self.signatures:
            pat = sig.get("pattern")
            msk = sig.get("mask")
            name = sig.get("name", "unknown")
            if isinstance(pat, bytes) and isinstance(msk, bytes) and len(pat) == len(msk):
                for offset in self._match_pattern(data, pat, msk):
                    va = base_addr + offset
                    if va not in matches:  # keep first match per signature
                        matches[va] = name
                    break  # one match per signature is enough for demo

        return matches


class VulnScanner:
    """High-level scanner for anti-debug, stack issues and FLIRT matching.

    Integrates FlirtMatcher as .flirt attribute (per documented usage).
    """

    def __init__(self, binary: Binary) -> None:
        """Initialize with a Binary instance.

        Args:
            binary: The binary to analyze.
        """
        self.binary = binary
        self.flirt = FlirtMatcher(binary)

    def find_anti_debug(self) -> list[str]:
        """Scan strings and symbols for common anti-debugging indicators.

        Returns:
            List of matched anti-debug artifacts.
        """
        findings: list[str] = []
        for s in self.binary.strings():
            if isinstance(s, str) and any(
                kw in s.lower() for kw in ("ptrace", "debugger", "antidebug", "isdebuggerpresent")
            ):
                findings.append(s)
        return findings

    def detect_stack_smash(self) -> list[str]:
        """Detect potential stack buffer overflow candidates (unsafe libc calls).

        Returns:
            List of suspicious function names found in symbols.
        """
        findings: list[str] = []
        for sym in self.binary.symbols():
            name = getattr(sym, "name", None)
            if isinstance(name, str) and any(
                unsafe in name.lower() for unsafe in ("strcpy", "gets", "sprintf", "scanf")
            ):
                findings.append(name)
        return findings

    def match_flirt(self, download: bool = True) -> dict[int, str]:
        """Delegate to FlirtMatcher.

        Args:
            download: Whether to (re)download signatures.

        Returns:
            Address-to-name map of identified library functions.
        """
        return self.flirt.match(download=download)


if __name__ == "__main__":
    # Quick smoke test (requires a binary)
    print("FlirtMatcher and VulnScanner loaded successfully")
