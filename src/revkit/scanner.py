"""Pattern scanner for vulnerabilities, anti-debug tricks and FLIRT signatures.

VulnScanner provides high-level methods for common binary issues.
FlirtMatcher downloads (or uses builtins), caches, and matches short
byte-patterns against executable code. Bytes are transparently
base64-encoded for JSON cache compatibility.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from .core import Binary


class FlirtMatcher:
    """FLIRT-style signature matcher with cache in ~/.cache/revkit/flirt.

    Builtin signatures are always available; download() populates a JSON
    cache (bytes patterns are stored as base64). match() returns
    {virtual_address: library_function_name}.
    """

    def __init__(self, binary: Binary) -> None:
        """Initialize with a Binary and load builtin signatures."""
        if not isinstance(binary, Binary):
            raise TypeError("binary must be a revkit.Binary instance")
        self.binary = binary
        self.cache_dir = Path.home() / ".cache" / "revkit" / "flirt"
        self.signatures: list[dict[str, Any]] = []
        self._load_builtin()

    def _load_builtin(self) -> None:
        """Populate a small set of common x86/ARM library signatures.

        Patterns come from typical function prologues.
        """
        self.signatures = [
            {
                "name": "printf",
                "pattern": b"H\x83\xec\x08\xe8",
                "mask": b"\xff\xff\xff\xff\xff",
                "offset": 0,
            },
            {
                "name": "__libc_start_main",
                "pattern": b"\x48\x89\xe5\x48\x83",
                "mask": b"\xff\xff\xff\xff\xff",
                "offset": 0,
            },
            {
                "name": "malloc",
                "pattern": b"\x55\x48\x89\xe5",
                "mask": b"\xff\xff\xff\xff",
                "offset": 0,
            },
            {
                "name": "free",
                "pattern": b"\x48\x85\xff\x74",
                "mask": b"\xff\xff\xff\xff",
                "offset": 0,
            },
        ]

    def download(self, force: bool = False) -> None:
        """Ensure signatures are available in cache; force re-download.

        For tests/CI we use the builtin set and immediately cache it.
        Real implementation could fetch a larger database from a URL.
        """
        cache_file = self.cache_dir / "signatures.json"
        if not force and cache_file.exists():
            self._load()
            return

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._load_builtin()
        self._save()

    def _save(self) -> None:
        """Write signatures to JSON cache. Bytes are base64-encoded."""
        cache_file = self.cache_dir / "signatures.json"

        class _BytesEncoder(json.JSONEncoder):
            def default(self, o: Any) -> Any:
                if isinstance(o, bytes):
                    return {"__bytes__": base64.b64encode(o).decode("ascii")}
                return super().default(o)

        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(self.signatures, f, indent=2, cls=_BytesEncoder)

    def _load(self) -> None:
        """Load signatures from JSON cache, restoring bytes from base64."""
        cache_file = self.cache_dir / "signatures.json"

        def _object_hook(dct: dict[str, Any]) -> Any:
            if "__bytes__" in dct:
                return base64.b64decode(dct["__bytes__"])
            return dct

        with open(cache_file, encoding="utf-8") as f:
            self.signatures = json.load(f, object_hook=_object_hook)

    def match(self, download: bool = True) -> dict[int, str]:
        """Return VA -> library function name for all matched signatures.

        Uses full binary content for simple .find(); production code
        would limit to executable sections.
        """
        if download:
            self.download()

        matches: dict[int, str] = {}
        try:
            data = self.binary.read_bytes()
        except Exception:  # noqa: BLE001
            return matches

        base = self.binary.base_address
        for sig in self.signatures:
            pat = sig["pattern"]
            pos = data.find(pat)
            while pos != -1:
                va = base + pos + sig.get("offset", 0)
                matches[va] = sig["name"]
                pos = data.find(pat, pos + 1)
        return matches


class VulnScanner:
    """High-level scanner for vulnerabilities and anti-debug patterns.

    Also exposes FLIRT matching.
    """

    def __init__(self, binary: Binary) -> None:
        """Attach to a Binary instance."""
        if not isinstance(binary, Binary):
            raise TypeError("binary must be a revkit.Binary instance")
        self.binary = binary
        self.flirt = FlirtMatcher(binary)

    def find_anti_debug(self) -> list[dict[str, Any]]:
        """Look for common anti-debug techniques (ptrace, is_debugger_present)."""
        findings: list[dict[str, Any]] = []
        try:
            content = self.binary.read_bytes()
            if b"ptrace" in content or b"IsDebuggerPresent" in content:
                findings.append({"type": "anti_debug", "description": "ptrace/debugger check"})
        except Exception:  # noqa: BLE001
            pass
        return findings

    def detect_stack_smash(self) -> list[dict[str, Any]]:
        """Detect unsafe string functions that may allow stack smashing."""
        findings: list[dict[str, Any]] = []
        try:
            content = self.binary.read_bytes()
            for func in (b"gets", b"strcpy", b"strcat", b"sprintf"):
                if func in content:
                    findings.append({"type": "stack_smash", "function": func.decode("ascii", errors="replace")})
        except Exception:  # noqa: BLE001
            pass
        return findings

    def match_flirt(self, download: bool = False) -> dict[int, str]:
        """Run FLIRT matching (optionally downloading signatures first)."""
        return self.flirt.match(download=download)


if __name__ == "__main__":
    # Smoke test
    import tempfile

    shellcode = b"H\x83\xec\x08\xe8\x12\x34\x56\x78\xc3"
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name
    try:
        b = Binary(tmp)
        scanner = VulnScanner(b)
        matches = scanner.match_flirt(download=True)
        print(f"FLIRT matches: {len(matches)}")
        print("Anti-debug:", len(scanner.find_anti_debug()))
    finally:
        Path(tmp).unlink(missing_ok=True)
