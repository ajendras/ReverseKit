"""Radare2 bridge for advanced analysis, precise CFG and ESIL-based emulation.

Provides optional integration with radare2 via r2pipe. If radare2 is not installed
or r2pipe fails to open the binary, it gracefully falls back to pure-Python
implementations from other modules.
"""

from __future__ import annotations

import json
from typing import Any

import networkx as nx

from .core import Binary
from .disasm import get_function


class R2Bridge:
    """Bridge to radare2 for enhanced binary analysis features.

    Uses r2pipe to communicate with a radare2 instance. Supports advanced
    basic-block aware CFGs via afbJ and simple ESIL emulation. If r2pipe or
    the radare2 binary is unavailable, is_available() returns False and
    methods fall back to pure Python equivalents.
    """

    def __init__(self, binary: Binary, auto_analyze: bool = True) -> None:
        """Initialize the bridge.

        Args:
            binary: The revkit Binary to analyze.
            auto_analyze: If True, runs 'aaa' analysis on open.
        """
        if not isinstance(binary, Binary):
            raise TypeError("binary must be a revkit.Binary instance")

        self.binary = binary
        self._r2 = None
        self._available = False

        try:
            import r2pipe
            self._r2 = r2pipe.open(str(self.binary.path))
            if auto_analyze:
                self._r2.cmd("aaa")  # analyze all
            self._available = True
        except Exception:  # noqa: BLE001
            # r2pipe or radare2 not available - graceful degradation
            self._available = False
            if self._r2:
                try:
                    self._r2.quit()
                except Exception:
                    pass
                self._r2 = None

    def is_available(self) -> bool:
        """Return True if the radare2 bridge is functional."""
        return self._available and self._r2 is not None

    def advanced_cfg(self, function: str | int = "main") -> nx.DiGraph:
        """Build a precise basic-block CFG using radare2's analysis.

        If bridge not available, falls back to CFGBuilder.

        Args:
            function: Function name or address.

        Returns:
            networkx.DiGraph representing the CFG.
        """
        if not self.is_available():
            from .graph import CFGBuilder
            builder = CFGBuilder(self.binary)
            return builder.build_cfg(function)

        try:
            # Resolve to r2 function name if needed
            if isinstance(function, int):
                addr = function
                fcn_name = f"fcn.{addr:x}"
            else:
                fcn_name = str(function)
                addr = self._resolve_function_addr(fcn_name)

            # Get JSON basic blocks for the function
            json_str = self._r2.cmd(f"afbJ @ {fcn_name}")
            if not json_str or json_str.strip() == "":
                json_str = self._r2.cmd("afbJ")

            blocks = json.loads(json_str) if json_str and json_str.strip() else []

            G = nx.DiGraph()
            if isinstance(blocks, dict):
                blocks = [blocks]

            for block in blocks:
                bb_addr = block.get("addr", 0)
                G.add_node(
                    bb_addr,
                    addr=bb_addr,
                    size=block.get("size", 0),
                    jump=block.get("jump"),
                    fail=block.get("fail"),
                )

                for j in block.get("jump", []):
                    if isinstance(j, int):
                        G.add_edge(bb_addr, j, type="jump")
                for f in block.get("fail", []):
                    if isinstance(f, int):
                        G.add_edge(bb_addr, f, type="fail")

            if G.number_of_nodes() == 0:
                from .graph import CFGBuilder
                builder = CFGBuilder(self.binary)
                return builder.build_cfg(function)

            return G

        except Exception:  # noqa: BLE001
            from .graph import CFGBuilder
            builder = CFGBuilder(self.binary)
            return builder.build_cfg(function)

    def _resolve_function_addr(self, name: str) -> int:
        """Helper to get address of a function by name using r2."""
        if not self.is_available():
            return 0
        try:
            res = self._r2.cmd(f"?v {name}")
            if res and res.strip():
                try:
                    return int(res.strip(), 16)
                except ValueError:
                    pass
            for line in self._r2.cmd("afl").splitlines():
                if name in line:
                    parts = line.split()
                    if parts:
                        try:
                            return int(parts[0], 16)
                        except ValueError:
                            continue
        except Exception:
            pass
        return self.binary.entry_point() or 0

    def emulate(self, addr: int, steps: int = 20) -> dict[str, Any]:
        """Run simple ESIL emulation using radare2.

        Returns a dict with registers and memory state snapshot.
        Falls back to dummy values if r2 unavailable.
        """
        if not self.is_available():
            arch = getattr(self.binary, "architecture", "x86")
            pc_key = "rip" if "x86" in arch else "pc"
            return {
                "pc": hex(addr),
                "registers": {pc_key: addr + steps * 4},
                "steps": steps,
                "emulator": "fallback",
            }

        try:
            self._r2.cmd(f"s {hex(addr)}")
            self._r2.cmd("aei")
            self._r2.cmd(f"aes {steps}")
            regs = self._r2.cmdj("arj")
            pc = regs.get("rip") or regs.get("pc") or addr
            return {
                "pc": hex(pc),
                "registers": regs,
                "steps": steps,
                "emulator": "esil",
            }
        except Exception:  # noqa: BLE001
            return {
                "pc": hex(addr),
                "registers": {"rip": addr + 0x10},
                "steps": steps,
                "emulator": "fallback",
            }

    def close(self) -> None:
        """Close the r2pipe connection."""
        if self._r2 is not None:
            try:
                self._r2.quit()
            except Exception:
                pass
            self._r2 = None

    def __enter__(self):
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


if __name__ == "__main__":
    # Smoke test
    import tempfile
    from pathlib import Path

    shellcode = b"\x55\x48\x89\xe5\xb8\x2a\x00\x00\x00\xc3"
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name

    try:
        b = Binary(tmp)
        r2 = R2Bridge(b, auto_analyze=False)
        print(f"R2 available: {r2.is_available()}")
        if r2.is_available():
            cfg = r2.advanced_cfg("entry")
            print(f"CFG nodes: {cfg.number_of_nodes()}")
            emu = r2.emulate(b.entry_point(), steps=5)
            print(f"Emu PC: {emu.get('pc')}")
            r2.close()
        else:
            print("Radare2 not available in this environment - using fallback mode")
    except Exception as e:
        print("R2Bridge demo skipped:", e)
    finally:
        Path(tmp).unlink(missing_ok=True)
