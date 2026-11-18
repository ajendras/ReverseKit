"""Control-flow graph construction and export using NetworkX.

Builds a CFG from disassembled code and exports to PNG, SVG or DOT.
Uses the project visual direction (#111111 background, #ff0044 accent).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import networkx as nx

from .core import Binary
from .disasm import get_function


class CFGBuilder:
    """Builds and exports control-flow graphs for functions.

    Uses a simplified instruction-level CFG with jump detection.
    Designed to be embedded in HTML reports as SVG or saved as images.
    When a Radare2 bridge is attached to the Binary (via enable_r2()),
    delegates to the bridge for a more accurate basic-block aware CFG.
    """

    def __init__(self, binary: Binary) -> None:
        """Initialize with a loaded Binary.

        Args:
            binary: RevKit Binary instance.
        """
        if not isinstance(binary, Binary):
            raise TypeError("binary must be a revkit.Binary instance")
        self.binary = binary
        self._last_cfg: nx.DiGraph | None = None

    def build_cfg(self, function: str | int = "main") -> nx.DiGraph:
        """Construct a Control Flow Graph for a function.

        If Binary.r2bridge is available, uses R2Bridge.advanced_cfg for
        precise basic-block graph. Otherwise builds a simple linear + branch
        graph from Capstone disassembly.

        Args:
            function: Function name or address to graph.

        Returns:
            A directed NetworkX graph of the control flow.
        """
        # Delegate to R2 if available for better accuracy
        if (
            hasattr(self.binary, "r2bridge")
            and self.binary.r2bridge is not None
            and getattr(self.binary.r2bridge, "is_available", lambda: False)()
        ):
            return self.binary.r2bridge.advanced_cfg(function)

        func = get_function(self.binary, function)
        G = nx.DiGraph(name=f"CFG_{function}")

        if not func.instructions:
            G.add_node(func.address, label=func.name, type="entry")
            self._last_cfg = G
            return G

        addresses = []
        for insn in func.instructions:
            addr = insn.address
            addresses.append(addr)
            G.add_node(
                addr,
                label=f"{insn.mnemonic} {insn.op_str}",
                address=addr,
                mnemonic=insn.mnemonic,
            )

        # Add edges for sequential flow and detected branches
        for i, insn in enumerate(func.instructions[:-1]):
            curr = insn.address
            next_addr = func.instructions[i + 1].address

            # Default fallthrough
            G.add_edge(curr, next_addr, type="fallthrough")

            # Detect jumps
            if insn.mnemonic.startswith("j") or insn.mnemonic in ("call", "b", "bl", "jmp", "br"):
                try:
                    # Try to parse target address from op_str
                    op = insn.op_str.split(",")[-1].strip()
                    if op.startswith("0x"):
                        target = int(op, 16)
                        G.add_edge(curr, target, type="jump")
                except (ValueError, IndexError):
                    # Could not parse target, skip
                    pass

        self._last_cfg = G
        return G

    def export_png(self, output: str | Path) -> None:
        """Export the CFG as a PNG image with project styling."""
        if self._last_cfg is None:
            self.build_cfg()

        path = Path(output)
        plt.figure(figsize=(12, 8))
        plt.style.use("dark_background")

        pos = nx.spring_layout(self._last_cfg, seed=42, k=0.5)

        nx.draw_networkx_nodes(
            self._last_cfg,
            pos,
            node_color="#ff0044",
            node_size=600,
            alpha=0.9,
        )
        nx.draw_networkx_edges(
            self._last_cfg,
            pos,
            edge_color="#ffffff",
            arrows=True,
            arrowsize=15,
            alpha=0.7,
        )
        nx.draw_networkx_labels(
            self._last_cfg,
            pos,
            font_size=7,
            font_color="white",
            font_weight="bold",
        )

        plt.title(f"Control Flow Graph — {self._last_cfg.name}", color="#ff0044", fontsize=14)
        plt.axis("off")
        plt.savefig(path, dpi=300, bbox_inches="tight", facecolor="#111111")
        plt.close()

    def export_svg(self, output: str | Path) -> None:
        """Export the CFG as SVG (for HTML reports)."""
        if self._last_cfg is None:
            self.build_cfg()

        path = Path(output).with_suffix(".svg")
        plt.figure(figsize=(12, 8))
        plt.style.use("dark_background")

        pos = nx.spring_layout(self._last_cfg, seed=42, k=0.5)

        nx.draw_networkx_nodes(
            self._last_cfg,
            pos,
            node_color="#ff0044",
            node_size=700,
        )
        nx.draw_networkx_edges(
            self._last_cfg, pos, edge_color="#ffffff", arrows=True, arrowsize=20
        )
        nx.draw_networkx_labels(
            self._last_cfg,
            pos,
            font_size=8,
            font_color="#eeeeee",
        )

        plt.title(f"CFG for {self._last_cfg.name}", color="#ff0044", fontsize=16)
        plt.axis("off")
        plt.savefig(path, format="svg", bbox_inches="tight", facecolor="#111111")
        plt.close()

    def export_dot(self, output: str | Path) -> None:
        """Export CFG in Graphviz DOT format."""
        if self._last_cfg is None:
            self.build_cfg()

        path = Path(output).with_suffix(".dot")
        try:
            nx.nx_agraph.write_dot(self._last_cfg, path)
        except Exception:  # fallback if agraph not available
            with path.open("w") as f:
                f.write("digraph CFG {\n")
                f.write('    graph [bgcolor="#111111"]\n')
                f.write('    node [color="#ff0044", fontcolor="#ffffff"]\n')
                f.write('    edge [color="#ffffff"]\n')
                for node, data in self._last_cfg.nodes(data=True):
                    label = data.get("label", str(node))
                    f.write(f'    {node} [label="{label}"];\n')
                for u, v in self._last_cfg.edges():
                    f.write(f"    {u} -> {v};\n")
                f.write("}\n")

    def last_cfg(self) -> nx.DiGraph | None:
        """Return the most recently built CFG."""
        return self._last_cfg


if __name__ == "__main__":
    # Demo
    import tempfile
    from pathlib import Path

    shellcode = b"\x55\x48\x89\xe5\x48\x83\xec\x10\xb8\x01\x00\x00\x00\xc3"
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name
    try:
        b = Binary(tmp)
        builder = CFGBuilder(b)
        cfg = builder.build_cfg(0)
        print(f"Built CFG with {cfg.number_of_nodes()} nodes")
        print("Success")
    finally:
        Path(tmp).unlink(missing_ok=True)
