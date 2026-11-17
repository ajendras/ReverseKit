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

        Prefers Radare2 bridge (if attached and available) for accurate
        basic-block level CFG. Otherwise falls back to instruction-level
        analysis from Capstone.

        Args:
            function: Function name or address.

        Returns:
            NetworkX directed graph with address nodes and control-flow edges.

        Raises:
            ValueError: If function cannot be located.
        """
        # Prefer Radare2 for advanced accurate CFG if enabled on binary
        if (
            hasattr(self.binary, "r2bridge")
            and self.binary.r2bridge is not None
            and getattr(self.binary.r2bridge, "is_available", lambda: False)()
        ):
            return self.binary.r2bridge.advanced_cfg(function)

        func = get_function(self.binary, function)
        G = nx.DiGraph(name=f"CFG_{func.name}")

        if not func.instructions:
            G.add_node("entry", label="empty function")
            self._last_cfg = G
            return G

        # Add nodes for each instruction
        prev_node: str | None = None
        for insn in func.instructions:
            node_id = hex(insn.address)
            label = f"{hex(insn.address)}:\\n{insn.mnemonic} {insn.op_str}"
            G.add_node(
                node_id,
                label=label,
                address=insn.address,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
            )
            if prev_node is not None:
                G.add_edge(prev_node, node_id, label="fallthrough")

            # Detect control flow change
            if insn.mnemonic.lower() in {
                "jmp",
                "je",
                "jne",
                "jg",
                "jl",
                "jge",
                "jle",
                "ja",
                "jb",
                "jbe",
                "jae",
                "call",
                "ret",
                "b",
                "bl",
                "bx",
            }:
                op = insn.op_str.strip().split(",")[0]
                if op.startswith("0x"):
                    try:
                        target = int(op, 16)
                        target_id = hex(target)
                        G.add_node(
                            target_id,
                            label=f"{hex(target)}:\\n(target)",
                        )
                        G.add_edge(node_id, target_id, label=insn.mnemonic)
                    except ValueError:
                        pass
            prev_node = node_id

        self._last_cfg = G
        return G

    def export_png(self, path: str | Path) -> None:
        """Render the CFG to a PNG image using matplotlib.

        Uses project colours: black background, #ff0044 nodes/accents.
        """
        if self._last_cfg is None:
            self.build_cfg()

        assert self._last_cfg is not None
        G = self._last_cfg

        plt.figure(figsize=(14, 9), facecolor="#111111")
        pos = nx.spring_layout(G, seed=42, k=0.8)

        nx.draw_networkx_nodes(
            G,
            pos,
            node_color="#ff0044",
            node_size=2200,
            edgecolors="#111111",
            linewidths=2,
        )
        nx.draw_networkx_edges(
            G,
            pos,
            edge_color="#ffffff",
            arrows=True,
            arrowstyle="->",
            arrowsize=18,
            width=1.5,
        )

        labels = nx.get_node_attributes(G, "label")
        nx.draw_networkx_labels(
            G,
            pos,
            labels,
            font_size=7,
            font_color="#111111",
            font_family="monospace",
            font_weight="bold",
        )

        edge_labels = nx.get_edge_attributes(G, "label")
        nx.draw_networkx_edge_labels(
            G,
            pos,
            edge_labels,
            font_size=6,
            font_color="#eeeeee",
            bbox={"facecolor": "#111111", "edgecolor": "none", "alpha": 0.7},
        )

        plt.title(
            "REVKIT CONTROL FLOW GRAPH",
            fontsize=22,
            color="#ff0044",
            pad=30,
            fontweight="bold",
        )
        plt.axis("off")
        plt.tight_layout()

        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(
            out_path,
            dpi=280,
            bbox_inches="tight",
            facecolor="#111111",
        )
        plt.close()

    def export_svg(self, path: str | Path) -> None:
        """Export CFG as SVG (vector format) with project monochrome styling."""
        if self._last_cfg is None:
            self.build_cfg()

        assert self._last_cfg is not None
        G = self._last_cfg

        plt.figure(figsize=(16, 10), facecolor="#111111")
        pos = nx.spring_layout(G, seed=42, k=0.8)

        nx.draw_networkx_nodes(
            G,
            pos,
            node_color="#ff0044",
            node_size=1800,
            edgecolors="#111111",
            linewidths=1.5,
        )
        nx.draw_networkx_edges(
            G,
            pos,
            edge_color="#ffffff",
            arrows=True,
            arrowstyle="->",
            arrowsize=16,
            width=1.2,
        )

        labels = nx.get_node_attributes(G, "label")
        nx.draw_networkx_labels(
            G,
            pos,
            labels,
            font_size=7,
            font_color="#111111",
            font_family="monospace",
            font_weight="bold",
        )

        plt.title(
            "REVKIT CONTROL FLOW GRAPH",
            fontsize=20,
            color="#ff0044",
            pad=25,
            fontweight="bold",
        )
        plt.axis("off")
        plt.tight_layout()

        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(
            out_path,
            format="svg",
            bbox_inches="tight",
            facecolor="#111111",
        )
        plt.close()

    def export_dot(self, path: str | Path) -> None:
        """Export the graph in Graphviz DOT format (pure text, no extra deps)."""
        if self._last_cfg is None:
            self.build_cfg()

        assert self._last_cfg is not None
        G = self._last_cfg

        dot_lines = [
            "digraph RevKit_CFG {",
            '    bgcolor="#111111";',
            '    node [shape=box, style="filled,rounded", fillcolor="#ff0044", '
            'fontcolor="#111111", fontname="monospace", fontsize=9];',
            '    edge [color="#ff0044", fontcolor="#eeeeee", fontsize=8];',
            "    rankdir=TB;",
            "",
        ]

        for node, data in G.nodes(data=True):
            label = data.get("label", str(node)).replace('"', '\\"').replace("\n", "\\n")
            dot_lines.append(f'    "{node}" [label="{label}"];')

        for u, v, data in G.edges(data=True):
            label = data.get("label", "")
            if label:
                dot_lines.append(f'    "{u}" -> "{v}" [label="{label}"];')
            else:
                dot_lines.append(f'    "{u}" -> "{v}";')

        dot_lines.append("}")

        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(dot_lines), encoding="utf-8")

    def __repr__(self) -> str:
        return f"<CFGBuilder binary={self.binary.path.name}>"


if __name__ == "__main__":
    # Runnable example that creates a small CFG and exports all formats
    import tempfile
    from pathlib import Path

    shellcode = (
        b"\x48\x31\xc0\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57"
        b"\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05"
    )
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp_path = f.name

    tmp_dir = Path(tempfile.mkdtemp())
    try:
        binary = Binary(tmp_path)
        builder = CFGBuilder(binary)
        cfg = builder.build_cfg(0)
        print(f"Built CFG with {cfg.number_of_nodes()} nodes, "
              f"{cfg.number_of_edges()} edges")

        builder.export_png(tmp_dir / "cfg.png")
        builder.export_svg(tmp_dir / "cfg.svg")
        builder.export_dot(tmp_dir / "cfg.dot")

        print(f"Exports written to {tmp_dir}")
        print("   ✓ PNG, SVG, DOT generated with #ff0044 accent")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
