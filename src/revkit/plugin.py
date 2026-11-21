"""Plugin system for third-party analyzers.

Defines the Analyzer abstract base class that custom analyzers must
subclass. Plugins are discovered at runtime via the ``revkit.analyzers``
entry point group (declared in a package's pyproject.toml). The
``run_plugins()`` helper is used by ``analyze()`` to execute selected
plugins and merge their results into reports.

Consistent with the rest of the codebase: lazy, defensive, no external
dependencies beyond stdlib, broad exception handling for robustness,
and a smoke-test ``if __name__ == "__main__"`` block.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
import importlib.metadata
from typing import Any

from .core import Binary


class Analyzer(ABC):
    """Abstract base for RevKit analyzers.

    Subclass this in your own package, implement ``.analyze(binary)``,
    set class attributes ``name`` and ``description``, then register it
    under the ``revkit.analyzers`` entry point. Results are automatically
    included in ``analyze()`` output and in generated reports.
    """

    name: str = "analyzer"
    description: str = "Undocumented analyzer"

    @abstractmethod
    def analyze(self, binary: Binary) -> dict[str, Any]:
        """Run analysis on a Binary and return a JSON-serializable dict.

        The dict can contain any keys useful to the caller (findings,
        statistics, etc.). It will be wrapped as ``{"name": ..., "description": ...,
        "result": <your_dict>}`` by ``run_plugins()``.
        """
        raise NotImplementedError


def get_analyzers() -> dict[str, type[Analyzer]]:
    """Return a mapping of registered analyzer name -> Analyzer subclass.

    Uses ``importlib.metadata`` to read the ``revkit.analyzers`` entry
    point group. Malformed plugins are silently skipped so that a single
    broken registration does not prevent the rest of the pipeline from
    running.
    """
    analyzers: dict[str, type[Analyzer]] = {}
    try:
        for entry in importlib.metadata.entry_points(group="revkit.analyzers"):
            try:
                cls: type[Analyzer] = entry.load()
                if issubclass(cls, Analyzer):
                    analyzers[entry.name] = cls
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        # No entry points or metadata unavailable (e.g. editable install edge cases)
        pass
    return analyzers


def run_plugins(
    binary: Binary, requested: list[str] | None = None
) -> list[dict[str, Any]]:
    """Execute the requested plugins (or all discovered plugins) on a Binary.

    Args:
        binary: The ``Binary`` instance to pass to each analyzer.
        requested: Optional list of plugin names. When omitted or empty,
            every registered analyzer is executed.

    Returns:
        List of result dictionaries. Each entry is either a successful
        ``{"name": , "description": , "result": <analyzer output>}`` or
        an error record ``{"name": , "error": "..."}``.
    """
    analyzers = get_analyzers()
    names = requested if requested is not None else list(analyzers.keys())

    results: list[dict[str, Any]] = []
    for name in names:
        if name not in analyzers:
            continue
        cls = analyzers[name]
        try:
            instance: Analyzer = cls()
            result = instance.analyze(binary)
            results.append(
                {
                    "name": getattr(instance, "name", name),
                    "description": getattr(instance, "description", ""),
                    "result": result,
                }
            )
        except Exception as exc:  # noqa: BLE001
            results.append({"name": name, "error": str(exc)})

    return results


if __name__ == "__main__":
    # Smoke test - demonstrates discovery (will be empty unless
    # entry points are registered in the current environment).
    discovered = get_analyzers()
    print(f"Discovered {len(discovered)} analyzer(s): {list(discovered.keys())}")

    # Demo with the built-in AIAnnotator (imported here only for the demo)
    from .annotator import AIAnnotator

    class DemoAnalyzer(Analyzer):
        name = "demo"
        description = "Example plugin for tests"

        def analyze(self, binary: Binary) -> dict[str, Any]:
            return {"demo_key": "demo_value", "strings": len(binary.strings())}

    demo = DemoAnalyzer()
    print("Demo analyzer result keys:", list(demo.analyze(Binary.__new__(Binary)).keys()))
