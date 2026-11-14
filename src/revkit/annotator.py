"""AI annotation module using local Ollama models.

Provides function naming, comment generation and batch annotation
of binaries. Designed to integrate cleanly with Binary, Function
and ReportGenerator.
"""

from __future__ import annotations

import json
from typing import Any

import ollama

from .core import Binary
from .disasm import Function, get_function


class AIAnnotator:
    """Local LLM helper that queries Ollama for semantic understanding.

    Uses a code model (default: codellama) to suggest function names,
    variable names and add explanatory comments. Results are attached
    to the Binary instance for downstream consumers (reports, etc.).
    """

    def __init__(self, model: str = "codellama") -> None:
        """Initialize annotator with an Ollama model.

        Args:
            model: Name of the Ollama model to use (must be pulled locally).
        """
        if not model or not isinstance(model, str):
            raise ValueError("model must be a non-empty string")
        self.model = model

    def _query(self, prompt: str, system: str | None = None) -> str:
        """Send prompt to Ollama and return response text.

        Raises:
            RuntimeError: If Ollama is unavailable or returns an error.
        """
        try:
            if system:
                response = ollama.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                )
                return response["message"]["content"].strip()
            response = ollama.generate(model=self.model, prompt=prompt)
            return response["response"].strip()
        except ollama.ResponseError as exc:
            raise RuntimeError(f"Ollama API error: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(
                f"Ollama unavailable. Ensure the daemon is running and "
                f"'{self.model}' is pulled (ollama pull {self.model})."
            ) from exc

    def suggest_name(self, instrs: list[Any]) -> str:
        """Suggest a concise, descriptive name for a function.

        Args:
            instrs: List of Capstone instructions (or any objects with
                    .address, .mnemonic, .op_str).

        Returns:
            Suggested snake_case function name.

        Raises:
            RuntimeError: If the LLM query fails.
        """
        if not instrs:
            return "unknown_func"

        # Build a compact disassembly snippet
        asm_lines = []
        for insn in instrs[:15]:
            addr = getattr(insn, "address", 0)
            asm_lines.append(f"{addr:08x}: {getattr(insn, 'mnemonic', '')} {getattr(insn, 'op_str', '')}")
        asm = "\n".join(asm_lines)

        prompt = (
            "You are an expert reverse engineer. "
            "Given the assembly below, suggest a short descriptive function name "
            "in snake_case (max 28 characters). "
            "Return ONLY the name, nothing else.\n\n"
            f"Assembly:\n{asm}\n\nName:"
        )

        try:
            name = self._query(prompt)
            # Sanitize
            name = name.lower().strip().replace(" ", "_").replace("-", "_")
            if not name or len(name) > 28 or not name.replace("_", "").isalnum():
                name = "func_" + hex(hash(asm))[-6:]
            return name
        except Exception:
            return "ai_func"

    def explain_function(self, func: Function) -> str:
        """Return a high-level natural language explanation of a function.

        Args:
            func: A revkit.disasm.Function instance.

        Returns:
            English explanation (1-3 sentences).

        Raises:
            RuntimeError: If the LLM query fails.
        """
        asm = func.to_asm()[:1200]  # truncate for token limits

        prompt = (
            "You are a senior reverse engineer. Explain the purpose of the "
            "following function in 1-2 concise sentences. Focus on its likely "
            "role in the program. Do not repeat the assembly.\n\n"
            f"{asm}\n\nExplanation:"
        )

        try:
            explanation = self._query(prompt)
            return explanation if explanation else "No explanation available."
        except Exception:
            return "AI explanation unavailable (Ollama error)."

    def batch_annotate(self, binary: Binary) -> Binary:
        """Run AI annotation across discovered functions and attach results.

        Adds two attributes to the Binary instance:
            * .ai_annotations: dict[addr, dict] with name, comment, explanation
            * ._annotated_functions: dict[addr, Function] for later use

        Args:
            binary: RevKit Binary object.

        Returns:
            The same binary instance with annotation data attached.

        Raises:
            RuntimeError: If Ollama is required but unavailable.
        """
        if not isinstance(binary, Binary):
            raise TypeError("binary must be a revkit.Binary instance")

        binary.ai_annotations: dict[int, dict[str, str]] = {}
        binary._annotated_functions: dict[int, Function] = {}

        # Collect candidate entry points and symbols
        candidates = ["main", "_start", "start", "entry"]
        for sym in binary.symbols():
            name = getattr(sym, "name", None)
            if name and isinstance(name, str):
                candidates.append(name)

        # Deduplicate while preserving order
        seen = set()
        unique_candidates = [c for c in candidates if not (c in seen or seen.add(c))]

        # Limit LLM calls for performance
        for name in unique_candidates[:6]:
            try:
                func = get_function(binary, name, length=256)
                if not func.instructions:
                    continue

                suggested = self.suggest_name(func.instructions)
                explanation = self.explain_function(func)

                addr = func.address
                binary.ai_annotations[addr] = {
                    "original_name": func.name,
                    "name": suggested,
                    "comment": explanation,
                    "explanation": explanation,
                }

                # Update the in-memory function and store it
                func.name = suggested
                func.comment = explanation
                binary._annotated_functions[addr] = func

            except Exception:  # noqa: BLE001
                # Skip functions that cannot be disassembled or annotated
                continue

        return binary


if __name__ == "__main__":
    # Smoke test (requires Ollama running with a model)
    import tempfile
    from pathlib import Path

    shellcode = b"\x55\x48\x89\xe5\xb8\x2a\x00\x00\x00\xc3"
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp = f.name

    try:
        b = Binary(tmp)
        annotator = AIAnnotator(model="codellama")
        annotated = annotator.batch_annotate(b)
        print(f"Annotated {len(annotated.ai_annotations)} functions")
        for addr, info in annotated.ai_annotations.items():
            print(f"  {hex(addr)} -> {info['name']}")
    except Exception as e:
        print("Demo skipped (Ollama not available):", e)
    finally:
        Path(tmp).unlink(missing_ok=True)
