"""Unicorn-based dynamic execution tracer.

Provides instruction-level tracing with optional register state capture.
Works best with flat binaries, RAW format and position-independent shellcode.
Supports x86, x86_64 and ARM. Emulation stops gracefully on memory or
instruction errors (common when exploring unknown binaries).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    Cs,
)

try:
    from unicorn import Uc, UcError, UC_ARCH_ARM, UC_ARCH_X86, UC_HOOK_CODE
    from unicorn import UC_MODE_32, UC_MODE_64, UC_MODE_ARM
    from unicorn.arm_const import (
        UC_ARM_REG_LR,
        UC_ARM_REG_PC,
        UC_ARM_REG_R0,
        UC_ARM_REG_R1,
        UC_ARM_REG_R2,
        UC_ARM_REG_R3,
        UC_ARM_REG_R4,
        UC_ARM_REG_R5,
        UC_ARM_REG_R6,
        UC_ARM_REG_R7,
        UC_ARM_REG_SP,
    )
    from unicorn.x86_const import (
        UC_X86_REG_EAX,
        UC_X86_REG_EBP,
        UC_X86_REG_EBX,
        UC_X86_REG_ECX,
        UC_X86_REG_EDI,
        UC_X86_REG_EDX,
        UC_X86_REG_EIP,
        UC_X86_REG_ESP,
        UC_X86_REG_ESI,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
        UC_X86_REG_RAX,
        UC_X86_REG_RBP,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDI,
        UC_X86_REG_RDX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSI,
        UC_X86_REG_RSP,
    )
except ImportError:
    Uc = None  # type: ignore[assignment]
    UcError = Exception  # type: ignore[assignment]
    UC_ARCH_X86 = UC_ARCH_ARM = 0  # type: ignore[assignment]
    UC_MODE_32 = UC_MODE_64 = UC_MODE_ARM = 0  # type: ignore[assignment]
    UC_HOOK_CODE = 0  # type: ignore[assignment]
    # Constants will not be used if Unicorn is unavailable

if TYPE_CHECKING:
    from .core import Binary


class UnicornTracer:
    """Instruction tracer using the Unicorn emulator."""

    def __init__(self) -> None:
        self.trace_log: list[dict[str, Any]] = []
        self.mu: Any = None
        self.md: Any = None
        self.arch: str = "x86"
        self.mode: int = 0

    def _code_hook(self, mu: Any, address: int, size: int, user_data: dict[str, Any]) -> None:
        """Unicorn code hook that records each executed instruction."""
        try:
            code = mu.mem_read(address, size)
            for insn in self.md.disasm(code, address):
                entry: dict[str, Any] = {
                    "address": address,
                    "instruction": f"{insn.mnemonic} {insn.op_str}",
                    "bytes": " ".join(f"{b:02x}" for b in insn.bytes),
                }
                if user_data.get("trace_regs", False):
                    entry["registers"] = self._get_registers(mu)
                self.trace_log.append(entry)
                break
        except Exception:  # noqa: BLE001
            self.trace_log.append(
                {"address": address, "instruction": "<unknown>", "bytes": ""}
            )

    def _get_registers(self, mu: Any) -> dict[str, int]:
        """Read common registers depending on architecture and mode."""
        regs: dict[str, int] = {}
        try:
            if "x86" in self.arch.lower():
                is_32bit = self.mode == UC_MODE_32
                if is_32bit:
                    reg_map = {
                        "eax": UC_X86_REG_EAX,
                        "ebx": UC_X86_REG_EBX,
                        "ecx": UC_X86_REG_ECX,
                        "edx": UC_X86_REG_EDX,
                        "esi": UC_X86_REG_ESI,
                        "edi": UC_X86_REG_EDI,
                        "esp": UC_X86_REG_ESP,
                        "ebp": UC_X86_REG_EBP,
                        "eip": UC_X86_REG_EIP,
                    }
                else:
                    reg_map = {
                        "rax": UC_X86_REG_RAX,
                        "rbx": UC_X86_REG_RBX,
                        "rcx": UC_X86_REG_RCX,
                        "rdx": UC_X86_REG_RDX,
                        "rsi": UC_X86_REG_RSI,
                        "rdi": UC_X86_REG_RDI,
                        "rsp": UC_X86_REG_RSP,
                        "rbp": UC_X86_REG_RBP,
                        "rip": UC_X86_REG_RIP,
                        "r8": UC_X86_REG_R8,
                        "r9": UC_X86_REG_R9,
                        "r10": UC_X86_REG_R10,
                        "r11": UC_X86_REG_R11,
                        "r12": UC_X86_REG_R12,
                        "r13": UC_X86_REG_R13,
                        "r14": UC_X86_REG_R14,
                        "r15": UC_X86_REG_R15,
                    }
                for name, const in reg_map.items():
                    try:
                        regs[name] = mu.reg_read(const)
                    except Exception:  # noqa: BLE001
                        pass
            elif "arm" in self.arch.lower():
                reg_map = {
                    "r0": UC_ARM_REG_R0,
                    "r1": UC_ARM_REG_R1,
                    "r2": UC_ARM_REG_R2,
                    "r3": UC_ARM_REG_R3,
                    "r4": UC_ARM_REG_R4,
                    "r5": UC_ARM_REG_R5,
                    "r6": UC_ARM_REG_R6,
                    "r7": UC_ARM_REG_R7,
                    "sp": UC_ARM_REG_SP,
                    "lr": UC_ARM_REG_LR,
                    "pc": UC_ARM_REG_PC,
                }
                for name, const in reg_map.items():
                    try:
                        regs[name] = mu.reg_read(const)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass
        return regs

    def trace(
        self,
        binary: Binary,
        start: int | None = None,
        steps: int = 10000,
        trace_regs: bool = False,
    ) -> list[dict[str, Any]]:
        """Run emulation from a start address and return trace log.

        Uses a generous memory mapping and falls back to loading the entire
        file at address 0 for RAW/shellcode. Stops gracefully on typical
        emulation errors (unmapped memory, invalid instructions).

        Args:
            binary: RevKit Binary instance.
            start: Virtual address to begin emulation (default: entry_point()).
            steps: Maximum instructions to emulate.
            trace_regs: Whether to capture register values after each step.

        Returns:
            List of dicts with address, instruction, bytes and optional registers.
        """
        if Uc is None:
            raise RuntimeError(
                "Unicorn is required for tracing. "
                "Install with: pip install unicorn"
            )

        if start is None:
            start = binary.entry_point() or 0

        self.trace_log = []
        self.arch = binary.architecture or "x86"

        # Architecture / mode mapping
        if "64" in self.arch or self.arch == "x86_64":
            uc_arch = UC_ARCH_X86
            uc_mode = UC_MODE_64
            cs_arch = CS_ARCH_X86
            cs_mode = CS_MODE_64
        elif "arm" in self.arch.lower():
            uc_arch = UC_ARCH_ARM
            uc_mode = UC_MODE_ARM
            cs_arch = CS_ARCH_ARM
            cs_mode = CS_MODE_ARM
        else:
            uc_arch = UC_ARCH_X86
            uc_mode = UC_MODE_32
            cs_arch = CS_ARCH_X86
            cs_mode = CS_MODE_32

        self.mode = uc_mode
        self.mu = Uc(uc_arch, uc_mode)
        self.md = Cs(cs_arch, cs_mode)
        self.md.skipdata = True

        # Memory mapping (page-aligned, generous for tests/CTF shellcode)
        page_size = 0x1000
        base = (start // page_size) * page_size
        map_size = 0x400000  # 4 MiB
        try:
            self.mu.mem_map(base, map_size, 7)  # UC_PROT_ALL
        except UcError:
            base = 0x0
            self.mu.mem_map(base, map_size, 7)

        # Load code
        try:
            code = binary.read_bytes(start, 0x2000)
            self.mu.mem_write(start, bytes(code))
            exec_start = start
        except Exception:  # noqa: BLE001
            # Fallback for RAW or small/empty files
            data = binary.path.read_bytes()
            code = data[:0x2000]
            self.mu.mem_write(base, bytes(code))
            exec_start = base

        # Set initial PC
        if uc_arch == UC_ARCH_X86:
            pc_reg = UC_X86_REG_RIP if uc_mode == UC_MODE_64 else UC_X86_REG_EIP
            self.mu.reg_write(pc_reg, exec_start)
        else:
            self.mu.reg_write(UC_ARM_REG_PC, exec_start)

        # Hook for per-instruction tracing
        self.mu.hook_add(
            UC_HOOK_CODE,
            self._code_hook,
            user_data={"trace_regs": trace_regs},
        )

        # Emulate (stop on typical errors is expected)
        try:
            self.mu.emu_start(exec_start, exec_start + len(code), count=steps)
        except UcError:
            # Partial trace is still useful; ignore unmapped/invalid-instr errors
            pass

        return self.trace_log


if __name__ == "__main__":
    # Smoke test (mirrors core.py test)
    import tempfile

    from .core import Binary

    shellcode = b"\x90\x90\x90\xc3"  # NOP NOP NOP RET
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(shellcode)
        tmp_path = f.name

    try:
        b = Binary(tmp_path)
        tracer = UnicornTracer()
        log = tracer.trace(b, steps=4, trace_regs=False)
        print(f"Traced {len(log)} instructions")
        for entry in log[:3]:
            print(hex(entry["address"]), entry.get("instruction", ""))
        print("Tracer smoke test passed")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
