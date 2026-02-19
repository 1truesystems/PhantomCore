"""
Control Flow Graph Builder
============================

Constructs a control flow graph (CFG) from disassembled binary code.
When Capstone is available, performs full instruction-level disassembly
to identify basic blocks, build edges (fall-through, conditional branch,
unconditional jump), and calculate McCabe's cyclomatic complexity.

A basic block is defined as a maximal sequence of instructions where:
    - The block has exactly one entry point (the first instruction)
    - The block has exactly one exit point (the last instruction)
    - There are no branches except at the exit

Cyclomatic complexity is computed as:
    M = E - N + 2P

where:
    - E = number of edges in the CFG
    - N = number of nodes (basic blocks)
    - P = number of connected components (approximated by entry points)

References:
    - McCabe, T. J. (1976). A Complexity Measure. IEEE Transactions on
      Software Engineering, SE-2(4), 308-320.
    - Aho, A. V., Lam, M. S., Sethi, R., & Ullman, J. D. (2006).
      Compilers: Principles, Techniques, and Tools (2nd ed.). Chapter 8.
    - Allen, F. E. (1970). Control Flow Analysis. ACM SIGPLAN Notices, 5(7).
    - Capstone disassembly engine: https://www.capstone-engine.org/
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from morph.core.models import CFGBlock, CFGResult


# ---------------------------------------------------------------------------
# Capstone import with graceful fallback
# ---------------------------------------------------------------------------

_CAPSTONE_AVAILABLE: bool = False
try:
    import capstone
    _CAPSTONE_AVAILABLE = True
except ImportError:
    capstone = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Instruction classification constants
# ---------------------------------------------------------------------------

# x86/x86_64 branch/jump mnemonics
_X86_UNCONDITIONAL_JUMPS: set[str] = {"jmp", "jmpq", "ljmp"}

_X86_CONDITIONAL_JUMPS: set[str] = {
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns",
    "jp", "jnp", "jpe", "jpo",
    "jcxz", "jecxz", "jrcxz",
    "loop", "loope", "loopne", "loopz", "loopnz",
}

_X86_CALL_MNEMONICS: set[str] = {"call", "callq", "lcall"}

_X86_RET_MNEMONICS: set[str] = {"ret", "retq", "retf", "retn", "iret", "iretd", "iretq"}

_X86_ALL_BRANCHES: set[str] = (
    _X86_UNCONDITIONAL_JUMPS | _X86_CONDITIONAL_JUMPS
    | _X86_CALL_MNEMONICS | _X86_RET_MNEMONICS
)

# ARM branch mnemonics
_ARM_BRANCH_MNEMONICS: set[str] = {
    "b", "bl", "blx", "bx", "bne", "beq", "bgt", "blt",
    "bge", "ble", "bhi", "bls", "bcs", "bcc", "bmi", "bpl",
    "bvs", "bvc", "cbz", "cbnz", "tbz", "tbnz",
}

_ARM_RET_MNEMONICS: set[str] = {"bx lr", "ret", "pop"}

# AArch64 branch mnemonics
_AARCH64_BRANCH_MNEMONICS: set[str] = {
    "b", "bl", "blr", "br", "ret",
    "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge",
    "b.lo", "b.hi", "b.ls", "b.hs",
    "cbz", "cbnz", "tbz", "tbnz",
}


# ---------------------------------------------------------------------------
# Internal instruction representation
# ---------------------------------------------------------------------------

class _Instruction:
    """A single disassembled instruction."""
    __slots__ = ("address", "size", "mnemonic", "op_str")

    def __init__(self, address: int, size: int, mnemonic: str, op_str: str) -> None:
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str

    def __repr__(self) -> str:
        return f"0x{self.address:x}: {self.mnemonic} {self.op_str}"


# ---------------------------------------------------------------------------
# CFGBuilder
# ---------------------------------------------------------------------------

class CFGBuilder:
    """Control Flow Graph constructor from disassembled binary code.

    Disassembles binary data, identifies basic blocks by partitioning
    at branch/call/return instructions, builds directed edges between
    blocks, and computes McCabe's cyclomatic complexity.

    Reference:
        McCabe, T. J. (1976). A Complexity Measure.
        Allen, F. E. (1970). Control Flow Analysis.

    Usage::

        builder = CFGBuilder()
        cfg = builder.build(code_bytes, arch="x86_64", entry_point=0x401000)
        print(f"Blocks: {len(cfg.blocks)}, Complexity: {cfg.cyclomatic_complexity}")
    """

    def build(
        self,
        data: bytes,
        arch: str = "x86",
        entry_point: int = 0,
        max_instructions: int = 100_000,
    ) -> CFGResult:
        """Build a control flow graph from binary code.

        Args:
            data: Raw machine code bytes.
            arch: Architecture string (``"x86"``, ``"x86_64"``,
                  ``"ARM"``, ``"AArch64"``).
            entry_point: Virtual address corresponding to the start
                         of ``data``.
            max_instructions: Maximum number of instructions to process
                              (safety limit for large binaries).

        Returns:
            CFGResult with basic blocks, edges, and complexity metrics.
        """
        if not data:
            return CFGResult()

        if not _CAPSTONE_AVAILABLE or capstone is None:
            return self._fallback_build(data, entry_point)

        # Step 1: Disassemble
        instructions = self._disassemble(data, arch, entry_point, max_instructions)
        if not instructions:
            return CFGResult()

        # Step 2: Find block leaders (block start addresses)
        leaders = self._find_leaders(instructions, arch, entry_point)

        # Step 3: Partition instructions into basic blocks
        blocks = self._partition_blocks(instructions, leaders)

        # Step 4: Build edges between blocks
        edges = self._build_edges(blocks, instructions, arch)

        # Step 5: Set predecessors
        self._set_predecessors(blocks, edges)

        # Step 6: Identify function entry points (CALL targets)
        func_entries = self._find_function_entries(instructions, arch, entry_point)

        # Step 7: Calculate cyclomatic complexity
        block_list = list(blocks.values())
        edge_list = list(edges)
        num_components = max(len(func_entries), 1)
        cyclomatic = len(edge_list) - len(block_list) + 2 * num_components

        return CFGResult(
            blocks=block_list,
            edges=edge_list,
            cyclomatic_complexity=max(cyclomatic, 1),
            entry_points=sorted(func_entries),
        )

    # ------------------------------------------------------------------ #
    #  Disassembly
    # ------------------------------------------------------------------ #

    def _disassemble(
        self,
        data: bytes,
        arch: str,
        base_address: int,
        max_instructions: int,
    ) -> list[_Instruction]:
        """Disassemble binary data using Capstone.

        Args:
            data: Raw machine code.
            arch: Architecture name.
            base_address: Virtual address of the first byte.
            max_instructions: Maximum instructions to process.

        Returns:
            List of _Instruction objects.
        """
        cs = self._create_capstone_engine(arch)
        if cs is None:
            return []

        instructions: list[_Instruction] = []
        count = 0

        try:
            for insn in cs.disasm(data, base_address):
                instructions.append(_Instruction(
                    address=insn.address,
                    size=insn.size,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                ))
                count += 1
                if count >= max_instructions:
                    break
        except Exception:
            pass

        return instructions

    # ------------------------------------------------------------------ #
    #  Leader identification
    # ------------------------------------------------------------------ #

    def _find_leaders(
        self,
        instructions: list[_Instruction],
        arch: str,
        entry_point: int,
    ) -> set[int]:
        """Identify basic block leader addresses.

        A leader is:
        1. The first instruction in the program (entry point)
        2. The target of any branch/jump instruction
        3. The instruction immediately after any branch/jump/call/return

        Args:
            instructions: Disassembled instructions.
            arch: Architecture string.
            entry_point: Program entry point address.

        Returns:
            Set of leader addresses.
        """
        leaders: set[int] = {entry_point}

        if instructions:
            leaders.add(instructions[0].address)

        branch_set, ret_set, call_set, uncond_set = self._get_branch_sets(arch)

        for i, insn in enumerate(instructions):
            mnem_lower = insn.mnemonic.lower()

            is_branch = mnem_lower in branch_set or mnem_lower in uncond_set
            is_call = mnem_lower in call_set
            is_ret = mnem_lower in ret_set

            if is_branch or is_call or is_ret:
                # The instruction following a branch/call/ret is a leader
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].address)

                # The branch target is a leader
                if is_branch or is_call:
                    target = self._parse_branch_target(insn)
                    if target is not None:
                        leaders.add(target)

        return leaders

    # ------------------------------------------------------------------ #
    #  Block partitioning
    # ------------------------------------------------------------------ #

    def _partition_blocks(
        self,
        instructions: list[_Instruction],
        leaders: set[int],
    ) -> dict[int, CFGBlock]:
        """Partition instructions into basic blocks at leader boundaries.

        Args:
            instructions: Disassembled instructions.
            leaders: Set of leader addresses.

        Returns:
            Dictionary mapping block start address to CFGBlock.
        """
        blocks: dict[int, CFGBlock] = {}
        current_block: Optional[CFGBlock] = None

        for insn in instructions:
            if insn.address in leaders:
                # Finalise previous block
                if current_block is not None:
                    blocks[current_block.address] = current_block

                # Start new block
                current_block = CFGBlock(
                    address=insn.address,
                    size=0,
                    instructions=[],
                    successors=[],
                    predecessors=[],
                )

            if current_block is not None:
                current_block.instructions.append(
                    f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".strip()
                )
                current_block.size += insn.size

        # Finalise last block
        if current_block is not None:
            blocks[current_block.address] = current_block

        return blocks

    # ------------------------------------------------------------------ #
    #  Edge construction
    # ------------------------------------------------------------------ #

    def _build_edges(
        self,
        blocks: dict[int, CFGBlock],
        instructions: list[_Instruction],
        arch: str,
    ) -> set[tuple[int, int]]:
        """Build directed edges between basic blocks.

        Edge types:
        - **Fall-through**: sequential flow to the next block
        - **Conditional branch**: both fall-through and branch target
        - **Unconditional jump**: branch target only
        - **Call**: both call target and return (fall-through)
        - **Return**: no outgoing edges (terminal block)

        Args:
            blocks: Mapping of block address to CFGBlock.
            instructions: All disassembled instructions.
            arch: Architecture string.

        Returns:
            Set of (source_block_addr, target_block_addr) tuples.
        """
        edges: set[tuple[int, int]] = set()
        branch_set, ret_set, call_set, uncond_set = self._get_branch_sets(arch)

        # Build instruction-to-block mapping
        insn_to_block: dict[int, int] = {}
        for block in blocks.values():
            for insn_str in block.instructions:
                addr_str = insn_str.split(":")[0].strip()
                try:
                    addr = int(addr_str, 16)
                    insn_to_block[addr] = block.address
                except ValueError:
                    pass

        # Build instruction index for next-instruction lookup
        insn_addrs = [insn.address for insn in instructions]
        insn_map = {insn.address: insn for insn in instructions}

        sorted_blocks = sorted(blocks.keys())
        block_set = set(sorted_blocks)

        for block_addr in sorted_blocks:
            block = blocks[block_addr]

            # Find the last instruction of this block
            last_insn_str = block.instructions[-1] if block.instructions else ""
            last_addr_str = last_insn_str.split(":")[0].strip()
            try:
                last_addr = int(last_addr_str, 16)
            except ValueError:
                continue

            last_insn = insn_map.get(last_addr)
            if last_insn is None:
                continue

            mnem_lower = last_insn.mnemonic.lower()

            is_uncond = mnem_lower in uncond_set
            is_cond = mnem_lower in (branch_set - uncond_set)
            is_call = mnem_lower in call_set
            is_ret = mnem_lower in ret_set

            if is_ret:
                # No outgoing edges from return blocks
                continue

            # Calculate fall-through address
            fall_through_addr = last_insn.address + last_insn.size

            if is_uncond:
                # Only branch target edge
                target = self._parse_branch_target(last_insn)
                if target is not None and target in block_set:
                    edges.add((block_addr, target))
                    block.successors.append(target)
            elif is_cond:
                # Both branch target and fall-through
                target = self._parse_branch_target(last_insn)
                if target is not None and target in block_set:
                    edges.add((block_addr, target))
                    block.successors.append(target)
                if fall_through_addr in block_set:
                    edges.add((block_addr, fall_through_addr))
                    block.successors.append(fall_through_addr)
            elif is_call:
                # Call: fall-through to next block (return continuation)
                # We do not add edges to the call target for intraprocedural CFG
                if fall_through_addr in block_set:
                    edges.add((block_addr, fall_through_addr))
                    block.successors.append(fall_through_addr)
            else:
                # Normal instruction: fall-through to next block
                if fall_through_addr in block_set:
                    edges.add((block_addr, fall_through_addr))
                    block.successors.append(fall_through_addr)

        return edges

    # ------------------------------------------------------------------ #
    #  Predecessor assignment
    # ------------------------------------------------------------------ #

    @staticmethod
    def _set_predecessors(
        blocks: dict[int, CFGBlock],
        edges: set[tuple[int, int]],
    ) -> None:
        """Populate predecessor lists from the edge set.

        Args:
            blocks: Block mapping.
            edges: Set of directed edges.
        """
        predecessors: dict[int, list[int]] = defaultdict(list)
        for src, dst in edges:
            predecessors[dst].append(src)

        for addr, block in blocks.items():
            block.predecessors = predecessors.get(addr, [])

    # ------------------------------------------------------------------ #
    #  Function entry detection
    # ------------------------------------------------------------------ #

    def _find_function_entries(
        self,
        instructions: list[_Instruction],
        arch: str,
        entry_point: int,
    ) -> list[int]:
        """Identify function entry points from CALL targets.

        Args:
            instructions: Disassembled instructions.
            arch: Architecture string.
            entry_point: Program entry point.

        Returns:
            Sorted list of function entry-point addresses.
        """
        _, _, call_set, _ = self._get_branch_sets(arch)
        entries: set[int] = {entry_point}

        for insn in instructions:
            if insn.mnemonic.lower() in call_set:
                target = self._parse_branch_target(insn)
                if target is not None:
                    entries.add(target)

        return sorted(entries)

    # ------------------------------------------------------------------ #
    #  Architecture-specific helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _get_branch_sets(
        arch: str,
    ) -> tuple[set[str], set[str], set[str], set[str]]:
        """Return branch, return, call, and unconditional-jump mnemonic sets.

        Args:
            arch: Architecture name.

        Returns:
            Tuple of (all_branches, returns, calls, unconditional_jumps).
        """
        arch_lower = arch.lower()

        if arch_lower in ("arm", "arm thumb-2"):
            branches = _ARM_BRANCH_MNEMONICS
            rets = _ARM_RET_MNEMONICS
            calls = {"bl", "blx"}
            uncond = {"b", "bx"}
        elif arch_lower in ("aarch64", "arm64"):
            branches = _AARCH64_BRANCH_MNEMONICS
            rets = {"ret"}
            calls = {"bl", "blr"}
            uncond = {"b", "br"}
        else:
            # Default: x86/x86_64
            branches = _X86_CONDITIONAL_JUMPS | _X86_UNCONDITIONAL_JUMPS
            rets = _X86_RET_MNEMONICS
            calls = _X86_CALL_MNEMONICS
            uncond = _X86_UNCONDITIONAL_JUMPS

        return branches, rets, calls, uncond

    @staticmethod
    def _parse_branch_target(insn: _Instruction) -> Optional[int]:
        """Parse the branch/jump target address from an instruction's operand.

        Args:
            insn: Disassembled instruction.

        Returns:
            Target address as integer, or ``None`` if the target is
            a register or cannot be parsed.
        """
        op_str = insn.op_str.strip()
        if not op_str:
            return None

        # Direct address: "0x401000" or "#0x401000"
        target_str = op_str.lstrip("#").strip()

        try:
            if target_str.startswith("0x") or target_str.startswith("0X"):
                return int(target_str, 16)
            elif target_str.isdigit():
                return int(target_str)
        except ValueError:
            pass

        return None

    @staticmethod
    def _create_capstone_engine(arch: str) -> Optional[object]:
        """Create a Capstone disassembly engine for the given architecture.

        Args:
            arch: Architecture name.

        Returns:
            Configured Capstone engine, or ``None`` if unavailable.
        """
        if not _CAPSTONE_AVAILABLE or capstone is None:
            return None

        arch_lower = arch.lower()
        arch_map: dict[str, tuple[int, int]] = {
            "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "i386": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "amd64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "arm thumb-2": (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
            "aarch64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }

        if arch_lower not in arch_map:
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
        else:
            cs_arch, cs_mode = arch_map[arch_lower]

        try:
            cs = capstone.Cs(cs_arch, cs_mode)
            cs.detail = False
            return cs
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    #  Fallback (no Capstone)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _fallback_build(data: bytes, entry_point: int) -> CFGResult:
        """Minimal CFG construction without disassembly.

        When Capstone is not available, creates a single basic block
        representing the entire code region.

        Args:
            data: Raw machine code.
            entry_point: Entry point address.

        Returns:
            CFGResult with a single block.
        """
        block = CFGBlock(
            address=entry_point,
            size=len(data),
            instructions=[
                f"0x{entry_point:x}: <{len(data)} bytes, disassembly unavailable>"
            ],
            successors=[],
            predecessors=[],
        )
        return CFGResult(
            blocks=[block],
            edges=[],
            cyclomatic_complexity=1,
            entry_points=[entry_point],
        )
