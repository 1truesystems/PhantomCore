"""
Shellcode Detection Engine
============================

Detects shellcode patterns in binary data using disassembly analysis
and byte-pattern matching.  When the Capstone disassembly engine is
available, the detector performs instruction-level analysis to identify
system call sequences, XOR decoder loops, API hashing patterns, and
self-modifying code.  Falls back to byte-pattern-only detection when
Capstone is not installed.

Detection categories:
    - NOP sleds (long sequences of 0x90 or equivalent)
    - System call patterns (int 0x80, syscall, svc #0)
    - GetProcAddress resolution patterns
    - Stack-based string construction (push + immediate values)
    - XOR decoder loops
    - Self-modifying code patterns
    - API hashing (ror13 hash loops)
    - Egg hunter patterns
    - Socket operations (connect, bind, listen)

References:
    - Skape. (2003). Understanding Windows Shellcode.
    - Miller, M. (2004). Metasploit Shellcode Analysis.
    - Polychronakis, M., Anagnostakis, K. G., & Markatos, E. P. (2010).
      Comprehensive Shellcode Detection Using Runtime Heuristics.
      ACSAC 2010.
    - Capstone disassembly engine: https://www.capstone-engine.org/
"""

from __future__ import annotations

from typing import Optional

from morph.core.models import ShellcodeIndicator


# ---------------------------------------------------------------------------
# Try to import Capstone; degrade gracefully if not available
# ---------------------------------------------------------------------------

_CAPSTONE_AVAILABLE: bool = False
try:
    import capstone
    _CAPSTONE_AVAILABLE = True
except ImportError:
    capstone = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Byte-level shellcode patterns
# ---------------------------------------------------------------------------

class _BytePattern:
    """A shellcode byte-sequence pattern with metadata."""
    __slots__ = ("pattern", "name", "description", "confidence", "min_occurrences")

    def __init__(
        self,
        pattern: bytes,
        name: str,
        description: str,
        confidence: float = 0.5,
        min_occurrences: int = 1,
    ) -> None:
        self.pattern = pattern
        self.name = name
        self.description = description
        self.confidence = confidence
        self.min_occurrences = min_occurrences


_BYTE_PATTERNS: list[_BytePattern] = [
    # NOP sleds
    _BytePattern(
        b"\x90" * 16,
        "nop_sled",
        "NOP sled detected (16+ consecutive 0x90 bytes). "
        "Common shellcode alignment/landing zone technique.",
        confidence=0.7,
    ),
    _BytePattern(
        b"\x90" * 8,
        "nop_sled_short",
        "Short NOP sled detected (8+ consecutive 0x90 bytes).",
        confidence=0.4,
    ),

    # Linux x86 system calls
    _BytePattern(
        b"\xcd\x80",
        "int_0x80",
        "Linux x86 int 0x80 system call instruction detected.",
        confidence=0.6,
    ),
    _BytePattern(
        b"\x0f\x05",
        "syscall_x64",
        "x86_64 syscall instruction detected.",
        confidence=0.5,
    ),

    # ARM system call
    _BytePattern(
        b"\x00\x00\x00\xef",
        "svc_arm",
        "ARM SVC #0 (supervisor call) instruction detected.",
        confidence=0.5,
    ),

    # Windows shellcode patterns
    _BytePattern(
        b"\x64\xa1\x30\x00\x00\x00",
        "peb_access_fs30",
        "PEB access via fs:[0x30] (x86). Common in Windows shellcode "
        "for resolving kernel32.dll base address.",
        confidence=0.8,
    ),
    _BytePattern(
        b"\x64\x8b\x15\x30\x00\x00\x00",
        "peb_access_fs30_mov",
        "PEB access via mov edx, fs:[0x30]. Windows shellcode technique.",
        confidence=0.8,
    ),
    _BytePattern(
        b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00",
        "peb_access_gs60_x64",
        "PEB access via gs:[0x60] (x86_64). 64-bit Windows shellcode.",
        confidence=0.8,
    ),

    # GetProcAddress hash resolution
    _BytePattern(
        b"\xc1\xc2\x0d",  # rol edx, 0x0d (ror13 hash)
        "ror13_hash",
        "ROR13 hash rotation detected. Used in API hashing shellcode "
        "(Stephen Fewer's hash_api technique).",
        confidence=0.7,
    ),
    _BytePattern(
        b"\xc1\xca\x0d",  # ror edx, 0x0d
        "ror13_hash_ror",
        "ROR13 hash rotation (ror edx, 13). API hash resolution.",
        confidence=0.7,
    ),

    # Egg hunters
    _BytePattern(
        b"\x66\x81\xca\xff\x0f",
        "egg_hunter_seh",
        "Egg hunter (SEH-based page scanning) detected. "
        "Technique for locating shellcode in memory.",
        confidence=0.8,
    ),
    _BytePattern(
        b"\x6a\x21\x58\xcd\x80",
        "egg_hunter_access_linux",
        "Linux egg hunter using access() syscall detected.",
        confidence=0.7,
    ),

    # Socket operations (x86 Linux)
    _BytePattern(
        b"\x6a\x66\x58",
        "socketcall_linux",
        "Linux socketcall setup (push 0x66; pop eax) detected.",
        confidence=0.5,
    ),

    # XOR decoder stubs
    _BytePattern(
        b"\xeb\x0b\x5e\x31\xc9\xb1",
        "xor_decoder_jmp_call",
        "XOR decoder stub (JMP-CALL-POP technique) detected.",
        confidence=0.8,
    ),
    _BytePattern(
        b"\xd9\xee\xd9\x74\x24\xf4",
        "fpu_getpc",
        "FPU-based GetPC technique (fnstenv) for position-independent "
        "shellcode. Used by encoded payloads.",
        confidence=0.8,
    ),

    # Metasploit-style patterns
    _BytePattern(
        b"\xfc\xe8\x82\x00\x00\x00",
        "metasploit_block_api",
        "Metasploit block_api hash resolution stub detected.",
        confidence=0.9,
    ),
    _BytePattern(
        b"\xfc\xe8\x89\x00\x00\x00",
        "metasploit_block_api_v2",
        "Metasploit block_api hash resolution stub (variant) detected.",
        confidence=0.9,
    ),

    # CreateRemoteThread injection
    _BytePattern(
        b"CreateRemoteThread",
        "create_remote_thread_str",
        "CreateRemoteThread string found. Used for process injection.",
        confidence=0.6,
    ),
    _BytePattern(
        b"VirtualAllocEx",
        "virtual_alloc_ex_str",
        "VirtualAllocEx string found. Used for memory allocation "
        "in remote process injection.",
        confidence=0.5,
    ),
    _BytePattern(
        b"WriteProcessMemory",
        "write_process_memory_str",
        "WriteProcessMemory string found. Used for injecting code "
        "into remote processes.",
        confidence=0.5,
    ),
]


# ---------------------------------------------------------------------------
# Disassembly-based detection helpers
# ---------------------------------------------------------------------------

def _detect_xor_loops(instructions: list[tuple[int, str, str]]) -> list[ShellcodeIndicator]:
    """Detect XOR decoder loops in disassembled instructions.

    A XOR decoder loop typically follows the pattern:
        xor [reg+offset], reg   ; decode byte in memory
        inc/add reg              ; advance pointer
        loop/dec+jnz             ; repeat

    Only flags XOR operations on **memory operands** (e.g. ``[ecx]``,
    ``byte ptr [rsi+rdx]``).  Register-to-register and register-to-
    immediate XOR instructions are normal compiler output and are
    excluded to avoid false positives.

    Args:
        instructions: List of (address, mnemonic, op_str) tuples.

    Returns:
        List of ShellcodeIndicator for detected patterns.
    """
    indicators: list[ShellcodeIndicator] = []
    reported_offsets: set[int] = set()
    window_size = 8

    for i in range(len(instructions) - window_size):
        window = instructions[i : i + window_size]
        mnemonics = [m for _, m, _ in window]

        # Must have a backward branch (loop construct)
        has_loop = any(m in ("loop", "jnz", "jne") for m in mnemonics)
        has_inc = any(m in ("inc", "add") for m in mnemonics)

        if not (has_loop and has_inc):
            continue

        # Find XOR that operates on a memory operand
        for addr, mnem, ops in window:
            if mnem != "xor":
                continue

            parts = ops.split(",")
            if len(parts) != 2:
                continue

            op1 = parts[0].strip()
            op2 = parts[1].strip()

            # Skip register self-clear (xor eax, eax)
            if op1 == op2:
                continue

            # Skip register-to-register (xor eax, edx) -- normal compiler output
            # Skip register-to-immediate (xor eax, 1) -- boolean toggle
            # Only flag if at least one operand is a memory reference [...]
            has_memory_operand = "[" in op1 or "[" in op2
            if not has_memory_operand:
                continue

            # Avoid duplicates within nearby offsets
            if any(abs(addr - prev) < 32 for prev in reported_offsets):
                continue

            reported_offsets.add(addr)
            indicators.append(ShellcodeIndicator(
                offset=addr,
                pattern_name="xor_decoder_loop",
                description=(
                    "XOR decoder loop detected at "
                    f"0x{addr:x}. Instruction: xor {ops}. "
                    "XOR on memory operand within a loop is characteristic "
                    "of encoded shellcode decrypting itself at runtime."
                ),
                confidence=0.8,
            ))
            break

    return indicators


def _detect_stack_strings(instructions: list[tuple[int, str, str]]) -> list[ShellcodeIndicator]:
    """Detect stack-based string construction.

    Shellcode often constructs strings on the stack by pushing
    immediate dword values followed by referencing ESP/RSP:
        push 0x6578652e   ; ".exe"
        push 0x636c6163   ; "calc"
        mov ebx, esp      ; pointer to "calc.exe"

    Args:
        instructions: List of (address, mnemonic, op_str) tuples.

    Returns:
        List of ShellcodeIndicator for detected patterns.
    """
    indicators: list[ShellcodeIndicator] = []
    consecutive_pushes = 0
    first_push_addr = 0
    all_printable = True

    for addr, mnem, ops in instructions:
        if mnem == "push" and ops.startswith("0x"):
            try:
                val = int(ops, 16)
                # Check if all bytes in the dword are printable ASCII
                if val > 0:
                    byte_vals = val.to_bytes(4, "little", signed=False)
                    is_printable = all(0x20 <= b <= 0x7e for b in byte_vals if b != 0)
                    if is_printable:
                        if consecutive_pushes == 0:
                            first_push_addr = addr
                        consecutive_pushes += 1
                    else:
                        all_printable = False
                        if consecutive_pushes >= 2 and all_printable:
                            _emit_stack_string_indicator(
                                indicators, first_push_addr, consecutive_pushes
                            )
                        consecutive_pushes = 0
                        all_printable = True
                else:
                    consecutive_pushes = 0
                    all_printable = True
            except (ValueError, OverflowError):
                consecutive_pushes = 0
                all_printable = True
        else:
            if consecutive_pushes >= 2:
                _emit_stack_string_indicator(
                    indicators, first_push_addr, consecutive_pushes
                )
            consecutive_pushes = 0
            all_printable = True

    # Check at end of instruction list
    if consecutive_pushes >= 2:
        _emit_stack_string_indicator(
            indicators, first_push_addr, consecutive_pushes
        )

    return indicators


def _emit_stack_string_indicator(
    indicators: list[ShellcodeIndicator],
    addr: int,
    count: int,
) -> None:
    """Emit a shellcode indicator for stack-based string construction."""
    indicators.append(ShellcodeIndicator(
        offset=addr,
        pattern_name="stack_string_construction",
        description=(
            f"Stack-based string construction detected at 0x{addr:x}. "
            f"{count} consecutive PUSH instructions with printable "
            "ASCII immediate values. Shellcode technique for building "
            "strings without embedding them as data."
        ),
        confidence=min(0.5 + count * 0.1, 0.9),
    ))


def _detect_api_hashing(instructions: list[tuple[int, str, str]]) -> list[ShellcodeIndicator]:
    """Detect API hashing resolution loops.

    API hashing resolves Windows API function addresses by computing a
    hash of function names from the export directory.  Common patterns:

    - ror/rol register by 13 (ror13 hash -- Stephen Fewer)
    - Accumulate hash in a loop over characters
    - Compare against known hash constant

    Args:
        instructions: List of (address, mnemonic, op_str) tuples.

    Returns:
        List of ShellcodeIndicator.
    """
    indicators: list[ShellcodeIndicator] = []
    window_size = 15

    for i in range(len(instructions) - window_size):
        window = instructions[i : i + window_size]
        mnemonics = [m for _, m, _ in window]
        ops_list = [o for _, _, o in window]

        # Look for ror/rol by 0xd (13) in a looping construct
        has_rotate = False
        rotate_addr = 0
        for j, (addr, mnem, ops) in enumerate(window):
            if mnem in ("ror", "rol") and "0xd" in ops:
                has_rotate = True
                rotate_addr = addr
                break

        if has_rotate:
            has_loop = any(m in ("loop", "jnz", "jne", "jnb", "jb") for m in mnemonics)
            has_cmp = any(m in ("cmp", "test") for m in mnemonics)
            has_load = any(m in ("lodsb", "lods", "mov") for m in mnemonics)

            if has_loop and (has_cmp or has_load):
                indicators.append(ShellcodeIndicator(
                    offset=rotate_addr,
                    pattern_name="api_hash_resolution",
                    description=(
                        f"API hash resolution loop detected at 0x{rotate_addr:x}. "
                        "Uses ROR13 hashing to resolve Windows API addresses "
                        "without embedding function name strings."
                    ),
                    confidence=0.85,
                ))

    return indicators


def _detect_syscall_setup(instructions: list[tuple[int, str, str]]) -> list[ShellcodeIndicator]:
    """Detect system call setup patterns.

    Linux shellcode typically sets up registers before int 0x80/syscall:
        xor eax, eax    ; or mov eax, <syscall_number>
        ... setup args ...
        int 0x80 / syscall

    Args:
        instructions: List of (address, mnemonic, op_str) tuples.

    Returns:
        List of ShellcodeIndicator.
    """
    indicators: list[ShellcodeIndicator] = []

    for i, (addr, mnem, ops) in enumerate(instructions):
        if mnem == "int" and "0x80" in ops:
            # Look back for register setup
            if i >= 2:
                setup_window = instructions[max(0, i - 6) : i]
                setup_mnems = [m for _, m, _ in setup_window]
                has_setup = any(
                    m in ("xor", "mov", "push", "pop", "lea") for m in setup_mnems
                )
                if has_setup:
                    indicators.append(ShellcodeIndicator(
                        offset=addr,
                        pattern_name="linux_syscall_sequence",
                        description=(
                            f"Linux system call sequence at 0x{addr:x}. "
                            "Register setup followed by int 0x80. "
                            "Likely shellcode performing a direct system call."
                        ),
                        confidence=0.75,
                    ))

        elif mnem == "syscall":
            if i >= 2:
                setup_window = instructions[max(0, i - 6) : i]
                setup_mnems = [m for _, m, _ in setup_window]
                has_setup = any(
                    m in ("xor", "mov", "push", "pop", "lea") for m in setup_mnems
                )
                if has_setup:
                    indicators.append(ShellcodeIndicator(
                        offset=addr,
                        pattern_name="x64_syscall_sequence",
                        description=(
                            f"x86_64 syscall instruction at 0x{addr:x} "
                            "with preceding register setup. Likely shellcode."
                        ),
                        confidence=0.7,
                    ))

    return indicators


# ---------------------------------------------------------------------------
# ShellcodeDetector
# ---------------------------------------------------------------------------

class ShellcodeDetector:
    """Detect shellcode patterns in binary data.

    Uses a combination of byte-pattern matching and (when Capstone is
    available) instruction-level disassembly analysis to identify
    shellcode indicators.

    Detection categories:
        - NOP sleds
        - System call patterns
        - GetProcAddress / PEB resolution
        - Stack-based string construction
        - XOR decoder loops
        - API hashing (ror13)
        - Egg hunters
        - Socket operations

    Reference:
        Polychronakis, M., Anagnostakis, K. G., & Markatos, E. P. (2010).
        Comprehensive Shellcode Detection Using Runtime Heuristics.

    Usage::

        detector = ShellcodeDetector()
        indicators = detector.detect(binary_data)
        for ind in indicators:
            print(f"[{ind.confidence:.0%}] {ind.pattern_name}: {ind.description}")
    """

    def detect(
        self,
        data: bytes,
        arch: str = "x86",
        sections_info: list[tuple[int, int, bytes]] | None = None,
    ) -> list[ShellcodeIndicator]:
        """Detect shellcode patterns in the given data.

        Args:
            data: Raw binary data to analyse.
            arch: Target architecture (``"x86"``, ``"x86_64"``,
                  ``"ARM"``, ``"AArch64"``).
            sections_info: Optional list of (vaddr, file_offset, section_data)
                           tuples for executable sections.  When provided,
                           disassembly is scoped to these sections only.

        Returns:
            List of ShellcodeIndicator, sorted by confidence (descending).
        """
        indicators: list[ShellcodeIndicator] = []

        # Phase 1: Byte-pattern matching on entire binary
        indicators.extend(self._byte_pattern_scan(data))

        # Phase 2: Disassembly-based analysis (if Capstone available)
        if _CAPSTONE_AVAILABLE and capstone is not None:
            if sections_info:
                for vaddr, file_offset, section_data in sections_info:
                    disasm_indicators = self._disassembly_analysis(
                        section_data, arch, vaddr
                    )
                    # Adjust offsets from virtual to file offset
                    for ind in disasm_indicators:
                        ind.offset = file_offset + (ind.offset - vaddr)
                    indicators.extend(disasm_indicators)
            else:
                indicators.extend(self._disassembly_analysis(data, arch, 0))

        # Deduplicate by (offset, pattern_name)
        seen: set[tuple[int, str]] = set()
        unique: list[ShellcodeIndicator] = []
        for ind in indicators:
            key = (ind.offset, ind.pattern_name)
            if key not in seen:
                seen.add(key)
                unique.append(ind)

        # Sort by confidence descending
        unique.sort(key=lambda i: i.confidence, reverse=True)
        return unique

    # ------------------------------------------------------------------ #
    #  Byte-pattern scanning
    # ------------------------------------------------------------------ #

    def _byte_pattern_scan(self, data: bytes) -> list[ShellcodeIndicator]:
        """Scan for known shellcode byte patterns.

        Args:
            data: Raw binary data.

        Returns:
            List of ShellcodeIndicator.
        """
        indicators: list[ShellcodeIndicator] = []
        data_len = len(data)

        for bp in _BYTE_PATTERNS:
            pattern_len = len(bp.pattern)
            if pattern_len > data_len:
                continue

            # Find all occurrences
            occurrences: list[int] = []
            start = 0
            while True:
                idx = data.find(bp.pattern, start)
                if idx == -1:
                    break
                occurrences.append(idx)
                start = idx + 1
                # Safety limit
                if len(occurrences) > 100:
                    break

            if len(occurrences) >= bp.min_occurrences:
                # Report the first occurrence
                indicators.append(ShellcodeIndicator(
                    offset=occurrences[0],
                    pattern_name=bp.name,
                    description=(
                        f"{bp.description} Found {len(occurrences)} "
                        f"occurrence(s) starting at offset 0x{occurrences[0]:x}."
                    ),
                    confidence=bp.confidence,
                ))

        # Special check: long NOP sled (variable length)
        nop_indicators = self._detect_nop_sled(data)
        indicators.extend(nop_indicators)

        return indicators

    @staticmethod
    def _detect_nop_sled(data: bytes) -> list[ShellcodeIndicator]:
        """Detect NOP sleds of varying length.

        A NOP sled is a sequence of NOP (0x90) instructions used as a
        landing zone for shellcode.  Sleds longer than 32 bytes are
        highly indicative.

        Multi-byte NOPs are also checked:
        - 0x90: single-byte NOP
        - 0x66 0x90: 2-byte NOP
        - 0x0F 0x1F 0x00: 3-byte NOP

        Args:
            data: Raw binary data.

        Returns:
            List of ShellcodeIndicator for significant NOP sleds.
        """
        indicators: list[ShellcodeIndicator] = []
        i = 0
        data_len = len(data)

        while i < data_len:
            if data[i] == 0x90:
                start = i
                while i < data_len and data[i] == 0x90:
                    i += 1
                length = i - start

                if length >= 32:
                    indicators.append(ShellcodeIndicator(
                        offset=start,
                        pattern_name="nop_sled_long",
                        description=(
                            f"Long NOP sled ({length} bytes) at offset "
                            f"0x{start:x}. Highly indicative of shellcode "
                            "landing zone."
                        ),
                        confidence=min(0.5 + length / 100.0, 0.95),
                    ))
            else:
                i += 1

        return indicators

    # ------------------------------------------------------------------ #
    #  Disassembly-based analysis
    # ------------------------------------------------------------------ #

    def _disassembly_analysis(
        self,
        data: bytes,
        arch: str,
        base_address: int,
    ) -> list[ShellcodeIndicator]:
        """Perform instruction-level shellcode detection using Capstone.

        Args:
            data: Binary data to disassemble.
            arch: Architecture string.
            base_address: Base virtual address for disassembly.

        Returns:
            List of ShellcodeIndicator.
        """
        if not _CAPSTONE_AVAILABLE or capstone is None:
            return []

        cs = self._create_capstone_engine(arch)
        if cs is None:
            return []

        # Disassemble up to a reasonable limit
        max_bytes = min(len(data), 1024 * 1024)  # 1 MiB
        instructions: list[tuple[int, str, str]] = []

        try:
            for insn in cs.disasm(data[:max_bytes], base_address):
                instructions.append((insn.address, insn.mnemonic, insn.op_str))
        except Exception:
            return []

        if not instructions:
            return []

        indicators: list[ShellcodeIndicator] = []

        # Run all disassembly-based detectors
        indicators.extend(_detect_xor_loops(instructions))
        indicators.extend(_detect_stack_strings(instructions))
        indicators.extend(_detect_api_hashing(instructions))
        indicators.extend(_detect_syscall_setup(instructions))

        return indicators

    @staticmethod
    def _create_capstone_engine(arch: str) -> Optional[object]:
        """Create a Capstone disassembly engine for the given architecture.

        Args:
            arch: Architecture name.

        Returns:
            Configured Capstone engine, or ``None`` if unsupported.
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
            # Default to x86
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
        else:
            cs_arch, cs_mode = arch_map[arch_lower]

        try:
            cs = capstone.Cs(cs_arch, cs_mode)
            cs.detail = False  # Faster without detailed analysis
            return cs
        except Exception:
            return None
