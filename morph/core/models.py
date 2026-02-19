"""
Morph Data Models
==================

Pydantic-based data models for binary analysis results produced by the
Morph framework.  These models capture structural, behavioural, and
statistical properties of analysed binary executables.

The modelling approach follows domain-driven design principles (Evans, 2003),
with each model representing a bounded-context value object.

References:
    - Evans, E. (2003). Domain-Driven Design. Addison-Wesley.
    - TIS Committee. (1995). Executable and Linkable Format (ELF) Specification.
    - Microsoft. (2024). PE Format. Microsoft Learn.
    - Google. (2024). DEX Format. Android Open Source Project.
    - McCabe, T. J. (1976). A Complexity Measure. IEEE Transactions on
      Software Engineering, SE-2(4), 308-320.
"""

from __future__ import annotations

import enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class BinaryFormat(str, enum.Enum):
    """Supported binary executable formats."""
    ELF = "elf"
    PE = "pe"
    DEX = "dex"
    MACHO = "macho"
    UNKNOWN = "unknown"


class StringCategory(str, enum.Enum):
    """Classification categories for extracted strings."""
    URL = "url"
    IP_ADDRESS = "ip_address"
    FILE_PATH = "file_path"
    REGISTRY = "registry"
    EMAIL = "email"
    CRYPTO = "crypto"
    SUSPICIOUS = "suspicious"
    DOMAIN = "domain"
    BASE64 = "base64"
    GENERAL = "general"


class ImportCategory(str, enum.Enum):
    """Categories of imported API functions by behaviour."""
    PROCESS_INJECTION = "process_injection"
    CODE_INJECTION = "code_injection"
    KEYLOGGING = "keylogging"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    FILE_OPERATIONS = "file_operations"
    NETWORK = "network"
    REGISTRY = "registry"
    CRYPTO = "crypto"
    PRIVILEGE = "privilege"
    GENERAL = "general"


# ---------------------------------------------------------------------------
# Core binary information
# ---------------------------------------------------------------------------

class BinaryInfo(BaseModel):
    """Top-level metadata about an analysed binary file.

    Attributes:
        path: Filesystem path to the binary.
        size: File size in bytes.
        format: Detected binary format (ELF, PE, DEX, etc.).
        arch: Architecture string (x86, x86_64, ARM, ARM64, etc.).
        bits: Address width (32 or 64).
        endian: Byte order (``"little"`` or ``"big"``).
        entry_point: Virtual address of the entry point.
        md5: MD5 hash of the file contents.
        sha256: SHA-256 hash of the file contents.
    """
    path: str = ""
    size: int = 0
    format: BinaryFormat = BinaryFormat.UNKNOWN
    arch: str = "unknown"
    bits: int = 0
    endian: str = "little"
    entry_point: int = 0
    md5: str = ""
    sha256: str = ""


# ---------------------------------------------------------------------------
# Section / Segment information
# ---------------------------------------------------------------------------

class SectionInfo(BaseModel):
    """Information about a single binary section or segment.

    Attributes:
        name: Section name (e.g. ``.text``, ``.data``).
        offset: File offset in bytes.
        size: Section size in bytes.
        vaddr: Virtual address when loaded into memory.
        flags: Permission/attribute flags as a human-readable string.
        entropy: Shannon entropy of the section data in [0.0, 8.0].
        type_guess: Heuristic classification of section contents.
    """
    name: str = ""
    offset: int = 0
    size: int = 0
    vaddr: int = 0
    flags: str = ""
    entropy: float = 0.0
    type_guess: str = ""


# ---------------------------------------------------------------------------
# Symbol information
# ---------------------------------------------------------------------------

class SymbolInfo(BaseModel):
    """A symbol entry from the binary's symbol table.

    Attributes:
        name: Symbol name.
        value: Symbol value (usually an address).
        size: Size of the object the symbol refers to.
        type: Symbol type (FUNC, OBJECT, NOTYPE, etc.).
        bind: Binding (LOCAL, GLOBAL, WEAK).
        section: Section name or index the symbol belongs to.
    """
    name: str = ""
    value: int = 0
    size: int = 0
    type: str = ""
    bind: str = ""
    section: str = ""


# ---------------------------------------------------------------------------
# Import information
# ---------------------------------------------------------------------------

class ImportInfo(BaseModel):
    """An imported library function.

    Attributes:
        library: Name of the shared library / DLL.
        function: Imported function name.
        address: Address in the import table.
        category: Behavioural category of the import.
    """
    library: str = ""
    function: str = ""
    address: int = 0
    category: ImportCategory = ImportCategory.GENERAL


# ---------------------------------------------------------------------------
# String extraction result
# ---------------------------------------------------------------------------

class StringResult(BaseModel):
    """A string extracted from the binary.

    Attributes:
        offset: File offset where the string was found.
        encoding: Encoding used (ascii, utf-16-le, utf-16-be, base64, hex).
        value: The decoded string value.
        category: Classification category.
    """
    offset: int = 0
    encoding: str = "ascii"
    value: str = ""
    category: StringCategory = StringCategory.GENERAL


# ---------------------------------------------------------------------------
# Shellcode detection
# ---------------------------------------------------------------------------

class ShellcodeIndicator(BaseModel):
    """An indicator of potential shellcode in the binary.

    Attributes:
        offset: File offset where the pattern was detected.
        pattern_name: Name of the matched shellcode pattern.
        description: Human-readable description of what was found.
        confidence: Detection confidence in [0.0, 1.0].
    """
    offset: int = 0
    pattern_name: str = ""
    description: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Control Flow Graph
# ---------------------------------------------------------------------------

class CFGBlock(BaseModel):
    """A basic block in a control flow graph.

    A basic block is a maximal sequence of instructions with:
    - One entry point (the first instruction)
    - One exit point (the last instruction)
    - No branches except at the exit

    Reference:
        Aho, A. V., Lam, M. S., Sethi, R., & Ullman, J. D. (2006).
        Compilers: Principles, Techniques, and Tools (2nd ed.). Chapter 8.

    Attributes:
        address: Start address of the basic block.
        size: Total byte size of all instructions.
        instructions: List of (address, mnemonic, operands) tuples as strings.
        successors: Addresses of successor blocks.
        predecessors: Addresses of predecessor blocks.
    """
    address: int = 0
    size: int = 0
    instructions: list[str] = Field(default_factory=list)
    successors: list[int] = Field(default_factory=list)
    predecessors: list[int] = Field(default_factory=list)


class CFGResult(BaseModel):
    """Complete control flow graph analysis result.

    Cyclomatic complexity is computed using McCabe's formula:
        M = E - N + 2P

    where E is the number of edges, N is the number of nodes (basic blocks),
    and P is the number of connected components (entry points).

    Reference:
        McCabe, T. J. (1976). A Complexity Measure. IEEE Transactions on
        Software Engineering, SE-2(4), 308-320.

    Attributes:
        blocks: All basic blocks in the CFG.
        edges: List of (source_addr, target_addr) edge tuples.
        cyclomatic_complexity: McCabe's cyclomatic complexity M.
        entry_points: Detected function entry-point addresses.
    """
    blocks: list[CFGBlock] = Field(default_factory=list)
    edges: list[tuple[int, int]] = Field(default_factory=list)
    cyclomatic_complexity: int = 0
    entry_points: list[int] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Aggregate analysis result
# ---------------------------------------------------------------------------

class BinaryAnalysisResult(BaseModel):
    """Complete analysis result for a single binary file.

    Aggregates all sub-analyses: header parsing, section enumeration,
    symbol extraction, import analysis, string extraction, shellcode
    detection, control flow graph construction, and entropy mapping.

    Attributes:
        info: Top-level binary metadata.
        sections: Parsed sections with entropy values.
        symbols: Extracted symbols from symbol tables.
        imports: Imported functions with categorisation.
        strings: Extracted and categorised strings.
        shellcode_indicators: Detected shellcode patterns.
        cfg: Control flow graph analysis.
        entropy_map: List of (offset, entropy) tuples for sliding-window analysis.
        risk_score: Overall risk score in [0.0, 100.0].
        packer_detected: Name of detected packer, or empty string.
    """
    info: BinaryInfo = Field(default_factory=BinaryInfo)
    sections: list[SectionInfo] = Field(default_factory=list)
    symbols: list[SymbolInfo] = Field(default_factory=list)
    imports: list[ImportInfo] = Field(default_factory=list)
    strings: list[StringResult] = Field(default_factory=list)
    shellcode_indicators: list[ShellcodeIndicator] = Field(default_factory=list)
    cfg: CFGResult = Field(default_factory=CFGResult)
    entropy_map: list[tuple[int, float]] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    packer_detected: str = ""
