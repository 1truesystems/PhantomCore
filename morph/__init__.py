"""
PhantomCore Morph -- Binary Analysis Framework
================================================

Morph is the binary analysis component of the PhantomCore cybersecurity
educational toolkit.  It provides comprehensive static analysis of
executable binaries in ELF, PE/COFF, and Android DEX formats.

Capabilities:
    - Multi-format binary parsing (ELF, PE, DEX)
    - Magic-number-based file type identification (80+ formats)
    - Per-section and sliding-window Shannon entropy analysis
    - Packer/cryptor detection via signatures and entropy heuristics
    - Multi-encoding string extraction and classification
    - Import API behavioural categorisation
    - Shellcode pattern detection (byte patterns + disassembly)
    - Control flow graph construction with cyclomatic complexity
    - Risk scoring and finding generation
    - HTML and JSON report generation

References:
    - Szor, P. (2005). The Art of Computer Virus Research and Defense.
    - Sikorski, M., & Honig, A. (2012). Practical Malware Analysis.
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
    - McCabe, T. J. (1976). A Complexity Measure.
    - TIS Committee. (1995). ELF Specification.
    - Microsoft. (2024). PE Format.
    - Google. (2024). DEX Format.
"""

__version__ = "1.0.0"
__all__ = [
    "MorphEngine",
    "BinaryAnalysisResult",
    "MorphConsoleOutput",
    "MorphReportGenerator",
]
