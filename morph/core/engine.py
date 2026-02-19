"""
Morph Analysis Engine
======================

Orchestrates the complete binary analysis pipeline: format detection,
header parsing, entropy analysis, string extraction, import categorisation,
shellcode detection, and control flow graph construction.

The engine follows a pipeline architecture where each analysis stage
operates independently on the binary data and/or results from previous
stages.  Results are aggregated into a :class:`BinaryAnalysisResult`.

Analysis Pipeline:
    1. Read file and compute hashes (MD5, SHA-256)
    2. Detect binary format via magic bytes
    3. Parse format-specific headers (ELF, PE, DEX)
    4. Compute per-section and sliding-window entropy
    5. Detect packer signatures and entropy anomalies
    6. Extract and categorise strings
    7. Categorise imported APIs
    8. Scan for shellcode patterns
    9. Build control flow graph (if Capstone available)
    10. Compute aggregate risk score
    11. Generate findings

References:
    - Szor, P. (2005). The Art of Computer Virus Research and Defense.
      Addison-Wesley Professional.
    - Sikorski, M., & Honig, A. (2012). Practical Malware Analysis.
      No Starch Press.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.config import PhantomConfig
from shared.logger import PhantomLogger
from shared.models import Finding, Risk, ScanResult, Severity

from morph.core.models import (
    BinaryAnalysisResult,
    BinaryFormat,
    BinaryInfo,
    CFGResult,
    ImportCategory,
    ImportInfo,
    SectionInfo,
    ShellcodeIndicator,
    StringCategory,
    StringResult,
    SymbolInfo,
)
from morph.parsers.magic import MagicIdentifier
from morph.parsers.elf_parser import ELFParser
from morph.parsers.pe_parser import PEParser
from morph.parsers.dex_parser import DEXParser
from morph.analyzers.entropy_map import EntropyMapAnalyzer
from morph.analyzers.strings import StringExtractor
from morph.analyzers.shellcode import ShellcodeDetector
from morph.analyzers.cfg_builder import CFGBuilder
from morph.analyzers.imports import ImportAnalyzer


# ---------------------------------------------------------------------------
# Risk score weights
# ---------------------------------------------------------------------------

_RISK_WEIGHTS: dict[str, float] = {
    "packer_detected": 15.0,
    "high_entropy_sections": 10.0,
    "shellcode_high_confidence": 20.0,
    "shellcode_medium_confidence": 10.0,
    "process_injection_imports": 15.0,
    "keylogging_imports": 15.0,
    "anti_debug_imports": 5.0,
    "anti_vm_imports": 5.0,
    "network_imports": 5.0,
    "privilege_imports": 10.0,
    "suspicious_strings": 10.0,
    "crypto_strings": 3.0,
    "high_complexity": 5.0,
}


# ---------------------------------------------------------------------------
# MorphEngine
# ---------------------------------------------------------------------------

class MorphEngine:
    """Orchestrates the complete Morph binary analysis pipeline.

    The engine reads a binary file, detects its format, parses
    format-specific headers, and runs all configured analysers to
    produce a comprehensive :class:`BinaryAnalysisResult`.

    Usage::

        engine = MorphEngine()
        result = await engine.analyze("/path/to/binary")
        print(f"Risk score: {result.risk_score}")

    Or synchronously::

        result = engine.analyze_sync("/path/to/binary")
    """

    def __init__(
        self,
        config: PhantomConfig | None = None,
        logger: PhantomLogger | None = None,
    ) -> None:
        """Initialise the analysis engine.

        Args:
            config: PhantomCore configuration.  Defaults are used if not provided.
            logger: Logger instance.  A new one is created if not provided.
        """
        self._config: PhantomConfig = config or PhantomConfig()
        self._logger: PhantomLogger = logger or PhantomLogger("morph.engine")
        self._magic: MagicIdentifier = MagicIdentifier()
        self._entropy_analyzer: EntropyMapAnalyzer = EntropyMapAnalyzer()
        self._string_extractor: StringExtractor = StringExtractor(min_length=4)
        self._shellcode_detector: ShellcodeDetector = ShellcodeDetector()
        self._cfg_builder: CFGBuilder = CFGBuilder()
        self._import_analyzer: ImportAnalyzer = ImportAnalyzer()

    # ------------------------------------------------------------------ #
    #  Main analysis entry point
    # ------------------------------------------------------------------ #

    async def analyze(
        self,
        file_path: str,
        format: str = "auto",
        strings_only: bool = False,
        entropy_only: bool = False,
    ) -> ScanResult:
        """Run the complete analysis pipeline on a binary file.

        This is the primary async entry point.  All CPU-bound work is
        delegated to :meth:`_run_pipeline` which can be awaited.

        Args:
            file_path: Path to the binary file to analyse.
            format: Force a specific format (``"elf"``, ``"pe"``, ``"dex"``)
                    or ``"auto"`` for automatic detection.
            strings_only: If ``True``, only extract strings (skip other analysis).
            entropy_only: If ``True``, only compute entropy (skip other analysis).

        Returns:
            ScanResult containing findings and raw analysis data.
        """
        started = datetime.now(timezone.utc)
        self._logger.info(f"Starting analysis of {file_path}")

        scan = ScanResult(
            tool_name="morph",
            target=file_path,
            start_time=started,
        )

        try:
            # Read file
            path = Path(file_path)
            if not path.exists():
                scan.summary = f"File not found: {file_path}"
                self._logger.error(scan.summary)
                return scan

            file_size = path.stat().st_size
            max_size = self._config.morph.max_file_size
            if file_size > max_size:
                scan.summary = (
                    f"File too large: {file_size:,} bytes "
                    f"(max: {max_size:,} bytes)"
                )
                self._logger.error(scan.summary)
                return scan

            data = path.read_bytes()

            # Run pipeline
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                self._run_pipeline,
                data,
                str(path.resolve()),
                format,
                strings_only,
                entropy_only,
            )

            # Set file metadata
            result.info.path = str(path.resolve())
            result.info.size = file_size

            # Generate findings from analysis
            findings = self._generate_findings(result)

            for finding in findings:
                scan.add_finding(finding)

            # Store raw analysis data
            scan.metadata = {
                "binary_analysis": result.model_dump(mode="json"),
            }

            scan.end_time = datetime.now(timezone.utc)

            summary_parts = [
                f"Analysis complete: {result.info.format.value.upper()}",
                f"{result.info.arch} {result.info.bits}-bit",
                f"Risk: {result.risk_score:.1f}/100",
                f"Sections: {len(result.sections)}",
                f"Imports: {len(result.imports)}",
                f"Strings: {len(result.strings)}",
                f"Shellcode indicators: {len(result.shellcode_indicators)}",
                f"Findings: {len(findings)}",
            ]
            scan.summary = " | ".join(summary_parts)
            self._logger.info(scan.summary)

        except Exception as exc:
            scan.summary = f"Analysis failed: {exc}"
            self._logger.exception(scan.summary)

        return scan

    def analyze_sync(
        self,
        file_path: str,
        format: str = "auto",
        strings_only: bool = False,
        entropy_only: bool = False,
    ) -> ScanResult:
        """Synchronous wrapper around :meth:`analyze`.

        Creates a new event loop if one is not already running.

        Args:
            file_path: Path to the binary file.
            format: Format override.
            strings_only: Strings-only mode.
            entropy_only: Entropy-only mode.

        Returns:
            ScanResult.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Already in an async context; create a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(
                    asyncio.run,
                    self.analyze(file_path, format, strings_only, entropy_only),
                )
                return future.result()
        else:
            return asyncio.run(
                self.analyze(file_path, format, strings_only, entropy_only)
            )

    def analyze_data(
        self,
        data: bytes,
        file_path: str = "<memory>",
        format: str = "auto",
    ) -> BinaryAnalysisResult:
        """Analyse raw bytes directly (without reading from disk).

        Useful for testing or analysing data already in memory.

        Args:
            data: Raw binary data.
            file_path: Display path for the result.
            format: Format override.

        Returns:
            BinaryAnalysisResult.
        """
        result = self._run_pipeline(data, file_path, format, False, False)
        result.info.path = file_path
        result.info.size = len(data)
        return result

    # ------------------------------------------------------------------ #
    #  Pipeline implementation
    # ------------------------------------------------------------------ #

    def _run_pipeline(
        self,
        data: bytes,
        file_path: str,
        format_hint: str,
        strings_only: bool,
        entropy_only: bool,
    ) -> BinaryAnalysisResult:
        """Execute the complete analysis pipeline.

        Args:
            data: Raw file bytes.
            file_path: File path for metadata.
            format_hint: Format hint or ``"auto"``.
            strings_only: If True, only extract strings.
            entropy_only: If True, only compute entropy.

        Returns:
            Populated BinaryAnalysisResult.
        """
        result = BinaryAnalysisResult()

        # Step 1: Compute hashes
        result.info.md5 = hashlib.md5(data).hexdigest()
        result.info.sha256 = hashlib.sha256(data).hexdigest()
        result.info.path = file_path
        result.info.size = len(data)

        # Step 2: Detect format
        if format_hint == "auto":
            detected_format = self._magic.identify_format(data)
        else:
            detected_format = format_hint.lower()

        self._logger.info(f"Detected format: {detected_format}")

        # Step 3: Parse format-specific headers
        sections: list[SectionInfo] = []
        symbols: list[SymbolInfo] = []
        imports: list[ImportInfo] = []
        exec_sections: list[tuple[int, int, bytes]] = []

        if not strings_only and not entropy_only:
            sections, symbols, imports, exec_sections = self._parse_format(
                data, detected_format, result
            )

        result.sections = sections
        result.symbols = symbols
        result.imports = imports

        # Step 4: Entropy analysis
        if sections:
            result.sections = self._entropy_analyzer.analyze(data, sections)

        # Sliding-window entropy map
        result.entropy_map = self._entropy_analyzer.sliding_window_entropy(
            data, window_size=256, step=256
        )

        if entropy_only:
            result.risk_score = self._compute_risk_score(result)
            return result

        # Step 5: Detect packers
        result.packer_detected = self._entropy_analyzer.detect_packer(
            data, result.sections
        )

        # Step 6: Extract strings
        result.strings = self._string_extractor.extract(data, min_length=4)
        self._logger.info(f"Extracted {len(result.strings)} strings")

        if strings_only:
            result.risk_score = self._compute_risk_score(result)
            return result

        # Step 7: Categorise imports
        if result.imports:
            result.imports = self._import_analyzer.categorize(result.imports)
            self._logger.info(f"Categorised {len(result.imports)} imports")

        # Step 8: Shellcode detection
        result.shellcode_indicators = self._shellcode_detector.detect(
            data,
            arch=result.info.arch,
            sections_info=exec_sections if exec_sections else None,
        )
        self._logger.info(
            f"Detected {len(result.shellcode_indicators)} shellcode indicators"
        )

        # Step 9: Build CFG (on executable sections)
        if exec_sections:
            # Use the largest executable section for CFG
            largest = max(exec_sections, key=lambda x: len(x[2]))
            vaddr, _offset, code_data = largest
            result.cfg = self._cfg_builder.build(
                code_data,
                arch=result.info.arch,
                entry_point=vaddr,
            )
            self._logger.info(
                f"CFG: {len(result.cfg.blocks)} blocks, "
                f"complexity={result.cfg.cyclomatic_complexity}"
            )
        else:
            # Fallback: try to build CFG from entire data
            if result.info.entry_point > 0:
                result.cfg = self._cfg_builder.build(
                    data,
                    arch=result.info.arch,
                    entry_point=result.info.entry_point,
                )

        # Step 10: Compute risk score
        result.risk_score = self._compute_risk_score(result)

        return result

    # ------------------------------------------------------------------ #
    #  Format-specific parsing
    # ------------------------------------------------------------------ #

    def _parse_format(
        self,
        data: bytes,
        format_name: str,
        result: BinaryAnalysisResult,
    ) -> tuple[
        list[SectionInfo],
        list[SymbolInfo],
        list[ImportInfo],
        list[tuple[int, int, bytes]],
    ]:
        """Dispatch to the appropriate format parser.

        Args:
            data: Raw binary data.
            format_name: Detected format string.
            result: BinaryAnalysisResult to populate info fields.

        Returns:
            Tuple of (sections, symbols, imports, executable_sections).
        """
        if format_name == "elf":
            return self._parse_elf(data, result)
        elif format_name == "pe":
            return self._parse_pe(data, result)
        elif format_name == "dex":
            return self._parse_dex(data, result)
        else:
            result.info.format = BinaryFormat.UNKNOWN
            self._logger.warning(f"Unsupported format: {format_name}")
            return [], [], [], []

    def _parse_elf(
        self,
        data: bytes,
        result: BinaryAnalysisResult,
    ) -> tuple[
        list[SectionInfo],
        list[SymbolInfo],
        list[ImportInfo],
        list[tuple[int, int, bytes]],
    ]:
        """Parse an ELF binary."""
        parser = ELFParser(data)
        if not parser.parse():
            self._logger.error("ELF parsing failed")
            result.info.format = BinaryFormat.ELF
            return [], [], [], []

        info = parser.get_binary_info()
        result.info.format = info.format
        result.info.arch = info.arch
        result.info.bits = info.bits
        result.info.endian = info.endian
        result.info.entry_point = info.entry_point

        sections = parser.get_sections()
        symbols = parser.get_symbols()
        imports = parser.get_imports()
        exec_sections = parser.get_executable_sections_info()

        self._logger.info(
            f"ELF: {info.arch} {info.bits}-bit, "
            f"{len(sections)} sections, {len(symbols)} symbols, "
            f"{len(imports)} imports"
        )

        return sections, symbols, imports, exec_sections

    def _parse_pe(
        self,
        data: bytes,
        result: BinaryAnalysisResult,
    ) -> tuple[
        list[SectionInfo],
        list[SymbolInfo],
        list[ImportInfo],
        list[tuple[int, int, bytes]],
    ]:
        """Parse a PE binary."""
        parser = PEParser(data)
        if not parser.parse():
            self._logger.error("PE parsing failed")
            result.info.format = BinaryFormat.PE
            return [], [], [], []

        info = parser.get_binary_info()
        result.info.format = info.format
        result.info.arch = info.arch
        result.info.bits = info.bits
        result.info.endian = info.endian
        result.info.entry_point = info.entry_point

        sections = parser.get_sections()
        imports = parser.get_imports()
        exports = parser.get_exports()
        exec_sections = parser.get_executable_sections_info()

        self._logger.info(
            f"PE: {info.arch} {info.bits}-bit, "
            f"{len(sections)} sections, {len(imports)} imports, "
            f"{len(exports)} exports"
        )

        return sections, exports, imports, exec_sections

    def _parse_dex(
        self,
        data: bytes,
        result: BinaryAnalysisResult,
    ) -> tuple[
        list[SectionInfo],
        list[SymbolInfo],
        list[ImportInfo],
        list[tuple[int, int, bytes]],
    ]:
        """Parse a DEX binary."""
        parser = DEXParser(data)
        if not parser.parse():
            self._logger.error("DEX parsing failed")
            result.info.format = BinaryFormat.DEX
            return [], [], [], []

        info = parser.get_binary_info()
        result.info.format = info.format
        result.info.arch = info.arch
        result.info.bits = info.bits
        result.info.endian = info.endian
        result.info.entry_point = info.entry_point

        sections = parser.get_sections()
        symbols = parser.get_symbols()
        imports = parser.get_imports()

        self._logger.info(
            f"DEX: {len(parser.get_class_names())} classes, "
            f"{len(symbols)} symbols, {len(imports)} framework imports"
        )

        return sections, symbols, imports, []

    # ------------------------------------------------------------------ #
    #  Risk score computation
    # ------------------------------------------------------------------ #

    def _compute_risk_score(self, result: BinaryAnalysisResult) -> float:
        """Compute an aggregate risk score from all analysis results.

        The score is a weighted sum of individual risk indicators,
        capped at 100.0.

        Args:
            result: The analysis result to score.

        Returns:
            Risk score in [0.0, 100.0].
        """
        score = 0.0

        # Packer detection
        if result.packer_detected:
            score += _RISK_WEIGHTS["packer_detected"]

        # High-entropy sections (possible encryption/packing)
        high_entropy_count = sum(
            1 for s in result.sections if s.entropy > 7.0
        )
        if high_entropy_count > 0:
            score += min(
                high_entropy_count * _RISK_WEIGHTS["high_entropy_sections"],
                20.0,
            )

        # Shellcode indicators (capped to avoid false-positive inflation)
        shellcode_score = 0.0
        for ind in result.shellcode_indicators:
            if ind.confidence >= 0.8:
                shellcode_score += _RISK_WEIGHTS["shellcode_high_confidence"]
            elif ind.confidence >= 0.5:
                shellcode_score += _RISK_WEIGHTS["shellcode_medium_confidence"]
        score += min(shellcode_score, 30.0)

        # Import categories
        import_cats: set[str] = {imp.category.value for imp in result.imports}
        if ImportCategory.PROCESS_INJECTION.value in import_cats:
            score += _RISK_WEIGHTS["process_injection_imports"]
        if ImportCategory.KEYLOGGING.value in import_cats:
            score += _RISK_WEIGHTS["keylogging_imports"]
        if ImportCategory.ANTI_DEBUG.value in import_cats:
            score += _RISK_WEIGHTS["anti_debug_imports"]
        if ImportCategory.ANTI_VM.value in import_cats:
            score += _RISK_WEIGHTS["anti_vm_imports"]
        if ImportCategory.NETWORK.value in import_cats:
            score += _RISK_WEIGHTS["network_imports"]
        if ImportCategory.PRIVILEGE.value in import_cats:
            score += _RISK_WEIGHTS["privilege_imports"]

        # Suspicious strings
        suspicious_string_count = sum(
            1 for s in result.strings
            if s.category == StringCategory.SUSPICIOUS
        )
        if suspicious_string_count > 0:
            score += min(
                suspicious_string_count * 2.0,
                _RISK_WEIGHTS["suspicious_strings"],
            )

        # Crypto strings
        crypto_string_count = sum(
            1 for s in result.strings
            if s.category == StringCategory.CRYPTO
        )
        if crypto_string_count > 0:
            score += _RISK_WEIGHTS["crypto_strings"]

        # High cyclomatic complexity
        if result.cfg.cyclomatic_complexity > 50:
            score += _RISK_WEIGHTS["high_complexity"]

        return min(score, 100.0)

    # ------------------------------------------------------------------ #
    #  Finding generation
    # ------------------------------------------------------------------ #

    def _generate_findings(self, result: BinaryAnalysisResult) -> list[Finding]:
        """Generate security findings from the analysis result.

        Args:
            result: Complete analysis result.

        Returns:
            List of Finding models.
        """
        findings: list[Finding] = []

        # Import analysis findings
        if result.imports:
            import_findings = self._import_analyzer.analyze(result.imports)
            findings.extend(import_findings)

        # Packer finding
        if result.packer_detected:
            findings.append(Finding(
                title="Packed binary detected",
                description=(
                    f"Binary appears to be packed with: {result.packer_detected}. "
                    "Packed binaries may contain obfuscated malicious code."
                ),
                severity=Severity.HIGH,
                risk=Risk.HIGH,
                confidence=0.8,
                evidence={"packer": result.packer_detected},
                recommendation=(
                    "Unpack the binary before further analysis. Use the "
                    "appropriate unpacker tool (e.g., upx -d for UPX)."
                ),
                references=[
                    "Szor, P. (2005). The Art of Computer Virus Research and Defense.",
                ],
            ))

        # Shellcode findings
        high_confidence_shellcode = [
            ind for ind in result.shellcode_indicators
            if ind.confidence >= 0.7
        ]
        if high_confidence_shellcode:
            findings.append(Finding(
                title="High-confidence shellcode patterns detected",
                description=(
                    f"Found {len(high_confidence_shellcode)} high-confidence "
                    "shellcode indicator(s). Patterns: "
                    + ", ".join(ind.pattern_name for ind in high_confidence_shellcode[:5])
                ),
                severity=Severity.CRITICAL,
                risk=Risk.CRITICAL,
                confidence=max(ind.confidence for ind in high_confidence_shellcode),
                evidence={
                    "indicators": [
                        {
                            "offset": ind.offset,
                            "pattern": ind.pattern_name,
                            "confidence": ind.confidence,
                        }
                        for ind in high_confidence_shellcode
                    ],
                },
                recommendation=(
                    "Analyse the binary in a sandboxed environment. "
                    "The detected patterns are characteristic of shellcode."
                ),
                references=[
                    "Polychronakis, M., et al. (2010). Comprehensive "
                    "Shellcode Detection Using Runtime Heuristics.",
                ],
            ))

        # High entropy finding
        high_entropy_sections = [
            s for s in result.sections if s.entropy > 7.5
        ]
        if high_entropy_sections:
            findings.append(Finding(
                title="Encrypted or compressed sections detected",
                description=(
                    f"Found {len(high_entropy_sections)} section(s) with "
                    "entropy above 7.5, indicating encryption or compression: "
                    + ", ".join(f"{s.name} ({s.entropy:.2f})" for s in high_entropy_sections[:5])
                ),
                severity=Severity.MEDIUM,
                risk=Risk.MEDIUM,
                confidence=0.7,
                evidence={
                    "sections": [
                        {"name": s.name, "entropy": s.entropy}
                        for s in high_entropy_sections
                    ],
                },
                recommendation=(
                    "High-entropy sections may contain encrypted payloads "
                    "or packed code. Investigate with dynamic analysis."
                ),
                references=[
                    "Shannon, C. E. (1948). A Mathematical Theory of Communication.",
                    "Lyda, R., & Hamrock, J. (2007). Using Entropy Analysis "
                    "to Find Encrypted and Packed Malware.",
                ],
            ))

        # Suspicious strings finding
        suspicious_strings = [
            s for s in result.strings
            if s.category == StringCategory.SUSPICIOUS
        ]
        if suspicious_strings:
            findings.append(Finding(
                title="Suspicious strings detected",
                description=(
                    f"Found {len(suspicious_strings)} suspicious string(s): "
                    + ", ".join(
                        f'"{s.value[:50]}"' for s in suspicious_strings[:5]
                    )
                ),
                severity=Severity.MEDIUM,
                risk=Risk.MEDIUM,
                confidence=0.6,
                evidence={
                    "strings": [
                        {"offset": s.offset, "value": s.value}
                        for s in suspicious_strings[:20]
                    ],
                },
                recommendation=(
                    "Review the suspicious strings in context. They may "
                    "indicate command execution, process manipulation, or "
                    "other potentially malicious behaviour."
                ),
            ))

        # Overall risk finding
        if result.risk_score >= 75.0:
            findings.append(Finding(
                title="Critical risk binary",
                description=(
                    f"Overall risk score: {result.risk_score:.1f}/100.0. "
                    "Multiple high-risk indicators detected."
                ),
                severity=Severity.CRITICAL,
                risk=Risk.CRITICAL,
                confidence=0.9,
                evidence={"risk_score": result.risk_score},
                recommendation=(
                    "This binary exhibits multiple characteristics of "
                    "malicious software. Handle with extreme caution."
                ),
            ))
        elif result.risk_score >= 50.0:
            findings.append(Finding(
                title="High risk binary",
                description=(
                    f"Overall risk score: {result.risk_score:.1f}/100.0. "
                    "Several suspicious indicators detected."
                ),
                severity=Severity.HIGH,
                risk=Risk.HIGH,
                confidence=0.7,
                evidence={"risk_score": result.risk_score},
                recommendation=(
                    "This binary shows suspicious characteristics. "
                    "Perform dynamic analysis in a sandboxed environment."
                ),
            ))

        return findings
