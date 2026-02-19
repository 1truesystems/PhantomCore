"""
Cipher Analysis Engine
=======================

Central orchestrator for the Cipher cryptographic analysis framework.
The CipherEngine class coordinates all analyzers and returns unified
ScanResult objects compatible with the PhantomCore shared model layer.

Architecture follows the Facade pattern (Gamma et al., 1994), providing
a simplified interface over the individual analyzer subsystems.

References:
    - Gamma, E., Helm, R., Johnson, R., & Vlissides, J. (1994).
      Design Patterns: Elements of Reusable Object-Oriented Software.
      Addison-Wesley.
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
    - NIST SP 800-22 Rev. 1a (2010). Statistical Test Suite for RNG.
    - NIST SP 800-131A Rev. 2 (2019). Cryptographic Algorithm Transitions.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.config import PhantomConfig
from shared.logger import PhantomLogger
from shared.models import Finding, Risk, ScanResult, Severity

from cipher.analyzers.entropy import EntropyAnalyzer
from cipher.analyzers.hash_id import HashIdentifier
from cipher.analyzers.cipher_suite import CipherSuiteAnalyzer
from cipher.analyzers.password_entropy import PasswordEntropyAnalyzer
from cipher.analyzers.frequency import FrequencyAnalyzer
from cipher.analyzers.key_strength import KeyStrengthAnalyzer
from cipher.analyzers.rng_tester import RNGTester
from cipher.core.models import (
    CipherGrade,
    DataType,
    EntropyResult,
    HashIdentification,
    CipherSuiteResult,
    PasswordAnalysis,
    PasswordStrength,
    FrequencyResult,
    KeyStrengthResult,
    RNGSuiteResult,
)


class CipherEngine:
    """Orchestrates all Cipher cryptographic analysis operations.

    The engine coordinates entropy analysis, hash identification, TLS
    cipher suite evaluation, password strength analysis, frequency
    analysis, key strength assessment, and RNG statistical testing.

    Usage::

        engine = CipherEngine()
        result = await engine.analyze_entropy(Path("sample.bin"))
        result = await engine.analyze_hash("5d41402abc4b2a76b9719d911017c592")
        result = await engine.analyze_tls("example.com")
        result = await engine.analyze_password("P@ssw0rd!")

    Attributes:
        config: PhantomCore configuration instance.
        logger: Logger for the cipher engine.
    """

    def __init__(self, config: Optional[PhantomConfig] = None) -> None:
        self.config = config or PhantomConfig()
        self.logger = PhantomLogger("cipher.engine")

        # Instantiate analyzers
        self._entropy_analyzer = EntropyAnalyzer(
            block_sizes=self.config.cipher.block_sizes,
            max_sample_size=self.config.cipher.max_sample_size,
        )
        self._hash_identifier = HashIdentifier()
        self._cipher_suite_analyzer = CipherSuiteAnalyzer()
        self._password_analyzer = PasswordEntropyAnalyzer()
        self._frequency_analyzer = FrequencyAnalyzer()
        self._key_strength_analyzer = KeyStrengthAnalyzer()
        self._rng_tester = RNGTester()

    # ------------------------------------------------------------------ #
    #  Entropy Analysis
    # ------------------------------------------------------------------ #

    async def analyze_entropy(self, file_path: Path) -> ScanResult:
        """Analyse the entropy characteristics of a file.

        Reads the file (up to max_sample_size bytes) and computes Shannon,
        min-entropy, Renyi entropy, and block-level entropy measurements.

        Args:
            file_path: Path to the file to analyse.

        Returns:
            ScanResult containing entropy findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="cipher",
            target=str(file_path),
            start_time=started_at,
        )

        self.logger.info(f"Starting entropy analysis: {file_path}")

        try:
            data = self._read_file(file_path)
            entropy_result: EntropyResult = self._entropy_analyzer.analyze(data)

            # Generate findings based on entropy analysis
            result.metadata = entropy_result.model_dump()

            # Primary entropy finding
            severity = self._entropy_severity(entropy_result)
            result.add_finding(Finding(
                title="Entropy Analysis Complete",
                description=(
                    f"Shannon entropy: {entropy_result.shannon:.4f} bits/byte. "
                    f"Min-entropy: {entropy_result.min_entropy:.4f} bits/byte. "
                    f"Renyi (alpha=2): {entropy_result.renyi:.4f} bits/byte. "
                    f"Data classified as: {entropy_result.data_type.value}."
                ),
                severity=severity,
                risk=self._entropy_risk(entropy_result),
                confidence=0.95,
                evidence={
                    "shannon": entropy_result.shannon,
                    "min_entropy": entropy_result.min_entropy,
                    "renyi": entropy_result.renyi,
                    "data_type": entropy_result.data_type.value,
                    "unique_bytes": entropy_result.unique_bytes,
                    "data_size": entropy_result.data_size,
                },
                references=[
                    "Shannon, C. E. (1948). A Mathematical Theory of Communication.",
                    "Renyi, A. (1961). On Measures of Entropy and Information.",
                ],
            ))

            # High-entropy warning (potential encryption/compression)
            if entropy_result.shannon >= 7.5:
                result.add_finding(Finding(
                    title="High Entropy Detected",
                    description=(
                        f"The data exhibits very high entropy ({entropy_result.shannon:.4f} "
                        f"bits/byte), suggesting encrypted, compressed, or random content. "
                        f"This is consistent with AES-encrypted or strongly compressed data."
                    ),
                    severity=Severity.INFO,
                    risk=Risk.LOW,
                    confidence=0.85,
                    recommendation="Investigate whether this file should be encrypted at this location.",
                ))

            # Low-entropy warning (potential plaintext in supposedly encrypted data)
            if entropy_result.shannon < 3.0 and entropy_result.data_size > 0:
                result.add_finding(Finding(
                    title="Low Entropy Detected",
                    description=(
                        f"The data has low entropy ({entropy_result.shannon:.4f} bits/byte), "
                        f"indicating plain text or highly structured data with limited "
                        f"information density."
                    ),
                    severity=Severity.INFO,
                    risk=Risk.NEGLIGIBLE,
                    confidence=0.90,
                ))

            # Block entropy variance analysis
            if len(entropy_result.block_entropies) > 1:
                entropies = [b.entropy for b in entropy_result.block_entropies]
                avg = sum(entropies) / len(entropies)
                variance = sum((e - avg) ** 2 for e in entropies) / len(entropies)
                if variance > 2.0:
                    result.add_finding(Finding(
                        title="High Entropy Variance Across Blocks",
                        description=(
                            f"Significant entropy variation detected across blocks "
                            f"(variance: {variance:.4f}). This may indicate mixed content "
                            f"types, embedded encrypted sections, or file format headers."
                        ),
                        severity=Severity.LOW,
                        risk=Risk.LOW,
                        confidence=0.70,
                    ))

            result.summary = (
                f"Entropy analysis of {file_path.name}: "
                f"H={entropy_result.shannon:.4f} bits/byte, "
                f"classified as {entropy_result.data_type.value}"
            )

        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            result.add_finding(Finding(
                title="File Not Found",
                description=f"The specified file could not be found: {file_path}",
                severity=Severity.HIGH,
                risk=Risk.HIGH,
            ))
            result.summary = f"Error: file not found ({file_path})"
        except PermissionError:
            self.logger.error(f"Permission denied: {file_path}")
            result.add_finding(Finding(
                title="Permission Denied",
                description=f"Insufficient permissions to read: {file_path}",
                severity=Severity.HIGH,
                risk=Risk.HIGH,
            ))
            result.summary = f"Error: permission denied ({file_path})"
        except Exception as exc:
            self.logger.exception(f"Entropy analysis failed: {exc}")
            result.add_finding(Finding(
                title="Analysis Error",
                description=f"Unexpected error during entropy analysis: {exc}",
                severity=Severity.MEDIUM,
                risk=Risk.MEDIUM,
            ))
            result.summary = f"Error during entropy analysis: {exc}"

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)
        self.logger.info(f"Entropy analysis completed in {elapsed:.3f}s")
        return result

    # ------------------------------------------------------------------ #
    #  Hash Identification
    # ------------------------------------------------------------------ #

    async def analyze_hash(self, hash_value: str) -> ScanResult:
        """Identify the likely hash algorithm for a given hash string.

        Args:
            hash_value: The hash string to identify.

        Returns:
            ScanResult containing hash identification findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="cipher",
            target=hash_value[:64] + ("..." if len(hash_value) > 64 else ""),
            start_time=started_at,
        )

        self.logger.info(f"Starting hash identification: {hash_value[:32]}...")

        try:
            identifications: list[HashIdentification] = self._hash_identifier.identify(
                hash_value
            )

            for identification in identifications:
                result.metadata = identification.model_dump()

                if identification.possible_types:
                    best = identification.possible_types[0]
                    result.add_finding(Finding(
                        title=f"Hash Identified: Most Likely {best.name}",
                        description=(
                            f"Hash value (length={identification.length}, "
                            f"charset={identification.charset}) most closely matches "
                            f"{best.name} with {best.confidence:.0%} confidence. "
                            f"{best.description}"
                        ),
                        severity=Severity.INFO,
                        risk=Risk.NEGLIGIBLE,
                        confidence=best.confidence,
                        evidence={
                            "hash_length": identification.length,
                            "charset": identification.charset,
                            "top_matches": [
                                {"name": t.name, "confidence": t.confidence}
                                for t in identification.possible_types[:5]
                            ],
                            "prefix": identification.prefix,
                            "is_salted": identification.is_salted,
                        },
                    ))

                    # Weak hash algorithm warning
                    weak_hashes = {"MD5", "MD4", "MD2", "SHA-1", "LM", "CRC32",
                                   "CRC32B", "Adler-32", "MySQL (old)", "Cisco Type 7"}
                    for ht in identification.possible_types[:3]:
                        if ht.name in weak_hashes and ht.confidence > 0.5:
                            result.add_finding(Finding(
                                title=f"Weak Hash Algorithm: {ht.name}",
                                description=(
                                    f"The hash may be {ht.name}, which is considered "
                                    f"cryptographically weak. Collision and preimage "
                                    f"attacks are practical."
                                ),
                                severity=Severity.MEDIUM,
                                risk=Risk.MEDIUM,
                                confidence=ht.confidence,
                                recommendation=(
                                    "Migrate to SHA-256, SHA-3, or BLAKE2b for "
                                    "integrity. Use bcrypt/Argon2 for passwords."
                                ),
                                references=[
                                    "Wang, X., & Yu, H. (2005). How to Break MD5.",
                                    "Stevens, M. et al. (2017). The First Collision for Full SHA-1.",
                                ],
                            ))
                            break
                else:
                    result.add_finding(Finding(
                        title="Hash Type Unidentified",
                        description=(
                            f"Could not identify the hash type for the given input "
                            f"(length={identification.length}, charset={identification.charset})."
                        ),
                        severity=Severity.LOW,
                        risk=Risk.NEGLIGIBLE,
                        confidence=0.5,
                    ))

            result.summary = self._hash_summary(identifications)

        except Exception as exc:
            self.logger.exception(f"Hash identification failed: {exc}")
            result.add_finding(Finding(
                title="Hash Identification Error",
                description=f"Error during hash identification: {exc}",
                severity=Severity.MEDIUM,
                risk=Risk.LOW,
            ))
            result.summary = f"Error: {exc}"

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)
        return result

    # ------------------------------------------------------------------ #
    #  TLS Cipher Suite Analysis
    # ------------------------------------------------------------------ #

    async def analyze_tls(
        self, host: str, port: int = 443
    ) -> ScanResult:
        """Analyse TLS cipher suites offered by a remote host.

        Args:
            host: Target hostname or IP address.
            port: Target port (default 443).

        Returns:
            ScanResult containing TLS cipher suite findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="cipher",
            target=f"{host}:{port}",
            start_time=started_at,
        )

        self.logger.info(f"Starting TLS analysis: {host}:{port}")

        try:
            tls_result: CipherSuiteResult = await self._cipher_suite_analyzer.analyze(
                host, port
            )
            result.metadata = tls_result.model_dump()

            # Overall grade finding
            grade_severity = self._grade_to_severity(tls_result.grade)
            result.add_finding(Finding(
                title=f"TLS Grade: {tls_result.grade.value}",
                description=(
                    f"TLS configuration for {host}:{port} received grade "
                    f"{tls_result.grade.value}. Protocol: {tls_result.protocol}. "
                    f"Cipher suites: {len(tls_result.suites)}."
                ),
                severity=grade_severity,
                risk=self._grade_to_risk(tls_result.grade),
                confidence=0.90,
                evidence={
                    "grade": tls_result.grade.value,
                    "protocol": tls_result.protocol,
                    "suite_count": len(tls_result.suites),
                    "tls_1_3": tls_result.supports_tls_13,
                    "forward_secrecy": tls_result.supports_forward_secrecy,
                },
                references=[
                    "NIST SP 800-131A Rev. 2 (2019). Cryptographic Algorithm Transitions.",
                    "NIST SP 800-52 Rev. 2 (2019). TLS Implementation Guidelines.",
                ],
            ))

            # TLS 1.3 support check
            if not tls_result.supports_tls_13:
                result.add_finding(Finding(
                    title="TLS 1.3 Not Supported",
                    description=(
                        "The server does not appear to support TLS 1.3. "
                        "TLS 1.3 provides improved security and performance."
                    ),
                    severity=Severity.LOW,
                    risk=Risk.LOW,
                    confidence=0.80,
                    recommendation="Enable TLS 1.3 on the server.",
                ))

            # Forward secrecy check
            if not tls_result.supports_forward_secrecy:
                result.add_finding(Finding(
                    title="No Forward Secrecy",
                    description=(
                        "The server does not offer cipher suites with forward "
                        "secrecy (ECDHE/DHE key exchange). Compromise of the "
                        "server's private key could allow decryption of past sessions."
                    ),
                    severity=Severity.MEDIUM,
                    risk=Risk.MEDIUM,
                    confidence=0.85,
                    recommendation="Enable ECDHE-based cipher suites.",
                ))

            # Weak ciphers check
            if tls_result.has_weak_ciphers:
                result.add_finding(Finding(
                    title="Weak Cipher Suites Detected",
                    description=(
                        "The server offers one or more cipher suites considered "
                        "weak (RC4, DES, 3DES, export ciphers, NULL ciphers)."
                    ),
                    severity=Severity.HIGH,
                    risk=Risk.HIGH,
                    confidence=0.95,
                    recommendation="Disable all weak cipher suites immediately.",
                ))

            # Add recommendations as findings
            for rec in tls_result.recommendations:
                result.add_finding(Finding(
                    title="TLS Recommendation",
                    description=rec,
                    severity=Severity.INFO,
                    risk=Risk.NEGLIGIBLE,
                    confidence=0.80,
                ))

            result.summary = (
                f"TLS analysis of {host}:{port}: Grade {tls_result.grade.value}, "
                f"Protocol {tls_result.protocol}, "
                f"{len(tls_result.suites)} cipher suite(s)"
            )

        except ConnectionRefusedError:
            self.logger.error(f"Connection refused: {host}:{port}")
            result.add_finding(Finding(
                title="Connection Refused",
                description=f"Could not connect to {host}:{port}.",
                severity=Severity.HIGH,
                risk=Risk.HIGH,
            ))
            result.summary = f"Connection refused: {host}:{port}"
        except Exception as exc:
            self.logger.exception(f"TLS analysis failed: {exc}")
            result.add_finding(Finding(
                title="TLS Analysis Error",
                description=f"Error during TLS analysis: {exc}",
                severity=Severity.MEDIUM,
                risk=Risk.MEDIUM,
            ))
            result.summary = f"Error: {exc}"

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)
        return result

    # ------------------------------------------------------------------ #
    #  Password Analysis
    # ------------------------------------------------------------------ #

    async def analyze_password(self, password: str) -> ScanResult:
        """Analyse the strength and entropy of a password.

        Args:
            password: The password to analyse.

        Returns:
            ScanResult containing password strength findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="cipher",
            target="[password]",
            start_time=started_at,
        )

        self.logger.info("Starting password analysis")

        try:
            pw_result: PasswordAnalysis = self._password_analyzer.analyze(password)
            result.metadata = pw_result.model_dump()

            # Primary strength finding
            severity = self._password_severity(pw_result.strength)
            result.add_finding(Finding(
                title=f"Password Strength: {pw_result.strength.value.replace('_', ' ').title()}",
                description=(
                    f"Password entropy: {pw_result.entropy:.2f} bits. "
                    f"Character pool: {pw_result.char_pool_size}. "
                    f"Length: {pw_result.length}. Score: {pw_result.score}/100."
                ),
                severity=severity,
                risk=self._password_risk(pw_result.strength),
                confidence=0.90,
                evidence={
                    "entropy_bits": pw_result.entropy,
                    "char_pool_size": pw_result.char_pool_size,
                    "length": pw_result.length,
                    "strength": pw_result.strength.value,
                    "score": pw_result.score,
                    "nist_compliant": pw_result.nist_compliant,
                },
                references=[
                    "NIST SP 800-63B (2017). Digital Identity Guidelines.",
                    "Weir, M. et al. (2009). Testing Metrics for Password "
                    "Creation Policies. CCS '09.",
                ],
            ))

            # Pattern warnings
            for pattern in pw_result.patterns_detected:
                result.add_finding(Finding(
                    title=f"Pattern Detected: {pattern.pattern_type}",
                    description=(
                        f"Detected {pattern.pattern_type} pattern '{pattern.value}' "
                        f"at position {pattern.position}. This reduces effective "
                        f"entropy by approximately {pattern.penalty:.1f} bits."
                    ),
                    severity=Severity.LOW,
                    risk=Risk.LOW,
                    confidence=0.75,
                ))

            # NIST compliance
            if not pw_result.nist_compliant:
                result.add_finding(Finding(
                    title="NIST SP 800-63B Non-Compliant",
                    description=(
                        "The password does not meet NIST SP 800-63B guidelines "
                        "(minimum 8 characters, not a commonly used password)."
                    ),
                    severity=Severity.MEDIUM,
                    risk=Risk.MEDIUM,
                    confidence=0.85,
                    recommendation="Use a password of at least 8 characters that is not commonly used.",
                ))

            # Add suggestions as informational findings
            for suggestion in pw_result.suggestions:
                result.add_finding(Finding(
                    title="Password Improvement Suggestion",
                    description=suggestion,
                    severity=Severity.INFO,
                    risk=Risk.NEGLIGIBLE,
                ))

            result.summary = (
                f"Password analysis: {pw_result.strength.value}, "
                f"entropy={pw_result.entropy:.1f} bits, score={pw_result.score}/100"
            )

        except Exception as exc:
            self.logger.exception(f"Password analysis failed: {exc}")
            result.add_finding(Finding(
                title="Password Analysis Error",
                description=f"Error during password analysis: {exc}",
                severity=Severity.MEDIUM,
                risk=Risk.LOW,
            ))
            result.summary = f"Error: {exc}"

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)
        return result

    # ------------------------------------------------------------------ #
    #  Frequency Analysis
    # ------------------------------------------------------------------ #

    async def analyze_frequency(self, file_path: Path) -> ScanResult:
        """Perform frequency analysis on file data.

        Args:
            file_path: Path to the file to analyse.

        Returns:
            ScanResult containing frequency analysis findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="cipher",
            target=str(file_path),
            start_time=started_at,
        )

        self.logger.info(f"Starting frequency analysis: {file_path}")

        try:
            data = self._read_file(file_path)
            freq_result: FrequencyResult = self._frequency_analyzer.analyze(data)
            result.metadata = freq_result.model_dump()

            result.add_finding(Finding(
                title=f"Frequency Analysis: {freq_result.likely_cipher_type.value}",
                description=(
                    f"Chi-squared statistic: {freq_result.chi_squared:.4f} "
                    f"(p={freq_result.chi_squared_p_value:.6f}). "
                    f"Index of Coincidence: {freq_result.ic:.6f}. "
                    f"Likely cipher type: {freq_result.likely_cipher_type.value}."
                ),
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
                confidence=0.80,
                evidence={
                    "chi_squared": freq_result.chi_squared,
                    "p_value": freq_result.chi_squared_p_value,
                    "ic": freq_result.ic,
                    "cipher_type": freq_result.likely_cipher_type.value,
                },
                references=[
                    "Pearson, K. (1900). Chi-squared test.",
                    "Friedman, W. F. (1922). The Index of Coincidence.",
                ],
            ))

            if freq_result.kasiski_key_lengths:
                result.add_finding(Finding(
                    title="Kasiski Examination Results",
                    description=(
                        f"Kasiski examination suggests likely key lengths: "
                        f"{freq_result.kasiski_key_lengths[:5]}. "
                        f"This analysis is most relevant for polyalphabetic ciphers."
                    ),
                    severity=Severity.INFO,
                    risk=Risk.NEGLIGIBLE,
                    confidence=0.65,
                    references=[
                        "Kasiski, F. W. (1863). Die Geheimschriften und die "
                        "Dechiffrirkunst."
                    ],
                ))

            result.summary = (
                f"Frequency analysis: IC={freq_result.ic:.6f}, "
                f"type={freq_result.likely_cipher_type.value}"
            )

        except FileNotFoundError:
            result.add_finding(Finding(
                title="File Not Found",
                description=f"File not found: {file_path}",
                severity=Severity.HIGH,
                risk=Risk.HIGH,
            ))
            result.summary = f"Error: file not found ({file_path})"
        except Exception as exc:
            self.logger.exception(f"Frequency analysis failed: {exc}")
            result.add_finding(Finding(
                title="Frequency Analysis Error",
                description=f"Error: {exc}",
                severity=Severity.MEDIUM,
                risk=Risk.LOW,
            ))
            result.summary = f"Error: {exc}"

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)
        return result

    # ------------------------------------------------------------------ #
    #  Key Strength Analysis
    # ------------------------------------------------------------------ #

    async def analyze_key_strength(
        self, algorithm: str, key_size: int
    ) -> ScanResult:
        """Evaluate the strength of a cryptographic key configuration.

        Args:
            algorithm: Algorithm name (e.g. "RSA", "AES").
            key_size: Key size in bits.

        Returns:
            ScanResult containing key strength findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="cipher",
            target=f"{algorithm}-{key_size}",
            start_time=started_at,
        )

        try:
            ks_result: KeyStrengthResult = self._key_strength_analyzer.analyze(
                algorithm, key_size
            )
            result.metadata = ks_result.model_dump()

            severity = Severity.INFO
            if ks_result.status == "deprecated":
                severity = Severity.HIGH
            elif ks_result.status == "legacy":
                severity = Severity.MEDIUM
            elif ks_result.status == "weak":
                severity = Severity.CRITICAL

            result.add_finding(Finding(
                title=f"Key Strength: {algorithm}-{key_size}",
                description=(
                    f"Effective security: {ks_result.effective_strength} bits. "
                    f"Status: {ks_result.status}. "
                    f"Quantum-safe: {'Yes' if ks_result.quantum_safe else 'No'}. "
                    f"{ks_result.recommendation}"
                ),
                severity=severity,
                risk=Risk.LOW if ks_result.status == "acceptable" else Risk.MEDIUM,
                confidence=0.95,
                evidence={
                    "algorithm": ks_result.algorithm,
                    "key_size": ks_result.key_size,
                    "effective_strength": ks_result.effective_strength,
                    "quantum_safe": ks_result.quantum_safe,
                    "quantum_strength": ks_result.quantum_strength,
                    "status": ks_result.status,
                },
                references=[
                    "NIST SP 800-131A Rev. 2 (2019).",
                    "NIST SP 800-57 Part 1 Rev. 5 (2020). Key Management.",
                ],
            ))

            if not ks_result.quantum_safe:
                result.add_finding(Finding(
                    title="Not Quantum-Resistant",
                    description=(
                        f"{algorithm}-{key_size} is vulnerable to quantum computing "
                        f"attacks. Shor's algorithm can break RSA/EC in polynomial time. "
                        f"Post-quantum strength: {ks_result.quantum_strength} bits."
                    ),
                    severity=Severity.LOW,
                    risk=Risk.LOW,
                    confidence=0.90,
                    recommendation="Plan migration to post-quantum algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium).",
                ))

            result.summary = (
                f"{algorithm}-{key_size}: {ks_result.effective_strength}-bit "
                f"effective security, status={ks_result.status}"
            )

        except Exception as exc:
            self.logger.exception(f"Key strength analysis failed: {exc}")
            result.add_finding(Finding(
                title="Key Strength Analysis Error",
                description=f"Error: {exc}",
                severity=Severity.MEDIUM,
                risk=Risk.LOW,
            ))
            result.summary = f"Error: {exc}"

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)
        return result

    # ------------------------------------------------------------------ #
    #  RNG Testing
    # ------------------------------------------------------------------ #

    async def analyze_rng(self, file_path: Path) -> ScanResult:
        """Run NIST SP 800-22 statistical tests on file data.

        Args:
            file_path: Path to the file containing random data.

        Returns:
            ScanResult containing RNG test findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="cipher",
            target=str(file_path),
            start_time=started_at,
        )

        self.logger.info(f"Starting RNG testing: {file_path}")

        try:
            data = self._read_file(file_path)
            rng_result: RNGSuiteResult = self._rng_tester.run_suite(data)
            result.metadata = rng_result.model_dump()

            overall_severity = Severity.INFO if rng_result.overall_pass else Severity.MEDIUM

            result.add_finding(Finding(
                title=f"RNG Test Suite: {'PASS' if rng_result.overall_pass else 'FAIL'}",
                description=(
                    f"Ran {rng_result.total_tests} NIST SP 800-22 statistical tests. "
                    f"Passed: {rng_result.tests_passed}/{rng_result.total_tests}. "
                    f"Data size: {rng_result.data_size_bits} bits. "
                    f"{rng_result.assessment}"
                ),
                severity=overall_severity,
                risk=Risk.LOW if rng_result.overall_pass else Risk.MEDIUM,
                confidence=0.85,
                references=[
                    "NIST SP 800-22 Rev. 1a (2010). Statistical Test Suite.",
                ],
            ))

            for test in rng_result.tests:
                if not test.passed:
                    result.add_finding(Finding(
                        title=f"RNG Test Failed: {test.test_name}",
                        description=(
                            f"{test.description} p-value={test.p_value:.6f} "
                            f"(threshold=0.01). Statistic={test.statistic:.6f}."
                        ),
                        severity=Severity.LOW,
                        risk=Risk.LOW,
                        confidence=0.80,
                    ))

            result.summary = (
                f"RNG tests: {rng_result.tests_passed}/{rng_result.total_tests} passed"
            )

        except FileNotFoundError:
            result.add_finding(Finding(
                title="File Not Found",
                description=f"File not found: {file_path}",
                severity=Severity.HIGH,
                risk=Risk.HIGH,
            ))
            result.summary = f"Error: file not found ({file_path})"
        except Exception as exc:
            self.logger.exception(f"RNG testing failed: {exc}")
            result.add_finding(Finding(
                title="RNG Test Error",
                description=f"Error: {exc}",
                severity=Severity.MEDIUM,
                risk=Risk.LOW,
            ))
            result.summary = f"Error: {exc}"

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)
        return result

    # ------------------------------------------------------------------ #
    #  Private Helpers
    # ------------------------------------------------------------------ #

    def _read_file(self, file_path: Path) -> bytes:
        """Read a file up to max_sample_size bytes."""
        max_size = self.config.cipher.max_sample_size
        with open(file_path, "rb") as f:
            return f.read(max_size)

    @staticmethod
    def _entropy_severity(result: EntropyResult) -> Severity:
        """Map entropy result to a severity level."""
        if result.data_type == DataType.ENCRYPTED_RANDOM:
            return Severity.INFO
        elif result.data_type == DataType.COMPRESSED:
            return Severity.INFO
        elif result.data_type == DataType.PLAIN_TEXT:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def _entropy_risk(result: EntropyResult) -> Risk:
        """Map entropy result to a risk level."""
        if result.data_type == DataType.ENCRYPTED_RANDOM:
            return Risk.LOW
        return Risk.NEGLIGIBLE

    @staticmethod
    def _grade_to_severity(grade: CipherGrade) -> Severity:
        """Map a TLS grade to a severity level."""
        mapping = {
            CipherGrade.A_PLUS: Severity.INFO,
            CipherGrade.A: Severity.INFO,
            CipherGrade.B: Severity.LOW,
            CipherGrade.C: Severity.MEDIUM,
            CipherGrade.D: Severity.HIGH,
            CipherGrade.F: Severity.CRITICAL,
        }
        return mapping.get(grade, Severity.MEDIUM)

    @staticmethod
    def _grade_to_risk(grade: CipherGrade) -> Risk:
        """Map a TLS grade to a risk level."""
        mapping = {
            CipherGrade.A_PLUS: Risk.NEGLIGIBLE,
            CipherGrade.A: Risk.NEGLIGIBLE,
            CipherGrade.B: Risk.LOW,
            CipherGrade.C: Risk.MEDIUM,
            CipherGrade.D: Risk.HIGH,
            CipherGrade.F: Risk.CRITICAL,
        }
        return mapping.get(grade, Risk.MEDIUM)

    @staticmethod
    def _password_severity(strength: PasswordStrength) -> Severity:
        """Map password strength to a severity level."""
        mapping = {
            PasswordStrength.VERY_WEAK: Severity.CRITICAL,
            PasswordStrength.WEAK: Severity.HIGH,
            PasswordStrength.FAIR: Severity.MEDIUM,
            PasswordStrength.STRONG: Severity.LOW,
            PasswordStrength.VERY_STRONG: Severity.INFO,
        }
        return mapping.get(strength, Severity.MEDIUM)

    @staticmethod
    def _password_risk(strength: PasswordStrength) -> Risk:
        """Map password strength to a risk level."""
        mapping = {
            PasswordStrength.VERY_WEAK: Risk.CRITICAL,
            PasswordStrength.WEAK: Risk.HIGH,
            PasswordStrength.FAIR: Risk.MEDIUM,
            PasswordStrength.STRONG: Risk.LOW,
            PasswordStrength.VERY_STRONG: Risk.NEGLIGIBLE,
        }
        return mapping.get(strength, Risk.MEDIUM)

    @staticmethod
    def _hash_summary(identifications: list[HashIdentification]) -> str:
        """Generate a summary string for hash identifications."""
        if not identifications:
            return "No hash identifications produced."
        ident = identifications[0]
        if ident.possible_types:
            top = ident.possible_types[0]
            return (
                f"Hash identification: most likely {top.name} "
                f"({top.confidence:.0%} confidence)"
            )
        return "Hash type could not be determined."
