"""
Cipher Core Data Models
========================

Pydantic models for the Cipher cryptographic analysis engine. These models
represent structured results from entropy analysis, hash identification,
cipher suite evaluation, password strength assessment, frequency analysis,
key strength estimation, and random number generator testing.

All models are serialisable to JSON and designed for consumption by both
the CLI output layer and HTML report generators.

References:
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
      Bell System Technical Journal, 27(3), 379-423.
    - NIST SP 800-22 Rev. 1a (2010). A Statistical Test Suite for
      Random and Pseudorandom Number Generators.
    - NIST SP 800-131A Rev. 2 (2019). Transitioning the Use of
      Cryptographic Algorithms and Key Lengths.
    - NIST SP 800-63B (2017). Digital Identity Guidelines --
      Authentication and Lifecycle Management.
    - Friedman, W. F. (1922). The Index of Coincidence and Its
      Applications in Cryptanalysis. Riverbank Publication No. 22.
    - Pearson, K. (1900). On the criterion that a given system of
      deviations from the probable. Philosophical Magazine, 50(302).
"""

from __future__ import annotations

import enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ===================================================================== #
#  Enumerations
# ===================================================================== #


class DataType(str, enum.Enum):
    """Classification of data based on its entropy characteristics.

    Entropy ranges are empirically derived from analysis of common
    file formats and cryptographic outputs.
    """

    EMPTY_UNIFORM = "empty_uniform"        # H in [0, 1)
    PLAIN_TEXT = "plain_text"              # H in [1, 3)
    STRUCTURED_DATA = "structured_data"    # H in [3, 5)
    COMPRESSED_TEXT = "compressed_text"     # H in [5, 6)
    ENCODED_DATA = "encoded_data"          # H in [6, 7)
    COMPRESSED = "compressed"              # H in [7, 7.5)
    ENCRYPTED_RANDOM = "encrypted_random"  # H in [7.5, 8]


class PasswordStrength(str, enum.Enum):
    """Qualitative password strength rating.

    Reference:
        NIST SP 800-63B (2017). Digital Identity Guidelines.
    """

    VERY_WEAK = "very_weak"
    WEAK = "weak"
    FAIR = "fair"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


class CipherGrade(str, enum.Enum):
    """TLS/cipher suite quality grade (A+ to F).

    Modelled after the SSL Labs grading methodology, incorporating
    NIST SP 800-131A recommendations for algorithm transitions.
    """

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class CipherType(str, enum.Enum):
    """Likely cipher type classification based on frequency analysis."""

    MONOALPHABETIC = "monoalphabetic"
    POLYALPHABETIC = "polyalphabetic"
    TRANSPOSITION = "transposition"
    RANDOM_OR_MODERN = "random_or_modern"
    PLAINTEXT = "plaintext"


# ===================================================================== #
#  Entropy Models
# ===================================================================== #


class BlockEntropy(BaseModel):
    """Entropy measurement for a single data block.

    Attributes:
        offset: Byte offset of the block start within the file.
        size: Block size in bytes.
        entropy: Shannon entropy of this block (bits per byte).
    """

    offset: int
    size: int
    entropy: float


class EntropyResult(BaseModel):
    """Complete entropy analysis result for a data sample.

    Attributes:
        shannon: Shannon entropy H(X) in bits per byte [0.0, 8.0].
        min_entropy: Min-entropy H_inf(X) in bits per byte.
        renyi: Renyi entropy of order 2 (collision entropy) in bits.
        block_entropies: Per-block entropy measurements for visualisation.
        data_type: Classified data type based on entropy range.
        data_size: Total size of analysed data in bytes.
        unique_bytes: Number of distinct byte values observed (0-256).
        entropy_map: List of entropy values per block for heatmap display.
    """

    shannon: float = 0.0
    min_entropy: float = 0.0
    renyi: float = 0.0
    block_entropies: list[BlockEntropy] = Field(default_factory=list)
    data_type: DataType = DataType.EMPTY_UNIFORM
    data_size: int = 0
    unique_bytes: int = 0
    entropy_map: list[float] = Field(default_factory=list)


# ===================================================================== #
#  Hash Identification Models
# ===================================================================== #


class HashType(BaseModel):
    """A candidate hash algorithm identification.

    Attributes:
        name: Algorithm name (e.g. "SHA-256", "bcrypt").
        confidence: Confidence score in [0.0, 1.0].
        description: Short description of the hash algorithm.
        hashcat_mode: Corresponding hashcat mode number, if known.
        john_format: Corresponding John the Ripper format name, if known.
    """

    name: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    description: str = ""
    hashcat_mode: Optional[int] = None
    john_format: Optional[str] = None


class HashIdentification(BaseModel):
    """Result of hash type identification.

    Attributes:
        hash_value: The original hash string (possibly truncated for display).
        possible_types: Ranked list of candidate hash types.
        length: Character length of the hash string.
        charset: Character set detected (hex, base64, alphanumeric, etc.).
        is_salted: Whether the hash appears to contain a salt component.
        prefix: Any format prefix detected (e.g. "$2b$", "$argon2id$").
    """

    hash_value: str
    possible_types: list[HashType] = Field(default_factory=list)
    length: int = 0
    charset: str = "unknown"
    is_salted: bool = False
    prefix: str = ""


# ===================================================================== #
#  Cipher Suite Models
# ===================================================================== #


class CipherSuiteInfo(BaseModel):
    """Details of a single cipher suite offered by a TLS endpoint.

    Attributes:
        name: Cipher suite name (e.g. "TLS_AES_256_GCM_SHA384").
        protocol: Protocol version (e.g. "TLSv1.3").
        key_exchange: Key exchange algorithm (e.g. "ECDHE").
        authentication: Authentication algorithm (e.g. "RSA").
        encryption: Bulk encryption algorithm (e.g. "AES-256-GCM").
        mac: MAC algorithm (e.g. "SHA384", "AEAD").
        bits: Encryption key size in bits.
        grade: Individual suite grade.
    """

    name: str
    protocol: str = ""
    key_exchange: str = ""
    authentication: str = ""
    encryption: str = ""
    mac: str = ""
    bits: int = 0
    grade: CipherGrade = CipherGrade.C


class CertificateInfo(BaseModel):
    """TLS certificate information.

    Attributes:
        subject: Certificate subject (CN).
        issuer: Certificate issuer.
        serial_number: Certificate serial number as hex string.
        not_before: Validity start date as ISO string.
        not_after: Validity end date as ISO string.
        signature_algorithm: Signature algorithm used.
        public_key_bits: Public key size in bits.
        san: Subject Alternative Names list.
    """

    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    signature_algorithm: str = ""
    public_key_bits: int = 0
    san: list[str] = Field(default_factory=list)


class CipherSuiteResult(BaseModel):
    """Aggregated TLS cipher suite analysis result.

    Attributes:
        host: Target hostname.
        port: Target port.
        protocol: Highest supported TLS protocol version.
        suites: List of supported cipher suites.
        grade: Overall grade for the TLS configuration.
        certificate: Certificate details.
        supports_tls_13: Whether TLS 1.3 is supported.
        supports_forward_secrecy: Whether forward secrecy is available.
        has_weak_ciphers: Whether any weak ciphers are offered.
        recommendations: List of improvement recommendations.
    """

    host: str
    port: int = 443
    protocol: str = ""
    suites: list[CipherSuiteInfo] = Field(default_factory=list)
    grade: CipherGrade = CipherGrade.F
    certificate: Optional[CertificateInfo] = None
    supports_tls_13: bool = False
    supports_forward_secrecy: bool = False
    has_weak_ciphers: bool = False
    recommendations: list[str] = Field(default_factory=list)


# ===================================================================== #
#  Password Analysis Models
# ===================================================================== #


class PasswordPattern(BaseModel):
    """A detected pattern within a password.

    Attributes:
        pattern_type: Type of pattern (e.g. "dictionary", "keyboard", "date").
        value: The matched substring or pattern description.
        position: Start position within the password.
        penalty: Entropy penalty in bits.
    """

    pattern_type: str
    value: str = ""
    position: int = 0
    penalty: float = 0.0


class CrackTimeEstimate(BaseModel):
    """Password crack time estimate at a given attack speed.

    Attributes:
        scenario: Description of the attack scenario.
        guesses_per_second: Attack speed in guesses per second.
        seconds: Estimated time in seconds.
        display: Human-readable time string.
    """

    scenario: str
    guesses_per_second: float
    seconds: float
    display: str = ""


class PasswordAnalysis(BaseModel):
    """Complete password strength analysis result.

    Attributes:
        password_masked: Masked version of the password for display.
        length: Password character length.
        entropy: Shannon entropy of the password in bits.
        char_pool_size: Effective character pool size.
        strength: Qualitative strength rating.
        crack_time_estimates: Crack time at various attack speeds.
        patterns_detected: List of detected weakening patterns.
        suggestions: List of improvement suggestions.
        nist_compliant: Whether the password meets NIST SP 800-63B guidelines.
        score: Numeric score from 0 to 100.
    """

    password_masked: str = ""
    length: int = 0
    entropy: float = 0.0
    char_pool_size: int = 0
    strength: PasswordStrength = PasswordStrength.VERY_WEAK
    crack_time_estimates: list[CrackTimeEstimate] = Field(default_factory=list)
    patterns_detected: list[PasswordPattern] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)
    nist_compliant: bool = False
    score: int = 0


# ===================================================================== #
#  Frequency Analysis Models
# ===================================================================== #


class FrequencyResult(BaseModel):
    """Result of byte-level frequency analysis.

    Attributes:
        distribution: Normalised byte frequency distribution (256 entries).
        chi_squared: Chi-squared statistic against uniform distribution.
        chi_squared_p_value: P-value of the chi-squared test.
        ic: Index of Coincidence.
        likely_cipher_type: Classified cipher type from IC analysis.
        most_common_bytes: Top 10 most frequent byte values.
        least_common_bytes: Bottom 10 least frequent byte values.
        kasiski_key_lengths: Likely key lengths from Kasiski examination.
        byte_count: Total number of bytes analysed.
    """

    distribution: dict[int, float] = Field(default_factory=dict)
    chi_squared: float = 0.0
    chi_squared_p_value: float = 1.0
    ic: float = 0.0
    likely_cipher_type: CipherType = CipherType.PLAINTEXT
    most_common_bytes: list[tuple[int, float]] = Field(default_factory=list)
    least_common_bytes: list[tuple[int, float]] = Field(default_factory=list)
    kasiski_key_lengths: list[int] = Field(default_factory=list)
    byte_count: int = 0


# ===================================================================== #
#  Key Strength Models
# ===================================================================== #


class KeyStrengthResult(BaseModel):
    """Result of cryptographic key strength evaluation.

    Attributes:
        algorithm: Algorithm name (e.g. "RSA", "AES", "ECDSA").
        key_size: Nominal key size in bits.
        effective_strength: Effective security level in bits.
        quantum_safe: Whether the algorithm is considered quantum-resistant.
        quantum_strength: Post-quantum effective strength (Grover/Shor).
        recommendation: NIST recommendation for this configuration.
        status: Current assessment status (e.g. "acceptable", "deprecated").
        nist_level: NIST security strength category (1-5) if applicable.
        comparable_symmetric: Equivalent symmetric key size for comparison.
        details: Additional algorithm-specific details.
    """

    algorithm: str
    key_size: int
    effective_strength: int = 0
    quantum_safe: bool = False
    quantum_strength: int = 0
    recommendation: str = ""
    status: str = "unknown"
    nist_level: Optional[int] = None
    comparable_symmetric: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


# ===================================================================== #
#  RNG Testing Models
# ===================================================================== #


class RNGTestResult(BaseModel):
    """Result of a single NIST SP 800-22 statistical test.

    Attributes:
        test_name: Name of the statistical test.
        p_value: Computed p-value from the test.
        passed: Whether the test passed (p_value >= 0.01).
        description: Human-readable description of what was tested.
        statistic: The raw test statistic value.
    """

    test_name: str
    p_value: float = 0.0
    passed: bool = False
    description: str = ""
    statistic: float = 0.0


class RNGSuiteResult(BaseModel):
    """Aggregated result from the full NIST SP 800-22 test suite.

    Attributes:
        tests: Individual test results.
        total_tests: Number of tests executed.
        tests_passed: Number of tests that passed.
        tests_failed: Number of tests that failed.
        overall_pass: Whether the data passes the suite (all tests pass).
        data_size_bits: Size of the input data in bits.
        assessment: Human-readable overall assessment.
    """

    tests: list[RNGTestResult] = Field(default_factory=list)
    total_tests: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    overall_pass: bool = False
    data_size_bits: int = 0
    assessment: str = ""
