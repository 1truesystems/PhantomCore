"""
Key Strength Analyzer
======================

Evaluates the strength of cryptographic key configurations against
current NIST recommendations, including post-quantum resistance
assessment.

The analyzer maintains a database of algorithm specifications covering:
- Asymmetric algorithms: RSA, DSA, ECDSA, EdDSA, DH, ECDH
- Symmetric algorithms: AES, ChaCha20, 3DES, Blowfish, Twofish, Camellia
- Post-quantum: CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+

Quantum resistance estimation:
- Grover's algorithm halves the effective security of symmetric ciphers:
  AES-256 -> 128-bit post-quantum security
- Shor's algorithm breaks RSA, DSA, DH, ECDSA, ECDH in polynomial time:
  RSA-2048 -> 0-bit post-quantum security

NIST security strength categories (SP 800-57):
    Level 1: 128 bits (AES-128, RSA-3072, P-256)
    Level 2: 192 bits (AES-192, RSA-7680, P-384)
    Level 3: 256 bits (AES-256, RSA-15360, P-521)

References:
    - NIST SP 800-131A Rev. 2 (2019). Transitioning the Use of
      Cryptographic Algorithms and Key Lengths.
    - NIST SP 800-57 Part 1 Rev. 5 (2020). Recommendation for
      Key Management.
    - Grover, L. K. (1996). A Fast Quantum Mechanical Algorithm for
      Database Search. STOC '96.
    - Shor, P. W. (1994). Algorithms for Quantum Computation: Discrete
      Logarithms and Factoring. FOCS '94.
    - NIST IR 8413 (2022). Status Report on the Third Round of the
      NIST Post-Quantum Cryptography Standardization Process.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cipher.core.models import KeyStrengthResult


# ===================================================================== #
#  Algorithm Specification Database
# ===================================================================== #

@dataclass(frozen=True, slots=True)
class AlgorithmSpec:
    """Specification for a cryptographic algorithm configuration.

    Attributes:
        algorithm: Canonical algorithm name.
        key_size: Nominal key size in bits.
        effective_strength: Classical effective security in bits.
        quantum_strength: Post-quantum effective security in bits.
        quantum_safe: Whether the algorithm resists quantum attacks.
        status: Current assessment ("strong", "acceptable", "legacy", "deprecated", "weak").
        nist_level: NIST security strength category (1-5, or None).
        comparable_symmetric: Equivalent symmetric key size.
        notes: Additional notes about this configuration.
    """

    algorithm: str
    key_size: int
    effective_strength: int
    quantum_strength: int
    quantum_safe: bool
    status: str
    nist_level: Optional[int]
    comparable_symmetric: int
    notes: str


# Database of algorithm specifications
_ALGORITHM_DATABASE: dict[str, dict[int, AlgorithmSpec]] = {
    # ============================================================ #
    #  RSA -- Integer Factorisation Problem
    # ============================================================ #
    "RSA": {
        512: AlgorithmSpec(
            algorithm="RSA", key_size=512, effective_strength=56,
            quantum_strength=0, quantum_safe=False, status="weak",
            nist_level=None, comparable_symmetric=56,
            notes="Factorable in hours with commodity hardware. Do not use.",
        ),
        1024: AlgorithmSpec(
            algorithm="RSA", key_size=1024, effective_strength=80,
            quantum_strength=0, quantum_safe=False, status="deprecated",
            nist_level=None, comparable_symmetric=80,
            notes="Deprecated by NIST since 2013. Vulnerable to well-funded adversaries.",
        ),
        2048: AlgorithmSpec(
            algorithm="RSA", key_size=2048, effective_strength=112,
            quantum_strength=0, quantum_safe=False, status="acceptable",
            nist_level=1, comparable_symmetric=112,
            notes="Acceptable through 2030 per NIST SP 800-131A. Minimum recommended.",
        ),
        3072: AlgorithmSpec(
            algorithm="RSA", key_size=3072, effective_strength=128,
            quantum_strength=0, quantum_safe=False, status="acceptable",
            nist_level=1, comparable_symmetric=128,
            notes="Provides 128-bit security. Recommended for new deployments.",
        ),
        4096: AlgorithmSpec(
            algorithm="RSA", key_size=4096, effective_strength=152,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=2, comparable_symmetric=152,
            notes="Strong classical security. Higher performance cost.",
        ),
        7680: AlgorithmSpec(
            algorithm="RSA", key_size=7680, effective_strength=192,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=2, comparable_symmetric=192,
            notes="192-bit equivalent security. Significant performance impact.",
        ),
        15360: AlgorithmSpec(
            algorithm="RSA", key_size=15360, effective_strength=256,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=3, comparable_symmetric=256,
            notes="256-bit equivalent security. Very large key, impractical for most uses.",
        ),
    },

    # ============================================================ #
    #  DSA -- Digital Signature Algorithm
    # ============================================================ #
    "DSA": {
        1024: AlgorithmSpec(
            algorithm="DSA", key_size=1024, effective_strength=80,
            quantum_strength=0, quantum_safe=False, status="deprecated",
            nist_level=None, comparable_symmetric=80,
            notes="Deprecated. Migrate to ECDSA or EdDSA.",
        ),
        2048: AlgorithmSpec(
            algorithm="DSA", key_size=2048, effective_strength=112,
            quantum_strength=0, quantum_safe=False, status="legacy",
            nist_level=1, comparable_symmetric=112,
            notes="Legacy use only. Prefer ECDSA P-256 or Ed25519.",
        ),
        3072: AlgorithmSpec(
            algorithm="DSA", key_size=3072, effective_strength=128,
            quantum_strength=0, quantum_safe=False, status="legacy",
            nist_level=1, comparable_symmetric=128,
            notes="Legacy. NIST recommends ECDSA for new applications.",
        ),
    },

    # ============================================================ #
    #  ECDSA -- Elliptic Curve Digital Signature Algorithm
    # ============================================================ #
    "ECDSA": {
        256: AlgorithmSpec(
            algorithm="ECDSA", key_size=256, effective_strength=128,
            quantum_strength=0, quantum_safe=False, status="acceptable",
            nist_level=1, comparable_symmetric=128,
            notes="P-256 (secp256r1). Widely deployed and recommended.",
        ),
        384: AlgorithmSpec(
            algorithm="ECDSA", key_size=384, effective_strength=192,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=2, comparable_symmetric=192,
            notes="P-384 (secp384r1). Used for high-security applications.",
        ),
        521: AlgorithmSpec(
            algorithm="ECDSA", key_size=521, effective_strength=256,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=3, comparable_symmetric=256,
            notes="P-521 (secp521r1). Maximum NIST curve security.",
        ),
    },

    # ============================================================ #
    #  EdDSA -- Edwards-curve Digital Signature Algorithm
    # ============================================================ #
    "EdDSA": {
        255: AlgorithmSpec(
            algorithm="EdDSA", key_size=255, effective_strength=128,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=1, comparable_symmetric=128,
            notes="Ed25519 (Curve25519). High performance, constant-time, safe curves.",
        ),
        448: AlgorithmSpec(
            algorithm="EdDSA", key_size=448, effective_strength=224,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=2, comparable_symmetric=224,
            notes="Ed448 (Curve448). Higher security variant of EdDSA.",
        ),
    },

    # ============================================================ #
    #  DH -- Diffie-Hellman Key Exchange
    # ============================================================ #
    "DH": {
        1024: AlgorithmSpec(
            algorithm="DH", key_size=1024, effective_strength=80,
            quantum_strength=0, quantum_safe=False, status="deprecated",
            nist_level=None, comparable_symmetric=80,
            notes="Vulnerable to Logjam attack. Do not use.",
        ),
        2048: AlgorithmSpec(
            algorithm="DH", key_size=2048, effective_strength=112,
            quantum_strength=0, quantum_safe=False, status="acceptable",
            nist_level=1, comparable_symmetric=112,
            notes="Minimum acceptable. Prefer ECDH.",
        ),
        4096: AlgorithmSpec(
            algorithm="DH", key_size=4096, effective_strength=152,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=2, comparable_symmetric=152,
            notes="Strong classical security. Significant handshake overhead.",
        ),
    },

    # ============================================================ #
    #  ECDH -- Elliptic Curve Diffie-Hellman
    # ============================================================ #
    "ECDH": {
        256: AlgorithmSpec(
            algorithm="ECDH", key_size=256, effective_strength=128,
            quantum_strength=0, quantum_safe=False, status="acceptable",
            nist_level=1, comparable_symmetric=128,
            notes="P-256 or X25519. Preferred for TLS key exchange.",
        ),
        384: AlgorithmSpec(
            algorithm="ECDH", key_size=384, effective_strength=192,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=2, comparable_symmetric=192,
            notes="P-384. High-security key exchange.",
        ),
        521: AlgorithmSpec(
            algorithm="ECDH", key_size=521, effective_strength=256,
            quantum_strength=0, quantum_safe=False, status="strong",
            nist_level=3, comparable_symmetric=256,
            notes="P-521. Maximum NIST curve key exchange security.",
        ),
    },

    # ============================================================ #
    #  AES -- Advanced Encryption Standard
    # ============================================================ #
    "AES": {
        128: AlgorithmSpec(
            algorithm="AES", key_size=128, effective_strength=128,
            quantum_strength=64, quantum_safe=True, status="acceptable",
            nist_level=1, comparable_symmetric=128,
            notes="AES-128. Post-quantum: 64 bits via Grover's algorithm.",
        ),
        192: AlgorithmSpec(
            algorithm="AES", key_size=192, effective_strength=192,
            quantum_strength=96, quantum_safe=True, status="strong",
            nist_level=2, comparable_symmetric=192,
            notes="AES-192. Post-quantum: 96 bits via Grover's algorithm.",
        ),
        256: AlgorithmSpec(
            algorithm="AES", key_size=256, effective_strength=256,
            quantum_strength=128, quantum_safe=True, status="strong",
            nist_level=3, comparable_symmetric=256,
            notes="AES-256. Post-quantum: 128 bits via Grover's algorithm. Recommended.",
        ),
    },

    # ============================================================ #
    #  ChaCha20 -- Stream Cipher
    # ============================================================ #
    "ChaCha20": {
        256: AlgorithmSpec(
            algorithm="ChaCha20", key_size=256, effective_strength=256,
            quantum_strength=128, quantum_safe=True, status="strong",
            nist_level=3, comparable_symmetric=256,
            notes="ChaCha20-Poly1305. Excellent performance on non-AES-NI hardware.",
        ),
    },

    # ============================================================ #
    #  3DES -- Triple Data Encryption Standard
    # ============================================================ #
    "3DES": {
        168: AlgorithmSpec(
            algorithm="3DES", key_size=168, effective_strength=112,
            quantum_strength=56, quantum_safe=False, status="deprecated",
            nist_level=None, comparable_symmetric=112,
            notes="Effective strength limited to 112 bits (meet-in-the-middle). "
                  "64-bit block vulnerable to Sweet32 attack. Deprecated by NIST.",
        ),
        112: AlgorithmSpec(
            algorithm="3DES", key_size=112, effective_strength=80,
            quantum_strength=40, quantum_safe=False, status="deprecated",
            nist_level=None, comparable_symmetric=80,
            notes="Two-key 3DES. Deprecated.",
        ),
    },

    # ============================================================ #
    #  Blowfish
    # ============================================================ #
    "Blowfish": {
        128: AlgorithmSpec(
            algorithm="Blowfish", key_size=128, effective_strength=128,
            quantum_strength=64, quantum_safe=True, status="legacy",
            nist_level=1, comparable_symmetric=128,
            notes="64-bit block size limits data-per-key. Use AES instead.",
        ),
        256: AlgorithmSpec(
            algorithm="Blowfish", key_size=256, effective_strength=256,
            quantum_strength=128, quantum_safe=True, status="legacy",
            nist_level=3, comparable_symmetric=256,
            notes="Limited by 64-bit block size. Use AES-256 or ChaCha20 instead.",
        ),
        448: AlgorithmSpec(
            algorithm="Blowfish", key_size=448, effective_strength=256,
            quantum_strength=128, quantum_safe=True, status="legacy",
            nist_level=3, comparable_symmetric=256,
            notes="Maximum Blowfish key. Block size limitation remains.",
        ),
    },

    # ============================================================ #
    #  Twofish
    # ============================================================ #
    "Twofish": {
        128: AlgorithmSpec(
            algorithm="Twofish", key_size=128, effective_strength=128,
            quantum_strength=64, quantum_safe=True, status="acceptable",
            nist_level=1, comparable_symmetric=128,
            notes="AES finalist. 128-bit block. Secure but less widely deployed.",
        ),
        192: AlgorithmSpec(
            algorithm="Twofish", key_size=192, effective_strength=192,
            quantum_strength=96, quantum_safe=True, status="strong",
            nist_level=2, comparable_symmetric=192,
            notes="Twofish-192. Strong alternative to AES.",
        ),
        256: AlgorithmSpec(
            algorithm="Twofish", key_size=256, effective_strength=256,
            quantum_strength=128, quantum_safe=True, status="strong",
            nist_level=3, comparable_symmetric=256,
            notes="Twofish-256. Maximum security configuration.",
        ),
    },

    # ============================================================ #
    #  Camellia
    # ============================================================ #
    "Camellia": {
        128: AlgorithmSpec(
            algorithm="Camellia", key_size=128, effective_strength=128,
            quantum_strength=64, quantum_safe=True, status="acceptable",
            nist_level=1, comparable_symmetric=128,
            notes="Japanese standard cipher. Comparable to AES-128.",
        ),
        192: AlgorithmSpec(
            algorithm="Camellia", key_size=192, effective_strength=192,
            quantum_strength=96, quantum_safe=True, status="strong",
            nist_level=2, comparable_symmetric=192,
            notes="Camellia-192.",
        ),
        256: AlgorithmSpec(
            algorithm="Camellia", key_size=256, effective_strength=256,
            quantum_strength=128, quantum_safe=True, status="strong",
            nist_level=3, comparable_symmetric=256,
            notes="Camellia-256. Maximum configuration.",
        ),
    },

    # ============================================================ #
    #  Post-Quantum Algorithms (NIST PQC Winners)
    # ============================================================ #
    "CRYSTALS-Kyber": {
        512: AlgorithmSpec(
            algorithm="CRYSTALS-Kyber", key_size=512, effective_strength=128,
            quantum_strength=128, quantum_safe=True, status="strong",
            nist_level=1, comparable_symmetric=128,
            notes="ML-KEM-512. NIST PQC standard for key encapsulation (FIPS 203).",
        ),
        768: AlgorithmSpec(
            algorithm="CRYSTALS-Kyber", key_size=768, effective_strength=192,
            quantum_strength=192, quantum_safe=True, status="strong",
            nist_level=3, comparable_symmetric=192,
            notes="ML-KEM-768. Recommended security level.",
        ),
        1024: AlgorithmSpec(
            algorithm="CRYSTALS-Kyber", key_size=1024, effective_strength=256,
            quantum_strength=256, quantum_safe=True, status="strong",
            nist_level=5, comparable_symmetric=256,
            notes="ML-KEM-1024. Highest security level.",
        ),
    },
    "CRYSTALS-Dilithium": {
        2: AlgorithmSpec(
            algorithm="CRYSTALS-Dilithium", key_size=2, effective_strength=128,
            quantum_strength=128, quantum_safe=True, status="strong",
            nist_level=2, comparable_symmetric=128,
            notes="ML-DSA-44. NIST PQC standard for digital signatures (FIPS 204).",
        ),
        3: AlgorithmSpec(
            algorithm="CRYSTALS-Dilithium", key_size=3, effective_strength=192,
            quantum_strength=192, quantum_safe=True, status="strong",
            nist_level=3, comparable_symmetric=192,
            notes="ML-DSA-65. Recommended security level.",
        ),
        5: AlgorithmSpec(
            algorithm="CRYSTALS-Dilithium", key_size=5, effective_strength=256,
            quantum_strength=256, quantum_safe=True, status="strong",
            nist_level=5, comparable_symmetric=256,
            notes="ML-DSA-87. Highest security level.",
        ),
    },
    "SPHINCS+": {
        128: AlgorithmSpec(
            algorithm="SPHINCS+", key_size=128, effective_strength=128,
            quantum_strength=128, quantum_safe=True, status="strong",
            nist_level=1, comparable_symmetric=128,
            notes="SLH-DSA. Stateless hash-based signatures (FIPS 205). Large signatures.",
        ),
        192: AlgorithmSpec(
            algorithm="SPHINCS+", key_size=192, effective_strength=192,
            quantum_strength=192, quantum_safe=True, status="strong",
            nist_level=3, comparable_symmetric=192,
            notes="SLH-DSA-192. Higher security.",
        ),
        256: AlgorithmSpec(
            algorithm="SPHINCS+", key_size=256, effective_strength=256,
            quantum_strength=256, quantum_safe=True, status="strong",
            nist_level=5, comparable_symmetric=256,
            notes="SLH-DSA-256. Maximum security.",
        ),
    },
}

# Algorithm name aliases for flexible lookup
_ALGORITHM_ALIASES: dict[str, str] = {
    "rsa": "RSA",
    "dsa": "DSA",
    "ecdsa": "ECDSA",
    "eddsa": "EdDSA",
    "ed25519": "EdDSA",
    "ed448": "EdDSA",
    "dh": "DH",
    "diffie-hellman": "DH",
    "ecdh": "ECDH",
    "x25519": "ECDH",
    "x448": "ECDH",
    "aes": "AES",
    "aes-128": "AES",
    "aes-192": "AES",
    "aes-256": "AES",
    "aes128": "AES",
    "aes192": "AES",
    "aes256": "AES",
    "chacha20": "ChaCha20",
    "chacha20-poly1305": "ChaCha20",
    "3des": "3DES",
    "triple-des": "3DES",
    "tripledes": "3DES",
    "des-ede3": "3DES",
    "blowfish": "Blowfish",
    "bf": "Blowfish",
    "twofish": "Twofish",
    "camellia": "Camellia",
    "kyber": "CRYSTALS-Kyber",
    "crystals-kyber": "CRYSTALS-Kyber",
    "ml-kem": "CRYSTALS-Kyber",
    "dilithium": "CRYSTALS-Dilithium",
    "crystals-dilithium": "CRYSTALS-Dilithium",
    "ml-dsa": "CRYSTALS-Dilithium",
    "sphincs+": "SPHINCS+",
    "sphincs": "SPHINCS+",
    "slh-dsa": "SPHINCS+",
}


class KeyStrengthAnalyzer:
    """Evaluates the security strength of cryptographic key configurations.

    Queries an internal database of algorithm specifications and provides
    assessments including effective security bits, quantum resistance,
    and NIST compliance status.

    Usage::

        analyzer = KeyStrengthAnalyzer()
        result = analyzer.analyze("RSA", 2048)
        print(f"Effective: {result.effective_strength} bits")
        print(f"Quantum-safe: {result.quantum_safe}")
        print(f"Status: {result.status}")
    """

    def analyze(self, algorithm: str, key_size: int) -> KeyStrengthResult:
        """Evaluate the strength of a cryptographic key configuration.

        Args:
            algorithm: Algorithm name (case-insensitive, aliases supported).
            key_size: Key size in bits.

        Returns:
            KeyStrengthResult with security assessment.
        """
        # Resolve algorithm alias
        canonical = _ALGORITHM_ALIASES.get(algorithm.lower(), algorithm)

        # Handle Ed25519/Ed448 mapping
        if algorithm.lower() == "ed25519":
            key_size = 255
        elif algorithm.lower() == "ed448":
            key_size = 448
        elif algorithm.lower() in ("x25519",):
            canonical = "ECDH"
            key_size = 256

        # Look up in database
        algo_specs = _ALGORITHM_DATABASE.get(canonical)
        if algo_specs is None:
            return self._unknown_algorithm(algorithm, key_size)

        spec = algo_specs.get(key_size)
        if spec is None:
            # Find the closest known key size
            spec = self._find_closest_spec(algo_specs, key_size)
            if spec is None:
                return self._unknown_key_size(canonical, key_size)

        # Generate recommendation based on status
        recommendation = self._generate_recommendation(spec)

        return KeyStrengthResult(
            algorithm=spec.algorithm,
            key_size=spec.key_size,
            effective_strength=spec.effective_strength,
            quantum_safe=spec.quantum_safe,
            quantum_strength=spec.quantum_strength,
            recommendation=recommendation,
            status=spec.status,
            nist_level=spec.nist_level,
            comparable_symmetric=spec.comparable_symmetric,
            details={
                "notes": spec.notes,
                "algorithm_type": self._algorithm_type(canonical),
                "vulnerability": self._quantum_vulnerability(canonical),
            },
        )

    @staticmethod
    def _find_closest_spec(
        specs: dict[int, AlgorithmSpec], key_size: int
    ) -> Optional[AlgorithmSpec]:
        """Find the closest key size specification in the database."""
        if not specs:
            return None

        # Find the nearest key size
        known_sizes = sorted(specs.keys())
        closest = min(known_sizes, key=lambda s: abs(s - key_size))

        # Only use if reasonably close (within 25%)
        if abs(closest - key_size) / max(closest, 1) < 0.25:
            return specs[closest]

        # Interpolate/extrapolate for RSA-like algorithms
        # If key_size is larger than all known sizes, use the largest
        if key_size > max(known_sizes):
            return specs[max(known_sizes)]

        return None

    @staticmethod
    def _unknown_algorithm(algorithm: str, key_size: int) -> KeyStrengthResult:
        """Return a result for an unrecognised algorithm."""
        return KeyStrengthResult(
            algorithm=algorithm,
            key_size=key_size,
            effective_strength=0,
            quantum_safe=False,
            quantum_strength=0,
            recommendation=(
                f"Algorithm '{algorithm}' is not in the evaluation database. "
                f"Verify it against NIST SP 800-131A or consult a cryptographer."
            ),
            status="unknown",
            nist_level=None,
            comparable_symmetric=0,
            details={"error": "Algorithm not found in database"},
        )

    @staticmethod
    def _unknown_key_size(algorithm: str, key_size: int) -> KeyStrengthResult:
        """Return a result for an unrecognised key size."""
        return KeyStrengthResult(
            algorithm=algorithm,
            key_size=key_size,
            effective_strength=0,
            quantum_safe=False,
            quantum_strength=0,
            recommendation=(
                f"Key size {key_size} is not standard for {algorithm}. "
                f"Use a standard key size from NIST recommendations."
            ),
            status="unknown",
            nist_level=None,
            comparable_symmetric=0,
            details={"error": f"Non-standard key size for {algorithm}"},
        )

    @staticmethod
    def _generate_recommendation(spec: AlgorithmSpec) -> str:
        """Generate a recommendation string based on the algorithm spec."""
        if spec.status == "strong":
            return (
                f"{spec.algorithm}-{spec.key_size} provides strong security "
                f"({spec.effective_strength}-bit effective). "
                f"{'Quantum-resistant. ' if spec.quantum_safe else 'Plan post-quantum migration. '}"
                f"{spec.notes}"
            )
        elif spec.status == "acceptable":
            return (
                f"{spec.algorithm}-{spec.key_size} is acceptable for current use "
                f"({spec.effective_strength}-bit effective). "
                f"Consider upgrading for long-term security. "
                f"{spec.notes}"
            )
        elif spec.status == "legacy":
            return (
                f"{spec.algorithm}-{spec.key_size} is for legacy systems only "
                f"({spec.effective_strength}-bit effective). "
                f"Migrate to a modern algorithm. {spec.notes}"
            )
        elif spec.status == "deprecated":
            return (
                f"{spec.algorithm}-{spec.key_size} is DEPRECATED "
                f"({spec.effective_strength}-bit effective). "
                f"Migrate immediately. {spec.notes}"
            )
        elif spec.status == "weak":
            return (
                f"{spec.algorithm}-{spec.key_size} is CRITICALLY WEAK "
                f"({spec.effective_strength}-bit effective). "
                f"Do not use under any circumstances. {spec.notes}"
            )
        return spec.notes

    @staticmethod
    def _algorithm_type(canonical: str) -> str:
        """Return the algorithm category."""
        asymmetric = {"RSA", "DSA", "ECDSA", "EdDSA", "DH", "ECDH"}
        symmetric = {"AES", "ChaCha20", "3DES", "Blowfish", "Twofish", "Camellia"}
        pqc = {"CRYSTALS-Kyber", "CRYSTALS-Dilithium", "SPHINCS+"}

        if canonical in asymmetric:
            return "asymmetric"
        elif canonical in symmetric:
            return "symmetric"
        elif canonical in pqc:
            return "post-quantum"
        return "unknown"

    @staticmethod
    def _quantum_vulnerability(canonical: str) -> str:
        """Describe the quantum computing vulnerability."""
        shor_vulnerable = {"RSA", "DSA", "ECDSA", "EdDSA", "DH", "ECDH"}
        grover_affected = {"AES", "ChaCha20", "3DES", "Blowfish", "Twofish", "Camellia"}

        if canonical in shor_vulnerable:
            return (
                "Vulnerable to Shor's algorithm (polynomial-time quantum attack "
                "on integer factorisation and discrete logarithm problems)."
            )
        elif canonical in grover_affected:
            return (
                "Affected by Grover's algorithm (quadratic speedup for brute-force search, "
                "effectively halving the key length)."
            )
        return "Designed to be quantum-resistant."

    def list_algorithms(self) -> list[str]:
        """Return a list of all supported algorithm names."""
        return sorted(_ALGORITHM_DATABASE.keys())

    def list_key_sizes(self, algorithm: str) -> list[int]:
        """Return supported key sizes for an algorithm.

        Args:
            algorithm: Algorithm name.

        Returns:
            Sorted list of supported key sizes.
        """
        canonical = _ALGORITHM_ALIASES.get(algorithm.lower(), algorithm)
        specs = _ALGORITHM_DATABASE.get(canonical, {})
        return sorted(specs.keys())
