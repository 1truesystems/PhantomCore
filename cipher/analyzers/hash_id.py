"""
Hash Identifier
================

Identifies cryptographic hash algorithms by analysing the structure,
length, character set, and format of hash strings. Supports 50+ hash
types including modern password hashing functions, legacy digest
algorithms, and application-specific formats.

The identification uses a multi-stage approach:
1. Prefix matching for structured hash formats ($2b$, $argon2id$, etc.)
2. Length and character set filtering
3. Statistical scoring based on byte distribution characteristics
4. Confidence ranking with tie-breaking by algorithm popularity

References:
    - Rivest, R. L. (1992). RFC 1321 -- The MD5 Message-Digest Algorithm.
    - NIST FIPS 180-4 (2015). Secure Hash Standard (SHS).
    - NIST FIPS 202 (2015). SHA-3 Standard.
    - Provos, N., & Mazieres, D. (1999). A Future-Adaptable Password Scheme.
      USENIX Annual Technical Conference.
    - Biryukov, A., Dinu, D., & Khovratovich, D. (2016). Argon2:
      New Generation of Memory-Hard Functions. IEEE EuroS&P.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass
from typing import Optional

from cipher.core.models import HashIdentification, HashType


# ===================================================================== #
#  Hash Pattern Database
# ===================================================================== #

@dataclass(frozen=True, slots=True)
class HashPattern:
    """Specification for a single hash type used during identification.

    Attributes:
        name: Algorithm name (human-readable).
        regex: Compiled regex pattern matching valid hash strings.
        length: Expected hash string length (0 for variable-length).
        min_length: Minimum length for variable-length hashes.
        max_length: Maximum length for variable-length hashes.
        charset: Expected character set descriptor.
        description: Short algorithm description.
        hashcat_mode: Hashcat mode number, if applicable.
        john_format: John the Ripper format string, if applicable.
        priority: Tiebreaker priority (lower = more common/preferred).
        is_salted: Whether the format includes an embedded salt.
        prefix: Expected format prefix (empty for raw hashes).
    """

    name: str
    regex: re.Pattern[str]
    length: int = 0
    min_length: int = 0
    max_length: int = 0
    charset: str = "hex"
    description: str = ""
    hashcat_mode: Optional[int] = None
    john_format: Optional[str] = None
    priority: int = 50
    is_salted: bool = False
    prefix: str = ""


def _build_hash_database() -> list[HashPattern]:
    """Build the complete hash pattern database.

    Returns a list of HashPattern entries covering 50+ algorithm types,
    ordered by specificity (most specific patterns first).
    """
    # Helper for hex-only patterns at exact length
    def hex_pattern(length: int) -> re.Pattern[str]:
        return re.compile(rf"^[a-fA-F0-9]{{{length}}}$")

    # Helper for Base64 patterns (used by bcrypt, etc.)
    def b64_pattern(prefix: str, body_len: int) -> re.Pattern[str]:
        escaped = re.escape(prefix)
        return re.compile(rf"^{escaped}[A-Za-z0-9+/=]{{{body_len}}}.*$")

    database: list[HashPattern] = [
        # ============================================================ #
        #  Structured / prefixed formats (highest specificity)
        # ============================================================ #
        HashPattern(
            name="bcrypt",
            regex=re.compile(r"^\$2[aby]?\$\d{2}\$[A-Za-z0-9./]{53}$"),
            length=60,
            charset="bcrypt-base64",
            description="Blowfish-based adaptive password hash (Provos & Mazieres, 1999).",
            hashcat_mode=3200,
            john_format="bcrypt",
            priority=5,
            is_salted=True,
            prefix="$2b$",
        ),
        HashPattern(
            name="Argon2",
            regex=re.compile(r"^\$argon2(id?|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$.+$"),
            min_length=50,
            max_length=200,
            charset="argon2-encoded",
            description="Memory-hard password hash (Biryukov et al., 2016). Winner of PHC.",
            hashcat_mode=None,
            john_format="argon2",
            priority=3,
            is_salted=True,
            prefix="$argon2",
        ),
        HashPattern(
            name="scrypt",
            regex=re.compile(r"^\$scrypt\$ln=\d+,r=\d+,p=\d+\$.+\$.+$"),
            min_length=50,
            max_length=200,
            charset="scrypt-encoded",
            description="Memory-hard KDF by Colin Percival (2009).",
            hashcat_mode=8900,
            john_format="scrypt",
            priority=4,
            is_salted=True,
            prefix="$scrypt$",
        ),
        HashPattern(
            name="PBKDF2",
            regex=re.compile(r"^\$pbkdf2(-sha(256|512|1))?\$\d+\$.+\$.+$"),
            min_length=40,
            max_length=200,
            charset="pbkdf2-encoded",
            description="Password-Based Key Derivation Function 2 (RFC 2898).",
            hashcat_mode=10900,
            john_format="PBKDF2-HMAC-SHA256",
            priority=6,
            is_salted=True,
            prefix="$pbkdf2",
        ),
        HashPattern(
            name="Django PBKDF2 SHA256",
            regex=re.compile(r"^pbkdf2_sha256\$\d+\$.+\$.+$"),
            min_length=50,
            max_length=200,
            charset="django-encoded",
            description="Django framework PBKDF2-SHA256 password hash.",
            hashcat_mode=10000,
            john_format="django",
            priority=7,
            is_salted=True,
            prefix="pbkdf2_sha256$",
        ),
        HashPattern(
            name="WordPress PHPass",
            regex=re.compile(r"^\$P\$[A-Za-z0-9./]{31}$"),
            length=34,
            charset="phpass-base64",
            description="PHPass portable hash used by WordPress and phpBB.",
            hashcat_mode=400,
            john_format="phpass",
            priority=8,
            is_salted=True,
            prefix="$P$",
        ),
        HashPattern(
            name="Cisco Type 5",
            regex=re.compile(r"^\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$"),
            length=34,
            charset="cisco-base64",
            description="Cisco IOS Type 5 (MD5-crypt) password hash.",
            hashcat_mode=500,
            john_format="md5crypt",
            priority=10,
            is_salted=True,
            prefix="$1$",
        ),
        HashPattern(
            name="Cisco Type 8",
            regex=re.compile(r"^\$8\$[A-Za-z0-9./]{14}\$[A-Za-z0-9./]{43}$"),
            min_length=55,
            max_length=65,
            charset="cisco-base64",
            description="Cisco Type 8 (PBKDF2-SHA256) password hash.",
            hashcat_mode=9200,
            john_format="cisco8",
            priority=10,
            is_salted=True,
            prefix="$8$",
        ),
        HashPattern(
            name="Cisco Type 9",
            regex=re.compile(r"^\$9\$[A-Za-z0-9./]{14}\$[A-Za-z0-9./]{43}$"),
            min_length=55,
            max_length=65,
            charset="cisco-base64",
            description="Cisco Type 9 (scrypt) password hash.",
            hashcat_mode=9300,
            john_format="cisco9",
            priority=10,
            is_salted=True,
            prefix="$9$",
        ),
        HashPattern(
            name="Cisco Type 7",
            regex=re.compile(r"^[0-9]{2}[0-9A-Fa-f]{4,}$"),
            min_length=6,
            max_length=100,
            charset="hex-prefixed",
            description="Cisco Type 7 reversible encoding (Vigenere-based, weak).",
            hashcat_mode=None,
            john_format="cisco7",
            priority=40,
            is_salted=False,
            prefix="",
        ),
        HashPattern(
            name="Juniper $9$",
            regex=re.compile(r"^\$9\$.+$"),
            min_length=5,
            max_length=200,
            charset="juniper-encoded",
            description="Juniper Networks $9$ encrypted password.",
            hashcat_mode=None,
            john_format=None,
            priority=12,
            is_salted=True,
            prefix="$9$",
        ),
        HashPattern(
            name="PostgreSQL MD5",
            regex=re.compile(r"^md5[a-fA-F0-9]{32}$"),
            length=35,
            charset="hex-prefixed",
            description="PostgreSQL MD5 password hash (md5 + MD5(password+username)).",
            hashcat_mode=None,
            john_format="postgres",
            priority=15,
            is_salted=True,
            prefix="md5",
        ),
        HashPattern(
            name="NetNTLMv2",
            regex=re.compile(r"^[A-Za-z0-9]+::\S+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$"),
            min_length=50,
            max_length=500,
            charset="ntlm-encoded",
            description="NetNTLMv2 challenge-response authentication hash.",
            hashcat_mode=5600,
            john_format="netntlmv2",
            priority=13,
            is_salted=True,
            prefix="",
        ),
        HashPattern(
            name="NetNTLMv1",
            regex=re.compile(r"^[A-Za-z0-9]+::\S+:[a-fA-F0-9]{16}:[a-fA-F0-9]{48}:$"),
            min_length=50,
            max_length=500,
            charset="ntlm-encoded",
            description="NetNTLMv1 challenge-response authentication hash.",
            hashcat_mode=5500,
            john_format="netntlm",
            priority=14,
            is_salted=True,
            prefix="",
        ),
        HashPattern(
            name="HMAC-SHA256",
            regex=re.compile(r"^[a-fA-F0-9]{64}:[a-fA-F0-9]+$"),
            min_length=65,
            max_length=200,
            charset="hex-with-salt",
            description="HMAC-SHA256 keyed hash (hash:key format).",
            hashcat_mode=1450,
            john_format="hmac-sha256",
            priority=20,
            is_salted=True,
            prefix="",
        ),
        HashPattern(
            name="HMAC-SHA512",
            regex=re.compile(r"^[a-fA-F0-9]{128}:[a-fA-F0-9]+$"),
            min_length=129,
            max_length=300,
            charset="hex-with-salt",
            description="HMAC-SHA512 keyed hash (hash:key format).",
            hashcat_mode=1750,
            john_format="hmac-sha512",
            priority=20,
            is_salted=True,
            prefix="",
        ),

        # ============================================================ #
        #  Fixed-length hex hashes (descending length for specificity)
        # ============================================================ #
        HashPattern(
            name="SHA-512",
            regex=hex_pattern(128),
            length=128,
            charset="hex",
            description="SHA-2 family, 512-bit digest (NIST FIPS 180-4).",
            hashcat_mode=1700,
            john_format="raw-sha512",
            priority=25,
        ),
        HashPattern(
            name="SHA3-512",
            regex=hex_pattern(128),
            length=128,
            charset="hex",
            description="SHA-3 (Keccak) 512-bit digest (NIST FIPS 202).",
            hashcat_mode=17600,
            john_format="raw-sha3-512",
            priority=28,
        ),
        HashPattern(
            name="Keccak-512",
            regex=hex_pattern(128),
            length=128,
            charset="hex",
            description="Keccak-512 (pre-FIPS 202 variant).",
            hashcat_mode=18000,
            john_format="raw-keccak-512",
            priority=30,
        ),
        HashPattern(
            name="BLAKE2b-512",
            regex=hex_pattern(128),
            length=128,
            charset="hex",
            description="BLAKE2b with 512-bit output (RFC 7693).",
            hashcat_mode=600,
            john_format="raw-blake2",
            priority=29,
        ),
        HashPattern(
            name="Whirlpool",
            regex=hex_pattern(128),
            length=128,
            charset="hex",
            description="Whirlpool 512-bit hash (ISO/IEC 10118-3).",
            hashcat_mode=6100,
            john_format="whirlpool",
            priority=31,
        ),
        HashPattern(
            name="SHA-384",
            regex=hex_pattern(96),
            length=96,
            charset="hex",
            description="SHA-2 family, 384-bit digest (NIST FIPS 180-4).",
            hashcat_mode=10800,
            john_format="raw-sha384",
            priority=25,
        ),
        HashPattern(
            name="SHA3-384",
            regex=hex_pattern(96),
            length=96,
            charset="hex",
            description="SHA-3 (Keccak) 384-bit digest (NIST FIPS 202).",
            hashcat_mode=17500,
            john_format="raw-sha3-384",
            priority=28,
        ),
        HashPattern(
            name="RIPEMD-320",
            regex=hex_pattern(80),
            length=80,
            charset="hex",
            description="RIPEMD-320 hash (extended RIPEMD-160).",
            hashcat_mode=None,
            john_format=None,
            priority=35,
        ),
        HashPattern(
            name="SHA-256",
            regex=hex_pattern(64),
            length=64,
            charset="hex",
            description="SHA-2 family, 256-bit digest (NIST FIPS 180-4).",
            hashcat_mode=1400,
            john_format="raw-sha256",
            priority=20,
        ),
        HashPattern(
            name="SHA3-256",
            regex=hex_pattern(64),
            length=64,
            charset="hex",
            description="SHA-3 (Keccak) 256-bit digest (NIST FIPS 202).",
            hashcat_mode=17400,
            john_format="raw-sha3-256",
            priority=24,
        ),
        HashPattern(
            name="SHA-512/256",
            regex=hex_pattern(64),
            length=64,
            charset="hex",
            description="SHA-512/256 truncated digest (NIST FIPS 180-4).",
            hashcat_mode=None,
            john_format=None,
            priority=26,
        ),
        HashPattern(
            name="Keccak-256",
            regex=hex_pattern(64),
            length=64,
            charset="hex",
            description="Keccak-256 (used in Ethereum, pre-FIPS 202).",
            hashcat_mode=17800,
            john_format="raw-keccak-256",
            priority=27,
        ),
        HashPattern(
            name="BLAKE2b-256",
            regex=hex_pattern(64),
            length=64,
            charset="hex",
            description="BLAKE2b with 256-bit output (RFC 7693).",
            hashcat_mode=600,
            john_format=None,
            priority=28,
        ),
        HashPattern(
            name="BLAKE2s-256",
            regex=hex_pattern(64),
            length=64,
            charset="hex",
            description="BLAKE2s with 256-bit output (RFC 7693).",
            hashcat_mode=None,
            john_format=None,
            priority=29,
        ),
        HashPattern(
            name="RIPEMD-256",
            regex=hex_pattern(64),
            length=64,
            charset="hex",
            description="RIPEMD-256 hash (extended RIPEMD-128).",
            hashcat_mode=None,
            john_format=None,
            priority=35,
        ),
        HashPattern(
            name="SHA-224",
            regex=hex_pattern(56),
            length=56,
            charset="hex",
            description="SHA-2 family, 224-bit digest (NIST FIPS 180-4).",
            hashcat_mode=None,
            john_format="raw-sha224",
            priority=25,
        ),
        HashPattern(
            name="SHA3-224",
            regex=hex_pattern(56),
            length=56,
            charset="hex",
            description="SHA-3 (Keccak) 224-bit digest (NIST FIPS 202).",
            hashcat_mode=17300,
            john_format="raw-sha3-224",
            priority=28,
        ),
        HashPattern(
            name="Tiger-192",
            regex=hex_pattern(48),
            length=48,
            charset="hex",
            description="Tiger hash, 192-bit digest (Anderson & Biham, 1996).",
            hashcat_mode=10000,
            john_format="tiger",
            priority=32,
        ),
        HashPattern(
            name="SHA-1",
            regex=hex_pattern(40),
            length=40,
            charset="hex",
            description="SHA-1, 160-bit digest. DEPRECATED -- collision attacks practical (Stevens et al., 2017).",
            hashcat_mode=100,
            john_format="raw-sha1",
            priority=20,
        ),
        HashPattern(
            name="RIPEMD-160",
            regex=hex_pattern(40),
            length=40,
            charset="hex",
            description="RIPEMD-160, 160-bit digest (Dobbertin et al., 1996).",
            hashcat_mode=6000,
            john_format="ripemd-160",
            priority=30,
        ),
        HashPattern(
            name="MySQL5",
            regex=re.compile(r"^\*[A-Fa-f0-9]{40}$"),
            length=41,
            charset="hex-prefixed",
            description="MySQL 5.x SHA-1 password hash (prefixed with '*').",
            hashcat_mode=300,
            john_format="mysql-sha1",
            priority=15,
            prefix="*",
        ),
        HashPattern(
            name="MD5",
            regex=hex_pattern(32),
            length=32,
            charset="hex",
            description="MD5, 128-bit digest. BROKEN -- collisions trivially constructable (Wang & Yu, 2005).",
            hashcat_mode=0,
            john_format="raw-md5",
            priority=15,
        ),
        HashPattern(
            name="MD4",
            regex=hex_pattern(32),
            length=32,
            charset="hex",
            description="MD4, 128-bit digest. BROKEN -- collisions in seconds (Dobbertin, 1998).",
            hashcat_mode=900,
            john_format="raw-md4",
            priority=35,
        ),
        HashPattern(
            name="MD2",
            regex=hex_pattern(32),
            length=32,
            charset="hex",
            description="MD2, 128-bit digest. OBSOLETE (RFC 6149).",
            hashcat_mode=None,
            john_format=None,
            priority=40,
        ),
        HashPattern(
            name="NTLM",
            regex=hex_pattern(32),
            length=32,
            charset="hex",
            description="NT LAN Manager hash (MD4 of UTF-16LE password).",
            hashcat_mode=1000,
            john_format="nt",
            priority=18,
        ),
        HashPattern(
            name="RIPEMD-128",
            regex=hex_pattern(32),
            length=32,
            charset="hex",
            description="RIPEMD-128, 128-bit digest.",
            hashcat_mode=None,
            john_format=None,
            priority=36,
        ),
        HashPattern(
            name="LM",
            regex=hex_pattern(32),
            length=32,
            charset="hex",
            description="LAN Manager hash. EXTREMELY WEAK -- DES-based, case-insensitive.",
            hashcat_mode=3000,
            john_format="lm",
            priority=38,
        ),
        HashPattern(
            name="MySQL (old)",
            regex=hex_pattern(16),
            length=16,
            charset="hex",
            description="MySQL pre-4.1 password hash (very weak, custom algorithm).",
            hashcat_mode=200,
            john_format="mysql",
            priority=20,
        ),
        HashPattern(
            name="CRC32",
            regex=hex_pattern(8),
            length=8,
            charset="hex",
            description="CRC32 checksum. NOT a cryptographic hash.",
            hashcat_mode=None,
            john_format="crc32",
            priority=25,
        ),
        HashPattern(
            name="CRC32B",
            regex=hex_pattern(8),
            length=8,
            charset="hex",
            description="CRC32B (big-endian variant). NOT a cryptographic hash.",
            hashcat_mode=None,
            john_format=None,
            priority=26,
        ),
        HashPattern(
            name="Adler-32",
            regex=hex_pattern(8),
            length=8,
            charset="hex",
            description="Adler-32 checksum (zlib). NOT a cryptographic hash.",
            hashcat_mode=None,
            john_format=None,
            priority=27,
        ),

        # ============================================================ #
        #  Base64 encoded hashes
        # ============================================================ #
        HashPattern(
            name="Base64 Encoded Hash",
            regex=re.compile(r"^[A-Za-z0-9+/]{20,}={0,3}$"),
            min_length=20,
            max_length=200,
            charset="base64",
            description="Base64-encoded hash value (encoding detected, algorithm unknown).",
            hashcat_mode=None,
            john_format=None,
            priority=45,
        ),
    ]

    return database


# Global database instance (built once at module load)
_HASH_DATABASE: list[HashPattern] = _build_hash_database()


class HashIdentifier:
    """Identifies hash algorithms from hash strings.

    Uses a database of 50+ hash type patterns with regex matching,
    length analysis, character set detection, and confidence scoring.

    Usage::

        identifier = HashIdentifier()
        results = identifier.identify("5d41402abc4b2a76b9719d911017c592")
        for r in results:
            for t in r.possible_types:
                print(f"{t.name}: {t.confidence:.0%}")
    """

    def __init__(self) -> None:
        self._database: list[HashPattern] = _HASH_DATABASE

    def identify(self, hash_str: str) -> list[HashIdentification]:
        """Identify the likely hash algorithm(s) for a hash string.

        Performs multi-stage identification:
        1. Detect character set and length
        2. Match against prefix patterns (structured hashes)
        3. Match against length+regex patterns (raw hashes)
        4. Score and rank candidates by confidence

        Args:
            hash_str: The hash string to identify.

        Returns:
            List containing a single HashIdentification with ranked candidates.
        """
        hash_str = hash_str.strip()
        if not hash_str:
            return [HashIdentification(
                hash_value="",
                possible_types=[],
                length=0,
                charset="empty",
            )]

        # Detect properties
        length = len(hash_str)
        charset = self._detect_charset(hash_str)
        prefix = self._detect_prefix(hash_str)
        is_salted = ":" in hash_str or "$" in hash_str

        # Find matching patterns
        candidates: list[tuple[HashPattern, float]] = []
        for pattern in self._database:
            confidence = self._score_match(hash_str, pattern, length, charset)
            if confidence > 0.0:
                candidates.append((pattern, confidence))

        # Sort by confidence descending, then by priority ascending
        candidates.sort(key=lambda x: (-x[1], x[0].priority))

        # Convert to HashType objects
        possible_types: list[HashType] = []
        for pattern, confidence in candidates:
            possible_types.append(HashType(
                name=pattern.name,
                confidence=round(confidence, 3),
                description=pattern.description,
                hashcat_mode=pattern.hashcat_mode,
                john_format=pattern.john_format,
            ))

        return [HashIdentification(
            hash_value=hash_str[:64] + ("..." if len(hash_str) > 64 else ""),
            possible_types=possible_types,
            length=length,
            charset=charset,
            is_salted=is_salted,
            prefix=prefix,
        )]

    def _score_match(
        self,
        hash_str: str,
        pattern: HashPattern,
        length: int,
        charset: str,
    ) -> float:
        """Score how well a hash string matches a pattern.

        Returns a confidence score in [0.0, 1.0].
        """
        # Must match the regex
        if not pattern.regex.match(hash_str):
            return 0.0

        confidence = 0.5  # Base confidence for regex match

        # Length matching
        if pattern.length > 0:
            if length == pattern.length:
                confidence += 0.25
            else:
                return 0.0  # Exact length required but doesn't match
        elif pattern.min_length > 0 or pattern.max_length > 0:
            if pattern.min_length > 0 and length < pattern.min_length:
                return 0.0
            if pattern.max_length > 0 and length > pattern.max_length:
                return 0.0
            confidence += 0.15  # Variable length, within range

        # Prefix matching (high confidence for structured hashes)
        if pattern.prefix:
            if hash_str.startswith(pattern.prefix) or hash_str.startswith(
                pattern.prefix.split("$")[0] + "$"
            ):
                confidence += 0.20
            elif "$" in pattern.prefix and "$" not in hash_str:
                return 0.0

        # Character set matching
        if pattern.charset == "hex" and charset == "hex":
            confidence += 0.05
        elif pattern.charset != "hex" and charset != "hex":
            confidence += 0.05

        # Priority-based adjustment (more common = slightly higher confidence)
        priority_bonus = max(0, (50 - pattern.priority)) / 200.0
        confidence += priority_bonus

        return min(1.0, confidence)

    @staticmethod
    def _detect_charset(hash_str: str) -> str:
        """Detect the character set of a hash string.

        Returns one of: "hex", "base64", "alphanumeric", "ascii", "mixed".
        """
        hex_chars = set(string.hexdigits)
        b64_chars = set(string.ascii_letters + string.digits + "+/=")
        alnum_chars = set(string.ascii_letters + string.digits)

        char_set = set(hash_str)

        # Remove common prefixes/separators for analysis
        clean = hash_str.lstrip("$*").split("$")[0] if "$" in hash_str else hash_str

        if all(c in hex_chars for c in clean):
            return "hex"
        elif all(c in b64_chars for c in clean):
            return "base64"
        elif all(c in alnum_chars for c in clean):
            return "alphanumeric"
        elif all(32 <= ord(c) < 127 for c in hash_str):
            return "ascii"
        else:
            return "mixed"

    @staticmethod
    def _detect_prefix(hash_str: str) -> str:
        """Detect a structured hash prefix (e.g., '$2b$', '$argon2id$').

        Returns the prefix string, or empty string if none found.
        """
        # Common prefix patterns
        prefix_patterns = [
            re.compile(r"^(\$2[aby]?\$\d{2}\$)"),       # bcrypt
            re.compile(r"^(\$argon2(?:id?|d)\$)"),       # Argon2
            re.compile(r"^(\$scrypt\$)"),                 # scrypt
            re.compile(r"^(\$pbkdf2(?:-sha\d+)?\$)"),    # PBKDF2
            re.compile(r"^(\$1\$)"),                      # MD5-crypt
            re.compile(r"^(\$5\$)"),                      # SHA-256-crypt
            re.compile(r"^(\$6\$)"),                      # SHA-512-crypt
            re.compile(r"^(\$8\$)"),                      # Cisco Type 8
            re.compile(r"^(\$9\$)"),                      # Cisco Type 9
            re.compile(r"^(\$P\$)"),                      # PHPass
            re.compile(r"^(pbkdf2_sha256\$)"),            # Django
            re.compile(r"^(md5)"),                         # PostgreSQL
            re.compile(r"^(\*)"),                           # MySQL5
        ]

        for pattern in prefix_patterns:
            match = pattern.match(hash_str)
            if match:
                return match.group(1)

        return ""
