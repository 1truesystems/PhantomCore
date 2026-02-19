"""
Hash Parser
============

Extracts cryptographic hash strings from files and text input. Supports
multiple common hash dump formats including raw hashes, user:hash pairs,
hash:salt combinations, and structured hash formats (bcrypt, Argon2, etc.).

Supported formats:
    - Raw hash: e.g. ``5d41402abc4b2a76b9719d911017c592``
    - User:hash: e.g. ``admin:5d41402abc4b2a76b9719d911017c592``
    - Hash:salt: e.g. ``5d41402abc4b2a76b9719d911017c592:random_salt``
    - Structured: e.g. ``$2b$12$LJ3m4ys3Lg...`` (bcrypt)
    - Shadow: e.g. ``user:$6$salt$hash:...`` (Unix /etc/shadow)
    - PWDUMP: e.g. ``user:uid:lm_hash:ntlm_hash:::`` (Windows)

References:
    - Unix crypt(3) manual page.
    - Provos, N., & Mazieres, D. (1999). A Future-Adaptable Password Scheme.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


# ===================================================================== #
#  Hash Extraction Patterns
# ===================================================================== #

# Regex patterns for common hash formats (ordered by specificity)
_HASH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Structured hash formats (highest priority)
    ("bcrypt", re.compile(
        r"\$2[aby]?\$\d{2}\$[A-Za-z0-9./]{53}"
    )),
    ("argon2", re.compile(
        r"\$argon2(?:id?|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"
    )),
    ("scrypt", re.compile(
        r"\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"
    )),
    ("pbkdf2", re.compile(
        r"\$pbkdf2(?:-sha(?:256|512|1))?\$\d+\$[A-Za-z0-9+/=.]+\$[A-Za-z0-9+/=.]+"
    )),
    ("django_pbkdf2", re.compile(
        r"pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"
    )),
    ("phpass", re.compile(
        r"\$P\$[A-Za-z0-9./]{31}"
    )),
    ("sha512_crypt", re.compile(
        r"\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{86}"
    )),
    ("sha256_crypt", re.compile(
        r"\$5\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{43}"
    )),
    ("md5_crypt", re.compile(
        r"\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}"
    )),
    # MySQL5 with asterisk prefix
    ("mysql5", re.compile(
        r"\*[A-Fa-f0-9]{40}"
    )),
    # PostgreSQL MD5
    ("postgres_md5", re.compile(
        r"md5[a-fA-F0-9]{32}"
    )),
    # Raw hex hashes (various lengths, in descending order)
    ("sha512_hex", re.compile(
        r"\b[a-fA-F0-9]{128}\b"
    )),
    ("sha384_hex", re.compile(
        r"\b[a-fA-F0-9]{96}\b"
    )),
    ("sha256_hex", re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    )),
    ("sha1_hex", re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    )),
    ("md5_hex", re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    )),
    ("crc32_hex", re.compile(
        r"\b[a-fA-F0-9]{8}\b"
    )),
]

# Patterns for structured hash file formats
_SHADOW_PATTERN = re.compile(
    r"^([^:]+):(\$\d+\$[^:]+):.*$"
)
_PWDUMP_PATTERN = re.compile(
    r"^([^:]+):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::"
)
_USER_HASH_PATTERN = re.compile(
    r"^([^:\s]+):([a-fA-F0-9]{16,128})$"
)
_HASH_SALT_PATTERN = re.compile(
    r"^([a-fA-F0-9]{16,128}):(.+)$"
)


class HashParser:
    """Extracts hash strings from files and text input.

    Supports multiple hash dump formats commonly encountered in
    penetration testing and security auditing.

    Usage::

        parser = HashParser()
        hashes = parser.parse_file(Path("/etc/shadow"))
        hashes = parser.parse_string("admin:5d41402abc4b2a76b9719d911017c592")
    """

    def __init__(self, min_hex_length: int = 16) -> None:
        """Initialise the hash parser.

        Args:
            min_hex_length: Minimum length for raw hex strings to be
                considered potential hashes (default 16, avoids false
                positives from short hex values).
        """
        self.min_hex_length = min_hex_length

    def parse_file(self, filepath: Path) -> list[str]:
        """Extract hash strings from a file.

        Reads the file line by line and attempts to extract hash strings
        from each line using multiple format parsers.

        Args:
            filepath: Path to the file to parse.

        Returns:
            List of extracted hash strings (deduplicated, order preserved).

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
        """
        hashes: list[str] = []
        seen: set[str] = set()

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                extracted = self._parse_line(line)
                for h in extracted:
                    if h not in seen:
                        hashes.append(h)
                        seen.add(h)

        return hashes

    def parse_string(self, text: str) -> list[str]:
        """Extract hash strings from a text string.

        Processes the text line by line and extracts all hash-like
        strings found.

        Args:
            text: Input text potentially containing hash strings.

        Returns:
            List of extracted hash strings (deduplicated, order preserved).
        """
        hashes: list[str] = []
        seen: set[str] = set()

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            extracted = self._parse_line(line)
            for h in extracted:
                if h not in seen:
                    hashes.append(h)
                    seen.add(h)

        return hashes

    def _parse_line(self, line: str) -> list[str]:
        """Parse a single line and extract hash strings.

        Tries multiple format parsers in order of specificity.

        Args:
            line: A single line of text.

        Returns:
            List of hash strings found in the line.
        """
        results: list[str] = []

        # Try shadow format: user:$id$salt$hash:...
        match = _SHADOW_PATTERN.match(line)
        if match:
            results.append(match.group(2))
            return results

        # Try PWDUMP format: user:uid:lm_hash:ntlm_hash:::
        match = _PWDUMP_PATTERN.match(line)
        if match:
            lm_hash = match.group(2)
            ntlm_hash = match.group(3)
            # Skip empty/null LM hashes
            if lm_hash.lower() != "aad3b435b51404eeaad3b435b51404ee":
                results.append(lm_hash)
            results.append(ntlm_hash)
            return results

        # Try structured hash formats (bcrypt, argon2, etc.)
        for name, pattern in _HASH_PATTERNS:
            for match in pattern.finditer(line):
                h = match.group(0)
                if self._is_valid_hash(h):
                    results.append(h)

            if results:
                return results

        # Try user:hash format
        match = _USER_HASH_PATTERN.match(line)
        if match:
            h = match.group(2)
            if len(h) >= self.min_hex_length:
                results.append(h)
                return results

        # Try hash:salt format
        match = _HASH_SALT_PATTERN.match(line)
        if match:
            h = match.group(1)
            salt = match.group(2)
            if len(h) >= self.min_hex_length:
                results.append(f"{h}:{salt}")
                return results

        # Try raw hash (entire line is a hex hash)
        stripped = line.strip()
        if re.match(r"^[a-fA-F0-9]+$", stripped) and len(stripped) >= self.min_hex_length:
            results.append(stripped)

        return results

    def _is_valid_hash(self, h: str) -> bool:
        """Validate that a string looks like a genuine hash.

        Filters out common false positives like short numbers,
        timestamps, and version strings.

        Args:
            h: Potential hash string.

        Returns:
            True if the string is likely a hash.
        """
        # Structured hashes (with $ prefix) are always valid
        if h.startswith("$") or h.startswith("*") or h.startswith("pbkdf2"):
            return True

        # For raw hex, require minimum length
        if re.match(r"^[a-fA-F0-9]+$", h):
            return len(h) >= self.min_hex_length

        return len(h) >= 8

    @staticmethod
    def detect_format(line: str) -> Optional[str]:
        """Detect the hash dump format of a line.

        Args:
            line: A single line of text.

        Returns:
            Format name string, or None if unrecognised.
        """
        line = line.strip()

        if _SHADOW_PATTERN.match(line):
            return "shadow"
        if _PWDUMP_PATTERN.match(line):
            return "pwdump"
        if _USER_HASH_PATTERN.match(line):
            return "user:hash"
        if _HASH_SALT_PATTERN.match(line):
            return "hash:salt"

        # Check for structured formats
        for name, pattern in _HASH_PATTERNS:
            if pattern.match(line):
                return name

        if re.match(r"^[a-fA-F0-9]+$", line) and len(line) >= 16:
            return "raw_hex"

        return None
