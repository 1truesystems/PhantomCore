"""
Binary String Extractor
========================

Multi-encoding string extraction and classification engine for binary
analysis.  Extracts printable strings in ASCII, UTF-16 LE/BE, detects
embedded Base64 and hex-encoded data, and classifies extracted strings
into security-relevant categories.

The extraction algorithm scans for contiguous runs of printable characters
in each supported encoding, applying minimum length thresholds to filter
noise.  Extracted strings are then classified using regular expression
patterns against known categories of indicators (URLs, IPs, file paths,
registry keys, email addresses, cryptographic terms, and suspicious
API/command references).

References:
    - Strings(1) Unix utility algorithm.
    - Mandiant. (2023). FLOSS: FireEye Labs Obfuscated String Solver.
    - YARA documentation for string matching patterns.
"""

from __future__ import annotations

import base64
import re
from typing import Optional

from morph.core.models import StringCategory, StringResult


# ---------------------------------------------------------------------------
# Character set definitions
# ---------------------------------------------------------------------------

# Printable ASCII: 0x20-0x7E plus tab (0x09), newline (0x0A), CR (0x0D)
_ASCII_PRINTABLE: set[int] = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

# Base64 alphabet
_BASE64_CHARS: set[int] = (
    set(range(ord("A"), ord("Z") + 1))
    | set(range(ord("a"), ord("z") + 1))
    | set(range(ord("0"), ord("9") + 1))
    | {ord("+"), ord("/"), ord("=")}
)


# ---------------------------------------------------------------------------
# Classification regex patterns
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}",
    re.ASCII,
)
_FTP_PATTERN = re.compile(
    r"ftp://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}",
    re.ASCII,
)

_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_IPV6_PATTERN = re.compile(
    r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    r"|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}"
)

_UNIX_PATH_PATTERN = re.compile(
    r"/(?:usr|etc|bin|sbin|var|tmp|home|root|opt|dev|proc|sys|mnt|lib)"
    r"(?:/[a-zA-Z0-9._\-]+)+",
    re.ASCII,
)

_WINDOWS_PATH_PATTERN = re.compile(
    r"[A-Za-z]:\\(?:[a-zA-Z0-9._\- ]+\\)*[a-zA-Z0-9._\- ]+",
    re.ASCII,
)

_REGISTRY_PATTERN = re.compile(
    r"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
    r"|HKLM|HKCU|HKCR|HKU|HKCC)"
    r"\\[a-zA-Z0-9\\._\- ]+",
    re.ASCII | re.IGNORECASE,
)

_EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.ASCII,
)

_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|ru|cn|de|uk|fr|info|biz|xyz|top|cc|pw|tk|ml"
    r"|ga|cf|gq|onion|bit)\b",
    re.ASCII | re.IGNORECASE,
)

_CRYPTO_KEYWORDS = re.compile(
    r"\b(?:password|passwd|secret|private.?key|public.?key|"
    r"encrypt|decrypt|cipher|aes|des|rsa|sha256|sha1|md5|"
    r"certificate|cert|ssl|tls|pgp|gpg|hmac|"
    r"BEGIN.?(?:RSA|DSA|EC|PGP|CERTIFICATE|PRIVATE|PUBLIC))\b",
    re.ASCII | re.IGNORECASE,
)

_SUSPICIOUS_KEYWORDS = re.compile(
    r"\b(?:cmd\.exe|command\.com|powershell|/bin/sh|/bin/bash|"
    r"eval|exec|system|popen|subprocess|ShellExecute|"
    r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|"
    r"NtQueueApcThread|NtCreateThreadEx|RtlCreateUserThread|"
    r"LoadLibrary[AW]?|GetProcAddress|CreateProcess[AW]?|"
    r"WinExec|CreateFile[AW]?|DeleteFile[AW]?|"
    r"SetWindowsHookEx[AW]?|GetAsyncKeyState|"
    r"IsDebuggerPresent|CheckRemoteDebuggerPresent|"
    r"InternetOpen[AW]?|URLDownloadToFile[AW]?|"
    r"WSASocket[AW]?|WSAStartup|"
    r"RegSetValue|RegCreateKey|"
    r"AdjustTokenPrivileges|OpenProcessToken|"
    r"GetTempPath[AW]?|GetSystemDirectory[AW]?)\b",
    re.ASCII | re.IGNORECASE,
)

# Base64-encoded data detector: at least 20 chars of base64 alphabet
_BASE64_PATTERN = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    re.ASCII,
)

# Hex-encoded string: pairs of hex digits, at least 16 chars
_HEX_PATTERN = re.compile(
    r"(?:[0-9a-fA-F]{2}){8,}",
    re.ASCII,
)


# ---------------------------------------------------------------------------
# StringExtractor
# ---------------------------------------------------------------------------

class StringExtractor:
    """Multi-encoding string extraction and classification engine.

    Extracts printable strings from binary data using multiple encoding
    strategies and classifies them into security-relevant categories.

    Supported encodings:
        - ASCII (printable byte sequences)
        - UTF-16 Little-Endian
        - UTF-16 Big-Endian
        - Base64 (detected and decoded)
        - Hex-encoded (detected and decoded)

    Categories:
        - URL, IP address, file path, registry key, email
        - Domain names, crypto-related, suspicious API/commands
        - General (uncategorised)

    Usage::

        extractor = StringExtractor(min_length=4)
        results = extractor.extract(binary_data)
        for s in results:
            print(f"[{s.category}] {s.value}")
    """

    def __init__(self, min_length: int = 4) -> None:
        """Initialise the extractor.

        Args:
            min_length: Minimum string length to extract (default: 4).
                        Shorter strings are discarded as noise.
        """
        self._min_length: int = max(1, min_length)

    def extract(
        self,
        data: bytes,
        min_length: int | None = None,
    ) -> list[StringResult]:
        """Extract and classify strings from binary data.

        Performs extraction in all supported encodings, deduplicates by
        value, and classifies each string.

        Args:
            data: Raw binary data to scan.
            min_length: Override the minimum string length for this call.

        Returns:
            List of StringResult models, sorted by file offset.
        """
        ml = min_length if min_length is not None else self._min_length

        results: list[StringResult] = []

        # ASCII extraction
        results.extend(self._extract_ascii(data, ml))

        # UTF-16 LE extraction
        results.extend(self._extract_utf16(data, ml, "utf-16-le"))

        # UTF-16 BE extraction
        results.extend(self._extract_utf16(data, ml, "utf-16-be"))

        # Base64 detection (from ASCII strings)
        results.extend(self._detect_base64(data, ml))

        # Hex-encoded detection
        results.extend(self._detect_hex_encoded(data, ml))

        # Deduplicate by (offset, value) and classify
        seen: set[tuple[int, str]] = set()
        unique: list[StringResult] = []
        for sr in results:
            key = (sr.offset, sr.value)
            if key not in seen:
                seen.add(key)
                sr.category = self._classify(sr.value)
                unique.append(sr)

        # Sort by offset
        unique.sort(key=lambda s: s.offset)
        return unique

    # ------------------------------------------------------------------ #
    #  ASCII extraction
    # ------------------------------------------------------------------ #

    def _extract_ascii(self, data: bytes, min_length: int) -> list[StringResult]:
        """Extract ASCII printable strings.

        Scans for contiguous runs of printable ASCII bytes meeting the
        minimum length threshold.

        Args:
            data: Raw binary data.
            min_length: Minimum string length.

        Returns:
            List of StringResult with encoding="ascii".
        """
        results: list[StringResult] = []
        current_start: int = -1
        current_chars: list[int] = []

        for i, byte in enumerate(data):
            if byte in _ASCII_PRINTABLE:
                if current_start == -1:
                    current_start = i
                current_chars.append(byte)
            else:
                if len(current_chars) >= min_length:
                    value = bytes(current_chars).decode("ascii", errors="replace").strip()
                    if len(value) >= min_length:
                        results.append(StringResult(
                            offset=current_start,
                            encoding="ascii",
                            value=value,
                        ))
                current_start = -1
                current_chars = []

        # Handle trailing string
        if len(current_chars) >= min_length:
            value = bytes(current_chars).decode("ascii", errors="replace").strip()
            if len(value) >= min_length:
                results.append(StringResult(
                    offset=current_start,
                    encoding="ascii",
                    value=value,
                ))

        return results

    # ------------------------------------------------------------------ #
    #  UTF-16 extraction
    # ------------------------------------------------------------------ #

    def _extract_utf16(
        self,
        data: bytes,
        min_length: int,
        encoding: str,
    ) -> list[StringResult]:
        """Extract UTF-16 encoded strings.

        Scans for patterns of alternating printable-byte/null-byte (LE)
        or null-byte/printable-byte (BE) pairs.

        Args:
            data: Raw binary data.
            min_length: Minimum character length.
            encoding: ``"utf-16-le"`` or ``"utf-16-be"``.

        Returns:
            List of StringResult.
        """
        results: list[StringResult] = []
        is_le = encoding == "utf-16-le"
        data_len = len(data)

        i = 0
        while i < data_len - 1:
            # Check for a UTF-16 character pattern
            if is_le:
                char_byte = data[i]
                null_byte = data[i + 1]
            else:
                null_byte = data[i]
                char_byte = data[i + 1]

            if null_byte == 0 and char_byte in _ASCII_PRINTABLE:
                # Start of a potential UTF-16 string
                start = i
                chars: list[int] = [char_byte]
                j = i + 2

                while j < data_len - 1:
                    if is_le:
                        cb = data[j]
                        nb = data[j + 1]
                    else:
                        nb = data[j]
                        cb = data[j + 1]

                    if nb == 0 and cb in _ASCII_PRINTABLE:
                        chars.append(cb)
                        j += 2
                    else:
                        break

                if len(chars) >= min_length:
                    value = bytes(chars).decode("ascii", errors="replace").strip()
                    if len(value) >= min_length:
                        results.append(StringResult(
                            offset=start,
                            encoding=encoding,
                            value=value,
                        ))

                i = j
            else:
                i += 1

        return results

    # ------------------------------------------------------------------ #
    #  Base64 detection
    # ------------------------------------------------------------------ #

    def _detect_base64(self, data: bytes, min_length: int) -> list[StringResult]:
        """Detect and decode Base64-encoded strings.

        Scans the binary for sequences matching the Base64 alphabet with
        proper padding, then attempts to decode them.

        Args:
            data: Raw binary data.
            min_length: Minimum decoded string length.

        Returns:
            List of StringResult with encoding="base64".
        """
        results: list[StringResult] = []

        # Search for Base64 patterns in the ASCII representation
        try:
            text = data.decode("ascii", errors="ignore")
        except Exception:
            return results

        for match in _BASE64_PATTERN.finditer(text):
            b64_str = match.group(0)
            if len(b64_str) < 20:
                continue

            try:
                decoded = base64.b64decode(b64_str, validate=True)
                # Check if decoded content is printable text
                decoded_text = decoded.decode("utf-8", errors="strict")
                if len(decoded_text) >= min_length and self._is_meaningful(decoded_text):
                    results.append(StringResult(
                        offset=match.start(),
                        encoding="base64",
                        value=decoded_text,
                        category=StringCategory.BASE64,
                    ))
            except Exception:
                continue

        return results

    # ------------------------------------------------------------------ #
    #  Hex-encoded detection
    # ------------------------------------------------------------------ #

    def _detect_hex_encoded(self, data: bytes, min_length: int) -> list[StringResult]:
        """Detect hex-encoded strings.

        Scans for long runs of hexadecimal digit pairs and attempts to
        decode them as ASCII text.

        Args:
            data: Raw binary data.
            min_length: Minimum decoded string length.

        Returns:
            List of StringResult with encoding="hex".
        """
        results: list[StringResult] = []

        try:
            text = data.decode("ascii", errors="ignore")
        except Exception:
            return results

        for match in _HEX_PATTERN.finditer(text):
            hex_str = match.group(0)
            if len(hex_str) < 16:
                continue

            try:
                decoded = bytes.fromhex(hex_str)
                decoded_text = decoded.decode("ascii", errors="strict")
                if len(decoded_text) >= min_length and self._is_meaningful(decoded_text):
                    results.append(StringResult(
                        offset=match.start(),
                        encoding="hex",
                        value=decoded_text,
                    ))
            except Exception:
                continue

        return results

    # ------------------------------------------------------------------ #
    #  Classification
    # ------------------------------------------------------------------ #

    def _classify(self, value: str) -> StringCategory:
        """Classify a string into a security-relevant category.

        Tests the string against each category pattern in priority order
        and returns the first match.

        Args:
            value: The extracted string to classify.

        Returns:
            StringCategory enumeration value.
        """
        if _URL_PATTERN.search(value) or _FTP_PATTERN.search(value):
            return StringCategory.URL

        if _EMAIL_PATTERN.search(value):
            return StringCategory.EMAIL

        if _IPV4_PATTERN.search(value) or _IPV6_PATTERN.search(value):
            return StringCategory.IP_ADDRESS

        if _REGISTRY_PATTERN.search(value):
            return StringCategory.REGISTRY

        if _WINDOWS_PATH_PATTERN.search(value) or _UNIX_PATH_PATTERN.search(value):
            return StringCategory.FILE_PATH

        if _SUSPICIOUS_KEYWORDS.search(value):
            return StringCategory.SUSPICIOUS

        if _CRYPTO_KEYWORDS.search(value):
            return StringCategory.CRYPTO

        if _DOMAIN_PATTERN.search(value):
            return StringCategory.DOMAIN

        return StringCategory.GENERAL

    # ------------------------------------------------------------------ #
    #  Utility
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_meaningful(text: str) -> bool:
        """Check if decoded text is meaningful (not random gibberish).

        A string is considered meaningful if it has a high ratio of
        printable characters and contains at least some alphabetic content.

        Args:
            text: Decoded text string.

        Returns:
            ``True`` if the string appears meaningful.
        """
        if not text:
            return False

        printable_count = sum(1 for c in text if c.isprintable())
        alpha_count = sum(1 for c in text if c.isalpha())

        printable_ratio = printable_count / len(text)
        alpha_ratio = alpha_count / len(text)

        return printable_ratio > 0.7 and alpha_ratio > 0.2
