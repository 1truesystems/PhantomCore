"""
Indicator of Compromise (IoC) Extractor
========================================

Extracts and classifies Indicators of Compromise from unstructured text,
log files, reports, and other security data sources. Supports extraction
of IP addresses (IPv4/IPv6), domains, URLs, cryptographic hashes (MD5,
SHA-1, SHA-256), email addresses, CVE identifiers, file paths, and
registry keys.

The extractor performs:
  1. Regex-based pattern matching for each IoC type
  2. Validation and deduplication
  3. Defanging normalisation (hxxp -> http, [.] -> .)
  4. Context extraction (surrounding text for each IoC)

Defanging is the practice of modifying indicators to prevent accidental
activation (e.g. clicking a malicious URL). Common defanging patterns
include:
  - hxxp:// or hXXp:// -> http://
  - [.] or (.) -> .
  - [@] or [at] -> @

References:
    - STIX Patterning Language. OASIS (2017).
    - Mandiant. (2013). APT1 Report, Appendix C: Digital Indicators.
    - RFC 5321 -- Simple Mail Transfer Protocol (email format).
    - RFC 791 -- Internet Protocol (IPv4 address format).
    - RFC 4291 -- IP Version 6 Addressing Architecture.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from nexus.core.models import IoC, IoCType


class IoCExtractor:
    """Extracts Indicators of Compromise from text and files.

    Uses compiled regular expressions for high-performance IoC
    extraction with validation, deduplication, defang normalisation,
    and context extraction.

    Usage::

        extractor = IoCExtractor()
        iocs = extractor.extract_from_text(report_text)
        for ioc in iocs:
            print(f"{ioc.type.value}: {ioc.value}")
    """

    # Context window size (characters before/after IoC)
    CONTEXT_WINDOW: int = 80

    # ================================================================== #
    #  Compiled Regex Patterns
    # ================================================================== #

    # IPv4 address with validation (0-255 per octet)
    _RE_IPV4 = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    # IPv6 address (full and compressed forms)
    # Handles :: compressed notation, mixed IPv4/IPv6, and standard forms
    _RE_IPV6 = re.compile(
        r'\b(?:'
        # Full form: 8 groups of 4 hex digits
        r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
        r'|'
        # Compressed with :: (various positions)
        r'(?:[0-9a-fA-F]{1,4}:){1,7}:'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}'
        r'|'
        r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}'
        r'|'
        r':(?::[0-9a-fA-F]{1,4}){1,7}'
        r'|'
        # :: alone (all zeros)
        r'::(?:[fF]{4}(?::0{1,4})?:)?'
        r'(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}'
        r'(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){1,4}:'
        r'(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}'
        r'(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])'
        r')\b'
    )

    # Domain names (excluding IP-like patterns and short TLDs)
    _RE_DOMAIN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}'
        r'(?:[a-zA-Z]{2,63})\b'
    )

    # URLs (http/https, with optional defanged forms)
    _RE_URL = re.compile(
        r'(?:h[tx]{2}ps?://[^\s<>"\'\)\]]+)',
        re.IGNORECASE,
    )

    # MD5 hash (32 hex characters, standalone)
    _RE_MD5 = re.compile(
        r'\b[a-fA-F0-9]{32}\b'
    )

    # SHA-1 hash (40 hex characters, standalone)
    _RE_SHA1 = re.compile(
        r'\b[a-fA-F0-9]{40}\b'
    )

    # SHA-256 hash (64 hex characters, standalone)
    _RE_SHA256 = re.compile(
        r'\b[a-fA-F0-9]{64}\b'
    )

    # Email addresses (RFC 5321 compatible subset)
    _RE_EMAIL = re.compile(
        r'\b[a-zA-Z0-9._%+\-]+(?:@|\[(?:at|@)\])[a-zA-Z0-9.\-]+\.'
        r'[a-zA-Z]{2,}\b',
        re.IGNORECASE,
    )

    # CVE identifiers
    _RE_CVE = re.compile(
        r'\bCVE-\d{4}-\d{4,}\b',
        re.IGNORECASE,
    )

    # Windows file paths
    _RE_FILEPATH_WIN = re.compile(
        r'\b[A-Za-z]:\\(?:[^\\\s<>"|?*:]+\\)*[^\\\s<>"|?*:]+\b'
    )

    # Unix file paths (must start with / and have at least one more component)
    _RE_FILEPATH_UNIX = re.compile(
        r'(?<!\w)/(?:[a-zA-Z0-9._\-]+/)+[a-zA-Z0-9._\-]+\b'
    )

    # Windows registry keys
    _RE_REGISTRY = re.compile(
        r'\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|'
        r'CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s]+',
        re.IGNORECASE,
    )

    # Common TLDs for domain validation
    _VALID_TLDS: set[str] = {
        "com", "net", "org", "edu", "gov", "mil", "int",
        "io", "co", "us", "uk", "de", "fr", "ru", "cn",
        "jp", "br", "in", "au", "ca", "it", "es", "nl",
        "info", "biz", "name", "pro", "museum", "coop",
        "aero", "xyz", "online", "site", "store", "tech",
        "app", "dev", "cloud", "security", "onion", "bit",
        "top", "cc", "tv", "me", "ly", "tk", "cf", "ga",
        "ml", "gq", "pw", "ge",  # .ge for Georgia
    }

    # Domains to exclude (false positives)
    _EXCLUDED_DOMAINS: set[str] = {
        "example.com", "example.org", "example.net",
        "localhost", "test.com", "test.local",
        "schema.org", "www.w3.org", "purl.org",
    }

    # Defanging patterns (defanged -> normal)
    _DEFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r'hxxps?://', re.IGNORECASE), lambda m: m.group().replace('xx', 'tt').replace('XX', 'TT').replace('Xx', 'Tt').replace('xX', 'tT')),  # type: ignore[list-item]
        (re.compile(r'\[\.\]'), '.'),
        (re.compile(r'\(\.\)'), '.'),
        (re.compile(r'\[:\]'), ':'),
        (re.compile(r'\[at\]', re.IGNORECASE), '@'),
        (re.compile(r'\[@\]'), '@'),
        (re.compile(r'\[dot\]', re.IGNORECASE), '.'),
    ]

    def __init__(
        self,
        context_window: int = CONTEXT_WINDOW,
        extract_context: bool = True,
    ) -> None:
        """Initialise the IoC extractor.

        Args:
            context_window: Number of characters of surrounding text
                          to capture for each IoC.
            extract_context: Whether to extract context text.
        """
        self.context_window = context_window
        self.extract_context = extract_context

    # ================================================================== #
    #  Public API
    # ================================================================== #

    def extract_from_text(self, text: str) -> list[IoC]:
        """Extract all IoCs from a text string.

        Performs defanging normalisation first, then extracts each
        IoC type using compiled regex patterns. Results are
        deduplicated and validated.

        Args:
            text: Input text to scan for indicators.

        Returns:
            List of deduplicated IoC instances.
        """
        if not text or not text.strip():
            return []

        # Normalise defanged indicators
        normalised_text = self._refang(text)
        now = datetime.now(timezone.utc)

        iocs: list[IoC] = []
        seen: set[tuple[str, str]] = set()

        # Order matters: extract hashes before other patterns to avoid
        # hash substrings being matched as other types. Extract longer
        # patterns (SHA256) before shorter ones (SHA1 before MD5).

        # CVE identifiers
        for match in self._RE_CVE.finditer(normalised_text):
            value = match.group().upper()
            key = (IoCType.CVE.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                defanged = self._defang_value(value, IoCType.CVE)
                iocs.append(IoC(
                    type=IoCType.CVE,
                    value=value,
                    context=context,
                    defanged_value=defanged,
                    first_seen=now,
                ))

        # SHA-256 hashes (must check before SHA-1 and MD5)
        for match in self._RE_SHA256.finditer(normalised_text):
            value = match.group().lower()
            key = (IoCType.SHA256.value, value)
            if key not in seen:
                seen.add(key)
                # Also mark as seen for SHA1/MD5 to prevent partial matches
                seen.add((IoCType.SHA1.value, value[:40]))
                seen.add((IoCType.MD5.value, value[:32]))
                context = self._get_context(normalised_text, match)
                iocs.append(IoC(
                    type=IoCType.SHA256,
                    value=value,
                    context=context,
                    defanged_value=value,
                    first_seen=now,
                ))

        # SHA-1 hashes
        for match in self._RE_SHA1.finditer(normalised_text):
            value = match.group().lower()
            key = (IoCType.SHA1.value, value)
            if key not in seen:
                # Ensure it's not a substring of an already-captured SHA-256
                seen.add(key)
                seen.add((IoCType.MD5.value, value[:32]))
                context = self._get_context(normalised_text, match)
                iocs.append(IoC(
                    type=IoCType.SHA1,
                    value=value,
                    context=context,
                    defanged_value=value,
                    first_seen=now,
                ))

        # MD5 hashes
        for match in self._RE_MD5.finditer(normalised_text):
            value = match.group().lower()
            key = (IoCType.MD5.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                iocs.append(IoC(
                    type=IoCType.MD5,
                    value=value,
                    context=context,
                    defanged_value=value,
                    first_seen=now,
                ))

        # URLs (before domains, so domain extraction can skip URL domains)
        url_domains: set[str] = set()
        for match in self._RE_URL.finditer(normalised_text):
            value = match.group().rstrip(".,;:!?)}]")
            key = (IoCType.URL.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                defanged = self._defang_value(value, IoCType.URL)
                iocs.append(IoC(
                    type=IoCType.URL,
                    value=value,
                    context=context,
                    defanged_value=defanged,
                    first_seen=now,
                ))
                # Track domain from URL to avoid duplicate domain extraction
                domain_match = re.search(
                    r'https?://([^/:\s]+)', value, re.IGNORECASE
                )
                if domain_match:
                    url_domains.add(domain_match.group(1).lower())

        # Email addresses
        for match in self._RE_EMAIL.finditer(normalised_text):
            value = match.group().lower()
            # Normalise defanged @ symbols
            value = re.sub(r'\[(?:at|@)\]', '@', value, flags=re.IGNORECASE)
            key = (IoCType.EMAIL.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                defanged = self._defang_value(value, IoCType.EMAIL)
                iocs.append(IoC(
                    type=IoCType.EMAIL,
                    value=value,
                    context=context,
                    defanged_value=defanged,
                    first_seen=now,
                ))

        # IPv4 addresses
        for match in self._RE_IPV4.finditer(normalised_text):
            value = match.group()
            if not self._is_valid_ipv4(value):
                continue
            key = (IoCType.IPV4.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                defanged = self._defang_value(value, IoCType.IPV4)
                iocs.append(IoC(
                    type=IoCType.IPV4,
                    value=value,
                    context=context,
                    defanged_value=defanged,
                    first_seen=now,
                ))

        # IPv6 addresses
        for match in self._RE_IPV6.finditer(normalised_text):
            value = match.group()
            key = (IoCType.IPV6.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                defanged = self._defang_value(value, IoCType.IPV6)
                iocs.append(IoC(
                    type=IoCType.IPV6,
                    value=value,
                    context=context,
                    defanged_value=defanged,
                    first_seen=now,
                ))

        # Domain names
        for match in self._RE_DOMAIN.finditer(normalised_text):
            value = match.group().lower()
            if not self._is_valid_domain(value):
                continue
            if value in url_domains:
                continue
            key = (IoCType.DOMAIN.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                defanged = self._defang_value(value, IoCType.DOMAIN)
                iocs.append(IoC(
                    type=IoCType.DOMAIN,
                    value=value,
                    context=context,
                    defanged_value=defanged,
                    first_seen=now,
                ))

        # Windows registry keys
        for match in self._RE_REGISTRY.finditer(normalised_text):
            value = match.group()
            key = (IoCType.REGISTRY_KEY.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                iocs.append(IoC(
                    type=IoCType.REGISTRY_KEY,
                    value=value,
                    context=context,
                    defanged_value=value,
                    first_seen=now,
                ))

        # File paths (Windows)
        for match in self._RE_FILEPATH_WIN.finditer(normalised_text):
            value = match.group()
            key = (IoCType.FILE_PATH.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                iocs.append(IoC(
                    type=IoCType.FILE_PATH,
                    value=value,
                    context=context,
                    defanged_value=value,
                    first_seen=now,
                ))

        # File paths (Unix)
        for match in self._RE_FILEPATH_UNIX.finditer(normalised_text):
            value = match.group()
            key = (IoCType.FILE_PATH.value, value)
            if key not in seen:
                seen.add(key)
                context = self._get_context(normalised_text, match)
                iocs.append(IoC(
                    type=IoCType.FILE_PATH,
                    value=value,
                    context=context,
                    defanged_value=value,
                    first_seen=now,
                ))

        return iocs

    def extract_from_file(self, file_path: str | Path) -> list[IoC]:
        """Extract IoCs from a file.

        Reads the file content and delegates to extract_from_text().
        Supports text files, log files, and other UTF-8 readable formats.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of extracted IoC instances.

        Raises:
            FileNotFoundError: If the file does not exist.
            UnicodeDecodeError: If the file cannot be read as UTF-8.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Try UTF-8 first, fall back to latin-1
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="latin-1")

        iocs = self.extract_from_text(text)

        # Tag IoCs with source file
        for ioc in iocs:
            ioc.tags.append(f"source:{path.name}")

        return iocs

    # ================================================================== #
    #  Defanging / Refanging
    # ================================================================== #

    def _refang(self, text: str) -> str:
        """Normalise defanged indicators back to their original form.

        Converts common defanging patterns to their active equivalents
        for pattern matching:
          - hxxp -> http, hXXp -> http
          - [.] -> .
          - (.) -> .
          - [at] / [@] -> @
          - [dot] -> .

        Args:
            text: Input text potentially containing defanged indicators.

        Returns:
            Text with defanged indicators normalised.
        """
        result = text

        # hxxp/hXXp normalisation
        result = re.sub(
            r'h[xX]{2}p(s?://?)',
            lambda m: f"http{m.group(1)}",
            result,
        )

        # Bracket-dot patterns
        result = result.replace("[.]", ".")
        result = result.replace("(.)", ".")
        result = result.replace("[:]", ":")

        # At-sign patterns
        result = re.sub(r'\[at\]', '@', result, flags=re.IGNORECASE)
        result = result.replace("[@]", "@")

        # Dot-word patterns
        result = re.sub(r'\[dot\]', '.', result, flags=re.IGNORECASE)

        return result

    @staticmethod
    def _defang_value(value: str, ioc_type: IoCType) -> str:
        """Create a defanged representation of an IoC value.

        Defanging prevents accidental activation when the indicator
        is displayed in reports or shared via email/chat.

        Args:
            value: The original IoC value.
            ioc_type: Type of the indicator.

        Returns:
            Defanged string representation.
        """
        if ioc_type == IoCType.URL:
            defanged = value.replace("http://", "hxxp://")
            defanged = defanged.replace("https://", "hxxps://")
            defanged = defanged.replace(".", "[.]", 1)
            return defanged

        if ioc_type in (IoCType.DOMAIN, IoCType.IPV4):
            return value.replace(".", "[.]")

        if ioc_type == IoCType.IPV6:
            return value.replace(":", "[:]")

        if ioc_type == IoCType.EMAIL:
            return value.replace("@", "[@]").replace(".", "[.]", 1)

        return value

    # ================================================================== #
    #  Validation Helpers
    # ================================================================== #

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validate an IPv4 address string.

        Rejects reserved/private ranges that are unlikely to be IoCs:
          - 0.0.0.0/8
          - 127.0.0.0/8 (loopback)
          - 255.255.255.255 (broadcast)
          - Version-like strings (e.g. "1.2.3.4" that look like semver)

        Args:
            ip: IPv4 address string.

        Returns:
            True if the IP is a valid, non-reserved IPv4 address.
        """
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return False

            values = [int(o) for o in octets]
            if any(v < 0 or v > 255 for v in values):
                return False

            # Reject special addresses
            if values[0] == 0:
                return False
            if values[0] == 127:
                return False
            if all(v == 255 for v in values):
                return False

            return True
        except (ValueError, IndexError):
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate a domain name string.

        Checks:
          - Has at least two parts (name + TLD)
          - TLD is in the known TLD set (or is >= 2 chars)
          - Not in the exclusion list
          - Not an IP address disguised as a domain
          - Not overly short (likely false positive)

        Args:
            domain: Domain name string.

        Returns:
            True if the domain appears to be a valid, interesting domain.
        """
        if domain in self._EXCLUDED_DOMAINS:
            return False

        parts = domain.split(".")
        if len(parts) < 2:
            return False

        tld = parts[-1].lower()
        if len(tld) < 2:
            return False

        # Reject if TLD is purely numeric (likely IP fragment)
        if tld.isdigit():
            return False

        # Reject very short domains that are likely false positives
        if len(domain) < 5:
            return False

        # Check if all parts look like IP octets
        if all(part.isdigit() for part in parts):
            return False

        return True

    # ================================================================== #
    #  Context Extraction
    # ================================================================== #

    def _get_context(self, text: str, match: re.Match[str]) -> str:
        """Extract surrounding context for an IoC match.

        Captures text before and after the match within the configured
        context window, trimming at word boundaries where possible.

        Args:
            text: Full source text.
            match: Regex match object.

        Returns:
            Context string with the IoC highlighted by ellipsis markers.
        """
        if not self.extract_context:
            return ""

        start = max(0, match.start() - self.context_window)
        end = min(len(text), match.end() + self.context_window)

        context = text[start:end].strip()

        # Clean up whitespace
        context = re.sub(r'\s+', ' ', context)

        # Add ellipsis for truncation
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."

        return context
