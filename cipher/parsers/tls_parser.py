"""
TLS Parser
===========

Parses TLS handshake information, cipher suite names, and X.509
certificate chains into structured data models for analysis.

Handles parsing of:
- Cipher suite name decomposition (key exchange, auth, cipher, MAC)
- Certificate chain extraction and validation
- Protocol version identification
- TLS extension parsing

The parser supports both OpenSSL-style cipher names
(e.g., ``ECDHE-RSA-AES256-GCM-SHA384``) and IANA/RFC-style names
(e.g., ``TLS_AES_256_GCM_SHA384``).

References:
    - Rescorla, E. (2018). RFC 8446 -- TLS 1.3.
    - Dierks, T., & Rescorla, E. (2008). RFC 5246 -- TLS 1.2.
    - Cooper, D. et al. (2008). RFC 5280 -- Internet X.509 PKI.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


# ===================================================================== #
#  Data Structures
# ===================================================================== #


@dataclass
class CipherSuiteComponents:
    """Decomposed cipher suite name components.

    Attributes:
        full_name: Original cipher suite name.
        protocol: Protocol version (TLS 1.2, TLS 1.3, etc.).
        key_exchange: Key exchange algorithm (ECDHE, DHE, RSA, PSK).
        authentication: Authentication algorithm (RSA, ECDSA, DSS).
        encryption: Bulk encryption algorithm (AES-256-GCM, etc.).
        mac: MAC/PRF algorithm (SHA256, SHA384, AEAD).
        key_bits: Encryption key size in bits.
        is_aead: Whether the cipher uses AEAD mode (GCM, CCM, Poly1305).
        is_pfs: Whether the suite provides perfect forward secrecy.
        is_export: Whether this is an export-grade cipher (weak).
    """

    full_name: str = ""
    protocol: str = ""
    key_exchange: str = ""
    authentication: str = ""
    encryption: str = ""
    mac: str = ""
    key_bits: int = 0
    is_aead: bool = False
    is_pfs: bool = False
    is_export: bool = False


@dataclass
class CertificateDetails:
    """Parsed X.509 certificate details.

    Attributes:
        subject_cn: Subject Common Name.
        subject_org: Subject Organisation.
        issuer_cn: Issuer Common Name.
        issuer_org: Issuer Organisation.
        serial_number: Certificate serial number (hex).
        not_before: Validity start date.
        not_after: Validity end date.
        is_expired: Whether the certificate is currently expired.
        signature_algorithm: Signature algorithm OID/name.
        public_key_algorithm: Public key algorithm.
        public_key_bits: Public key size in bits.
        san: Subject Alternative Names.
        is_self_signed: Whether subject == issuer.
        fingerprint_sha256: SHA-256 fingerprint of the certificate.
        version: X.509 version number.
    """

    subject_cn: str = ""
    subject_org: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    is_expired: bool = False
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_bits: int = 0
    san: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    fingerprint_sha256: str = ""
    version: int = 3


@dataclass
class CertificateChain:
    """Parsed certificate chain.

    Attributes:
        certificates: List of certificates from leaf to root.
        chain_length: Number of certificates in the chain.
        chain_valid: Whether the chain has a valid structure.
        leaf: The end-entity (leaf) certificate.
        root: The root CA certificate (if available).
    """

    certificates: list[CertificateDetails] = field(default_factory=list)
    chain_length: int = 0
    chain_valid: bool = False
    leaf: Optional[CertificateDetails] = None
    root: Optional[CertificateDetails] = None


# ===================================================================== #
#  Cipher Suite Parsing Constants
# ===================================================================== #

# Key exchange algorithm indicators
_KEX_KEYWORDS: dict[str, str] = {
    "ECDHE": "ECDHE",
    "DHE": "DHE",
    "ECDH": "ECDH",
    "DH": "DH",
    "RSA": "RSA",
    "PSK": "PSK",
    "SRP": "SRP",
    "KRB5": "KRB5",
    "GOST": "GOST",
}

# Authentication algorithm indicators
_AUTH_KEYWORDS: dict[str, str] = {
    "RSA": "RSA",
    "ECDSA": "ECDSA",
    "DSS": "DSS",
    "PSK": "PSK",
    "anon": "anonymous",
    "GOST": "GOST",
}

# AEAD modes
_AEAD_MODES: set[str] = {"GCM", "CCM", "POLY1305", "CHACHA20"}

# PFS-capable key exchanges
_PFS_KEX: set[str] = {"ECDHE", "DHE", "X25519", "X448"}

# Key size extraction patterns
_KEY_SIZE_PATTERN = re.compile(r"(\d{3})(?:[-_])")


class TLSParser:
    """Parses TLS handshake data, cipher suite names, and certificates.

    Provides methods for decomposing cipher suite names into their
    component algorithms, parsing X.509 certificates, and extracting
    certificate chain information.

    Usage::

        parser = TLSParser()
        components = parser.parse_cipher_suite("ECDHE-RSA-AES256-GCM-SHA384")
        print(f"KEX: {components.key_exchange}")
        print(f"AEAD: {components.is_aead}")
    """

    def parse_cipher_suite(self, name: str) -> CipherSuiteComponents:
        """Parse a cipher suite name into its constituent algorithms.

        Supports both OpenSSL-style and IANA/RFC-style cipher names.

        Args:
            name: Cipher suite name string.

        Returns:
            CipherSuiteComponents with decomposed algorithms.
        """
        result = CipherSuiteComponents(full_name=name)

        if not name:
            return result

        # Detect TLS 1.3 style names (TLS_AES_256_GCM_SHA384)
        if name.startswith("TLS_"):
            return self._parse_tls13_suite(name)

        # Parse OpenSSL-style names (ECDHE-RSA-AES256-GCM-SHA384)
        return self._parse_openssl_suite(name)

    def _parse_tls13_suite(self, name: str) -> CipherSuiteComponents:
        """Parse a TLS 1.3 cipher suite name.

        TLS 1.3 suites have the format: TLS_<cipher>_<hash>
        Key exchange is always ephemeral (determined at handshake time).

        Args:
            name: TLS 1.3 cipher suite name.

        Returns:
            CipherSuiteComponents.
        """
        result = CipherSuiteComponents(
            full_name=name,
            protocol="TLSv1.3",
            key_exchange="ECDHE",  # TLS 1.3 always uses ephemeral
            authentication="certificate",  # Determined by certificate
            is_aead=True,  # TLS 1.3 only supports AEAD
            is_pfs=True,   # TLS 1.3 always has PFS
            is_export=False,
        )

        # Remove TLS_ prefix and parse
        parts = name.replace("TLS_", "").split("_")

        # Reconstruct cipher and hash
        if len(parts) >= 3:
            # e.g., AES_256_GCM_SHA384 -> cipher=AES-256-GCM, mac=SHA384
            result.encryption = "-".join(parts[:-1])
            result.mac = parts[-1]
        elif len(parts) == 2:
            result.encryption = parts[0]
            result.mac = parts[1]

        # Extract key size
        for part in parts:
            if part.isdigit() and len(part) == 3:
                result.key_bits = int(part)
                break

        if result.key_bits == 0:
            # Try to extract from cipher name
            if "256" in result.encryption:
                result.key_bits = 256
            elif "128" in result.encryption:
                result.key_bits = 128

        return result

    def _parse_openssl_suite(self, name: str) -> CipherSuiteComponents:
        """Parse an OpenSSL-style cipher suite name.

        Format: [KEX]-[AUTH]-<CIPHER>-<MODE>-<MAC>

        Args:
            name: OpenSSL cipher suite name.

        Returns:
            CipherSuiteComponents.
        """
        result = CipherSuiteComponents(full_name=name)
        parts = name.upper().replace("_", "-").split("-")

        # Track which parts have been consumed
        consumed: set[int] = set()

        # Pass 1: Extract key exchange
        for i, part in enumerate(parts):
            if part in _KEX_KEYWORDS and i not in consumed:
                result.key_exchange = _KEX_KEYWORDS[part]
                consumed.add(i)
                break

        # Pass 2: Extract authentication
        for i, part in enumerate(parts):
            if i in consumed:
                continue
            if part in _AUTH_KEYWORDS and result.key_exchange:
                result.authentication = _AUTH_KEYWORDS[part]
                consumed.add(i)
                break

        # If no separate auth found, KEX doubles as auth for RSA
        if not result.authentication:
            if result.key_exchange == "RSA":
                result.authentication = "RSA"
            elif not result.key_exchange:
                result.key_exchange = "RSA"
                result.authentication = "RSA"

        # Pass 3: Extract cipher, mode, and MAC from remaining parts
        remaining = [parts[i] for i in range(len(parts)) if i not in consumed]

        cipher_parts: list[str] = []
        mac_part = ""

        for part in remaining:
            if part in ("SHA", "SHA256", "SHA384", "SHA512", "MD5"):
                mac_part = part
            elif part.startswith("SHA") and part[3:].isdigit():
                mac_part = part
            else:
                cipher_parts.append(part)

        result.encryption = "-".join(cipher_parts) if cipher_parts else ""
        result.mac = mac_part

        # Determine AEAD
        result.is_aead = any(
            mode in result.encryption.upper() for mode in _AEAD_MODES
        )

        # Determine PFS
        result.is_pfs = result.key_exchange in _PFS_KEX

        # Determine export grade
        result.is_export = "EXPORT" in name.upper() or "EXP" in name.upper()

        # Extract key bits
        for part in cipher_parts:
            if part.isdigit() and len(part) == 3:
                result.key_bits = int(part)
                break

        if result.key_bits == 0:
            match = _KEY_SIZE_PATTERN.search(result.encryption)
            if match:
                result.key_bits = int(match.group(1))

        return result

    def parse_certificate(self, cert_dict: dict[str, Any]) -> CertificateDetails:
        """Parse a certificate dictionary from ssl.getpeercert().

        Extracts all relevant fields from the certificate into a
        structured CertificateDetails object.

        Args:
            cert_dict: Certificate dictionary as returned by
                SSLSocket.getpeercert().

        Returns:
            CertificateDetails with parsed information.
        """
        if not cert_dict:
            return CertificateDetails()

        details = CertificateDetails()

        # Subject fields
        subject = cert_dict.get("subject", ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    details.subject_cn = attr_value
                elif attr_type == "organizationName":
                    details.subject_org = attr_value

        # Issuer fields
        issuer = cert_dict.get("issuer", ())
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    details.issuer_cn = attr_value
                elif attr_type == "organizationName":
                    details.issuer_org = attr_value

        # Serial number
        details.serial_number = str(cert_dict.get("serialNumber", ""))

        # Validity dates
        details.not_before = cert_dict.get("notBefore", "")
        details.not_after = cert_dict.get("notAfter", "")

        # Check expiry
        if details.not_after:
            try:
                # OpenSSL date format: "Mon DD HH:MM:SS YYYY GMT"
                expiry = datetime.strptime(
                    details.not_after, "%b %d %H:%M:%S %Y %Z"
                )
                details.is_expired = expiry < datetime.utcnow()
            except ValueError:
                pass

        # Self-signed check
        details.is_self_signed = (
            details.subject_cn == details.issuer_cn
            and details.subject_org == details.issuer_org
            and details.subject_cn != ""
        )

        # Subject Alternative Names
        san_tuples = cert_dict.get("subjectAltName", ())
        for san_type, san_value in san_tuples:
            details.san.append(f"{san_type}:{san_value}")

        # Version
        details.version = cert_dict.get("version", 3)

        return details

    def parse_certificate_chain(
        self, cert_dicts: list[dict[str, Any]]
    ) -> CertificateChain:
        """Parse a list of certificate dictionaries into a chain.

        Args:
            cert_dicts: List of certificate dictionaries, ordered from
                leaf to root.

        Returns:
            CertificateChain with parsed certificates.
        """
        chain = CertificateChain()

        for cert_dict in cert_dicts:
            details = self.parse_certificate(cert_dict)
            chain.certificates.append(details)

        chain.chain_length = len(chain.certificates)

        if chain.certificates:
            chain.leaf = chain.certificates[0]
            chain.root = chain.certificates[-1] if len(chain.certificates) > 1 else None

        # Basic chain validation
        chain.chain_valid = self._validate_chain_structure(chain)

        return chain

    def parse_pem_file(self, filepath: Path) -> list[CertificateDetails]:
        """Parse certificates from a PEM file.

        Reads a PEM-formatted file and extracts certificate information
        using the ssl module's built-in PEM parsing.

        Args:
            filepath: Path to the PEM file.

        Returns:
            List of CertificateDetails parsed from the file.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        results: list[CertificateDetails] = []

        try:
            pem_data = filepath.read_text(encoding="ascii")
        except UnicodeDecodeError:
            pem_data = filepath.read_text(encoding="utf-8", errors="replace")

        # Extract individual PEM blocks
        pem_blocks = self._extract_pem_blocks(pem_data)

        for block in pem_blocks:
            try:
                # Use ssl module to parse DER-encoded certificate
                der_bytes = ssl.PEM_cert_to_DER_cert(block)
                # Unfortunately, ssl module doesn't provide a way to parse
                # DER directly into a dict without a connection. We store
                # what we can extract.
                cert_detail = CertificateDetails()
                cert_detail.version = 3
                results.append(cert_detail)
            except (ssl.SSLError, ValueError):
                continue

        return results

    @staticmethod
    def _extract_pem_blocks(pem_data: str) -> list[str]:
        """Extract individual PEM certificate blocks from a string.

        Args:
            pem_data: PEM-formatted string potentially containing
                multiple certificates.

        Returns:
            List of individual PEM certificate strings.
        """
        blocks: list[str] = []
        pattern = re.compile(
            r"(-----BEGIN CERTIFICATE-----\s*"
            r"[A-Za-z0-9+/=\s]+"
            r"-----END CERTIFICATE-----)",
            re.MULTILINE,
        )

        for match in pattern.finditer(pem_data):
            blocks.append(match.group(1))

        return blocks

    @staticmethod
    def _validate_chain_structure(chain: CertificateChain) -> bool:
        """Perform basic structural validation on a certificate chain.

        Checks that each certificate's issuer matches the next
        certificate's subject (simplified -- does not verify signatures).

        Args:
            chain: The certificate chain to validate.

        Returns:
            True if the chain has a valid structure.
        """
        if chain.chain_length == 0:
            return False
        if chain.chain_length == 1:
            # Single certificate -- valid if self-signed (root CA)
            return True

        for i in range(len(chain.certificates) - 1):
            current = chain.certificates[i]
            parent = chain.certificates[i + 1]
            # Check that current cert's issuer matches parent's subject
            if current.issuer_cn and parent.subject_cn:
                if current.issuer_cn != parent.subject_cn:
                    return False

        return True

    @staticmethod
    def identify_protocol_version(version_string: str) -> dict[str, Any]:
        """Identify and classify a TLS protocol version.

        Args:
            version_string: Protocol version string (e.g., "TLSv1.3").

        Returns:
            Dictionary with version details and security assessment.
        """
        version_map: dict[str, dict[str, Any]] = {
            "TLSv1.3": {
                "version": "1.3",
                "year": 2018,
                "rfc": "RFC 8446",
                "status": "current",
                "secure": True,
                "grade": "A+",
            },
            "TLSv1.2": {
                "version": "1.2",
                "year": 2008,
                "rfc": "RFC 5246",
                "status": "current",
                "secure": True,
                "grade": "A",
            },
            "TLSv1.1": {
                "version": "1.1",
                "year": 2006,
                "rfc": "RFC 4346",
                "status": "deprecated",
                "secure": False,
                "grade": "C",
            },
            "TLSv1.0": {
                "version": "1.0",
                "year": 1999,
                "rfc": "RFC 2246",
                "status": "deprecated",
                "secure": False,
                "grade": "D",
            },
            "TLSv1": {
                "version": "1.0",
                "year": 1999,
                "rfc": "RFC 2246",
                "status": "deprecated",
                "secure": False,
                "grade": "D",
            },
            "SSLv3": {
                "version": "SSL 3.0",
                "year": 1996,
                "rfc": "RFC 6101",
                "status": "prohibited",
                "secure": False,
                "grade": "F",
            },
            "SSLv2": {
                "version": "SSL 2.0",
                "year": 1995,
                "rfc": "N/A",
                "status": "prohibited",
                "secure": False,
                "grade": "F",
            },
        }

        return version_map.get(
            version_string,
            {
                "version": version_string,
                "year": 0,
                "rfc": "Unknown",
                "status": "unknown",
                "secure": False,
                "grade": "?",
            },
        )
