"""
TLS Cipher Suite Analyzer
===========================

Analyses TLS cipher suites offered by a remote server, evaluating
protocol versions, key exchange algorithms, bulk ciphers, and MAC
algorithms against current security recommendations.

The grading system is modelled after SSL Labs' methodology and
incorporates NIST SP 800-131A and SP 800-52 guidelines:

    A+ : TLS 1.3 only, or TLS 1.2 with AEAD + ECDHE + strong certificate
    A  : TLS 1.2+ with AEAD ciphers and forward secrecy
    B  : TLS 1.2 with non-AEAD or minor issues
    C  : TLS 1.1 present, or weak key exchange
    D  : TLS 1.0 present, or deprecated algorithms
    F  : SSL 2/3 present, NULL/export ciphers, or critical weaknesses

References:
    - NIST SP 800-131A Rev. 2 (2019). Transitioning the Use of
      Cryptographic Algorithms and Key Lengths.
    - NIST SP 800-52 Rev. 2 (2019). Guidelines for the Selection,
      Configuration, and Use of TLS Implementations.
    - Rescorla, E. (2018). RFC 8446 -- The Transport Layer Security
      (TLS) Protocol Version 1.3.
    - SSL Labs Grading Criteria (2023). https://github.com/ssllabs/research
"""

from __future__ import annotations

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from cipher.core.models import (
    CertificateInfo,
    CipherGrade,
    CipherSuiteInfo,
    CipherSuiteResult,
)


# ===================================================================== #
#  Cipher Classification Tables
# ===================================================================== #

# Protocol version scoring (higher = better)
_PROTOCOL_SCORES: dict[str, int] = {
    "TLSv1.3": 100,
    "TLSv1.2": 85,
    "TLSv1.1": 40,
    "TLSv1": 20,
    "TLSv1.0": 20,
    "SSLv3": 5,
    "SSLv2": 0,
}

# Key exchange algorithm scores
_KEX_SCORES: dict[str, int] = {
    "ECDHE": 100,
    "X25519": 100,
    "X448": 100,
    "DHE": 80,
    "DH": 60,
    "ECDH": 70,
    "RSA": 40,
    "PSK": 50,
    "NULL": 0,
    "EXPORT": 0,
}

# Bulk cipher scores
_CIPHER_SCORES: dict[str, int] = {
    "AES-256-GCM": 100,
    "AES-128-GCM": 95,
    "CHACHA20-POLY1305": 100,
    "CHACHA20": 100,
    "AES-256-CCM": 90,
    "AES-128-CCM": 85,
    "AES-256-CBC": 70,
    "AES-128-CBC": 65,
    "AES-256": 75,
    "AES-128": 70,
    "CAMELLIA-256": 70,
    "CAMELLIA-128": 65,
    "ARIA-256-GCM": 80,
    "ARIA-128-GCM": 75,
    "3DES": 20,
    "DES-CBC3": 20,
    "DES": 5,
    "RC4": 5,
    "RC2": 5,
    "IDEA": 30,
    "SEED": 40,
    "NULL": 0,
    "EXPORT": 0,
}

# Weak cipher keywords
_WEAK_KEYWORDS: set[str] = {
    "RC4", "RC2", "DES", "3DES", "DES-CBC3", "NULL", "EXPORT",
    "anon", "ADH", "AECDH", "MD5",
}


class CipherSuiteAnalyzer:
    """Analyses TLS cipher suites offered by a remote server.

    Connects to the target host, negotiates TLS, extracts cipher suite
    information, and evaluates the overall security posture.

    Usage::

        analyzer = CipherSuiteAnalyzer()
        result = await analyzer.analyze("example.com", 443)
        print(f"Grade: {result.grade.value}")
    """

    def __init__(self, timeout: float = 10.0) -> None:
        """Initialise the cipher suite analyzer.

        Args:
            timeout: Connection timeout in seconds.
        """
        self.timeout = timeout

    async def analyze(
        self, host: str, port: int = 443
    ) -> CipherSuiteResult:
        """Analyse TLS configuration of a remote host.

        Attempts to connect using the system's OpenSSL library, extracts
        the negotiated cipher suite and certificate information, then
        grades the configuration.

        Args:
            host: Target hostname or IP address.
            port: Target port (default 443).

        Returns:
            CipherSuiteResult with grade and detailed findings.
        """
        result = CipherSuiteResult(host=host, port=port)

        try:
            # Run the blocking SSL operations in an executor
            loop = asyncio.get_event_loop()
            conn_info = await loop.run_in_executor(
                None, self._connect_and_inspect, host, port
            )

            if conn_info is None:
                result.grade = CipherGrade.F
                result.recommendations.append(
                    "Could not establish TLS connection. Verify the host accepts TLS."
                )
                return result

            protocol_version = conn_info.get("protocol", "")
            cipher_name = conn_info.get("cipher_name", "")
            cipher_bits = conn_info.get("cipher_bits", 0)
            cipher_protocol = conn_info.get("cipher_protocol", "")
            cert_info = conn_info.get("certificate", None)
            all_ciphers = conn_info.get("all_ciphers", [])

            result.protocol = protocol_version or cipher_protocol

            # Parse the negotiated cipher suite
            suite_info = self._parse_cipher_suite(
                cipher_name, cipher_protocol, cipher_bits
            )
            result.suites.append(suite_info)

            # Add additional ciphers from shared_ciphers if available
            for extra_cipher in all_ciphers:
                if isinstance(extra_cipher, (tuple, list)) and len(extra_cipher) >= 3:
                    extra_name, extra_proto, extra_bits = (
                        extra_cipher[0],
                        extra_cipher[1],
                        extra_cipher[2],
                    )
                    if extra_name != cipher_name:
                        extra_info = self._parse_cipher_suite(
                            extra_name, extra_proto, extra_bits
                        )
                        result.suites.append(extra_info)

            # Parse certificate information
            if cert_info:
                result.certificate = self._parse_certificate(cert_info)

            # Evaluate features
            result.supports_tls_13 = any(
                "TLSv1.3" in (s.protocol or "") for s in result.suites
            ) or "TLSv1.3" in result.protocol
            result.supports_forward_secrecy = any(
                s.key_exchange in ("ECDHE", "DHE", "X25519", "X448")
                for s in result.suites
            )
            result.has_weak_ciphers = any(
                self._is_weak_cipher(s.name) for s in result.suites
            )

            # Compute overall grade
            result.grade = self._compute_grade(result)

            # Generate recommendations
            result.recommendations = self._generate_recommendations(result)

        except (socket.timeout, socket.gaierror) as exc:
            result.grade = CipherGrade.F
            result.recommendations.append(
                f"Connection failed: {exc}. Verify hostname and port."
            )
        except ssl.SSLError as exc:
            result.grade = CipherGrade.F
            result.recommendations.append(
                f"SSL/TLS error: {exc}. The server may not support TLS."
            )
        except ConnectionRefusedError:
            result.grade = CipherGrade.F
            result.recommendations.append(
                f"Connection refused at {host}:{port}."
            )
        except Exception as exc:
            result.grade = CipherGrade.F
            result.recommendations.append(f"Unexpected error: {exc}")

        return result

    def _connect_and_inspect(
        self, host: str, port: int
    ) -> Optional[dict]:
        """Perform the blocking TLS connection and extract information.

        Returns a dict with protocol, cipher, and certificate info,
        or None if the connection failed.
        """
        context = ssl.create_default_context()
        # Allow inspection of all protocols (we're auditing, not connecting securely)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection(
                (host, port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get negotiated cipher
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else ""
                    cipher_protocol = cipher_info[1] if cipher_info and len(cipher_info) > 1 else ""
                    cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0

                    # Get protocol version
                    protocol_version = ssock.version() or ""

                    # Get certificate
                    cert = ssock.getpeercert()

                    # Get shared ciphers (all ciphers the server and client both support)
                    shared = []
                    try:
                        shared = ssock.shared_ciphers() or []
                    except AttributeError:
                        pass

                    return {
                        "protocol": protocol_version,
                        "cipher_name": cipher_name,
                        "cipher_bits": cipher_bits,
                        "cipher_protocol": cipher_protocol,
                        "certificate": cert,
                        "all_ciphers": shared,
                    }
        except ssl.SSLCertVerificationError:
            # Retry without certificate verification to still get cipher info
            context_nocheck = ssl.create_default_context()
            context_nocheck.check_hostname = False
            context_nocheck.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection(
                    (host, port), timeout=self.timeout
                ) as sock:
                    with context_nocheck.wrap_socket(
                        sock, server_hostname=host
                    ) as ssock:
                        cipher_info = ssock.cipher()
                        cipher_name = cipher_info[0] if cipher_info else ""
                        cipher_protocol = cipher_info[1] if cipher_info and len(cipher_info) > 1 else ""
                        cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0
                        protocol_version = ssock.version() or ""
                        cert = ssock.getpeercert(binary_form=False)
                        shared = []
                        try:
                            shared = ssock.shared_ciphers() or []
                        except AttributeError:
                            pass
                        return {
                            "protocol": protocol_version,
                            "cipher_name": cipher_name,
                            "cipher_bits": cipher_bits,
                            "cipher_protocol": cipher_protocol,
                            "certificate": cert,
                            "all_ciphers": shared,
                        }
            except Exception:
                return None
        except Exception:
            return None

    def _parse_cipher_suite(
        self, name: str, protocol: str, bits: int
    ) -> CipherSuiteInfo:
        """Parse a cipher suite name into its components.

        Extracts key exchange, authentication, encryption, and MAC
        algorithms from the cipher suite name string.

        Args:
            name: Cipher suite name (e.g., "ECDHE-RSA-AES256-GCM-SHA384").
            protocol: Protocol version string.
            bits: Key size in bits.

        Returns:
            CipherSuiteInfo with parsed components.
        """
        parts = name.upper().replace("_", "-").split("-")

        key_exchange = ""
        authentication = ""
        encryption = ""
        mac = ""

        # Parse TLS 1.3 style names (e.g., TLS_AES_256_GCM_SHA384)
        if name.startswith("TLS_"):
            key_exchange = "ECDHE"  # TLS 1.3 always uses ephemeral
            authentication = "ECDSA/RSA"  # Determined by certificate
            # Extract cipher and MAC from name
            cleaned = name.replace("TLS_", "").replace("_", "-")
            encryption = cleaned.rsplit("-", 1)[0] if "-" in cleaned else cleaned
            mac = cleaned.rsplit("-", 1)[-1] if "-" in cleaned else "AEAD"
        else:
            # Parse OpenSSL-style names (e.g., ECDHE-RSA-AES256-GCM-SHA384)
            for part in parts:
                if part in ("ECDHE", "DHE", "DH", "RSA", "PSK", "ECDH"):
                    if not key_exchange:
                        key_exchange = part
                    elif not authentication:
                        authentication = part
                elif part in ("RSA", "ECDSA", "DSS", "PSK") and key_exchange:
                    authentication = part
                elif any(c in part for c in ("AES", "CHACHA", "DES", "RC4",
                                              "CAMELLIA", "ARIA", "NULL",
                                              "IDEA", "SEED")):
                    encryption = part if not encryption else f"{encryption}-{part}"
                elif part in ("GCM", "CCM", "CBC", "CTR", "POLY1305"):
                    encryption = f"{encryption}-{part}" if encryption else part
                elif part in ("SHA", "SHA256", "SHA384", "SHA512", "MD5"):
                    mac = part

            if not key_exchange and not authentication:
                key_exchange = "RSA"
                authentication = "RSA"

        # Determine individual suite grade
        grade = self._grade_suite(key_exchange, encryption, mac, protocol, bits)

        return CipherSuiteInfo(
            name=name,
            protocol=protocol,
            key_exchange=key_exchange,
            authentication=authentication or key_exchange,
            encryption=encryption,
            mac=mac,
            bits=bits,
            grade=grade,
        )

    def _grade_suite(
        self,
        kex: str,
        cipher: str,
        mac: str,
        protocol: str,
        bits: int,
    ) -> CipherGrade:
        """Grade an individual cipher suite.

        Evaluates protocol version, key exchange, cipher algorithm,
        and key size to produce a letter grade.

        Args:
            kex: Key exchange algorithm.
            cipher: Bulk encryption algorithm.
            mac: MAC algorithm.
            protocol: Protocol version.
            bits: Key size.

        Returns:
            CipherGrade for this suite.
        """
        # Protocol score
        proto_score = _PROTOCOL_SCORES.get(protocol, 50)

        # Key exchange score
        kex_score = _KEX_SCORES.get(kex.upper(), 50)

        # Cipher score -- find best matching key
        cipher_upper = cipher.upper()
        cipher_score = 50
        for cipher_key, score in _CIPHER_SCORES.items():
            if cipher_key in cipher_upper:
                cipher_score = score
                break

        # Bit size adjustments
        if bits >= 256:
            cipher_score = min(100, cipher_score + 5)
        elif bits < 128 and bits > 0:
            cipher_score = max(0, cipher_score - 20)

        # MAC penalty
        if "MD5" in (mac or "").upper():
            cipher_score = max(0, cipher_score - 20)

        # Weighted average
        overall = (proto_score * 0.30 + kex_score * 0.30 +
                   cipher_score * 0.40)

        if overall >= 90:
            return CipherGrade.A_PLUS if proto_score == 100 else CipherGrade.A
        elif overall >= 75:
            return CipherGrade.B
        elif overall >= 55:
            return CipherGrade.C
        elif overall >= 35:
            return CipherGrade.D
        else:
            return CipherGrade.F

    @staticmethod
    def _is_weak_cipher(name: str) -> bool:
        """Check if a cipher suite name indicates a weak cipher."""
        name_upper = name.upper()
        return any(weak in name_upper for weak in _WEAK_KEYWORDS)

    def _compute_grade(self, result: CipherSuiteResult) -> CipherGrade:
        """Compute the overall grade for a TLS configuration.

        The overall grade is the minimum (worst) of all individual suite
        grades, with additional penalties for specific weaknesses.

        Args:
            result: The cipher suite result to grade.

        Returns:
            Overall CipherGrade.
        """
        if not result.suites:
            return CipherGrade.F

        # Get the worst suite grade
        grade_order = [
            CipherGrade.A_PLUS, CipherGrade.A, CipherGrade.B,
            CipherGrade.C, CipherGrade.D, CipherGrade.F,
        ]
        worst_idx = 0
        for suite in result.suites:
            idx = grade_order.index(suite.grade) if suite.grade in grade_order else 5
            worst_idx = max(worst_idx, idx)

        # Additional penalties
        if result.has_weak_ciphers:
            worst_idx = max(worst_idx, 4)  # At least D

        # Protocol penalties
        protocol = (result.protocol or "").upper()
        if "SSLV2" in protocol or "SSLV3" in protocol:
            worst_idx = 5  # F
        elif "TLSV1.0" in protocol or "TLSV1" == protocol:
            worst_idx = max(worst_idx, 3)  # At least C

        return grade_order[min(worst_idx, 5)]

    @staticmethod
    def _parse_certificate(cert_dict: dict) -> CertificateInfo:
        """Parse a certificate dictionary from ssl.getpeercert().

        Args:
            cert_dict: Certificate dict returned by SSLSocket.getpeercert().

        Returns:
            CertificateInfo model.
        """
        if not cert_dict:
            return CertificateInfo()

        # Extract subject CN
        subject = ""
        subject_tuples = cert_dict.get("subject", ())
        for rdn in subject_tuples:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    subject = attr_value
                    break

        # Extract issuer CN
        issuer = ""
        issuer_tuples = cert_dict.get("issuer", ())
        for rdn in issuer_tuples:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    issuer = attr_value
                    break

        # Extract SAN
        san_list: list[str] = []
        san_tuples = cert_dict.get("subjectAltName", ())
        for san_type, san_value in san_tuples:
            san_list.append(f"{san_type}:{san_value}")

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=str(cert_dict.get("serialNumber", "")),
            not_before=cert_dict.get("notBefore", ""),
            not_after=cert_dict.get("notAfter", ""),
            signature_algorithm=cert_dict.get("signatureAlgorithm", ""),
            public_key_bits=0,  # Not directly available from getpeercert()
            san=san_list,
        )

    @staticmethod
    def _generate_recommendations(result: CipherSuiteResult) -> list[str]:
        """Generate security recommendations based on the analysis.

        Args:
            result: The cipher suite analysis result.

        Returns:
            List of recommendation strings.
        """
        recs: list[str] = []

        if not result.supports_tls_13:
            recs.append(
                "Enable TLS 1.3 for improved security and performance. "
                "TLS 1.3 eliminates many legacy vulnerabilities. (RFC 8446)"
            )

        if not result.supports_forward_secrecy:
            recs.append(
                "Enable ECDHE key exchange for perfect forward secrecy. "
                "This protects past sessions if the server key is compromised."
            )

        if result.has_weak_ciphers:
            recs.append(
                "Disable weak cipher suites (RC4, DES, 3DES, export, NULL). "
                "These are vulnerable to known attacks. (NIST SP 800-131A)"
            )

        protocol = (result.protocol or "").upper()
        if "TLSV1.0" in protocol or "TLSV1.1" in protocol:
            recs.append(
                "Disable TLS 1.0 and TLS 1.1. These protocol versions are "
                "deprecated by RFC 8996 (2021) and major browsers."
            )

        has_cbc = any("CBC" in s.encryption.upper() for s in result.suites)
        if has_cbc:
            recs.append(
                "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) over "
                "CBC mode. CBC is vulnerable to padding oracle attacks (BEAST, Lucky13)."
            )

        if not recs:
            recs.append(
                "TLS configuration appears well-configured. Continue monitoring "
                "for new vulnerability disclosures."
            )

        return recs
