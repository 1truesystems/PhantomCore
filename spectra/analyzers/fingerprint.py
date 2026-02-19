"""
Spectra Service Fingerprinter
==============================

Naive Bayes service classification for network hosts based on
observed traffic characteristics. Combines port-based priors with
packet-size distributions, protocol behaviour, and timing patterns
to identify running services.

The classifier uses a simplified Naive Bayes approach:

    P(Service | Evidence) = P(E1|S) * P(E2|S) * ... * P(En|S) * P(S)
                           / P(E)

where each evidence factor is conditionally independent given the service
class (the "naive" assumption). This simplification enables tractable
computation while providing reasonable accuracy for service identification.

References:
    - Mitchell, T. M. (1997). Machine Learning. McGraw-Hill. Chapter 6:
      Bayesian Learning, pp. 154-200.
    - Nmap Service Probes. https://nmap.org/book/vscan.html
    - IANA Service Name and Transport Protocol Port Number Registry.
      https://www.iana.org/assignments/service-names-port-numbers
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

import numpy as np

from shared.logger import PhantomLogger

from spectra.core.models import NetworkFlow, NetworkHost

logger = PhantomLogger("spectra.fingerprint")


# ---------------------------------------------------------------------------
#  Service Knowledge Base
# ---------------------------------------------------------------------------

class _ServiceSignature:
    """Definition of a known service's traffic signature."""

    def __init__(
        self,
        name: str,
        default_ports: set[int],
        protocol: str,
        avg_packet_size_range: tuple[float, float],
        typical_packet_count_range: tuple[int, int],
        description: str,
        keywords: list[str] | None = None,
    ) -> None:
        self.name = name
        self.default_ports = default_ports
        self.protocol = protocol
        self.avg_packet_size_range = avg_packet_size_range
        self.typical_packet_count_range = typical_packet_count_range
        self.description = description
        self.keywords = keywords or []


# Known service signature database
_KNOWN_SERVICES: list[_ServiceSignature] = [
    _ServiceSignature(
        name="HTTP",
        default_ports={80, 8080, 8000, 8888},
        protocol="TCP",
        avg_packet_size_range=(200.0, 1500.0),
        typical_packet_count_range=(3, 10000),
        description="Hypertext Transfer Protocol (web traffic)",
        keywords=["GET", "POST", "HTTP/", "Content-Type"],
    ),
    _ServiceSignature(
        name="HTTPS/TLS",
        default_ports={443, 8443},
        protocol="TCP",
        avg_packet_size_range=(100.0, 1500.0),
        typical_packet_count_range=(5, 10000),
        description="HTTP over TLS (encrypted web traffic)",
        keywords=[],
    ),
    _ServiceSignature(
        name="DNS",
        default_ports={53},
        protocol="UDP",
        avg_packet_size_range=(30.0, 512.0),
        typical_packet_count_range=(1, 100),
        description="Domain Name System (name resolution)",
        keywords=[],
    ),
    _ServiceSignature(
        name="SSH",
        default_ports={22, 2222},
        protocol="TCP",
        avg_packet_size_range=(50.0, 500.0),
        typical_packet_count_range=(10, 50000),
        description="Secure Shell (encrypted remote access)",
        keywords=["SSH-"],
    ),
    _ServiceSignature(
        name="SMTP",
        default_ports={25, 465, 587},
        protocol="TCP",
        avg_packet_size_range=(50.0, 5000.0),
        typical_packet_count_range=(5, 500),
        description="Simple Mail Transfer Protocol (email relay)",
        keywords=["EHLO", "MAIL FROM", "RCPT TO", "220 "],
    ),
    _ServiceSignature(
        name="FTP",
        default_ports={21, 20},
        protocol="TCP",
        avg_packet_size_range=(50.0, 1500.0),
        typical_packet_count_range=(5, 1000),
        description="File Transfer Protocol",
        keywords=["220 ", "USER ", "PASS ", "LIST", "RETR"],
    ),
    _ServiceSignature(
        name="MySQL",
        default_ports={3306},
        protocol="TCP",
        avg_packet_size_range=(50.0, 16000.0),
        typical_packet_count_range=(5, 50000),
        description="MySQL Database Server",
        keywords=["mysql_native_password"],
    ),
    _ServiceSignature(
        name="PostgreSQL",
        default_ports={5432},
        protocol="TCP",
        avg_packet_size_range=(50.0, 8000.0),
        typical_packet_count_range=(5, 50000),
        description="PostgreSQL Database Server",
        keywords=[],
    ),
    _ServiceSignature(
        name="Redis",
        default_ports={6379},
        protocol="TCP",
        avg_packet_size_range=(20.0, 500.0),
        typical_packet_count_range=(5, 100000),
        description="Redis In-Memory Data Store",
        keywords=["PING", "PONG", "+OK", "$"],
    ),
    _ServiceSignature(
        name="RDP",
        default_ports={3389},
        protocol="TCP",
        avg_packet_size_range=(100.0, 8000.0),
        typical_packet_count_range=(50, 100000),
        description="Remote Desktop Protocol (Windows remote access)",
        keywords=[],
    ),
    _ServiceSignature(
        name="VNC",
        default_ports={5900, 5901},
        protocol="TCP",
        avg_packet_size_range=(50.0, 8000.0),
        typical_packet_count_range=(50, 100000),
        description="Virtual Network Computing (remote desktop)",
        keywords=["RFB "],
    ),
    _ServiceSignature(
        name="IMAP",
        default_ports={143, 993},
        protocol="TCP",
        avg_packet_size_range=(50.0, 5000.0),
        typical_packet_count_range=(5, 500),
        description="Internet Message Access Protocol (email retrieval)",
        keywords=["* OK", "CAPABILITY"],
    ),
    _ServiceSignature(
        name="POP3",
        default_ports={110, 995},
        protocol="TCP",
        avg_packet_size_range=(50.0, 5000.0),
        typical_packet_count_range=(5, 200),
        description="Post Office Protocol v3 (email retrieval)",
        keywords=["+OK"],
    ),
    _ServiceSignature(
        name="LDAP",
        default_ports={389, 636},
        protocol="TCP",
        avg_packet_size_range=(50.0, 2000.0),
        typical_packet_count_range=(5, 5000),
        description="Lightweight Directory Access Protocol",
        keywords=[],
    ),
    _ServiceSignature(
        name="SMB",
        default_ports={445, 139},
        protocol="TCP",
        avg_packet_size_range=(100.0, 65000.0),
        typical_packet_count_range=(10, 100000),
        description="Server Message Block (Windows file sharing)",
        keywords=["\xffSMB"],
    ),
    _ServiceSignature(
        name="SNMP",
        default_ports={161, 162},
        protocol="UDP",
        avg_packet_size_range=(50.0, 1500.0),
        typical_packet_count_range=(1, 10000),
        description="Simple Network Management Protocol",
        keywords=[],
    ),
    _ServiceSignature(
        name="NTP",
        default_ports={123},
        protocol="UDP",
        avg_packet_size_range=(48.0, 100.0),
        typical_packet_count_range=(1, 100),
        description="Network Time Protocol",
        keywords=[],
    ),
    _ServiceSignature(
        name="WinRM",
        default_ports={5985, 5986},
        protocol="TCP",
        avg_packet_size_range=(100.0, 8000.0),
        typical_packet_count_range=(5, 10000),
        description="Windows Remote Management (WS-Management)",
        keywords=[],
    ),
]

# Build port-to-service lookup
_PORT_SERVICE_MAP: dict[int, list[str]] = defaultdict(list)
for _svc in _KNOWN_SERVICES:
    for _port in _svc.default_ports:
        _PORT_SERVICE_MAP[_port].append(_svc.name)


class ServiceFingerprinter:
    """Naive Bayes service fingerprinter for network hosts.

    Classifies services running on observed hosts by combining multiple
    evidence factors using Naive Bayes classification:

    1. Port-based prior: P(Service) based on observed port number.
    2. Packet size likelihood: P(AvgSize | Service) modelled as Gaussian.
    3. Protocol likelihood: P(Protocol | Service) based on TCP/UDP match.
    4. Payload keyword match: P(Keywords | Service) from known banners.

    Reference:
        Mitchell, T. M. (1997). Machine Learning. McGraw-Hill.
        Chapter 6: Bayesian Learning. pp. 154-200.

    Usage::

        fingerprinter = ServiceFingerprinter()
        services = fingerprinter.fingerprint(host, flows)
    """

    def __init__(self, confidence_threshold: float = 0.3) -> None:
        """Initialise the fingerprinter.

        Args:
            confidence_threshold: Minimum confidence score to include
                a service identification in results.
        """
        self.confidence_threshold: float = confidence_threshold
        self._signatures: list[_ServiceSignature] = _KNOWN_SERVICES

    def fingerprint(
        self,
        host: NetworkHost,
        flows: list[NetworkFlow],
    ) -> dict[int, dict[str, Any]]:
        """Fingerprint services on a given host from its observed flows.

        For each port observed on the host, applies Naive Bayes
        classification to determine the most likely service.

        Args:
            host: The network host to fingerprint.
            flows: All network flows (will be filtered to this host).

        Returns:
            Dictionary mapping port number to service identification
            result, containing:
            - ``service``: identified service name
            - ``confidence``: classification confidence [0.0, 1.0]
            - ``description``: service description
            - ``evidence``: list of evidence factors used
        """
        # Collect flows involving this host as destination (incoming)
        host_flows: dict[int, list[NetworkFlow]] = defaultdict(list)
        for flow in flows:
            if flow.dst_ip == host.ip and flow.dst_port > 0:
                host_flows[flow.dst_port].append(flow)
            elif flow.src_ip == host.ip and flow.src_port > 0:
                # Also consider outbound flows from known service ports
                if flow.src_port in _PORT_SERVICE_MAP:
                    host_flows[flow.src_port].append(flow)

        results: dict[int, dict[str, Any]] = {}

        for port in host.ports:
            port_flows = host_flows.get(port, [])

            # Classify using Naive Bayes
            classification = self._classify_port(port, port_flows)

            if classification["confidence"] >= self.confidence_threshold:
                results[port] = classification

        return results

    def fingerprint_all(
        self,
        hosts: dict[str, NetworkHost],
        flows: list[NetworkFlow],
    ) -> dict[str, dict[int, dict[str, Any]]]:
        """Fingerprint services on all hosts.

        Args:
            hosts: Dictionary of IP -> NetworkHost.
            flows: All network flows.

        Returns:
            Dictionary mapping IP -> port -> service identification.
        """
        all_results: dict[str, dict[int, dict[str, Any]]] = {}

        for ip, host in hosts.items():
            host_services = self.fingerprint(host, flows)
            if host_services:
                all_results[ip] = host_services
                # Update the host's services dict
                for port, svc_info in host_services.items():
                    host.services[port] = svc_info["service"]

        logger.info(
            f"Service fingerprinting: "
            f"{sum(len(v) for v in all_results.values())} "
            f"services identified across "
            f"{len(all_results)} hosts"
        )

        return all_results

    # ------------------------------------------------------------------ #
    #  Naive Bayes Classification
    # ------------------------------------------------------------------ #

    def _classify_port(
        self,
        port: int,
        port_flows: list[NetworkFlow],
    ) -> dict[str, Any]:
        """Classify the service on a port using Naive Bayes.

        Computes posterior probability for each known service given
        the observed evidence:

            P(S|E) proportional to P(S) * P(port|S) * P(size|S) * P(proto|S) * P(payload|S)

        The service with highest posterior probability is selected.

        Reference:
            Mitchell, T. M. (1997). Machine Learning. McGraw-Hill.
            Chapter 6. pp. 177-179 (Naive Bayes Classifier).

        Args:
            port: Port number to classify.
            port_flows: Flows observed on this port.

        Returns:
            Classification result dict with service, confidence, etc.
        """
        if not self._signatures:
            return self._unknown_result(port)

        n_services = len(self._signatures)

        # Compute log-posteriors for numerical stability
        # log P(S|E) = log P(S) + log P(port|S) + log P(size|S) + ...
        log_posteriors: list[float] = []

        for sig in self._signatures:
            log_post = 0.0
            evidence_factors: list[str] = []

            # 1. Port-based prior: P(port | Service)
            port_score = self._port_likelihood(port, sig)
            log_post += math.log(max(port_score, 1e-10))
            if port_score > 0.5:
                evidence_factors.append(f"Port {port} matches {sig.name} default ports")

            # 2. Uniform service prior: P(Service) = 1/N
            log_post += math.log(1.0 / n_services)

            if port_flows:
                # 3. Average packet size likelihood: P(avg_size | Service)
                avg_sizes = [f.avg_packet_size for f in port_flows if f.avg_packet_size > 0]
                if avg_sizes:
                    mean_size = sum(avg_sizes) / len(avg_sizes)
                    size_score = self._size_likelihood(mean_size, sig)
                    log_post += math.log(max(size_score, 1e-10))
                    if size_score > 0.5:
                        evidence_factors.append(
                            f"Avg packet size {mean_size:.0f}B matches {sig.name} profile"
                        )

                # 4. Protocol likelihood: P(protocol | Service)
                protocols = {f.protocol for f in port_flows}
                proto_score = self._protocol_likelihood(protocols, sig)
                log_post += math.log(max(proto_score, 1e-10))
                if proto_score > 0.5:
                    evidence_factors.append(
                        f"Protocol {'|'.join(protocols)} matches {sig.name}"
                    )

                # 5. Payload keyword match: P(keywords | Service)
                payload_score = self._payload_likelihood(port_flows, sig)
                log_post += math.log(max(payload_score, 1e-10))
                if payload_score > 0.5:
                    evidence_factors.append(
                        f"Payload keywords match {sig.name} signatures"
                    )

            log_posteriors.append(log_post)

        # Convert log-posteriors to probabilities via softmax
        max_log = max(log_posteriors)
        exp_posteriors = [math.exp(lp - max_log) for lp in log_posteriors]
        total = sum(exp_posteriors)

        if total > 0:
            posteriors = [e / total for e in exp_posteriors]
        else:
            posteriors = [1.0 / n_services] * n_services

        # Find best match
        best_idx = max(range(n_services), key=lambda i: posteriors[i])
        best_sig = self._signatures[best_idx]
        confidence = posteriors[best_idx]

        # Build evidence list for best match
        evidence: list[str] = []
        if port in best_sig.default_ports:
            evidence.append(f"Port {port} is a default port for {best_sig.name}")

        if port_flows:
            avg_sizes = [f.avg_packet_size for f in port_flows if f.avg_packet_size > 0]
            if avg_sizes:
                mean_size = sum(avg_sizes) / len(avg_sizes)
                lo, hi = best_sig.avg_packet_size_range
                if lo <= mean_size <= hi:
                    evidence.append(
                        f"Avg packet size ({mean_size:.0f}B) within "
                        f"{best_sig.name} range [{lo:.0f}, {hi:.0f}]B"
                    )

            protocols = {f.protocol for f in port_flows}
            if best_sig.protocol in protocols or any(
                p.startswith(best_sig.protocol) for p in protocols
            ):
                evidence.append(
                    f"Transport protocol matches ({best_sig.protocol})"
                )

        return {
            "service": best_sig.name,
            "confidence": round(confidence, 4),
            "description": best_sig.description,
            "evidence": evidence,
            "port": port,
            "all_scores": {
                self._signatures[i].name: round(posteriors[i], 4)
                for i in range(n_services)
                if posteriors[i] > 0.01
            },
        }

    # ------------------------------------------------------------------ #
    #  Likelihood Functions
    # ------------------------------------------------------------------ #

    def _port_likelihood(self, port: int, sig: _ServiceSignature) -> float:
        """Compute P(port | Service).

        Returns high probability if the port matches a known default port,
        moderate probability for nearby ports, and low base probability
        otherwise.
        """
        if port in sig.default_ports:
            return 0.9
        # Check if port is close to a known port (within 10)
        for known_port in sig.default_ports:
            if abs(port - known_port) <= 10:
                return 0.3
        return 0.05

    def _size_likelihood(
        self, avg_size: float, sig: _ServiceSignature
    ) -> float:
        """Compute P(avg_packet_size | Service) using Gaussian model.

        Models the average packet size as normally distributed with mean
        at the centre of the service's typical range and standard deviation
        covering the range.

        Reference:
            Mitchell, T. M. (1997). Machine Learning. McGraw-Hill.
            Chapter 6, Eq. 6.13 (Gaussian Naive Bayes).
        """
        lo, hi = sig.avg_packet_size_range
        mean = (lo + hi) / 2.0
        std = (hi - lo) / 4.0  # ~95% within range assuming Gaussian
        if std <= 0:
            std = 100.0

        # Gaussian PDF (unnormalised, since we only need relative values)
        z = (avg_size - mean) / std
        return math.exp(-0.5 * z * z)

    def _protocol_likelihood(
        self, observed_protocols: set[str], sig: _ServiceSignature
    ) -> float:
        """Compute P(protocol | Service).

        Returns high probability if the observed protocol matches the
        service's expected protocol.
        """
        expected = sig.protocol
        # Map high-level protocol names to transport
        transport_map: dict[str, str] = {
            "HTTP": "TCP",
            "HTTPS": "TCP",
            "DNS": "UDP",  # DNS can be both, but predominantly UDP
        }

        for proto in observed_protocols:
            if proto == expected:
                return 0.9
            # Check transport layer match
            mapped = transport_map.get(proto, proto)
            if mapped == expected:
                return 0.7

        return 0.1

    def _payload_likelihood(
        self, flows: list[NetworkFlow], sig: _ServiceSignature
    ) -> float:
        """Compute P(payload_keywords | Service).

        Checks if any known service keywords appear in the payload
        samples of observed flows. This is a strong signal when
        available.
        """
        if not sig.keywords:
            return 0.5  # No keywords to match -- neutral

        for flow in flows:
            if not flow.payload_sample:
                continue

            try:
                payload_str = flow.payload_sample.decode(
                    "utf-8", errors="ignore"
                ).lower()
            except Exception:
                continue

            for keyword in sig.keywords:
                if keyword.lower() in payload_str:
                    return 0.95  # Strong match

        return 0.1  # Keywords defined but not found

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _unknown_result(self, port: int) -> dict[str, Any]:
        """Return an unknown service classification."""
        return {
            "service": "Unknown",
            "confidence": 0.0,
            "description": f"Unidentified service on port {port}",
            "evidence": [],
            "port": port,
            "all_scores": {},
        }
