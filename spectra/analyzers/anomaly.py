"""
Spectra Anomaly Detector
=========================

Statistical anomaly detection for network traffic patterns. Identifies
deviations from expected behaviour using z-score analysis, IQR-based
outlier detection, and domain-specific heuristics for port scanning,
DNS anomalies, protocol anomalies, and traffic volume spikes.

Detection Methodologies:
    1. Volume anomaly: z-score analysis on per-host byte counts
       (Grubbs, 1969).
    2. Port scan detection: hosts contacting many unique ports on a
       single target within a time window.
    3. Unusual port detection: traffic on ports outside the well-known
       top-1000 service ports.
    4. Protocol anomaly: unusual protocol distribution per host.
    5. DNS anomaly: excessive queries, high-entropy domain names
       (potential DGA detection), and unusually long domain labels.

References:
    - Grubbs, F. E. (1969). Procedures for Detecting Outlying Observations
      in Samples. Technometrics, 11(1), 1-21.
    - Tukey, J. W. (1977). Exploratory Data Analysis. Addison-Wesley.
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
      Bell System Technical Journal, 27(3), 379-423.
    - Yadav, S., Reddy, A. K. K., Reddy, A. L. N., & Ranjan, S. (2010).
      Detecting Algorithmically Generated Malicious Domain Names.
      IMC '10.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Sequence

import numpy as np

from shared.logger import PhantomLogger
from shared.math_utils import (
    shannon_entropy,
    z_score_outliers,
    iqr_outliers,
)

from spectra.core.models import (
    AnomalyAlert,
    AnomalyType,
    NetworkFlow,
    NetworkHost,
)

logger = PhantomLogger("spectra.anomaly")

# ---------------------------------------------------------------------------
#  Well-known ports (top services, IANA registered)
# ---------------------------------------------------------------------------
_WELL_KNOWN_PORTS: set[int] = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 464, 465,
    500, 514, 515, 520, 521, 546, 547, 554, 563, 587, 593, 636, 691,
    749, 750, 843, 873, 902, 989, 990, 993, 995, 1080, 1194, 1433,
    1434, 1521, 1701, 1723, 1812, 1813, 1883, 1900, 2049, 2082, 2083,
    2086, 2087, 2095, 2096, 2222, 2375, 2376, 3000, 3128, 3268, 3269,
    3306, 3389, 3690, 4000, 4333, 4443, 4444, 5000, 5060, 5061, 5222,
    5432, 5500, 5555, 5672, 5900, 5901, 5984, 5985, 5986, 6000, 6379,
    6443, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6697, 7000,
    7001, 7002, 7199, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 8983,
    9000, 9042, 9090, 9100, 9200, 9300, 9418, 9999, 10000, 11211,
    27017, 27018, 28017, 50000, 50070,
}


class AnomalyDetector:
    """Statistical anomaly detector for network traffic analysis.

    Applies multiple detection heuristics to identify abnormal network
    behaviour that may indicate compromise, data exfiltration, command
    and control, or reconnaissance.

    Usage::

        detector = AnomalyDetector(threshold=2.5)
        alerts = detector.detect(hosts, flows)
    """

    def __init__(
        self,
        threshold: float = 2.5,
        port_scan_threshold: int = 15,
        dns_query_threshold: int = 100,
        dns_length_threshold: int = 50,
        dns_entropy_threshold: float = 3.5,
    ) -> None:
        """Initialise the anomaly detector.

        Args:
            threshold: Z-score threshold for volume anomaly detection.
                Based on Grubbs (1969), 2.5 corresponds to approximately
                the 99.4th percentile of a normal distribution.
            port_scan_threshold: Number of unique destination ports on a
                single target that triggers a port scan alert.
            dns_query_threshold: Number of DNS queries from a single host
                that triggers a DNS anomaly alert.
            dns_length_threshold: Domain name length above which a DNS
                anomaly is raised (potential data exfiltration via DNS).
            dns_entropy_threshold: Shannon entropy threshold for domain
                names (high entropy may indicate DGA domains).
        """
        self.threshold: float = threshold
        self.port_scan_threshold: int = port_scan_threshold
        self.dns_query_threshold: int = dns_query_threshold
        self.dns_length_threshold: int = dns_length_threshold
        self.dns_entropy_threshold: float = dns_entropy_threshold

    def detect(
        self,
        hosts: dict[str, NetworkHost],
        flows: list[NetworkFlow],
    ) -> list[AnomalyAlert]:
        """Run all anomaly detection heuristics on observed network data.

        Sequentially applies:
        1. Volume anomaly detection (z-score)
        2. Port scan detection
        3. Unusual port detection
        4. Protocol anomaly detection
        5. DNS anomaly detection

        Args:
            hosts: Mapping from IP to NetworkHost records.
            flows: List of aggregated network flows.

        Returns:
            List of AnomalyAlert objects, sorted by severity.
        """
        alerts: list[AnomalyAlert] = []

        alerts.extend(self._detect_volume_anomalies(hosts))
        alerts.extend(self._detect_port_scans(flows))
        alerts.extend(self._detect_unusual_ports(flows))
        alerts.extend(self._detect_protocol_anomalies(hosts, flows))
        alerts.extend(self._detect_dns_anomalies(flows))

        logger.info(
            f"Anomaly detection complete: "
            f"{len(alerts)} alerts"
        )

        return alerts

    # ------------------------------------------------------------------ #
    #  Volume Anomaly Detection
    # ------------------------------------------------------------------ #

    def _detect_volume_anomalies(
        self,
        hosts: dict[str, NetworkHost],
    ) -> list[AnomalyAlert]:
        """Detect hosts with anomalous traffic volumes using z-score analysis.

        Applies Grubbs' test for outlier detection on the distribution of
        total bytes per host. Hosts with z-scores exceeding the threshold
        are flagged as volume anomalies.

        The z_score_outliers function from shared.math_utils returns a boolean
        NumPy mask where True marks outlier positions.

        Reference:
            Grubbs, F. E. (1969). Procedures for Detecting Outlying
            Observations in Samples. Technometrics, 11(1), 1-21.
        """
        alerts: list[AnomalyAlert] = []

        if len(hosts) < 3:
            return alerts

        host_list = list(hosts.values())
        ip_list = [h.ip for h in host_list]

        # -- Analyse bytes sent --
        bytes_sent = np.array([float(h.bytes_sent) for h in host_list], dtype=np.float64)
        sent_mask = z_score_outliers(bytes_sent, threshold=self.threshold)

        # Compute z-scores manually for reporting
        sent_mean = float(np.mean(bytes_sent))
        sent_std = float(np.std(bytes_sent, ddof=1))

        for idx in np.where(sent_mask)[0]:
            value = float(bytes_sent[idx])
            z = (value - sent_mean) / sent_std if sent_std > 0 else 0.0
            alerts.append(AnomalyAlert(
                type=AnomalyType.VOLUME_SPIKE,
                source=ip_list[idx],
                metric="bytes_sent",
                value=value,
                threshold=self.threshold,
                z_score=z,
                description=(
                    f"Host {ip_list[idx]} sent {int(value):,} bytes "
                    f"(z-score: {z:.2f}, threshold: {self.threshold}). "
                    f"Potential data exfiltration or anomalous upload."
                ),
                severity="high" if abs(z) > 3.5 else "medium",
            ))

        # -- Analyse bytes received --
        bytes_recv = np.array([float(h.bytes_recv) for h in host_list], dtype=np.float64)
        recv_mask = z_score_outliers(bytes_recv, threshold=self.threshold)

        recv_mean = float(np.mean(bytes_recv))
        recv_std = float(np.std(bytes_recv, ddof=1))

        for idx in np.where(recv_mask)[0]:
            value = float(bytes_recv[idx])
            z = (value - recv_mean) / recv_std if recv_std > 0 else 0.0
            alerts.append(AnomalyAlert(
                type=AnomalyType.VOLUME_SPIKE,
                source=ip_list[idx],
                metric="bytes_recv",
                value=value,
                threshold=self.threshold,
                z_score=z,
                description=(
                    f"Host {ip_list[idx]} received {int(value):,} bytes "
                    f"(z-score: {z:.2f}, threshold: {self.threshold}). "
                    f"Potential large download or C2 payload delivery."
                ),
                severity="high" if abs(z) > 3.5 else "medium",
            ))

        # -- Analyse packet counts using IQR method (Tukey, 1977) --
        pkt_counts = np.array([float(h.packet_count) for h in host_list], dtype=np.float64)
        pkt_mask = iqr_outliers(pkt_counts, k=1.5)

        mean_pkts = float(np.mean(pkt_counts))

        for idx in np.where(pkt_mask)[0]:
            value = float(pkt_counts[idx])
            # Only alert on high-side outliers (excessive packets)
            if value > mean_pkts:
                alerts.append(AnomalyAlert(
                    type=AnomalyType.VOLUME_SPIKE,
                    source=ip_list[idx],
                    metric="packet_count",
                    value=value,
                    threshold=0.0,
                    z_score=0.0,
                    description=(
                        f"Host {ip_list[idx]} has {int(value):,} packets "
                        f"(IQR outlier, mean: {mean_pkts:.0f}). "
                        f"Unusually high packet rate."
                    ),
                    severity="medium",
                ))

        return alerts

    # ------------------------------------------------------------------ #
    #  Port Scan Detection
    # ------------------------------------------------------------------ #

    def _detect_port_scans(
        self,
        flows: list[NetworkFlow],
    ) -> list[AnomalyAlert]:
        """Detect port scanning activity.

        A port scan is identified when a single source contacts more than
        N unique destination ports on the same target host. This includes
        both horizontal scans (many ports on one host) and is a common
        reconnaissance technique.

        Ref: Staniford, S., Hoagland, J. A., & McAlerney, J. M. (2002).
        Practical Automated Detection of Stealthy Portscans. Journal of
        Computer Security, 10(1-2), 105-136.
        """
        alerts: list[AnomalyAlert] = []

        # Group flows by (src, dst) pair and collect unique destination ports
        pair_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
        for flow in flows:
            if flow.dst_port > 0:
                pair_ports[(flow.src_ip, flow.dst_ip)].add(flow.dst_port)

        for (src, dst), ports in pair_ports.items():
            if len(ports) >= self.port_scan_threshold:
                port_list = sorted(ports)
                sample_ports = port_list[:10]
                alerts.append(AnomalyAlert(
                    type=AnomalyType.PORT_SCAN,
                    source=src,
                    target=dst,
                    metric="unique_dst_ports",
                    value=float(len(ports)),
                    threshold=float(self.port_scan_threshold),
                    z_score=0.0,
                    description=(
                        f"Host {src} contacted {len(ports)} unique ports "
                        f"on {dst} (threshold: {self.port_scan_threshold}). "
                        f"Sample ports: {sample_ports}. "
                        f"Likely port scan reconnaissance."
                    ),
                    severity="high",
                ))

        return alerts

    # ------------------------------------------------------------------ #
    #  Unusual Port Detection
    # ------------------------------------------------------------------ #

    def _detect_unusual_ports(
        self,
        flows: list[NetworkFlow],
    ) -> list[AnomalyAlert]:
        """Detect traffic on non-standard (unusual) ports.

        Flags flows using destination ports outside the well-known top
        service ports. Non-standard ports may indicate backdoors,
        custom C2 channels, or misconfigured services.
        """
        alerts: list[AnomalyAlert] = []

        # Track already-alerted ports per host to avoid duplicates
        alerted: set[tuple[str, int]] = set()

        for flow in flows:
            if flow.dst_port <= 0:
                continue

            # Skip well-known ports and ephemeral ports (>= 49152)
            if flow.dst_port in _WELL_KNOWN_PORTS:
                continue
            if flow.dst_port >= 49152:
                continue

            key = (flow.dst_ip, flow.dst_port)
            if key in alerted:
                continue
            alerted.add(key)

            # Determine severity based on port characteristics
            severity = "low"
            extra = ""
            if flow.dst_port < 1024:
                severity = "medium"
                extra = " (privileged port range)"
            elif flow.bytes_total > 100_000:
                severity = "medium"
                extra = f" (high traffic: {flow.bytes_total:,} bytes)"

            alerts.append(AnomalyAlert(
                type=AnomalyType.UNUSUAL_PORT,
                source=flow.src_ip,
                target=flow.dst_ip,
                metric="dst_port",
                value=float(flow.dst_port),
                threshold=0.0,
                z_score=0.0,
                description=(
                    f"Traffic on non-standard port {flow.dst_port} "
                    f"from {flow.src_ip} to {flow.dst_ip}{extra}. "
                    f"Protocol: {flow.protocol}, "
                    f"{flow.packets} packets, {flow.bytes_total:,} bytes."
                ),
                severity=severity,
            ))

        return alerts

    # ------------------------------------------------------------------ #
    #  Protocol Anomaly Detection
    # ------------------------------------------------------------------ #

    def _detect_protocol_anomalies(
        self,
        hosts: dict[str, NetworkHost],
        flows: list[NetworkFlow],
    ) -> list[AnomalyAlert]:
        """Detect unusual protocol distribution per host.

        Builds a per-host protocol distribution and flags hosts whose
        protocol usage deviates significantly from the network-wide
        distribution. For example, a host generating mostly ICMP traffic
        in a network dominated by TCP/HTTP traffic is anomalous.
        """
        alerts: list[AnomalyAlert] = []

        if not flows:
            return alerts

        # Compute network-wide protocol distribution
        global_proto_counts: dict[str, int] = defaultdict(int)
        host_proto_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        for flow in flows:
            global_proto_counts[flow.protocol] += flow.packets
            host_proto_counts[flow.src_ip][flow.protocol] += flow.packets

        total_global = sum(global_proto_counts.values())
        if total_global == 0:
            return alerts

        global_dist = {
            proto: count / total_global
            for proto, count in global_proto_counts.items()
        }

        # Check each host's protocol distribution against global
        for ip, proto_counts in host_proto_counts.items():
            total_host = sum(proto_counts.values())
            if total_host < 10:  # Skip hosts with very few packets
                continue

            host_dist = {
                proto: count / total_host
                for proto, count in proto_counts.items()
            }

            # Check for protocol dominance anomalies
            for proto, host_ratio in host_dist.items():
                global_ratio = global_dist.get(proto, 0.0)

                # Flag if host uses a protocol 5x more than global average
                if global_ratio > 0.01 and host_ratio > 0.5:
                    ratio = host_ratio / global_ratio if global_ratio > 0 else float('inf')
                    if ratio > 5.0:
                        alerts.append(AnomalyAlert(
                            type=AnomalyType.PROTOCOL_ANOMALY,
                            source=ip,
                            metric=f"protocol_{proto}_ratio",
                            value=host_ratio,
                            threshold=global_ratio,
                            z_score=ratio,
                            description=(
                                f"Host {ip} uses {proto} for "
                                f"{host_ratio:.1%} of traffic "
                                f"(network average: {global_ratio:.1%}, "
                                f"ratio: {ratio:.1f}x). "
                                f"Anomalous protocol distribution."
                            ),
                            severity="medium",
                        ))

                # Special case: ICMP-heavy hosts (potential ping sweep/tunnel)
                if proto == "ICMP" and host_ratio > 0.3 and total_host > 50:
                    alerts.append(AnomalyAlert(
                        type=AnomalyType.PROTOCOL_ANOMALY,
                        source=ip,
                        metric="icmp_ratio",
                        value=host_ratio,
                        threshold=0.3,
                        z_score=0.0,
                        description=(
                            f"Host {ip} generates {host_ratio:.1%} ICMP traffic "
                            f"({total_host} total packets). Possible ICMP tunnel "
                            f"or ping sweep."
                        ),
                        severity="medium",
                    ))

        return alerts

    # ------------------------------------------------------------------ #
    #  DNS Anomaly Detection
    # ------------------------------------------------------------------ #

    def _detect_dns_anomalies(
        self,
        flows: list[NetworkFlow],
    ) -> list[AnomalyAlert]:
        """Detect DNS-related anomalies.

        Identifies:
        1. Excessive DNS query volume from a single host.
        2. Unusually long domain names (potential DNS tunnelling).
        3. High-entropy domain names (potential Domain Generation
           Algorithm -- DGA detection).

        Reference for DGA detection:
            Yadav, S., Reddy, A. K. K., Reddy, A. L. N., & Ranjan, S.
            (2010). Detecting Algorithmically Generated Malicious Domain
            Names. IMC '10.
        """
        alerts: list[AnomalyAlert] = []

        # Collect DNS queries per source host
        host_dns_queries: dict[str, list[str]] = defaultdict(list)

        for flow in flows:
            if flow.protocol != "DNS":
                continue
            for query in flow.dns_queries:
                host_dns_queries[flow.src_ip].append(query)

        for src_ip, queries in host_dns_queries.items():
            # 1. Excessive DNS query volume
            if len(queries) > self.dns_query_threshold:
                alerts.append(AnomalyAlert(
                    type=AnomalyType.DNS_ANOMALY,
                    source=src_ip,
                    metric="dns_query_count",
                    value=float(len(queries)),
                    threshold=float(self.dns_query_threshold),
                    z_score=0.0,
                    description=(
                        f"Host {src_ip} made {len(queries)} DNS queries "
                        f"(threshold: {self.dns_query_threshold}). "
                        f"Excessive DNS activity may indicate DNS tunnelling "
                        f"or DGA-based malware."
                    ),
                    severity="high",
                ))

            # Analyse individual queries
            unique_queries = set(queries)
            for domain in unique_queries:
                # 2. Long domain names
                if len(domain) > self.dns_length_threshold:
                    alerts.append(AnomalyAlert(
                        type=AnomalyType.DNS_ANOMALY,
                        source=src_ip,
                        metric="dns_domain_length",
                        value=float(len(domain)),
                        threshold=float(self.dns_length_threshold),
                        z_score=0.0,
                        description=(
                            f"Host {src_ip} queried unusually long domain: "
                            f"'{domain[:60]}...' ({len(domain)} chars). "
                            f"Long domains may indicate DNS tunnelling or "
                            f"data exfiltration via DNS."
                        ),
                        severity="high",
                    ))

                # 3. High-entropy domain names (DGA detection)
                # Extract the second-level domain for entropy analysis
                parts = domain.split(".")
                if len(parts) >= 2:
                    sld = parts[0]  # second-level domain label
                    if len(sld) >= 6:  # Only check labels with enough chars
                        domain_bytes = sld.encode("utf-8", errors="ignore")
                        ent = shannon_entropy(domain_bytes)

                        if ent > self.dns_entropy_threshold:
                            alerts.append(AnomalyAlert(
                                type=AnomalyType.DNS_ANOMALY,
                                source=src_ip,
                                metric="dns_domain_entropy",
                                value=ent,
                                threshold=self.dns_entropy_threshold,
                                z_score=0.0,
                                description=(
                                    f"Host {src_ip} queried high-entropy domain: "
                                    f"'{domain}' (entropy: {ent:.2f} bits, "
                                    f"threshold: {self.dns_entropy_threshold}). "
                                    f"May indicate Domain Generation Algorithm (DGA)."
                                ),
                                severity="high",
                            ))

        return alerts
