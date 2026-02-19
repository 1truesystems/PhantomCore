"""
Spectra Engine -- Network Intelligence Engine Core
====================================================

Four-phase asynchronous analysis engine for network traffic intelligence.
Orchestrates the complete pipeline from packet capture through graph
construction, multi-strategy analysis, and finding correlation.

Pipeline Phases:
    Phase 1 -- Collection:
        Read PCAP file or perform live network capture via Scapy.
    Phase 2 -- Graph Construction:
        Build weighted communication graph from aggregated flows.
    Phase 3 -- Analysis:
        Run all analyzers in parallel: anomaly detection, graph analysis,
        Markov chain modelling, service fingerprinting, lateral movement
        detection, and beacon detection.
    Phase 4 -- Correlation:
        Combine findings, score risks, and produce final ScanResult.

References:
    - Jacobson, V. et al. (1989). libpcap: Packet Capture Library.
    - Page, L. et al. (1999). The PageRank Citation Ranking. Stanford.
    - Freeman, L. C. (1977). Centrality in Social Networks. Sociometry.
    - Blondel, V. D. et al. (2008). Fast Unfolding of Communities.
      Journal of Statistical Mechanics.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from shared.config import PhantomConfig
from shared.logger import PhantomLogger
from shared.models import Finding, Risk, ScanResult, Severity

from spectra.analyzers.anomaly import AnomalyDetector
from spectra.analyzers.beacon import BeaconDetector
from spectra.analyzers.fingerprint import ServiceFingerprinter
from spectra.analyzers.graph import GraphAnalyzer
from spectra.analyzers.lateral import LateralMovementDetector
from spectra.analyzers.markov import MarkovAnalyzer
from spectra.collectors.packet_collector import PacketCollector
from spectra.core.models import (
    AnomalyAlert,
    AnomalyType,
    BeaconResult,
    CommunicationGraph,
    LateralMovement,
    NetworkFlow,
    NetworkHost,
)

logger = PhantomLogger("spectra.engine")


class SpectraEngine:
    """Four-phase asynchronous network intelligence analysis engine.

    Orchestrates the entire Spectra analysis pipeline from raw packet
    data to structured security findings.

    Usage::

        engine = SpectraEngine(config=PhantomConfig())
        result = await engine.analyze_pcap("/path/to/capture.pcap")

        # Or for live capture:
        result = await engine.analyze_live("eth0", duration=60)
    """

    def __init__(
        self,
        config: Optional[PhantomConfig] = None,
        anomaly_threshold: float = 2.5,
        top_n: int = 10,
        verbose: bool = False,
    ) -> None:
        """Initialise the Spectra engine.

        Args:
            config: PhantomConfig instance. If None, defaults are used.
            anomaly_threshold: Z-score threshold for anomaly detection.
            top_n: Number of top nodes to report in graph analysis.
            verbose: Enable verbose logging.
        """
        self.config = config or PhantomConfig()
        self.anomaly_threshold = anomaly_threshold
        self.top_n = top_n
        self.verbose = verbose

        # Initialise sub-components
        spectra_cfg = self.config.spectra

        self.collector = PacketCollector(
            max_packets=spectra_cfg.max_packets,
            snap_length=spectra_cfg.snap_length,
            bpf_filter=spectra_cfg.bpf_filter,
        )

        self.anomaly_detector = AnomalyDetector(
            threshold=anomaly_threshold,
        )

        self.graph_analyzer = GraphAnalyzer(top_n=top_n)

        self.markov_analyzer = MarkovAnalyzer()

        self.fingerprinter = ServiceFingerprinter()

        self.lateral_detector = LateralMovementDetector()

        self.beacon_detector = BeaconDetector()

    # ================================================================== #
    #  Public API
    # ================================================================== #

    async def analyze_pcap(self, file_path: str) -> ScanResult:
        """Analyse a PCAP file through the complete 4-phase pipeline.

        Args:
            file_path: Path to the PCAP/PCAPNG file.

        Returns:
            ScanResult containing all findings and raw analysis data.

        Raises:
            FileNotFoundError: If the PCAP file does not exist.
            ValueError: If the file cannot be parsed.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)

        logger.info(f"Starting PCAP analysis: {file_path}")

        # ---- Phase 1: Collection ----
        logger.info("Phase 1: Collection")
        hosts, flows = await asyncio.get_event_loop().run_in_executor(
            None, self.collector.read_pcap, file_path
        )

        # ---- Phases 2-4 ----
        result = await self._run_analysis_pipeline(
            hosts, flows, target=file_path, started_at=started_at
        )

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)

        logger.info(
            f"Analysis complete in {elapsed:.2f}s: "
            f"{result.finding_count} findings"
        )

        return result

    async def analyze_live(
        self,
        interface: str,
        duration: int,
    ) -> ScanResult:
        """Perform live capture and analysis.

        Requires root/administrator privileges for raw packet capture.

        Args:
            interface: Network interface name (e.g., "eth0").
            duration: Capture duration in seconds.

        Returns:
            ScanResult containing all findings and raw analysis data.

        Raises:
            PermissionError: If insufficient privileges.
            OSError: If the interface does not exist.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Live analysis: {interface}, "
            f"{duration}s duration"
        )

        # ---- Phase 1: Live Collection ----
        logger.info("Phase 1: Live Capture")
        hosts, flows = await self.collector.live_capture(
            interface=interface,
            duration=duration,
        )

        # ---- Phases 2-4 ----
        target = f"live:{interface}:{duration}s"
        result = await self._run_analysis_pipeline(
            hosts, flows, target=target, started_at=started_at
        )

        elapsed = time.monotonic() - start_time
        result.end_time = datetime.now(timezone.utc)

        logger.info(
            f"Live analysis complete in {elapsed:.2f}s"
        )

        return result

    # ================================================================== #
    #  Internal Pipeline
    # ================================================================== #

    async def _run_analysis_pipeline(
        self,
        hosts: dict[str, NetworkHost],
        flows: list[NetworkFlow],
        target: str,
        started_at: datetime,
    ) -> ScanResult:
        """Execute analysis phases 2-4.

        Args:
            hosts: Collected host records.
            flows: Collected flow records.
            target: Target identifier string.
            started_at: Pipeline start time.

        Returns:
            Populated ScanResult.
        """
        result = ScanResult(
            tool_name="spectra",
            target=target,
            start_time=started_at,
        )

        if not hosts and not flows:
            result.summary = (
                "No data found in capture"
            )
            return result

        # ---- Phase 2: Graph Construction ----
        logger.info("Phase 2: Graph Construction")
        graph = self.graph_analyzer.build_graph(hosts, flows)

        comm_graph = CommunicationGraph(
            hosts=hosts,
            flows=flows,
            edges=[
                (u, v, d.get("weight", 0.0))
                for u, v, d in graph.edges(data=True)
            ],
        )

        # ---- Phase 3: Analysis ----
        logger.info("Phase 3: Analysis")

        # Run analyzers concurrently via asyncio
        loop = asyncio.get_event_loop()

        anomaly_task = loop.run_in_executor(
            None, self.anomaly_detector.detect, hosts, flows
        )
        graph_task = loop.run_in_executor(
            None, self.graph_analyzer.analyze, graph
        )
        markov_task = loop.run_in_executor(
            None, self.markov_analyzer.analyze, flows
        )
        fingerprint_task = loop.run_in_executor(
            None, self.fingerprinter.fingerprint_all, hosts, flows
        )
        lateral_task = loop.run_in_executor(
            None, self.lateral_detector.detect, graph, flows, hosts
        )
        beacon_task = loop.run_in_executor(
            None, self.beacon_detector.detect, flows
        )

        # Await all results
        (
            anomaly_alerts,
            graph_analysis,
            markov_analysis,
            service_fingerprints,
            lateral_movements,
            beacon_results,
        ) = await asyncio.gather(
            anomaly_task,
            graph_task,
            markov_task,
            fingerprint_task,
            lateral_task,
            beacon_task,
        )

        # ---- Phase 4: Correlation ----
        logger.info("Phase 4: Correlation")

        # Convert anomaly alerts to findings
        for alert in anomaly_alerts:
            finding = self._alert_to_finding(alert)
            result.add_finding(finding)

        # Convert beacon results to findings
        for beacon in beacon_results:
            if beacon.is_beacon:
                finding = self._beacon_to_finding(beacon)
                result.add_finding(finding)

        # Convert lateral movements to findings
        for movement in lateral_movements:
            finding = self._lateral_to_finding(movement)
            result.add_finding(finding)

        # Add graph-based findings (key nodes, isolated communities)
        graph_findings = self._graph_to_findings(graph_analysis)
        for finding in graph_findings:
            result.add_finding(finding)

        # Add Markov-based findings (anomalous transitions)
        markov_findings = self._markov_to_findings(markov_analysis)
        for finding in markov_findings:
            result.add_finding(finding)

        # Store raw analysis data
        result.metadata = {
            "hosts": {
                ip: {
                    "ip": h.ip,
                    "mac": h.mac,
                    "hostname": h.hostname,
                    "ports": sorted(h.ports),
                    "services": h.services,
                    "bytes_sent": h.bytes_sent,
                    "bytes_recv": h.bytes_recv,
                    "packet_count": h.packet_count,
                }
                for ip, h in hosts.items()
            },
            "flow_count": len(flows),
            "graph_analysis": {
                k: v for k, v in graph_analysis.items()
                if k not in ("betweenness", "eigenvector", "pagerank",
                             "in_degree", "out_degree")
            },
            "graph_key_nodes": graph_analysis.get("key_nodes", {}),
            "markov_analysis": {
                "unique_states": markov_analysis.get("unique_states", 0),
                "total_transitions": markov_analysis.get("total_transitions", 0),
                "kl_from_uniform": markov_analysis.get("kl_from_uniform", 0.0),
                "anomalous_transitions": markov_analysis.get(
                    "anomalous_transitions", []
                ),
                "predictions": markov_analysis.get("predictions", {}),
            },
            "service_fingerprints": {
                ip: {
                    str(port): info
                    for port, info in port_map.items()
                }
                for ip, port_map in service_fingerprints.items()
            },
            "anomaly_alerts": [
                {
                    "type": a.type.value,
                    "source": a.source,
                    "target": a.target,
                    "metric": a.metric,
                    "value": a.value,
                    "z_score": a.z_score,
                    "description": a.description,
                    "severity": a.severity,
                }
                for a in anomaly_alerts
            ],
            "beacon_results": [
                {
                    "src": b.src,
                    "dst": b.dst,
                    "interval_mean": b.interval_mean,
                    "interval_std": b.interval_std,
                    "entropy": b.entropy,
                    "confidence": b.confidence,
                    "is_beacon": b.is_beacon,
                    "flow_count": b.flow_count,
                    "cv": b.coefficient_of_variation,
                }
                for b in beacon_results
            ],
            "lateral_movements": [
                {
                    "path": m.path,
                    "technique": m.technique,
                    "confidence": m.confidence,
                    "evidence": m.evidence,
                    "timespan_seconds": m.timespan_seconds,
                    "ports_used": m.ports_used,
                }
                for m in lateral_movements
            ],
            "communication_graph": {
                "node_count": comm_graph.hosts.__len__(),
                "edge_count": len(comm_graph.edges),
            },
        }

        # Build summary
        result.summary = self._build_summary(
            result, hosts, flows, anomaly_alerts,
            beacon_results, lateral_movements
        )

        result.metadata = {
            "host_count": len(hosts),
            "flow_count": len(flows),
            "anomaly_count": len(anomaly_alerts),
            "beacon_count": sum(1 for b in beacon_results if b.is_beacon),
            "lateral_count": len(lateral_movements),
            "community_count": len(graph_analysis.get("communities", [])),
        }

        return result

    # ================================================================== #
    #  Finding Converters
    # ================================================================== #

    def _alert_to_finding(self, alert: AnomalyAlert) -> Finding:
        """Convert an AnomalyAlert to a shared Finding model."""
        severity_map: dict[str, Severity] = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        risk_map: dict[str, Risk] = {
            "critical": Risk.CRITICAL,
            "high": Risk.HIGH,
            "medium": Risk.MEDIUM,
            "low": Risk.LOW,
            "info": Risk.NEGLIGIBLE,
        }

        severity = severity_map.get(alert.severity, Severity.MEDIUM)
        risk = risk_map.get(alert.severity, Risk.MEDIUM)

        return Finding(
            title=f"Network Anomaly: {alert.type.value.replace('_', ' ').title()}",
            description=alert.description,
            severity=severity,
            risk=risk,
            confidence=min(1.0, max(0.0, abs(alert.z_score) / 5.0)) if alert.z_score else 0.7,
            evidence={
                "type": alert.type.value,
                "source": alert.source,
                "target": alert.target,
                "metric": alert.metric,
                "value": alert.value,
                "threshold": alert.threshold,
                "z_score": alert.z_score,
            },
            recommendation=self._anomaly_recommendation(alert),
            references=[
                "Grubbs, F. E. (1969). Procedures for Detecting Outlying "
                "Observations in Samples. Technometrics, 11(1), 1-21.",
            ],
        )

    def _beacon_to_finding(self, beacon: BeaconResult) -> Finding:
        """Convert a BeaconResult to a shared Finding model."""
        severity = Severity.HIGH if beacon.confidence > 0.7 else Severity.MEDIUM

        return Finding(
            title=f"C2 Beacon Detected: {beacon.src} -> {beacon.dst}",
            description=(
                f"Periodic beacon communication detected from {beacon.src} "
                f"to {beacon.dst}. Mean interval: {beacon.interval_mean:.1f}s, "
                f"CV: {beacon.coefficient_of_variation:.4f}, "
                f"entropy: {beacon.entropy:.2f} bits, "
                f"confidence: {beacon.confidence:.2f}."
            ),
            severity=severity,
            risk=Risk.HIGH if beacon.confidence > 0.7 else Risk.MEDIUM,
            confidence=beacon.confidence,
            evidence={
                "src": beacon.src,
                "dst": beacon.dst,
                "interval_mean": beacon.interval_mean,
                "interval_std": beacon.interval_std,
                "entropy": beacon.entropy,
                "cv": beacon.coefficient_of_variation,
                "acf_peak": beacon.autocorrelation_peak,
                "flow_count": beacon.flow_count,
            },
            recommendation=(
                f"Investigate the communication between {beacon.src} and "
                f"{beacon.dst}. The regular interval of ~{beacon.interval_mean:.0f}s "
                f"is characteristic of C2 beacon behaviour. Check if "
                f"{beacon.dst} is a known legitimate service. Consider "
                f"blocking the connection and scanning both hosts for malware."
            ),
            references=[
                "Bilge, L. et al. (2012). Disclosure: Detecting Botnet C&C "
                "Servers Through Large-Scale NetFlow Analysis. ACSAC.",
                "Shannon, C. E. (1948). A Mathematical Theory of Communication. "
                "Bell System Technical Journal, 27(3), 379-423.",
            ],
        )

    def _lateral_to_finding(self, movement: LateralMovement) -> Finding:
        """Convert a LateralMovement to a shared Finding model."""
        severity = Severity.CRITICAL if movement.confidence > 0.7 else Severity.HIGH

        path_str = " -> ".join(movement.path)

        return Finding(
            title=f"Lateral Movement: {movement.technique}",
            description=(
                f"Lateral movement detected via {movement.technique}. "
                f"Path: {path_str} ({movement.hop_count} hops). "
                f"Confidence: {movement.confidence:.2f}. "
                f"Timespan: {movement.timespan_seconds:.1f}s."
            ),
            severity=severity,
            risk=Risk.CRITICAL if movement.confidence > 0.7 else Risk.HIGH,
            confidence=movement.confidence,
            evidence={
                "path": movement.path,
                "technique": movement.technique,
                "evidence_details": movement.evidence,
                "ports_used": movement.ports_used,
                "timespan_seconds": movement.timespan_seconds,
                "hop_count": movement.hop_count,
            },
            recommendation=(
                f"Investigate all hosts in the movement path: {path_str}. "
                f"Isolate suspected compromised hosts immediately. "
                f"Check for unauthorized credentials and reset passwords "
                f"on affected systems. Review {movement.technique} "
                f"access logs on all hosts in the path."
            ),
            references=[
                "MITRE ATT&CK: Lateral Movement (TA0008). "
                "https://attack.mitre.org/tactics/TA0008/",
            ],
        )

    def _graph_to_findings(
        self, graph_analysis: dict[str, Any]
    ) -> list[Finding]:
        """Generate findings from graph analysis results."""
        findings: list[Finding] = []

        # Find high-betweenness nodes (potential chokepoints/pivots)
        key_nodes = graph_analysis.get("key_nodes", {})
        betweenness_top = key_nodes.get("betweenness", [])

        for node, score in betweenness_top[:3]:
            if score > 0.3:  # Significant betweenness
                findings.append(Finding(
                    title=f"High Betweenness Node: {node}",
                    description=(
                        f"Host {node} has high betweenness centrality "
                        f"({score:.4f}), indicating it serves as a critical "
                        f"bridge between network segments. Compromise of this "
                        f"node could enable lateral movement across segments."
                    ),
                    severity=Severity.MEDIUM,
                    risk=Risk.MEDIUM,
                    confidence=min(score * 2, 1.0),
                    evidence={"node": node, "betweenness_centrality": score},
                    recommendation=(
                        f"Ensure {node} is properly secured as a critical "
                        f"infrastructure node. Consider network segmentation "
                        f"to reduce its bridging role."
                    ),
                    references=[
                        "Freeman, L. C. (1977). A Set of Measures of "
                        "Centrality Based on Betweenness. Sociometry, 40(1).",
                    ],
                ))

        return findings

    def _markov_to_findings(
        self, markov_analysis: dict[str, Any]
    ) -> list[Finding]:
        """Generate findings from Markov chain analysis."""
        findings: list[Finding] = []

        anomalous = markov_analysis.get("anomalous_transitions", [])

        for transition in anomalous[:5]:  # Top 5 anomalous transitions
            findings.append(Finding(
                title=(
                    f"Anomalous Communication: "
                    f"{transition['src']} -> {transition['dst']}"
                ),
                description=transition.get("description", ""),
                severity=Severity.LOW,
                risk=Risk.LOW,
                confidence=max(0.0, 1.0 - transition.get("probability", 0.0) * 100),
                evidence=transition,
                recommendation=(
                    f"Investigate the communication between "
                    f"{transition['src']} and {transition['dst']}. "
                    f"This transition has very low probability in the "
                    f"observed Markov chain, suggesting it is unusual."
                ),
                references=[
                    "Norris, J. R. (1997). Markov Chains. "
                    "Cambridge University Press.",
                ],
            ))

        return findings

    # ================================================================== #
    #  Helpers
    # ================================================================== #

    def _anomaly_recommendation(self, alert: AnomalyAlert) -> str:
        """Generate recommendation text for an anomaly alert."""
        recs: dict[AnomalyType, str] = {
            AnomalyType.VOLUME_SPIKE: (
                f"Investigate traffic volume from/to {alert.source}. "
                f"Check for data exfiltration, large file transfers, "
                f"or compromised hosts generating excessive traffic."
            ),
            AnomalyType.PORT_SCAN: (
                f"Host {alert.source} appears to be port scanning "
                f"{alert.target}. This is a reconnaissance technique. "
                f"Block scanning activity and investigate the source host."
            ),
            AnomalyType.UNUSUAL_PORT: (
                f"Traffic on non-standard port {int(alert.value)} between "
                f"{alert.source} and {alert.target}. Verify this is a "
                f"legitimate service. Non-standard ports may indicate "
                f"backdoors or C2 channels."
            ),
            AnomalyType.PROTOCOL_ANOMALY: (
                f"Host {alert.source} has unusual protocol distribution. "
                f"Investigate whether this is expected behaviour or "
                f"indicates tunnelling or protocol abuse."
            ),
            AnomalyType.DNS_ANOMALY: (
                f"DNS anomaly from {alert.source}. Check for DNS "
                f"tunnelling, DGA-based malware, or data exfiltration "
                f"via DNS queries."
            ),
            AnomalyType.TIMING_ANOMALY: (
                f"Timing anomaly detected from {alert.source}. "
                f"Regular timing patterns may indicate automated "
                f"beacon communication."
            ),
            AnomalyType.BEACON_DETECTED: (
                f"Beacon-like communication detected from {alert.source}. "
                f"Investigate for C2 activity."
            ),
        }
        return recs.get(alert.type, "Investigate the anomalous activity.")

    def _build_summary(
        self,
        result: ScanResult,
        hosts: dict[str, NetworkHost],
        flows: list[NetworkFlow],
        anomaly_alerts: list[AnomalyAlert],
        beacon_results: list[BeaconResult],
        lateral_movements: list[LateralMovement],
    ) -> str:
        """Build a human-readable summary of analysis results."""
        total_bytes = sum(h.bytes_sent + h.bytes_recv for h in hosts.values())
        total_packets = sum(h.packet_count for h in hosts.values())
        beacon_count = sum(1 for b in beacon_results if b.is_beacon)

        lines = [
            f"Spectra Network Intelligence Analysis Summary",
            f"{'=' * 46}",
            f"Hosts: {len(hosts)} | Flows: {len(flows)}",
            f"Packets: {total_packets:,} | Bytes: {total_bytes:,}",
            f"Findings: {result.finding_count} "
            f"(Critical: {result.critical_count}, High: {result.high_count})",
            f"Anomalies: {len(anomaly_alerts)} | "
            f"Beacons: {beacon_count} | "
            f"Lateral Movements: {len(lateral_movements)}",
        ]

        return "\n".join(lines)
