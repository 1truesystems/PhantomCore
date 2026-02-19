"""
Spectra Data Models
====================

Pydantic-based data models for the Spectra Network Intelligence Engine,
representing network hosts, flows, anomaly alerts, communication graphs,
community structures, beacon detection results, and lateral movement paths.

These models follow domain-driven design (Evans, 2003) and provide
strongly typed data containers for the Spectra analysis pipeline.

References:
    - Evans, E. (2003). Domain-Driven Design. Addison-Wesley.
    - Pydantic v2 Documentation. https://docs.pydantic.dev/latest/
    - Blondel, V. D., Guillaume, J.-L., Lambiotte, R., & Lefebvre, E.
      (2008). Fast unfolding of communities in large networks.
      Journal of Statistical Mechanics, 2008(10), P10008.
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
      Bell System Technical Journal, 27(3), 379-423.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
#  Enumerations
# ---------------------------------------------------------------------------


class AnomalyType(str, enum.Enum):
    """Classification of network anomaly types detected by Spectra.

    Each anomaly type corresponds to a distinct detection heuristic
    in the :class:`~spectra.analyzers.anomaly.AnomalyDetector`.
    """

    VOLUME_SPIKE = "volume_spike"
    PORT_SCAN = "port_scan"
    UNUSUAL_PORT = "unusual_port"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    DNS_ANOMALY = "dns_anomaly"
    BEACON_DETECTED = "beacon_detected"


class Protocol(str, enum.Enum):
    """Network protocol enumeration for flow classification."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    ARP = "ARP"
    OTHER = "OTHER"


# ---------------------------------------------------------------------------
#  Network Host
# ---------------------------------------------------------------------------


class NetworkHost(BaseModel):
    """Represents a single host observed on the network.

    Aggregates all observed activity for a unique IP address, including
    MAC addresses, port activity, service fingerprints, and traffic volume.

    Attributes:
        ip: IPv4 or IPv6 address string.
        mac: MAC address (if observed via ARP or Ethernet header).
        hostname: Resolved hostname (if DNS resolution enabled).
        ports: Set of ports observed in use (source or destination).
        services: Mapping of port number to identified service name.
        first_seen: Timestamp of the first packet involving this host.
        last_seen: Timestamp of the last packet involving this host.
        bytes_sent: Total bytes sent by this host.
        bytes_recv: Total bytes received by this host.
        packet_count: Total packets involving this host (sent + received).
    """

    ip: str
    mac: str = ""
    hostname: str = ""
    ports: set[int] = Field(default_factory=set)
    services: dict[int, str] = Field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    packet_count: int = 0

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            set: list,
        }

    @property
    def total_bytes(self) -> int:
        """Total bytes transferred (sent + received)."""
        return self.bytes_sent + self.bytes_recv

    @property
    def duration_seconds(self) -> float:
        """Duration of observed activity in seconds."""
        if self.first_seen and self.last_seen:
            return (self.last_seen - self.first_seen).total_seconds()
        return 0.0


# ---------------------------------------------------------------------------
#  Network Flow
# ---------------------------------------------------------------------------


class NetworkFlow(BaseModel):
    """Represents a single network flow (aggregated by 5-tuple).

    A flow is a unidirectional sequence of packets sharing the same
    (src_ip, src_port, dst_ip, dst_port, protocol) 5-tuple.

    Attributes:
        src_ip: Source IP address.
        src_port: Source port number.
        dst_ip: Destination IP address.
        dst_port: Destination port number.
        protocol: Network protocol (TCP, UDP, ICMP, etc.).
        packets: Number of packets in this flow.
        bytes_total: Total bytes in this flow.
        start_time: Timestamp of the first packet in this flow.
        end_time: Timestamp of the last packet in this flow.
        flags: TCP flags observed (SYN, ACK, FIN, RST, etc.).
        packet_sizes: List of individual packet sizes for analysis.
        timestamps: List of individual packet timestamps for timing analysis.
        dns_queries: DNS query names if this is a DNS flow.
        payload_sample: First N bytes of payload for fingerprinting.
    """

    src_ip: str
    src_port: int = 0
    dst_ip: str
    dst_port: int = 0
    protocol: str = "TCP"
    packets: int = 1
    bytes_total: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    flags: list[str] = Field(default_factory=list)
    packet_sizes: list[int] = Field(default_factory=list)
    timestamps: list[float] = Field(default_factory=list)
    dns_queries: list[str] = Field(default_factory=list)
    payload_sample: bytes = b""

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            bytes: lambda v: v.hex(),
        }

    @property
    def duration_seconds(self) -> float:
        """Duration of the flow in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def five_tuple(self) -> tuple[str, int, str, int, str]:
        """Return the canonical 5-tuple identifier for this flow."""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)

    @property
    def avg_packet_size(self) -> float:
        """Average packet size in bytes."""
        if self.packets > 0:
            return self.bytes_total / self.packets
        return 0.0


# ---------------------------------------------------------------------------
#  Anomaly Alert
# ---------------------------------------------------------------------------


class AnomalyAlert(BaseModel):
    """A single anomaly detection alert from the Spectra engine.

    Produced by the :class:`~spectra.analyzers.anomaly.AnomalyDetector`
    when network behaviour deviates from established baselines.

    Attributes:
        type: Category of anomaly detected.
        source: Source IP address (or hostname) involved.
        target: Target IP address (or hostname) involved.
        metric: Name of the metric that triggered the alert.
        value: Observed value of the metric.
        threshold: Threshold that was exceeded.
        z_score: Z-score of the observation (if applicable).
        description: Human-readable description of the anomaly.
        severity: Severity string for display purposes.
        timestamp: When the anomaly was detected.
    """

    type: AnomalyType
    source: str = ""
    target: str = ""
    metric: str = ""
    value: float = 0.0
    threshold: float = 0.0
    z_score: float = 0.0
    description: str = ""
    severity: str = "medium"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
#  Communication Graph
# ---------------------------------------------------------------------------


class CommunicationGraph(BaseModel):
    """Represents the network communication graph built from observed flows.

    Nodes are hosts and edges are communication flows between them.
    This model is the input to the graph analysis phase.

    Attributes:
        hosts: Mapping from IP address to NetworkHost.
        flows: List of all observed network flows.
        edges: List of (src_ip, dst_ip, weight) tuples representing
            aggregated communication edges.
    """

    hosts: dict[str, NetworkHost] = Field(default_factory=dict)
    flows: list[NetworkFlow] = Field(default_factory=list)
    edges: list[tuple[str, str, float]] = Field(default_factory=list)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            set: list,
            bytes: lambda v: v.hex(),
        }


# ---------------------------------------------------------------------------
#  Community Detection Result
# ---------------------------------------------------------------------------


class CommunityResult(BaseModel):
    """Result of community detection on the communication graph.

    Communities represent groups of hosts that communicate more densely
    with each other than with the rest of the network. Detection uses
    modularity optimisation.

    Reference:
        Blondel, V. D., Guillaume, J.-L., Lambiotte, R., & Lefebvre, E.
        (2008). Fast unfolding of communities in large networks.
        Journal of Statistical Mechanics, 2008(10), P10008.

    Attributes:
        community_id: Unique identifier for this community.
        members: List of IP addresses belonging to this community.
        internal_edges: Number of edges within the community.
        external_edges: Number of edges crossing the community boundary.
        density: Edge density within the community [0.0, 1.0].
    """

    community_id: int
    members: list[str] = Field(default_factory=list)
    internal_edges: int = 0
    external_edges: int = 0
    density: float = 0.0

    @property
    def size(self) -> int:
        """Number of members in this community."""
        return len(self.members)

    @property
    def isolation_ratio(self) -> float:
        """Ratio of internal to total edges (measure of community isolation)."""
        total = self.internal_edges + self.external_edges
        if total == 0:
            return 0.0
        return self.internal_edges / total


# ---------------------------------------------------------------------------
#  Beacon Detection Result
# ---------------------------------------------------------------------------


class BeaconResult(BaseModel):
    """Result of beacon (C2 heartbeat) detection analysis.

    Beacons are characterised by regular, periodic communication
    patterns between a source and destination pair.

    Reference:
        Shannon, C. E. (1948). A Mathematical Theory of Communication.
        Bell System Technical Journal, 27(3), 379-423.
        (Timing entropy analysis for periodicity detection.)

    Attributes:
        src: Source IP address of the potential beacon.
        dst: Destination IP address (potential C2 server).
        interval_mean: Mean inter-arrival time in seconds.
        interval_std: Standard deviation of inter-arrival times.
        entropy: Timing entropy (low = more periodic).
        confidence: Confidence score [0.0, 1.0] that this is a beacon.
        is_beacon: Boolean classification result.
        flow_count: Number of flows in the beacon pair.
        coefficient_of_variation: Std/mean ratio (jitter metric).
        autocorrelation_peak: Highest autocorrelation value at non-zero lag.
    """

    src: str
    dst: str
    interval_mean: float = 0.0
    interval_std: float = 0.0
    entropy: float = 0.0
    confidence: float = 0.0
    is_beacon: bool = False
    flow_count: int = 0
    coefficient_of_variation: float = 0.0
    autocorrelation_peak: float = 0.0


# ---------------------------------------------------------------------------
#  Lateral Movement Detection
# ---------------------------------------------------------------------------


class LateralMovement(BaseModel):
    """Detected lateral movement pattern in the network.

    Lateral movement is the technique of moving through a network
    after initial compromise, typically involving sequential access
    to multiple hosts using credential-based protocols.

    Attributes:
        path: Ordered list of IP addresses in the movement path.
        evidence: List of evidence descriptions supporting detection.
        confidence: Confidence score [0.0, 1.0].
        technique: Identified lateral movement technique.
        timespan_seconds: Duration of the movement path.
        ports_used: Ports involved in the lateral movement.
    """

    path: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    technique: str = "unknown"
    timespan_seconds: float = 0.0
    ports_used: list[int] = Field(default_factory=list)

    @property
    def hop_count(self) -> int:
        """Number of hops in the lateral movement path."""
        return max(0, len(self.path) - 1)
