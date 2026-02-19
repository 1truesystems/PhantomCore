"""
Spectra Lateral Movement Detector
===================================

Detects lateral movement patterns in network communication graphs.
Lateral movement is the technique used by attackers to progressively
move through a network after initial compromise, typically using
legitimate credentials and management protocols.

Detection Strategies:
    1. Graph connectivity analysis: sequential multi-hop connections
       in short timeframes, hub-and-spoke patterns, new connections
       from recently contacted hosts.
    2. Temporal pattern analysis: short-lived connections followed by
       new connections, credential-related port usage.
    3. Technique classification: SMB/PsExec (445), WMI (135),
       RDP (3389), SSH (22), WinRM (5985).

References:
    - MITRE ATT&CK: Lateral Movement (TA0008).
      https://attack.mitre.org/tactics/TA0008/
    - Dunagan, J., Roussev, R., Daniels, B., Sailer, A., Siganos, G.,
      & Saroiu, S. (2009). Towards a Self-Managing Network:
      Detecting and Containing Network Worms. Microsoft Research.
    - Kent, A. D. (2015). Cybersecurity Data Sources for Dynamic
      Network Research. Proceedings of the Dynamic Networks Workshop.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

import networkx as nx

from shared.logger import PhantomLogger

from spectra.core.models import (
    LateralMovement,
    NetworkFlow,
    NetworkHost,
)

logger = PhantomLogger("spectra.lateral")

# ---------------------------------------------------------------------------
#  Lateral movement protocol signatures
# ---------------------------------------------------------------------------

# Ports commonly used for lateral movement techniques
_LATERAL_PORTS: dict[int, str] = {
    445: "SMB/PsExec",
    135: "WMI/DCOM",
    3389: "RDP",
    22: "SSH",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    139: "SMB/NetBIOS",
    23: "Telnet",
    5900: "VNC",
    3268: "LDAP/AD",
}

# Technique classification based on port patterns
_TECHNIQUE_MAP: dict[int, str] = {
    445: "SMB/PsExec Lateral Movement",
    139: "SMB/NetBIOS Lateral Movement",
    135: "WMI/DCOM Remote Execution",
    3389: "RDP Lateral Movement",
    22: "SSH Lateral Movement",
    5985: "WinRM Lateral Movement",
    5986: "WinRM (HTTPS) Lateral Movement",
    23: "Telnet Lateral Movement",
    5900: "VNC Lateral Movement",
}


class LateralMovementDetector:
    """Detects lateral movement patterns in network communications.

    Combines graph-based connectivity analysis with temporal pattern
    matching to identify multi-hop movement chains characteristic of
    post-compromise lateral movement.

    Usage::

        detector = LateralMovementDetector()
        movements = detector.detect(graph, flows, hosts)
    """

    def __init__(
        self,
        time_window_seconds: float = 300.0,
        min_hops: int = 2,
        min_confidence: float = 0.3,
    ) -> None:
        """Initialise the lateral movement detector.

        Args:
            time_window_seconds: Maximum time window (seconds) for a
                sequence of connections to be considered related.
            min_hops: Minimum number of hops to qualify as lateral
                movement (default 2 = at least A->B->C).
            min_confidence: Minimum confidence threshold for reporting
                a detected movement pattern.
        """
        self.time_window: float = time_window_seconds
        self.min_hops: int = min_hops
        self.min_confidence: float = min_confidence

    def detect(
        self,
        graph: nx.DiGraph,
        flows: list[NetworkFlow],
        hosts: dict[str, NetworkHost],
    ) -> list[LateralMovement]:
        """Run all lateral movement detection strategies.

        Applies:
        1. Sequential chain detection (A->B->C->D)
        2. Hub-and-spoke pattern detection
        3. New-connection-after-compromise pattern
        4. Credential port chain analysis

        Args:
            graph: Communication graph (NetworkX DiGraph).
            flows: List of network flows.
            hosts: Dictionary of IP -> NetworkHost.

        Returns:
            List of LateralMovement objects, sorted by confidence.
        """
        movements: list[LateralMovement] = []

        # Pre-process: build temporal flow index
        lateral_flows = self._filter_lateral_flows(flows)

        if not lateral_flows:
            logger.info(
                "No lateral-movement-related flows found"
            )
            return movements

        # Strategy 1: Sequential chain detection
        chains = self._detect_sequential_chains(lateral_flows)
        movements.extend(chains)

        # Strategy 2: Hub-and-spoke pattern
        spokes = self._detect_hub_and_spoke(lateral_flows)
        movements.extend(spokes)

        # Strategy 3: New connections from recently contacted hosts
        new_conn = self._detect_new_connection_chains(lateral_flows, flows)
        movements.extend(new_conn)

        # Filter by confidence threshold and deduplicate
        movements = [m for m in movements if m.confidence >= self.min_confidence]
        movements = self._deduplicate(movements)

        # Sort by confidence descending
        movements.sort(key=lambda m: m.confidence, reverse=True)

        logger.info(
            f"Lateral movement detection: "
            f"{len(movements)} patterns detected"
        )

        return movements

    # ------------------------------------------------------------------ #
    #  Flow Filtering
    # ------------------------------------------------------------------ #

    def _filter_lateral_flows(
        self,
        flows: list[NetworkFlow],
    ) -> list[NetworkFlow]:
        """Filter flows to those involving lateral movement protocols.

        Selects flows on credential-related ports (445, 135, 3389, 22,
        5985, etc.) that are characteristic of lateral movement.

        Args:
            flows: All network flows.

        Returns:
            Flows on lateral-movement-associated ports, sorted by time.
        """
        lateral: list[NetworkFlow] = []
        lateral_port_set = set(_LATERAL_PORTS.keys())

        for flow in flows:
            if flow.dst_port in lateral_port_set:
                lateral.append(flow)

        # Sort by start time
        lateral.sort(
            key=lambda f: f.start_time.timestamp() if f.start_time else 0.0
        )

        return lateral

    # ------------------------------------------------------------------ #
    #  Strategy 1: Sequential Chain Detection
    # ------------------------------------------------------------------ #

    def _detect_sequential_chains(
        self,
        lateral_flows: list[NetworkFlow],
    ) -> list[LateralMovement]:
        """Detect sequential A->B->C->D connection chains.

        Identifies chains where a host is contacted via a lateral
        movement port, and then that same host initiates a new lateral
        movement connection to another host within the time window.

        This pattern is the classic lateral movement signature: an
        attacker compromises host B, then uses B's credentials or
        access to move to host C.

        Reference:
            MITRE ATT&CK T1021: Remote Services.
            https://attack.mitre.org/techniques/T1021/
        """
        movements: list[LateralMovement] = []

        if len(lateral_flows) < 2:
            return movements

        # Build temporal adjacency: for each host, when was it a dst,
        # and when did it become a src?
        dst_times: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
        src_times: dict[str, list[tuple[float, str, int]]] = defaultdict(list)

        for flow in lateral_flows:
            ts = flow.start_time.timestamp() if flow.start_time else 0.0
            dst_times[flow.dst_ip].append((ts, flow.src_ip, flow.dst_port))
            src_times[flow.src_ip].append((ts, flow.dst_ip, flow.dst_port))

        # For each host that was BOTH a destination and later a source,
        # this is a potential pivot point
        pivot_hosts = set(dst_times.keys()) & set(src_times.keys())

        for pivot in pivot_hosts:
            incoming = sorted(dst_times[pivot], key=lambda x: x[0])
            outgoing = sorted(src_times[pivot], key=lambda x: x[0])

            for in_ts, in_src, in_port in incoming:
                # Find outgoing connections after this incoming connection
                for out_ts, out_dst, out_port in outgoing:
                    if out_ts <= in_ts:
                        continue  # Must be after incoming
                    if out_ts - in_ts > self.time_window:
                        break  # Outside time window

                    # Skip self-loops
                    if out_dst == in_src:
                        continue

                    # We have a chain: in_src -> pivot -> out_dst
                    path = [in_src, pivot, out_dst]

                    # Try to extend the chain further
                    path = self._extend_chain(
                        path, out_ts, src_times, dst_times
                    )

                    if len(path) - 1 >= self.min_hops:
                        # Calculate confidence
                        timespan = out_ts - in_ts
                        confidence = self._compute_chain_confidence(
                            path, [in_port, out_port], timespan
                        )

                        technique = _TECHNIQUE_MAP.get(
                            out_port,
                            _TECHNIQUE_MAP.get(in_port, "Unknown")
                        )

                        evidence = [
                            f"Sequential connection chain detected: "
                            f"{' -> '.join(path)}",
                            f"Incoming: {in_src} -> {pivot} "
                            f"(port {in_port}, {_LATERAL_PORTS.get(in_port, 'unknown')})",
                            f"Outgoing: {pivot} -> {out_dst} "
                            f"(port {out_port}, {_LATERAL_PORTS.get(out_port, 'unknown')})",
                            f"Time between hops: {timespan:.1f} seconds",
                        ]

                        movements.append(LateralMovement(
                            path=path,
                            evidence=evidence,
                            confidence=confidence,
                            technique=technique,
                            timespan_seconds=timespan,
                            ports_used=sorted(set([in_port, out_port])),
                        ))

        return movements

    def _extend_chain(
        self,
        path: list[str],
        last_ts: float,
        src_times: dict[str, list[tuple[float, str, int]]],
        dst_times: dict[str, list[tuple[float, str, int]]],
        max_depth: int = 6,
    ) -> list[str]:
        """Attempt to extend a chain by finding further hops.

        Greedily extends the movement path by checking if the last
        destination also initiated lateral connections within the window.

        Args:
            path: Current movement path.
            last_ts: Timestamp of the last hop.
            src_times: Source IP temporal index.
            dst_times: Destination IP temporal index.
            max_depth: Maximum chain length to prevent runaway.

        Returns:
            Extended path (may be unchanged if no extension found).
        """
        if len(path) >= max_depth:
            return path

        current_host = path[-1]
        path_set = set(path)

        outgoing = src_times.get(current_host, [])
        for out_ts, out_dst, out_port in sorted(outgoing, key=lambda x: x[0]):
            if out_ts <= last_ts:
                continue
            if out_ts - last_ts > self.time_window:
                break
            if out_dst in path_set:
                continue  # Avoid cycles

            extended = path + [out_dst]
            return self._extend_chain(
                extended, out_ts, src_times, dst_times, max_depth
            )

        return path

    # ------------------------------------------------------------------ #
    #  Strategy 2: Hub-and-Spoke Detection
    # ------------------------------------------------------------------ #

    def _detect_hub_and_spoke(
        self,
        lateral_flows: list[NetworkFlow],
    ) -> list[LateralMovement]:
        """Detect hub-and-spoke patterns from a single compromised host.

        A hub-and-spoke pattern occurs when a single host connects to
        multiple other hosts via lateral movement ports in a short
        timeframe. This suggests an attacker has compromised one host
        and is probing or exploiting multiple targets.

        Reference:
            Kent, A. D. (2015). Cybersecurity Data Sources for Dynamic
            Network Research. Los Alamos National Laboratory.
        """
        movements: list[LateralMovement] = []

        # Group outgoing lateral flows by source
        src_targets: dict[str, list[tuple[float, str, int]]] = defaultdict(list)

        for flow in lateral_flows:
            ts = flow.start_time.timestamp() if flow.start_time else 0.0
            src_targets[flow.src_ip].append((ts, flow.dst_ip, flow.dst_port))

        for src, targets in src_targets.items():
            if len(targets) < 3:  # Need at least 3 targets for spoke pattern
                continue

            # Sort by time
            targets_sorted = sorted(targets, key=lambda x: x[0])

            # Sliding window: find clusters of connections within time window
            window_start = 0
            for window_end in range(len(targets_sorted)):
                # Shrink window start
                while (
                    window_start < window_end
                    and targets_sorted[window_end][0]
                    - targets_sorted[window_start][0]
                    > self.time_window
                ):
                    window_start += 1

                window = targets_sorted[window_start : window_end + 1]
                unique_dsts = set(t[1] for t in window)

                if len(unique_dsts) >= 3:
                    dst_list = sorted(unique_dsts)
                    timespan = window[-1][0] - window[0][0]
                    ports_used = sorted(set(t[2] for t in window))

                    # Confidence based on number of unique targets and speed
                    base_confidence = min(0.4 + 0.1 * len(unique_dsts), 0.9)
                    if timespan < 60:
                        base_confidence += 0.1  # Rapid scanning boost

                    confidence = min(base_confidence, 0.95)

                    path = [src] + dst_list
                    technique = "Hub-and-Spoke Lateral Spread"

                    evidence = [
                        f"Host {src} connected to {len(unique_dsts)} unique targets "
                        f"via lateral movement ports within {timespan:.0f} seconds",
                        f"Targets: {', '.join(dst_list[:5])}"
                        + (f" (+{len(dst_list)-5} more)" if len(dst_list) > 5 else ""),
                        f"Ports used: {ports_used}",
                        f"Pattern: Hub-and-spoke (single source, multiple targets)",
                    ]

                    movements.append(LateralMovement(
                        path=path,
                        evidence=evidence,
                        confidence=confidence,
                        technique=technique,
                        timespan_seconds=timespan,
                        ports_used=ports_used,
                    ))

                    # Only report the largest window per source
                    break

        return movements

    # ------------------------------------------------------------------ #
    #  Strategy 3: New Connection Chain Detection
    # ------------------------------------------------------------------ #

    def _detect_new_connection_chains(
        self,
        lateral_flows: list[NetworkFlow],
        all_flows: list[NetworkFlow],
    ) -> list[LateralMovement]:
        """Detect new lateral connections from recently contacted hosts.

        Identifies hosts that begin making lateral connections shortly
        after being contacted for the first time. This "awakening"
        pattern suggests compromise followed by attacker-initiated
        lateral movement.

        The key insight is temporal: a host that has never initiated
        lateral connections before suddenly doing so after being
        contacted is suspicious.
        """
        movements: list[LateralMovement] = []

        # Build first-seen-as-source and first-seen-as-destination for lateral ports
        first_as_dst: dict[str, float] = {}
        first_as_src: dict[str, float] = {}
        src_connections: dict[str, list[tuple[float, str, int]]] = defaultdict(list)

        for flow in lateral_flows:
            ts = flow.start_time.timestamp() if flow.start_time else 0.0

            # Track first time each host was contacted via lateral port
            if flow.dst_ip not in first_as_dst or ts < first_as_dst[flow.dst_ip]:
                first_as_dst[flow.dst_ip] = ts

            # Track first time each host initiated lateral connection
            if flow.src_ip not in first_as_src or ts < first_as_src[flow.src_ip]:
                first_as_src[flow.src_ip] = ts

            src_connections[flow.src_ip].append((ts, flow.dst_ip, flow.dst_port))

        # Find hosts where first_as_src happened shortly after first_as_dst
        # (they were contacted, then started spreading)
        for ip in set(first_as_dst.keys()) & set(first_as_src.keys()):
            contacted_at = first_as_dst[ip]
            started_at = first_as_src[ip]

            # The host must have been contacted BEFORE it started spreading
            if started_at <= contacted_at:
                continue

            delay = started_at - contacted_at
            if delay > self.time_window:
                continue

            # Get the source that contacted this host
            contacting_sources: list[str] = []
            for flow in lateral_flows:
                if (
                    flow.dst_ip == ip
                    and flow.start_time
                    and abs(flow.start_time.timestamp() - contacted_at) < 1.0
                ):
                    contacting_sources.append(flow.src_ip)

            # Get the targets this host then contacted
            subsequent = [
                (ts, dst, port)
                for ts, dst, port in src_connections.get(ip, [])
                if ts >= started_at and ts - contacted_at <= self.time_window
            ]

            if not subsequent or not contacting_sources:
                continue

            targets = sorted(set(t[1] for t in subsequent))
            ports_used = sorted(set(t[2] for t in subsequent))

            if not targets:
                continue

            path = [contacting_sources[0], ip] + targets[:3]

            confidence = 0.5
            # Higher confidence if delay is short (rapid pivot)
            if delay < 30:
                confidence += 0.2
            elif delay < 120:
                confidence += 0.1
            # Higher confidence if multiple targets
            if len(targets) > 2:
                confidence += 0.1

            confidence = min(confidence, 0.9)

            evidence = [
                f"Host {ip} was first contacted on lateral port at "
                f"{datetime.fromtimestamp(contacted_at, tz=timezone.utc).isoformat()}",
                f"Host {ip} began lateral connections {delay:.1f}s later",
                f"Contacted by: {contacting_sources[0]}",
                f"Then connected to: {', '.join(targets[:5])}",
                f"Ports: {ports_used}",
                f"Pattern: Compromise then lateral spread",
            ]

            technique = "Post-Compromise Lateral Spread"
            if ports_used:
                primary_port = ports_used[0]
                if primary_port in _TECHNIQUE_MAP:
                    technique = _TECHNIQUE_MAP[primary_port]

            movements.append(LateralMovement(
                path=path,
                evidence=evidence,
                confidence=confidence,
                technique=technique,
                timespan_seconds=delay + (subsequent[-1][0] - started_at) if subsequent else delay,
                ports_used=ports_used,
            ))

        return movements

    # ------------------------------------------------------------------ #
    #  Confidence Scoring
    # ------------------------------------------------------------------ #

    def _compute_chain_confidence(
        self,
        path: list[str],
        ports: list[int],
        timespan: float,
    ) -> float:
        """Compute confidence score for a detected movement chain.

        Factors:
        - Chain length: longer chains are more suspicious.
        - Port consistency: same port throughout is more suspicious.
        - Timing: shorter timespans suggest automated movement.
        - Port type: certain ports (445, 135) are higher risk.

        Args:
            path: Movement path (list of IPs).
            ports: Ports used in the chain.
            timespan: Total time in seconds.

        Returns:
            Confidence score in [0.0, 1.0].
        """
        confidence = 0.3  # Base confidence for any detected chain

        # Chain length bonus
        hops = len(path) - 1
        if hops >= 3:
            confidence += 0.2
        elif hops >= 2:
            confidence += 0.1

        # Port consistency bonus (same technique throughout)
        unique_ports = set(ports)
        if len(unique_ports) == 1:
            confidence += 0.1

        # High-risk port bonus
        high_risk_ports = {445, 135, 3389}
        if any(p in high_risk_ports for p in ports):
            confidence += 0.1

        # Timing bonus (rapid movement is more suspicious)
        if timespan < 30:
            confidence += 0.15
        elif timespan < 120:
            confidence += 0.1
        elif timespan < 300:
            confidence += 0.05

        return min(confidence, 0.95)

    # ------------------------------------------------------------------ #
    #  Deduplication
    # ------------------------------------------------------------------ #

    def _deduplicate(
        self,
        movements: list[LateralMovement],
    ) -> list[LateralMovement]:
        """Remove duplicate or overlapping movement detections.

        Two movements are considered duplicates if their paths share
        more than 50% of nodes. In case of overlap, the higher-confidence
        detection is retained.

        Args:
            movements: List of detected movements.

        Returns:
            Deduplicated list.
        """
        if len(movements) <= 1:
            return movements

        # Sort by confidence descending
        movements.sort(key=lambda m: m.confidence, reverse=True)

        kept: list[LateralMovement] = []
        seen_paths: list[set[str]] = []

        for movement in movements:
            path_set = set(movement.path)

            # Check overlap with already-kept movements
            is_duplicate = False
            for existing_set in seen_paths:
                overlap = len(path_set & existing_set)
                max_size = max(len(path_set), len(existing_set))
                if max_size > 0 and overlap / max_size > 0.5:
                    is_duplicate = True
                    break

            if not is_duplicate:
                kept.append(movement)
                seen_paths.append(path_set)

        return kept
