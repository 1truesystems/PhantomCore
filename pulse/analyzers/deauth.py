"""
Pulse Deauthentication Detector
==================================

Detects and classifies 802.11 deauthentication attacks from captured
deauth frame events. Uses rate analysis, exponential moving averages,
and pattern classification to distinguish legitimate disconnections
from adversarial deauthentication flooding.

Deauthentication attacks are a common wireless denial-of-service
technique that exploits the unauthenticated nature of 802.11
management frames (prior to PMF/802.11w). Attackers send spoofed
deauth frames to force client disconnections, which can be used for:
    - Denial of service (persistent disconnection)
    - WPA handshake capture (forcing re-authentication)
    - Evil twin attacks (forcing clients to connect to rogue AP)
    - Network disruption during penetration testing

References:
    - Bellardo, J., & Savage, S. (2003). 802.11 Denial-of-Service
      Attacks: Real Vulnerabilities and Practical Solutions. USENIX
      Security Symposium.
    - IEEE. (2009). IEEE Std 802.11w-2009: Protected Management Frames.
    - Vanhoef, M., & Piessens, F. (2017). Key Reinstallation Attacks:
      Forcing Nonce Reuse in WPA2. CCS '17.
    - IEEE. (2020). IEEE Std 802.11-2020. Table 9-49: Reason codes.
    - Wright, J., & Cache, J. (2015). Hacking Exposed Wireless (3rd ed.).
      McGraw-Hill. Chapter 7: Attacking 802.11 Wireless Networks.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone, timedelta
from typing import Optional

from shared.logger import PhantomLogger

from pulse.core.models import (
    ATTACK_REASON_CODES,
    DEAUTH_REASON_CODES,
    LEGITIMATE_REASON_CODES,
    DeauthEvent,
    WirelessFinding,
    WirelessFindingType,
)

logger = PhantomLogger("pulse.analyzers.deauth")


# ---------------------------------------------------------------------------
# EMA (Exponential Moving Average) implementation
# ---------------------------------------------------------------------------


def exponential_moving_average(
    values: list[float],
    alpha: float = 0.3,
) -> list[float]:
    """Compute the Exponential Moving Average (EMA) of a time series.

    EMA is a weighted moving average that gives more weight to recent
    observations. The smoothing factor alpha controls the decay rate:

        EMA_t = alpha * X_t + (1 - alpha) * EMA_{t-1}

    Higher alpha means faster response to changes (less smoothing).
    Lower alpha means more smoothing (slower response).

    Reference:
        Hunter, J. S. (1986). The Exponentially Weighted Moving Average.
        Journal of Quality Technology, 18(4), 203-210.

    Args:
        values: Input time series values.
        alpha: Smoothing factor in (0, 1). Default 0.3.

    Returns:
        EMA-smoothed values of the same length as input.
    """
    if not values:
        return []

    ema: list[float] = [values[0]]
    for i in range(1, len(values)):
        ema_val = alpha * values[i] + (1.0 - alpha) * ema[i - 1]
        ema.append(ema_val)

    return ema


# ---------------------------------------------------------------------------
# Deauth Classification
# ---------------------------------------------------------------------------


class DeauthClassification:
    """Classification result for a deauthentication event pattern."""

    BROADCAST_FLOOD = "broadcast_flood"
    TARGETED_ATTACK = "targeted_attack"
    SELF_DEAUTH = "self_deauth"
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"

    def __init__(
        self,
        classification: str,
        confidence: float,
        description: str,
    ) -> None:
        self.classification = classification
        self.confidence = confidence
        self.description = description


# ---------------------------------------------------------------------------
# Deauth Detector
# ---------------------------------------------------------------------------


class DeauthDetector:
    """Detects and classifies 802.11 deauthentication attacks.

    Analyses captured deauthentication frame events to identify:
        - Deauthentication flood attacks (broadcast)
        - Targeted client deauthentication attacks
        - Legitimate disconnection events
        - Suspicious patterns requiring investigation

    The detector uses the following techniques:
        1. Rate analysis: deauth frames per second per source
        2. EMA smoothing: detect sustained vs. burst attacks
        3. Broadcast detection: FF:FF:FF:FF:FF:FF destination
        4. Reason code analysis: attack vs. legitimate codes
        5. Source identification: AP vs. external attacker

    Reference:
        Bellardo, J., & Savage, S. (2003). 802.11 Denial-of-Service
        Attacks: Real Vulnerabilities and Practical Solutions.

    Usage::

        detector = DeauthDetector()
        findings = detector.detect(deauth_events, threshold=10)
    """

    # Broadcast MAC address (all ones)
    BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

    def __init__(self) -> None:
        self._ema_alpha = 0.3

    def detect(
        self,
        events: list[DeauthEvent],
        threshold: int = 10,
        duration_seconds: float = 30.0,
    ) -> list[WirelessFinding]:
        """Detect deauthentication attacks from captured events.

        Args:
            events: List of deauthentication events.
            threshold: Minimum deauth count to trigger an alert.
            duration_seconds: Observation window duration in seconds.

        Returns:
            List of wireless findings describing detected attacks.
        """
        findings: list[WirelessFinding] = []

        if not events:
            return findings

        logger.info(
            f"Deauth analysis: "
            f"{len(events)} events, threshold={threshold}"
        )

        for event in events:
            # Classify the event
            classification = self._classify_event(
                event, threshold, duration_seconds
            )

            # Generate finding based on classification
            finding = self._classification_to_finding(event, classification)
            if finding:
                findings.append(finding)

        # Aggregate analysis: look for coordinated attacks
        aggregate_findings = self._detect_coordinated_attack(events, threshold)
        findings.extend(aggregate_findings)

        logger.info(
            f"Deauth analysis complete. Findings: {len(findings)}"
        )

        return findings

    def _classify_event(
        self,
        event: DeauthEvent,
        threshold: int,
        duration_seconds: float,
    ) -> DeauthClassification:
        """Classify a single deauthentication event.

        Classification logic:
            1. If destination is broadcast AND count > threshold:
               -> Broadcast flood attack
            2. If source is the BSSID (AP) AND count <= 2:
               -> Possible legitimate self-deauth
            3. If source is NOT the BSSID AND count > threshold:
               -> Targeted attack (spoofed source)
            4. If count <= threshold but reason code is suspicious:
               -> Suspicious activity
            5. If reason code is in legitimate set AND count is low:
               -> Legitimate disconnection

        Args:
            event: Deauthentication event to classify.
            threshold: Count threshold for attack classification.
            duration_seconds: Time window for rate calculation.

        Returns:
            DeauthClassification with type and confidence.
        """
        # Calculate deauth rate
        rate = event.count / max(duration_seconds, 1.0)

        # 1. Broadcast flood detection
        if event.dst_mac == self.BROADCAST_MAC:
            if event.count >= threshold:
                return DeauthClassification(
                    classification=DeauthClassification.BROADCAST_FLOOD,
                    confidence=min(0.99, 0.7 + (rate / 100.0) * 0.3),
                    description=(
                        f"Broadcast deauthentication flood detected. "
                        f"Source {event.src_mac} sent {event.count} deauth "
                        f"frames to broadcast address (FF:FF:FF:FF:FF:FF) "
                        f"on BSSID {event.bssid}. Rate: {rate:.1f} frames/"
                        f"sec. This disconnects ALL clients from the network."
                    ),
                )
            elif event.count >= threshold // 2:
                return DeauthClassification(
                    classification=DeauthClassification.SUSPICIOUS,
                    confidence=0.6,
                    description=(
                        f"Moderate broadcast deauthentication activity. "
                        f"{event.count} frames from {event.src_mac} to "
                        f"broadcast on BSSID {event.bssid}."
                    ),
                )

        # 2. Self-deauth (AP disconnecting a client)
        if event.src_mac == event.bssid:
            if event.count <= 3 and event.reason_code in LEGITIMATE_REASON_CODES:
                return DeauthClassification(
                    classification=DeauthClassification.LEGITIMATE,
                    confidence=0.85,
                    description=(
                        f"Legitimate deauthentication from AP {event.bssid} "
                        f"to client {event.dst_mac}. Reason: "
                        f"{DEAUTH_REASON_CODES.get(event.reason_code, 'Unknown')} "
                        f"(code {event.reason_code}). Count: {event.count}."
                    ),
                )
            elif event.count > threshold:
                # AP sending many deauths is suspicious
                return DeauthClassification(
                    classification=DeauthClassification.SUSPICIOUS,
                    confidence=0.7,
                    description=(
                        f"Excessive deauthentication from AP {event.bssid} "
                        f"to client {event.dst_mac}. Count: {event.count}, "
                        f"Rate: {rate:.1f}/sec. This may be a spoofed AP "
                        f"source address."
                    ),
                )
            else:
                return DeauthClassification(
                    classification=DeauthClassification.SELF_DEAUTH,
                    confidence=0.75,
                    description=(
                        f"AP {event.bssid} deauthenticated client "
                        f"{event.dst_mac}. Reason: "
                        f"{DEAUTH_REASON_CODES.get(event.reason_code, 'Unknown')} "
                        f"(code {event.reason_code}). Count: {event.count}."
                    ),
                )

        # 3. Targeted attack (source is not the AP)
        if event.count >= threshold:
            attack_likelihood = 0.8
            if event.reason_code in ATTACK_REASON_CODES:
                attack_likelihood = 0.95

            return DeauthClassification(
                classification=DeauthClassification.TARGETED_ATTACK,
                confidence=attack_likelihood,
                description=(
                    f"Targeted deauthentication attack detected. "
                    f"Source {event.src_mac} sent {event.count} deauth "
                    f"frames to {event.dst_mac} on BSSID {event.bssid}. "
                    f"Rate: {rate:.1f} frames/sec. Reason code: "
                    f"{event.reason_code} - "
                    f"{DEAUTH_REASON_CODES.get(event.reason_code, 'Unknown')}."
                ),
            )

        # 4. Suspicious reason codes
        if event.reason_code in ATTACK_REASON_CODES and event.count > 1:
            return DeauthClassification(
                classification=DeauthClassification.SUSPICIOUS,
                confidence=0.5 + (event.count / threshold) * 0.3,
                description=(
                    f"Suspicious deauthentication activity. "
                    f"{event.count} frames from {event.src_mac} to "
                    f"{event.dst_mac}. Reason code {event.reason_code} "
                    f"({DEAUTH_REASON_CODES.get(event.reason_code, 'Unknown')}) "
                    f"is commonly used in attacks."
                ),
            )

        # 5. Likely legitimate
        return DeauthClassification(
            classification=DeauthClassification.LEGITIMATE,
            confidence=0.7,
            description=(
                f"Low-volume deauthentication ({event.count} frame(s)) from "
                f"{event.src_mac} to {event.dst_mac}. Reason: "
                f"{DEAUTH_REASON_CODES.get(event.reason_code, 'Unknown')} "
                f"(code {event.reason_code}). Likely legitimate."
            ),
        )

    def _classification_to_finding(
        self,
        event: DeauthEvent,
        classification: DeauthClassification,
    ) -> Optional[WirelessFinding]:
        """Convert a classification into a WirelessFinding.

        Args:
            event: The original deauth event.
            classification: The classification result.

        Returns:
            WirelessFinding or None for legitimate events.
        """
        if classification.classification == DeauthClassification.LEGITIMATE:
            # Still report as INFO for completeness
            return WirelessFinding(
                type=WirelessFindingType.DEAUTH_ATTACK,
                severity="INFO",
                ap_bssid=event.bssid,
                description=classification.description,
                recommendation="No action required for legitimate disconnections.",
                evidence={
                    "src_mac": event.src_mac,
                    "dst_mac": event.dst_mac,
                    "bssid": event.bssid,
                    "reason_code": event.reason_code,
                    "reason_text": DEAUTH_REASON_CODES.get(event.reason_code, "Unknown"),
                    "count": event.count,
                    "classification": classification.classification,
                },
                confidence=classification.confidence,
            )

        if classification.classification == DeauthClassification.BROADCAST_FLOOD:
            return WirelessFinding(
                type=WirelessFindingType.DEAUTH_FLOOD,
                severity="CRITICAL",
                ap_bssid=event.bssid,
                description=classification.description,
                recommendation=(
                    "IMMEDIATE ACTION REQUIRED: "
                    "1) Enable Protected Management Frames (PMF/802.11w) on the AP. "
                    "2) Identify and locate the attack source using signal triangulation. "
                    "3) Consider upgrading to WPA3 which mandates PMF. "
                    "4) Deploy wireless IDS/IPS for continuous monitoring. "
                    "Reference: IEEE 802.11w-2009 provides deauth protection."
                ),
                evidence={
                    "src_mac": event.src_mac,
                    "dst_mac": event.dst_mac,
                    "bssid": event.bssid,
                    "reason_code": event.reason_code,
                    "reason_text": DEAUTH_REASON_CODES.get(event.reason_code, "Unknown"),
                    "count": event.count,
                    "attack_type": "broadcast_flood",
                    "classification": classification.classification,
                },
                confidence=classification.confidence,
            )

        if classification.classification == DeauthClassification.TARGETED_ATTACK:
            return WirelessFinding(
                type=WirelessFindingType.DEAUTH_ATTACK,
                severity="HIGH",
                ap_bssid=event.bssid,
                client_mac=event.dst_mac,
                description=classification.description,
                recommendation=(
                    "1) Enable PMF (802.11w) to protect against deauth attacks. "
                    "2) Check if the target client was recently forced to "
                    "re-authenticate (possible WPA handshake capture attempt). "
                    "3) Investigate whether a rogue AP appeared after the "
                    "deauth (evil twin attack pattern). "
                    "4) Monitor for EAPOL 4-way handshake frames near this event."
                ),
                evidence={
                    "src_mac": event.src_mac,
                    "dst_mac": event.dst_mac,
                    "bssid": event.bssid,
                    "reason_code": event.reason_code,
                    "reason_text": DEAUTH_REASON_CODES.get(event.reason_code, "Unknown"),
                    "count": event.count,
                    "attack_type": "targeted",
                    "classification": classification.classification,
                },
                confidence=classification.confidence,
            )

        if classification.classification == DeauthClassification.SUSPICIOUS:
            return WirelessFinding(
                type=WirelessFindingType.DEAUTH_ATTACK,
                severity="MEDIUM",
                ap_bssid=event.bssid,
                description=classification.description,
                recommendation=(
                    "Monitor this activity for escalation. Enable PMF on "
                    "the affected AP. If deauth rate increases, treat as "
                    "an active attack."
                ),
                evidence={
                    "src_mac": event.src_mac,
                    "dst_mac": event.dst_mac,
                    "bssid": event.bssid,
                    "reason_code": event.reason_code,
                    "reason_text": DEAUTH_REASON_CODES.get(event.reason_code, "Unknown"),
                    "count": event.count,
                    "classification": classification.classification,
                },
                confidence=classification.confidence,
            )

        # Self-deauth
        return WirelessFinding(
            type=WirelessFindingType.DEAUTH_ATTACK,
            severity="LOW",
            ap_bssid=event.bssid,
            description=classification.description,
            recommendation="Monitor for repeated occurrence.",
            evidence={
                "src_mac": event.src_mac,
                "dst_mac": event.dst_mac,
                "bssid": event.bssid,
                "reason_code": event.reason_code,
                "count": event.count,
                "classification": classification.classification,
            },
            confidence=classification.confidence,
        )

    def _detect_coordinated_attack(
        self,
        events: list[DeauthEvent],
        threshold: int,
    ) -> list[WirelessFinding]:
        """Detect coordinated deauth attacks targeting multiple BSSIDs.

        A coordinated attack involves the same source MAC sending
        deauth frames to multiple networks simultaneously, suggesting
        an automated attack tool.

        Args:
            events: All deauth events.
            threshold: Attack detection threshold.

        Returns:
            Additional findings for coordinated attacks.
        """
        findings: list[WirelessFinding] = []

        # Group by source MAC
        source_targets: dict[str, list[DeauthEvent]] = {}
        for event in events:
            if event.src_mac not in source_targets:
                source_targets[event.src_mac] = []
            source_targets[event.src_mac].append(event)

        for src_mac, src_events in source_targets.items():
            # Check if source targets multiple BSSIDs with high volume
            unique_bssids = set(e.bssid for e in src_events)
            total_deauths = sum(e.count for e in src_events)

            if len(unique_bssids) >= 2 and total_deauths >= threshold:
                findings.append(WirelessFinding(
                    type=WirelessFindingType.DEAUTH_FLOOD,
                    severity="CRITICAL",
                    description=(
                        f"Coordinated deauthentication attack detected from "
                        f"source {src_mac}. Targeting {len(unique_bssids)} "
                        f"different networks with {total_deauths} total deauth "
                        f"frames. Targeted BSSIDs: "
                        f"{', '.join(sorted(unique_bssids))}. This pattern "
                        f"indicates an automated attack tool (e.g., aireplay-ng, "
                        f"mdk3/mdk4, or similar)."
                    ),
                    recommendation=(
                        "1) Locate the attack source using RF direction finding. "
                        "2) Enable PMF on all affected access points. "
                        "3) Upgrade to WPA3 which mandates PMF. "
                        "4) Consider implementing 802.11w management frame "
                        "protection network-wide. "
                        "5) Report the attack to network security team."
                    ),
                    evidence={
                        "attack_source": src_mac,
                        "targeted_bssids": sorted(unique_bssids),
                        "total_deauths": total_deauths,
                        "events": [
                            {
                                "bssid": e.bssid,
                                "dst": e.dst_mac,
                                "count": e.count,
                                "reason": e.reason_code,
                            }
                            for e in src_events
                        ],
                        "attack_pattern": "coordinated_multi_bssid",
                    },
                    confidence=0.95,
                ))

        return findings

    @staticmethod
    def compute_deauth_rate_ema(
        events: list[DeauthEvent],
        window_seconds: float = 1.0,
        alpha: float = 0.3,
    ) -> list[float]:
        """Compute EMA-smoothed deauth rate over time.

        Bins events into time windows, calculates the rate per window,
        then applies exponential moving average smoothing.

        Args:
            events: Deauth events sorted by timestamp.
            window_seconds: Time bin width in seconds.
            alpha: EMA smoothing factor.

        Returns:
            EMA-smoothed rate values per time bin.
        """
        if not events:
            return []

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        start_time = sorted_events[0].timestamp
        end_time = sorted_events[-1].timestamp

        total_duration = (end_time - start_time).total_seconds()
        if total_duration <= 0:
            return [float(sum(e.count for e in events))]

        num_bins = max(1, int(math.ceil(total_duration / window_seconds)))
        bins: list[float] = [0.0] * num_bins

        for event in sorted_events:
            elapsed = (event.timestamp - start_time).total_seconds()
            bin_idx = min(int(elapsed / window_seconds), num_bins - 1)
            bins[bin_idx] += event.count

        # Convert counts to rates
        rates = [count / window_seconds for count in bins]

        # Apply EMA smoothing
        return exponential_moving_average(rates, alpha)
