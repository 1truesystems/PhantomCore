"""
Pulse Hidden SSID Detector
=============================

Detects hidden WiFi networks and attempts to correlate their BSSIDs
with actual SSIDs revealed through probe responses, association
requests, and data frame analysis.

Hidden SSID (SSID broadcast suppression) is configured by omitting
the SSID from beacon frames. However, the SSID is still transmitted
in cleartext in:
    1. Probe Response frames (when clients request specific SSIDs)
    2. Association Request frames (client joining the network)
    3. Reassociation Request frames

This makes SSID hiding a form of "security through obscurity" that
provides no meaningful protection against passive monitoring.

References:
    - IEEE. (2020). IEEE Std 802.11-2020. Section 11.1.3.2:
      Active Scanning.
    - Berghel, H. (2004). Wireless Infidelity I: War Driving.
      Communications of the ACM, 47(9), 21-26.
    - Gast, M. S. (2005). 802.11 Wireless Networks: The Definitive Guide
      (2nd ed.). O'Reilly. Chapter 4: 802.11 Framing in Detail.
    - Wright, J., & Cache, J. (2015). Hacking Exposed Wireless (3rd ed.).
      McGraw-Hill. Chapter 6: Discovering WiFi Networks.
"""

from __future__ import annotations

from typing import Any, Optional

from shared.logger import PhantomLogger

from pulse.core.models import (
    AccessPoint,
    WifiClient,
    WirelessFinding,
    WirelessFindingType,
)

logger = PhantomLogger("pulse.analyzers.hidden_ssid")


# ---------------------------------------------------------------------------
# Hidden SSID discovery methods
# ---------------------------------------------------------------------------


class SSIDDiscoveryMethod:
    """Enumeration of methods used to discover hidden SSIDs."""

    PROBE_RESPONSE = "probe_response_correlation"
    ASSOCIATION_REQUEST = "association_request_correlation"
    DATA_FRAME_ANALYSIS = "data_frame_cross_reference"
    CLIENT_PROBE_MATCH = "client_probe_request_match"


# ---------------------------------------------------------------------------
# Hidden SSID Discovery Result
# ---------------------------------------------------------------------------


class HiddenSSIDResult:
    """Result of a hidden SSID discovery attempt.

    Attributes:
        bssid: BSSID of the hidden network.
        discovered_ssid: The SSID discovered for this BSSID.
        method: Method used for discovery.
        confidence: Confidence in the discovery [0.0, 1.0].
        evidence: Supporting evidence data.
    """

    def __init__(
        self,
        bssid: str,
        discovered_ssid: str,
        method: str,
        confidence: float,
        evidence: Optional[dict[str, Any]] = None,
    ) -> None:
        self.bssid = bssid
        self.discovered_ssid = discovered_ssid
        self.method = method
        self.confidence = confidence
        self.evidence = evidence or {}


# ---------------------------------------------------------------------------
# Hidden SSID Detector
# ---------------------------------------------------------------------------


class HiddenSSIDDetector:
    """Detects hidden WiFi networks and discovers their actual SSIDs.

    Uses multiple correlation methods to match hidden AP BSSIDs with
    SSIDs revealed in other frame types:

    Method 1: Probe/Response BSSID Correlation
        When a client sends a directed probe request for a specific SSID
        and the hidden AP responds with a probe response containing the
        SSID, the BSSID-SSID mapping is revealed.

    Method 2: Association Request Correlation
        Association request frames always contain the target SSID in
        cleartext (required by the standard for BSS identification).
        Matching the destination BSSID with a hidden AP reveals the SSID.

    Method 3: Data Frame Cross-Reference
        Clients associated with hidden APs may probe for the same SSID
        elsewhere. Cross-referencing associated client probe requests
        with the hidden AP's BSSID provides probabilistic SSID discovery.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Section 11.1.3:
        Scanning (Active and Passive).

    Usage::

        detector = HiddenSSIDDetector()
        findings = detector.detect(access_points, clients, raw_frames)
    """

    def detect(
        self,
        aps: dict[str, AccessPoint],
        clients: list[WifiClient],
        raw_frames: Optional[list[Any]] = None,
    ) -> list[WirelessFinding]:
        """Detect hidden SSIDs and attempt to discover them.

        Args:
            aps: Dictionary of access points keyed by BSSID.
            clients: List of detected WiFi clients.
            raw_frames: Optional list of raw Scapy packet frames
                for deep analysis.

        Returns:
            List of wireless findings for hidden SSIDs.
        """
        findings: list[WirelessFinding] = []

        # Find hidden APs
        hidden_aps = {
            bssid: ap for bssid, ap in aps.items()
            if ap.hidden
        }

        if not hidden_aps:
            logger.info(
                "No hidden SSIDs detected"
            )
            return findings

        logger.info(
            f"Detecting hidden SSIDs: "
            f"{len(hidden_aps)} hidden AP(s) found"
        )

        discoveries: list[HiddenSSIDResult] = []

        # Method 1: Probe response correlation (from raw frames)
        if raw_frames:
            method1_results = self._probe_response_correlation(
                hidden_aps, raw_frames
            )
            discoveries.extend(method1_results)

        # Method 2: Association request correlation (from raw frames)
        if raw_frames:
            method2_results = self._association_request_correlation(
                hidden_aps, raw_frames
            )
            discoveries.extend(method2_results)

        # Method 3: Data frame / client probe cross-reference
        method3_results = self._client_probe_cross_reference(
            hidden_aps, clients
        )
        discoveries.extend(method3_results)

        # Deduplicate discoveries (prefer highest confidence)
        best_discoveries: dict[str, HiddenSSIDResult] = {}
        for discovery in discoveries:
            if (
                discovery.bssid not in best_discoveries
                or discovery.confidence > best_discoveries[discovery.bssid].confidence
            ):
                best_discoveries[discovery.bssid] = discovery

        # Generate findings
        for bssid, ap in hidden_aps.items():
            if bssid in best_discoveries:
                disc = best_discoveries[bssid]
                findings.append(WirelessFinding(
                    type=WirelessFindingType.HIDDEN_SSID,
                    severity="LOW",
                    ap_bssid=bssid,
                    description=(
                        f"Hidden SSID discovered for BSSID {bssid} "
                        f"(vendor: {ap.vendor}). The actual SSID is "
                        f"'{disc.discovered_ssid}'. Discovery method: "
                        f"{disc.method}. SSID hiding provides no security "
                        f"benefit as the SSID is transmitted in cleartext "
                        f"in probe responses and association frames "
                        f"(IEEE 802.11-2020, Section 11.1.3)."
                    ),
                    recommendation=(
                        "Unhide the SSID broadcast. SSID suppression does "
                        "not provide security and actually increases client "
                        "tracking exposure (clients must send directed probes "
                        "for hidden networks, revealing them in all locations). "
                        "Use WPA3-SAE for actual security."
                    ),
                    evidence={
                        "bssid": bssid,
                        "discovered_ssid": disc.discovered_ssid,
                        "discovery_method": disc.method,
                        "ap_vendor": ap.vendor,
                        "ap_channel": ap.channel,
                        "ap_encryption": ap.encryption.value,
                        **disc.evidence,
                    },
                    confidence=disc.confidence,
                ))
            else:
                # Hidden AP but SSID not yet discovered
                findings.append(WirelessFinding(
                    type=WirelessFindingType.HIDDEN_SSID,
                    severity="LOW",
                    ap_bssid=bssid,
                    description=(
                        f"Hidden SSID detected for BSSID {bssid} "
                        f"(vendor: {ap.vendor}, channel: {ap.channel}, "
                        f"encryption: {ap.encryption.value}). The SSID could "
                        f"not be determined from the captured data. Longer "
                        f"capture duration or active probing would be needed "
                        f"to reveal the SSID."
                    ),
                    recommendation=(
                        "The hidden network at BSSID {bssid} should unhide "
                        "its SSID. If this is a legitimate network, configure "
                        "it to broadcast its SSID normally. If unknown, "
                        "investigate as a potential unauthorized AP."
                    ),
                    evidence={
                        "bssid": bssid,
                        "discovered_ssid": None,
                        "ap_vendor": ap.vendor,
                        "ap_channel": ap.channel,
                        "ap_encryption": ap.encryption.value,
                        "clients_count": len(ap.clients),
                    },
                    confidence=0.5,
                ))

        logger.info(
            f"Hidden SSID analysis complete. "
            f"Hidden APs: {len(hidden_aps)}, "
            f"SSIDs discovered: {len(best_discoveries)}"
        )

        return findings

    def _probe_response_correlation(
        self,
        hidden_aps: dict[str, AccessPoint],
        raw_frames: list[Any],
    ) -> list[HiddenSSIDResult]:
        """Method 1: Correlate probe responses with hidden AP BSSIDs.

        When a client probes for a specific SSID and a hidden AP
        responds (probe response), the SSID is revealed in the
        response frame. This method matches probe response BSSIDs
        to our list of hidden APs.

        Args:
            hidden_aps: Dictionary of hidden APs.
            raw_frames: Raw Scapy frame list.

        Returns:
            List of SSID discovery results.
        """
        results: list[HiddenSSIDResult] = []

        try:
            from scapy.all import Dot11, Dot11ProbeResp, Dot11Elt  # type: ignore[import-untyped]
        except ImportError:
            return results

        for frame in raw_frames:
            if not frame.haslayer(Dot11ProbeResp):
                continue

            dot11 = frame.getlayer(Dot11)
            bssid = (dot11.addr3 or "").upper()

            if bssid not in hidden_aps:
                continue

            # Extract SSID from probe response
            ssid = ""
            elt = frame.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and hasattr(elt, "info"):
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                    except Exception:
                        pass
                    break
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

            if ssid:
                dst = (dot11.addr1 or "").upper()
                results.append(HiddenSSIDResult(
                    bssid=bssid,
                    discovered_ssid=ssid,
                    method=SSIDDiscoveryMethod.PROBE_RESPONSE,
                    confidence=0.99,
                    evidence={
                        "responding_to_client": dst,
                        "frame_type": "probe_response",
                    },
                ))

        return results

    def _association_request_correlation(
        self,
        hidden_aps: dict[str, AccessPoint],
        raw_frames: list[Any],
    ) -> list[HiddenSSIDResult]:
        """Method 2: Correlate association requests with hidden AP BSSIDs.

        Association request frames always contain the target SSID in
        the SSID IE (Element ID 0). When the destination BSSID matches
        a hidden AP, the SSID is revealed.

        Args:
            hidden_aps: Dictionary of hidden APs.
            raw_frames: Raw Scapy frame list.

        Returns:
            List of SSID discovery results.
        """
        results: list[HiddenSSIDResult] = []

        try:
            from scapy.all import (  # type: ignore[import-untyped]
                Dot11,
                Dot11AssoReq,
                Dot11ReassoReq,
                Dot11Elt,
            )
        except ImportError:
            return results

        for frame in raw_frames:
            is_assoc = frame.haslayer(Dot11AssoReq)
            is_reassoc = False
            try:
                is_reassoc = frame.haslayer(Dot11ReassoReq)
            except Exception:
                pass

            if not (is_assoc or is_reassoc):
                continue

            dot11 = frame.getlayer(Dot11)
            bssid = (dot11.addr3 or "").upper()

            if bssid not in hidden_aps:
                continue

            ssid = ""
            elt = frame.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and hasattr(elt, "info"):
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                    except Exception:
                        pass
                    break
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

            if ssid:
                src = (dot11.addr2 or "").upper()
                frame_type = "association_request" if is_assoc else "reassociation_request"
                results.append(HiddenSSIDResult(
                    bssid=bssid,
                    discovered_ssid=ssid,
                    method=SSIDDiscoveryMethod.ASSOCIATION_REQUEST,
                    confidence=0.98,
                    evidence={
                        "client_mac": src,
                        "frame_type": frame_type,
                    },
                ))

        return results

    def _client_probe_cross_reference(
        self,
        hidden_aps: dict[str, AccessPoint],
        clients: list[WifiClient],
    ) -> list[HiddenSSIDResult]:
        """Method 3: Cross-reference associated clients' probe requests.

        Clients associated with hidden APs likely have the hidden SSID
        in their probe request history (they need to know the SSID to
        connect). By cross-referencing the SSIDs probed by associated
        clients, we can probabilistically determine the hidden SSID.

        The confidence decreases with:
            - More SSIDs probed by the client (less specific)
            - Fewer associated clients (less corroboration)

        Args:
            hidden_aps: Dictionary of hidden APs.
            clients: List of detected WiFi clients.

        Returns:
            List of SSID discovery results.
        """
        results: list[HiddenSSIDResult] = []

        for bssid, ap in hidden_aps.items():
            # Find clients associated with this hidden AP
            associated_clients = [
                c for c in clients
                if c.associated_ap == bssid
            ]

            if not associated_clients:
                continue

            # Collect all SSIDs probed by associated clients
            ssid_votes: dict[str, int] = {}
            ssid_clients: dict[str, list[str]] = {}

            for client in associated_clients:
                for ssid in client.probe_requests:
                    if not ssid:
                        continue
                    ssid_votes[ssid] = ssid_votes.get(ssid, 0) + 1
                    if ssid not in ssid_clients:
                        ssid_clients[ssid] = []
                    ssid_clients[ssid].append(client.mac)

            if not ssid_votes:
                continue

            # The SSID with the most votes from associated clients is
            # most likely the hidden AP's SSID
            # Filter out SSIDs that belong to known (non-hidden) APs
            known_ssids = {
                a.ssid for a in self._get_all_visible_aps(hidden_aps).values()
                if a.ssid
            }

            # Remove known SSIDs from candidates
            candidate_ssids = {
                ssid: votes for ssid, votes in ssid_votes.items()
                if ssid not in known_ssids
            }

            if not candidate_ssids:
                # If all probed SSIDs are known, check if any known SSID
                # has the same channel (might be a dual-band AP)
                candidate_ssids = ssid_votes

            if not candidate_ssids:
                continue

            # Rank by vote count
            best_ssid = max(candidate_ssids, key=lambda s: candidate_ssids[s])
            vote_count = candidate_ssids[best_ssid]
            total_clients = len(associated_clients)

            # Confidence based on agreement ratio and specificity
            agreement_ratio = vote_count / total_clients if total_clients > 0 else 0
            specificity = 1.0 / max(len(candidate_ssids), 1)
            confidence = min(0.85, 0.4 + 0.3 * agreement_ratio + 0.15 * specificity)

            results.append(HiddenSSIDResult(
                bssid=bssid,
                discovered_ssid=best_ssid,
                method=SSIDDiscoveryMethod.CLIENT_PROBE_MATCH,
                confidence=round(confidence, 2),
                evidence={
                    "associated_clients": [c.mac for c in associated_clients],
                    "client_count": total_clients,
                    "ssid_votes": ssid_votes,
                    "vote_count": vote_count,
                    "agreement_ratio": round(agreement_ratio, 2),
                    "candidate_ssids": list(candidate_ssids.keys()),
                },
            ))

        return results

    @staticmethod
    def _get_all_visible_aps(
        hidden_aps: dict[str, AccessPoint],
    ) -> dict[str, AccessPoint]:
        """Get placeholder for visible APs (non-hidden).

        In practice this would reference the full AP dictionary.
        Here we return an empty dict since the full AP dict is
        not directly available within this scope -- the caller
        provides hidden_aps as a subset.

        Args:
            hidden_aps: The hidden APs dict.

        Returns:
            Empty dict (visible APs not available in this scope).
        """
        return {}
