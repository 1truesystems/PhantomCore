"""
Pulse Probe Request Analyzer
==============================

Analyses client probe request behaviour to assess privacy risks,
detect device fingerprinting vulnerabilities, and identify MAC
address randomization patterns.

Probe requests are management frames (type=0, subtype=4) that clients
transmit to discover available networks. They may reveal:
    - Location history (via SSID list)
    - Device identity (via real MAC addresses)
    - Device type (via supported rates and capabilities)
    - User behaviour patterns (via probe frequency and timing)

References:
    - Vanhoef, M., Matte, C., Cunche, M., Cardoso, L. S., & Piessens, F.
      (2016). Why MAC Address Randomization is Not Enough: An Analysis of
      Wi-Fi Probe Requests. AsiaCCS '16.
    - Cunche, M. (2014). I know your MAC address: targeted tracking of
      individual using Wi-Fi. Journal of Computer Virology and Hacking
      Techniques, 10(4), 219-227.
    - Martin, J., Mayberry, T., Donahue, C., Foppe, L., Brown, L.,
      Riggins, C., Rye, E. C., & Brown, D. (2017). A Study of MAC Address
      Randomization in Mobile Devices and When it Fails. PoPETs 2017(4).
    - IEEE. (2020). IEEE Std 802.11-2020. Section 11.1.3: Scanning.
"""

from __future__ import annotations

from typing import Optional

from shared.logger import PhantomLogger

from pulse.core.models import (
    OUI_DATABASE,
    WifiClient,
    WirelessFinding,
    WirelessFindingType,
)

logger = PhantomLogger("pulse.analyzers.probe")


# ---------------------------------------------------------------------------
# Known location-sensitive SSID patterns
# ---------------------------------------------------------------------------

LOCATION_SENSITIVE_PATTERNS: list[str] = [
    "airport", "hotel", "hospital", "school", "university", "library",
    "starbucks", "mcdonalds", "subway", "bus", "train", "station",
    "lounge", "clinic", "office", "company", "corp", "bank", "atm",
    "church", "mosque", "temple", "gym", "fitness", "spa", "cafe",
    "restaurant", "bar", "pub", "club", "mall", "shop", "store",
    "home", "house", "apartment", "flat", "residence",
]


# ---------------------------------------------------------------------------
# Probe Analyzer
# ---------------------------------------------------------------------------


class ProbeAnalyzer:
    """Analyses WiFi client probe request patterns for privacy risks.

    Evaluates each client's probe request behaviour to determine:
        - Whether real MAC addresses are exposed (tracking risk)
        - How many SSIDs are probed (location history leakage)
        - Whether location-sensitive SSIDs are present
        - MAC randomization adoption and effectiveness
        - Device fingerprinting susceptibility

    Reference:
        Vanhoef, M., et al. (2016). Why MAC Address Randomization is
        Not Enough: An Analysis of Wi-Fi Probe Requests. AsiaCCS.

    Usage::

        analyzer = ProbeAnalyzer()
        findings = analyzer.analyze(clients)
    """

    def __init__(
        self,
        *,
        excessive_probe_threshold: int = 5,
        location_risk_threshold: int = 2,
    ) -> None:
        """Initialize the probe analyzer.

        Args:
            excessive_probe_threshold: Number of unique SSIDs that
                constitutes excessive probing.
            location_risk_threshold: Number of location-sensitive SSIDs
                that triggers a location history finding.
        """
        self._excessive_threshold = excessive_probe_threshold
        self._location_threshold = location_risk_threshold

    def analyze(self, clients: list[WifiClient]) -> list[WirelessFinding]:
        """Analyze probe request patterns for all clients.

        Args:
            clients: List of detected WiFi clients with probe data.

        Returns:
            List of wireless findings describing privacy risks.
        """
        findings: list[WirelessFinding] = []

        if not clients:
            return findings

        # Aggregate statistics
        total_clients = len(clients)
        randomized_count = sum(1 for c in clients if c.is_randomized_mac)
        real_mac_count = total_clients - randomized_count

        logger.info(
            f"Probe analysis: {total_clients} clients, "
            f"{randomized_count} randomized MACs, {real_mac_count} real MACs"
        )

        # Per-client analysis
        for client in clients:
            client_findings = self._analyze_client(client)
            findings.extend(client_findings)

        # Environment-level analysis
        env_findings = self._analyze_environment(clients)
        findings.extend(env_findings)

        logger.info(
            f"Probe analysis complete. "
            f"Findings: {len(findings)}"
        )

        return findings

    def _analyze_client(self, client: WifiClient) -> list[WirelessFinding]:
        """Analyze a single client's probe behaviour.

        Args:
            client: WiFi client to analyze.

        Returns:
            List of findings for this client.
        """
        findings: list[WirelessFinding] = []

        # 1. Real MAC tracking risk
        if not client.is_randomized_mac and client.probe_requests:
            findings.append(WirelessFinding(
                type=WirelessFindingType.MAC_TRACKING,
                severity="MEDIUM",
                client_mac=client.mac,
                description=(
                    f"Client {client.mac} ({client.vendor}) is using a "
                    f"real (globally unique) MAC address while probing for "
                    f"{len(client.probe_requests)} network(s). This enables "
                    f"persistent device tracking across locations and time. "
                    f"The locally-administered bit (bit 1 of first octet) is "
                    f"not set, indicating a factory-assigned address."
                ),
                recommendation=(
                    "Enable MAC address randomization in device WiFi settings. "
                    "Modern operating systems (iOS 14+, Android 10+, Windows 10+) "
                    "support per-network randomized MAC addresses. Disable WiFi "
                    "scanning when not actively connecting to networks."
                ),
                evidence={
                    "mac": client.mac,
                    "vendor": client.vendor,
                    "is_randomized": False,
                    "probe_count": len(client.probe_requests),
                    "probed_ssids": client.probe_requests,
                },
                confidence=0.95,
            ))

        # 2. Excessive probing (location history leak)
        if len(client.probe_requests) >= self._excessive_threshold:
            findings.append(WirelessFinding(
                type=WirelessFindingType.PROBE_LEAK,
                severity="MEDIUM" if len(client.probe_requests) < 10 else "HIGH",
                client_mac=client.mac,
                description=(
                    f"Client {client.mac} is probing for "
                    f"{len(client.probe_requests)} unique SSIDs: "
                    f"{', '.join(client.probe_requests[:10])}"
                    f"{'...' if len(client.probe_requests) > 10 else ''}. "
                    f"Each probed SSID reveals a network the device has "
                    f"previously connected to, exposing the user's "
                    f"movement history and frequently visited locations."
                ),
                recommendation=(
                    "Remove saved networks that are no longer needed. "
                    "Disable 'Auto-Join' for public/temporary networks. "
                    "Use a VPN when connecting to public WiFi. On iOS, "
                    "use 'Forget This Network' for old connections. On "
                    "Android, manage saved networks in WiFi settings."
                ),
                evidence={
                    "mac": client.mac,
                    "ssid_count": len(client.probe_requests),
                    "ssids": client.probe_requests,
                },
                confidence=0.9,
            ))

        # 3. Location-sensitive SSID detection
        sensitive_ssids = self._find_location_sensitive_ssids(
            client.probe_requests
        )
        if len(sensitive_ssids) >= self._location_threshold:
            findings.append(WirelessFinding(
                type=WirelessFindingType.PROBE_LEAK,
                severity="HIGH",
                client_mac=client.mac,
                description=(
                    f"Client {client.mac} is probing for "
                    f"{len(sensitive_ssids)} location-sensitive SSIDs: "
                    f"{', '.join(sensitive_ssids)}. These network names "
                    f"reveal specific types of locations the user visits "
                    f"(e.g., hotels, airports, hospitals, workplaces), "
                    f"enabling targeted social engineering or physical "
                    f"surveillance."
                ),
                recommendation=(
                    "Remove saved WiFi networks for sensitive locations. "
                    "Use a generic network name for home WiFi. Avoid "
                    "connecting to networks with identifying names. "
                    "Enable MAC randomization and disable auto-join."
                ),
                evidence={
                    "mac": client.mac,
                    "sensitive_ssids": sensitive_ssids,
                    "all_ssids": client.probe_requests,
                },
                confidence=0.85,
            ))

        # 4. Randomized MAC with identifiable probes
        if client.is_randomized_mac and len(client.probe_requests) >= 3:
            # Even with randomized MAC, unique probe fingerprints
            # can be used for re-identification
            findings.append(WirelessFinding(
                type=WirelessFindingType.PROBE_LEAK,
                severity="LOW",
                client_mac=client.mac,
                description=(
                    f"Client {client.mac} uses a randomized MAC but probes "
                    f"for {len(client.probe_requests)} unique SSIDs. Research "
                    f"by Vanhoef et al. (2016) shows that the combination of "
                    f"probed SSIDs creates a fingerprint that can re-identify "
                    f"devices despite MAC randomization. The probe fingerprint "
                    f"[{', '.join(client.probe_requests[:5])}] may be unique "
                    f"enough for tracking."
                ),
                recommendation=(
                    "Minimize the number of saved WiFi networks. "
                    "Use Preferred Network Offload (PNO) scanning which "
                    "only probes for a subset of saved networks. Disable "
                    "WiFi when not in use."
                ),
                evidence={
                    "mac": client.mac,
                    "is_randomized": True,
                    "probe_fingerprint": client.probe_requests,
                    "fingerprint_size": len(client.probe_requests),
                },
                confidence=0.7,
            ))

        return findings

    def _analyze_environment(
        self, clients: list[WifiClient]
    ) -> list[WirelessFinding]:
        """Analyze the overall probe environment.

        Args:
            clients: All detected WiFi clients.

        Returns:
            Environment-level findings.
        """
        findings: list[WirelessFinding] = []

        total = len(clients)
        if total == 0:
            return findings

        randomized = sum(1 for c in clients if c.is_randomized_mac)
        real = total - randomized
        randomization_ratio = randomized / total if total > 0 else 0.0

        # Compute overall probe statistics
        all_probed_ssids: list[str] = []
        for client in clients:
            all_probed_ssids.extend(client.probe_requests)
        unique_ssids = set(all_probed_ssids)

        # Report MAC randomization adoption
        findings.append(WirelessFinding(
            type=WirelessFindingType.MAC_TRACKING,
            severity="INFO",
            description=(
                f"MAC randomization adoption: {randomized}/{total} "
                f"({randomization_ratio:.0%}) of detected clients use "
                f"randomized (locally administered) MAC addresses. "
                f"{real} client(s) expose their real hardware MAC. "
                f"Reference: Martin et al. (2017) found that MAC "
                f"randomization adoption varies significantly by OS "
                f"version and manufacturer."
            ),
            recommendation=(
                "Organizations should educate users about enabling "
                "MAC randomization. Network administrators should "
                "avoid relying on MAC addresses for device identification "
                "or access control."
            ),
            evidence={
                "total_clients": total,
                "randomized_clients": randomized,
                "real_mac_clients": real,
                "randomization_ratio": round(randomization_ratio, 3),
                "unique_probed_ssids": len(unique_ssids),
                "total_probes": len(all_probed_ssids),
            },
            confidence=1.0,
        ))

        # Report high-risk real MAC clients
        high_risk_clients = [
            c for c in clients
            if not c.is_randomized_mac and len(c.probe_requests) >= 3
        ]
        if high_risk_clients:
            client_details = []
            for c in high_risk_clients[:10]:
                client_details.append({
                    "mac": c.mac,
                    "vendor": c.vendor,
                    "ssids_probed": len(c.probe_requests),
                })

            findings.append(WirelessFinding(
                type=WirelessFindingType.MAC_TRACKING,
                severity="HIGH" if len(high_risk_clients) > 3 else "MEDIUM",
                description=(
                    f"{len(high_risk_clients)} client(s) are transmitting "
                    f"real MAC addresses while actively probing for multiple "
                    f"networks. These devices are highly trackable and their "
                    f"users' location histories can be reconstructed from "
                    f"probe request logs. Cunche (2014) demonstrated that "
                    f"probe requests can be used for targeted individual "
                    f"tracking."
                ),
                recommendation=(
                    "Prioritize MAC randomization on these devices. "
                    "Reduce saved network lists. Consider using WiFi "
                    "only when actively needed."
                ),
                evidence={
                    "high_risk_count": len(high_risk_clients),
                    "clients": client_details,
                },
                confidence=0.9,
            ))

        return findings

    @staticmethod
    def _find_location_sensitive_ssids(ssids: list[str]) -> list[str]:
        """Identify SSIDs that suggest specific location types.

        Args:
            ssids: List of SSID strings to check.

        Returns:
            Subset of SSIDs matching location-sensitive patterns.
        """
        sensitive: list[str] = []
        for ssid in ssids:
            ssid_lower = ssid.lower()
            for pattern in LOCATION_SENSITIVE_PATTERNS:
                if pattern in ssid_lower:
                    sensitive.append(ssid)
                    break
        return sensitive

    @staticmethod
    def lookup_vendor(mac: str) -> str:
        """Look up the vendor for a MAC address.

        Args:
            mac: MAC address in colon-separated format.

        Returns:
            Vendor name or "Unknown".
        """
        if not mac or len(mac) < 8:
            return "Unknown"
        prefix = mac[:8].upper()
        return OUI_DATABASE.get(prefix, "Unknown")

    @staticmethod
    def fingerprint_device(client: WifiClient) -> dict[str, any]:
        """Generate a device fingerprint from probe request behaviour.

        Creates a fingerprint combining:
            - Vendor (from OUI)
            - Probe request SSID set
            - MAC randomization usage
            - Signal strength pattern

        This fingerprint can be used to re-identify devices across
        observations even when MAC addresses change.

        Reference:
            Vanhoef, M., et al. (2016). Why MAC Address Randomization
            is Not Enough. Section 4: Device Fingerprinting.

        Args:
            client: WiFi client to fingerprint.

        Returns:
            Dictionary describing the device fingerprint.
        """
        # Sort SSIDs for consistent fingerprint
        sorted_ssids = sorted(set(client.probe_requests))

        # Create a hash-like fingerprint string
        fingerprint_components = [
            f"vendor={client.vendor}",
            f"randomized={client.is_randomized_mac}",
            f"ssids={','.join(sorted_ssids)}",
        ]
        fingerprint_str = "|".join(fingerprint_components)

        return {
            "mac": client.mac,
            "vendor": client.vendor,
            "is_randomized": client.is_randomized_mac,
            "probed_ssids": sorted_ssids,
            "ssid_count": len(sorted_ssids),
            "fingerprint": fingerprint_str,
            "uniqueness_estimate": min(1.0, len(sorted_ssids) * 0.15),
        }
