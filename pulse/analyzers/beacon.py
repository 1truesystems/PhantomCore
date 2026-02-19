"""
Pulse WiFi Beacon Analyzer
============================

Analyses WiFi access point beacon information to assess network
security configuration. Assigns letter grades (A through F) based on
encryption protocol, cipher suite, authentication method, Protected
Management Frames (PMF) status, and Wi-Fi Protected Setup (WPS) state.

This module specifically analyses WiFi beacon frames and is distinct
from the Spectra beacon detection module which focuses on C2 heartbeat
patterns.

Security grading follows the Wi-Fi Alliance's security certification
hierarchy, with WPA3-SAE representing the strongest consumer-grade
protection and Open/WEP representing the weakest.

References:
    - Wi-Fi Alliance. (2018). WPA3 Specification v1.0.
    - Wi-Fi Alliance. (2020). WPA3 Security Considerations.
    - Vanhoef, M., & Piessens, F. (2017). Key Reinstallation Attacks:
      Forcing Nonce Reuse in WPA2. CCS '17.
    - Viehbock, S. (2011). Brute Forcing Wi-Fi Protected Setup.
      https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf
    - IEEE. (2020). IEEE Std 802.11-2020. Section 12: Security.
    - IEEE. (2009). IEEE Std 802.11w-2009: Protected Management Frames.
"""

from __future__ import annotations

from typing import Optional

from shared.logger import PhantomLogger

from pulse.core.models import (
    AccessPoint,
    AuthKeyMgmt,
    CipherSuite,
    DEFAULT_SSID_PATTERNS,
    EncryptionType,
    SecurityGrade,
    WirelessFinding,
    WirelessFindingType,
)

logger = PhantomLogger("pulse.analyzers.beacon")


# ---------------------------------------------------------------------------
# Grading constants
# ---------------------------------------------------------------------------

_GRADE_SCORES: dict[str, int] = {
    "A+": 100,
    "A": 95,
    "A-": 90,
    "B+": 85,
    "B": 80,
    "B-": 75,
    "C+": 70,
    "C": 65,
    "C-": 60,
    "D+": 55,
    "D": 50,
    "D-": 45,
    "F": 20,
}


# ---------------------------------------------------------------------------
# Beacon Analyzer
# ---------------------------------------------------------------------------


class BeaconAnalyzer:
    """Analyses WiFi beacon frames to grade network security.

    Evaluates each access point's security posture and assigns a
    letter grade from A (strongest) to F (weakest) based on:

        A: WPA3-SAE + PMF + no WPS (best practice)
        B: WPA2-CCMP + PMF (strong)
        C+: WPA2-CCMP without PMF (adequate)
        C: WPA2-TKIP (acceptable but outdated cipher)
        D: WPA (TKIP only, legacy)
        F: WEP or Open (critically insecure)

    Additional deductions apply for:
        - WPS enabled (PIN attack vulnerability)
        - Hidden SSID (false sense of security)
        - Default SSID pattern (unconfigured network)
        - Non-standard beacon interval
        - Weak cipher usage alongside strong cipher

    Reference:
        Wi-Fi Alliance. (2020). WPA3 Security Considerations.

    Usage::

        analyzer = BeaconAnalyzer()
        graded_aps = analyzer.analyze(access_points)
    """

    def analyze(
        self, aps: dict[str, AccessPoint]
    ) -> list[tuple[AccessPoint, SecurityGrade]]:
        """Analyze all access points and assign security grades.

        Args:
            aps: Dictionary of access points keyed by BSSID.

        Returns:
            List of (AccessPoint, SecurityGrade) tuples sorted by
            grade (worst first) for priority-based reporting.
        """
        results: list[tuple[AccessPoint, SecurityGrade]] = []

        for bssid, ap in aps.items():
            grade = self._grade_ap(ap)
            results.append((ap, grade))

        # Sort by score ascending (worst grade first)
        results.sort(key=lambda x: x[1].score)

        logger.info(
            f"Beacon analysis complete. "
            f"Graded {len(results)} access points."
        )

        return results

    def analyze_to_findings(
        self, aps: dict[str, AccessPoint]
    ) -> list[WirelessFinding]:
        """Analyze access points and return findings.

        This is a convenience method that converts grades into
        WirelessFinding objects for unified reporting.

        Args:
            aps: Dictionary of access points keyed by BSSID.

        Returns:
            List of wireless security findings.
        """
        findings: list[WirelessFinding] = []
        graded = self.analyze(aps)

        for ap, grade in graded:
            # Generate findings for issues
            for issue in grade.issues:
                finding = self._issue_to_finding(ap, grade, issue)
                if finding:
                    findings.append(finding)

        return findings

    def _grade_ap(self, ap: AccessPoint) -> SecurityGrade:
        """Assign a security grade to a single access point.

        The grading algorithm evaluates the protocol stack from
        strongest to weakest:

        1. Base grade from encryption + cipher + AKM
        2. PMF bonus/penalty
        3. WPS penalty
        4. Hidden SSID notation
        5. Default SSID penalty
        6. Beacon interval anomaly check

        Args:
            ap: Access point to grade.

        Returns:
            SecurityGrade with letter grade, issues, and recommendations.
        """
        issues: list[str] = []
        recommendations: list[str] = []
        protocol_desc = f"{ap.encryption.value}"

        if ap.cipher != CipherSuite.NONE:
            protocol_desc += f" / {ap.cipher.value}"
        if ap.auth != AuthKeyMgmt.UNKNOWN:
            protocol_desc += f" / {ap.auth.value}"

        # -----------------------------------------------------------------
        # Step 1: Base grade from encryption + cipher + AKM
        # -----------------------------------------------------------------

        if ap.encryption == EncryptionType.WPA3:
            if ap.auth in (AuthKeyMgmt.SAE, AuthKeyMgmt.FT_SAE):
                if ap.cipher in (CipherSuite.GCMP_256, CipherSuite.CCMP_256):
                    base_grade = "A+"
                else:
                    base_grade = "A"
            elif ap.auth == AuthKeyMgmt.OWE:
                # OWE (Opportunistic Wireless Encryption) is WPA3 Open
                base_grade = "B+"
                issues.append(
                    "OWE provides encryption without authentication; "
                    "susceptible to active attacks"
                )
            else:
                base_grade = "A-"

        elif ap.encryption == EncryptionType.WPA2_WPA3:
            # Transition mode: supports both WPA2 and WPA3 clients
            base_grade = "A-"
            issues.append(
                "WPA2/WPA3 transition mode allows WPA2 connections "
                "which may be vulnerable to KRACK attacks (Vanhoef, 2017)"
            )
            recommendations.append(
                "Consider disabling WPA2 compatibility once all "
                "clients support WPA3-SAE"
            )

        elif ap.encryption == EncryptionType.WPA2:
            if ap.cipher == CipherSuite.CCMP:
                base_grade = "C+"
            elif ap.cipher == CipherSuite.GCMP:
                base_grade = "C+"
            elif ap.cipher == CipherSuite.TKIP:
                base_grade = "C"
                issues.append(
                    "TKIP cipher is deprecated; vulnerable to "
                    "Beck-Tews (2008) and Ohigashi-Morii (2009) attacks"
                )
                recommendations.append(
                    "Switch from TKIP to CCMP (AES) cipher suite"
                )
            else:
                base_grade = "C"

        elif ap.encryption == EncryptionType.WPA:
            base_grade = "D"
            issues.append(
                "WPA (first generation) uses RC4-based TKIP which has "
                "known cryptographic weaknesses"
            )
            recommendations.append(
                "Upgrade to WPA2-CCMP or preferably WPA3-SAE"
            )

        elif ap.encryption == EncryptionType.WEP:
            base_grade = "F"
            issues.append(
                "WEP is critically broken. The Fluhrer-Mantin-Shamir (FMS) "
                "attack (2001) and PTW attack (Pyshkin-Tews-Weinmann, 2007) "
                "can recover WEP keys in minutes from passive capture"
            )
            recommendations.append(
                "Immediately upgrade to WPA2-CCMP or WPA3-SAE. "
                "WEP provides no meaningful security"
            )

        elif ap.encryption == EncryptionType.OPEN:
            base_grade = "F"
            issues.append(
                "Open network without encryption. All traffic is transmitted "
                "in cleartext and is trivially interceptable"
            )
            recommendations.append(
                "Enable WPA2-CCMP or WPA3-SAE encryption. If open access "
                "is required, use WPA3-OWE (Enhanced Open) for opportunistic "
                "encryption"
            )

        else:
            base_grade = "C"

        # -----------------------------------------------------------------
        # Step 2: PMF (Protected Management Frames) evaluation
        # -----------------------------------------------------------------

        if ap.pmf:
            # PMF provides protection against deauth/disassoc attacks
            if base_grade in ("C+", "C"):
                base_grade = "B"  # Upgrade for PMF
            elif base_grade == "B-":
                base_grade = "B"
        else:
            if ap.encryption in (
                EncryptionType.WPA2, EncryptionType.WPA2_WPA3
            ):
                issues.append(
                    "Protected Management Frames (PMF/802.11w) not enabled. "
                    "Network is vulnerable to deauthentication attacks"
                )
                recommendations.append(
                    "Enable PMF (Management Frame Protection) in AP settings. "
                    "PMF protects against deauth-based denial of service and "
                    "is required for WPA3 certification"
                )
            if ap.encryption == EncryptionType.WPA3 and not ap.pmf:
                # WPA3 requires PMF; if missing, something is wrong
                issues.append(
                    "WPA3 without PMF is non-compliant with the WPA3 specification"
                )

        # -----------------------------------------------------------------
        # Step 3: WPS (Wi-Fi Protected Setup) penalty
        # -----------------------------------------------------------------

        if ap.wps_enabled:
            issues.append(
                "WPS (Wi-Fi Protected Setup) is enabled. The WPS PIN "
                "mechanism is vulnerable to brute-force attack due to "
                "design flaws that reduce the effective PIN space from "
                "10^8 to 10^4 + 10^3 attempts (Viehbock, 2011)"
            )
            recommendations.append(
                "Disable WPS in the access point configuration. Use "
                "WPA2/WPA3 passphrase or 802.1X for secure onboarding"
            )
            # Deduct one sub-grade for WPS
            grade_order = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]
            try:
                idx = grade_order.index(base_grade)
                if idx < len(grade_order) - 1:
                    base_grade = grade_order[min(idx + 1, len(grade_order) - 1)]
            except ValueError:
                pass

        # -----------------------------------------------------------------
        # Step 4: Hidden SSID
        # -----------------------------------------------------------------

        if ap.hidden:
            issues.append(
                "Hidden SSID (SSID broadcast suppressed). This provides "
                "no real security benefit as the SSID is revealed in "
                "probe responses, association requests, and data frames. "
                "It may cause clients to probe actively, increasing "
                "their tracking exposure"
            )
            recommendations.append(
                "Unhide the SSID. Rely on strong encryption (WPA3-SAE) "
                "rather than SSID hiding for security"
            )

        # -----------------------------------------------------------------
        # Step 5: Default SSID detection
        # -----------------------------------------------------------------

        if self._is_default_ssid(ap.ssid):
            issues.append(
                f"SSID '{ap.ssid}' matches a common default/manufacturer "
                f"pattern, suggesting the network may be unconfigured. "
                f"Default configurations often use weak passwords or "
                f"known password generation algorithms"
            )
            recommendations.append(
                "Change the SSID to a unique, non-identifying name. "
                "Change the password from the default value. Update "
                "the firmware to the latest version"
            )

        # -----------------------------------------------------------------
        # Step 6: Beacon interval anomaly
        # -----------------------------------------------------------------

        if ap.beacon_interval != 100 and ap.beacon_interval > 0:
            if ap.beacon_interval < 50:
                issues.append(
                    f"Unusually short beacon interval ({ap.beacon_interval} TU). "
                    "Standard is 100 TU. Very short intervals may indicate "
                    "a rogue AP or misconfiguration"
                )
            elif ap.beacon_interval > 1000:
                issues.append(
                    f"Very long beacon interval ({ap.beacon_interval} TU). "
                    "This may cause slow network discovery and association "
                    "delays for clients"
                )

        # -----------------------------------------------------------------
        # Step 7: AKM-specific notes
        # -----------------------------------------------------------------

        if ap.auth == AuthKeyMgmt.IEEE_802_1X:
            recommendations.append(
                "Enterprise (802.1X) authentication is in use. Ensure "
                "the RADIUS server certificate is properly validated "
                "by clients to prevent evil-twin attacks"
            )
        elif ap.auth == AuthKeyMgmt.PSK and ap.encryption != EncryptionType.WPA:
            recommendations.append(
                "Use a strong passphrase (12+ characters with mixed case, "
                "numbers, and symbols) or consider migrating to WPA3-SAE "
                "which provides protection against offline dictionary attacks"
            )

        # Build final grade
        score = _GRADE_SCORES.get(base_grade, 50)

        return SecurityGrade(
            grade=base_grade,
            protocol=protocol_desc,
            issues=issues,
            recommendations=recommendations,
            score=score,
        )

    @staticmethod
    def _is_default_ssid(ssid: str) -> bool:
        """Check if an SSID matches known default/manufacturer patterns.

        Args:
            ssid: SSID string to check.

        Returns:
            True if the SSID appears to be a default or manufacturer name.
        """
        if not ssid:
            return False

        ssid_lower = ssid.lower().strip()

        for pattern in DEFAULT_SSID_PATTERNS:
            if ssid_lower == pattern.lower():
                return True
            # Check if SSID is pattern + numbers (e.g., "NETGEAR-5G-1234")
            if ssid_lower.startswith(pattern.lower()):
                remainder = ssid_lower[len(pattern):]
                if not remainder or remainder.lstrip("-_ ").isdigit():
                    return True
                # Check for pattern-XG format (e.g., "NETGEAR-5G")
                stripped = remainder.lstrip("-_ ")
                if stripped in ("2g", "5g", "2.4g", "5g", "6g", "guest", "ext"):
                    return True

        return False

    @staticmethod
    def _issue_to_finding(
        ap: AccessPoint,
        grade: SecurityGrade,
        issue: str,
    ) -> Optional[WirelessFinding]:
        """Convert a security issue string into a WirelessFinding.

        Args:
            ap: The access point with the issue.
            grade: The security grade containing the issue.
            issue: Issue description string.

        Returns:
            WirelessFinding or None if the issue is informational only.
        """
        # Map issue keywords to finding types and severities
        issue_lower = issue.lower()

        if "wep" in issue_lower and "broken" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.WEAK_ENCRYPTION,
                severity="CRITICAL",
                ap_bssid=ap.bssid,
                description=f"[{ap.ssid or ap.bssid}] {issue}",
                recommendation=grade.recommendations[0] if grade.recommendations else "",
                evidence={
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "encryption": ap.encryption.value,
                    "grade": grade.grade,
                },
                confidence=1.0,
            )

        if "open network" in issue_lower or "cleartext" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.OPEN_NETWORK,
                severity="CRITICAL",
                ap_bssid=ap.bssid,
                description=f"[{ap.ssid or ap.bssid}] {issue}",
                recommendation=grade.recommendations[0] if grade.recommendations else "",
                evidence={
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "encryption": ap.encryption.value,
                    "grade": grade.grade,
                },
                confidence=1.0,
            )

        if "wps" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.WPS_ENABLED,
                severity="HIGH",
                ap_bssid=ap.bssid,
                description=f"[{ap.ssid or ap.bssid}] {issue}",
                recommendation=(
                    grade.recommendations[0] if grade.recommendations else
                    "Disable WPS in access point settings"
                ),
                evidence={
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "wps_enabled": True,
                    "grade": grade.grade,
                },
                confidence=0.95,
            )

        if "pmf" in issue_lower or "management frame" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.NO_PMF,
                severity="MEDIUM",
                ap_bssid=ap.bssid,
                description=f"[{ap.ssid or ap.bssid}] {issue}",
                recommendation="Enable PMF (802.11w) in access point configuration",
                evidence={
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "pmf": False,
                    "grade": grade.grade,
                },
                confidence=0.95,
            )

        if "hidden ssid" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.HIDDEN_SSID,
                severity="LOW",
                ap_bssid=ap.bssid,
                description=f"[{ap.bssid}] {issue}",
                recommendation="Unhide the SSID and rely on strong encryption",
                evidence={
                    "bssid": ap.bssid,
                    "hidden": True,
                    "grade": grade.grade,
                },
                confidence=0.9,
            )

        if "default" in issue_lower and "ssid" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.DEFAULT_SSID,
                severity="LOW",
                ap_bssid=ap.bssid,
                description=f"[{ap.ssid}] {issue}",
                recommendation="Change the SSID and password from defaults",
                evidence={
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "grade": grade.grade,
                },
                confidence=0.8,
            )

        if "tkip" in issue_lower and "deprecated" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.WEAK_ENCRYPTION,
                severity="MEDIUM",
                ap_bssid=ap.bssid,
                description=f"[{ap.ssid or ap.bssid}] {issue}",
                recommendation="Switch to CCMP (AES) cipher suite",
                evidence={
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "cipher": ap.cipher.value,
                    "grade": grade.grade,
                },
                confidence=0.95,
            )

        if "wpa" in issue_lower and "first generation" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.WEAK_ENCRYPTION,
                severity="HIGH",
                ap_bssid=ap.bssid,
                description=f"[{ap.ssid or ap.bssid}] {issue}",
                recommendation="Upgrade to WPA2-CCMP or WPA3-SAE",
                evidence={
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "encryption": ap.encryption.value,
                    "grade": grade.grade,
                },
                confidence=0.95,
            )

        if "beacon interval" in issue_lower:
            return WirelessFinding(
                type=WirelessFindingType.ANOMALOUS_BEACON,
                severity="LOW",
                ap_bssid=ap.bssid,
                description=f"[{ap.ssid or ap.bssid}] {issue}",
                recommendation="Set beacon interval to the standard 100 TU",
                evidence={
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "beacon_interval": ap.beacon_interval,
                    "grade": grade.grade,
                },
                confidence=0.7,
            )

        # Generic finding for unmatched issues
        severity = "LOW"
        if grade.score < 50:
            severity = "HIGH"
        elif grade.score < 70:
            severity = "MEDIUM"

        return WirelessFinding(
            type=WirelessFindingType.WEAK_ENCRYPTION,
            severity=severity,
            ap_bssid=ap.bssid,
            description=f"[{ap.ssid or ap.bssid}] {issue}",
            recommendation=grade.recommendations[0] if grade.recommendations else "",
            evidence={
                "bssid": ap.bssid,
                "ssid": ap.ssid,
                "grade": grade.grade,
                "score": grade.score,
            },
            confidence=0.8,
        )
