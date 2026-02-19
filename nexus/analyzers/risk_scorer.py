"""
Risk Scorer
============

Weighted multi-factor risk scoring engine that synthesises vulnerability
severity, exploitation probability, attack surface exposure, asset
criticality, and network accessibility into a single risk score with
a qualitative risk level classification.

The scoring methodology follows the NIST SP 800-30 risk assessment
framework, adapted for automated computation with quantitative inputs
from the Nexus analysis pipeline.

Scoring Formula:
    RiskScore = sum(weight_i * normalised_factor_i) for i in factors

Factor Weights:
    - Vulnerability Severity:  0.30 (max CVSS score * 10)
    - Exploit Availability:    0.25 (exploit_probability * 100)
    - Attack Surface:          0.20 (surface_score from graph analysis)
    - Asset Criticality:       0.15 (configurable per assessment)
    - Network Exposure:        0.10 (network accessibility metric)

Risk Levels:
    - Critical: 80-100 (immediate action required)
    - High:     60-79  (urgent remediation needed)
    - Medium:   40-59  (scheduled remediation)
    - Low:      20-39  (accept or monitor)
    - Info:      0-19  (informational, no action needed)

References:
    - NIST. (2012). SP 800-30 Rev. 1: Guide for Conducting Risk
      Assessments. National Institute of Standards and Technology.
    - OWASP. (2021). Risk Rating Methodology.
      https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
    - ISO/IEC 27005:2022. Information Security Risk Management.
"""

from __future__ import annotations

from typing import Any, Optional

from shared.models import Finding, Risk, RiskLevel, Severity

from nexus.core.models import (
    CVERecord,
    IoC,
    ThreatAssessment,
)


class RiskScorer:
    """Weighted multi-factor risk scoring engine.

    Combines five risk dimensions into a normalised risk score (0-100)
    and maps it to a qualitative risk level. Generates prioritised
    recommendations based on the highest-contributing factors.

    Attributes:
        weights: Dictionary of factor name to weight value.
        asset_criticality: Default asset criticality (0-100).

    Usage::

        scorer = RiskScorer()
        risk = scorer.score(threat_assessment)
        print(f"Risk: {risk}  ({scorer.last_score}/100)")
    """

    # Default factor weights (must sum to 1.0)
    DEFAULT_WEIGHTS: dict[str, float] = {
        "vulnerability_severity": 0.30,
        "exploit_availability": 0.25,
        "attack_surface": 0.20,
        "asset_criticality": 0.15,
        "network_exposure": 0.10,
    }

    # Risk level thresholds
    RISK_THRESHOLDS: list[tuple[float, RiskLevel]] = [
        (80.0, RiskLevel.CRITICAL),
        (60.0, RiskLevel.HIGH),
        (40.0, RiskLevel.MEDIUM),
        (20.0, RiskLevel.LOW),
        (0.0, RiskLevel.NEGLIGIBLE),
    ]

    def __init__(
        self,
        weights: Optional[dict[str, float]] = None,
        asset_criticality: float = 50.0,
    ) -> None:
        """Initialise the risk scorer.

        Args:
            weights: Custom factor weights. If provided, must contain
                    all five factor keys and sum to 1.0.
            asset_criticality: Default asset criticality score (0-100).
                              Used when assessment does not specify it.
        """
        self.weights = dict(self.DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)

        self.asset_criticality = max(0.0, min(100.0, asset_criticality))

        # Store last computation details for reporting
        self.last_score: float = 0.0
        self.last_breakdown: dict[str, float] = {}
        self.last_recommendations: list[str] = []

    def score(self, assessment: ThreatAssessment) -> Risk:
        """Compute the risk score and level for a threat assessment.

        Evaluates all five risk dimensions, computes the weighted
        aggregate score, maps to a risk level, and generates
        recommendations.

        Reference:
            NIST. (2012). SP 800-30 Rev. 1, Table G-2:
            Assessment Scale - Level of Risk.

        Args:
            assessment: Complete ThreatAssessment with CVEs, IoCs,
                       and attack surface data.

        Returns:
            Risk enum value (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE).
        """
        # Compute each factor score (normalised to 0-100)
        vuln_score = self._score_vulnerability_severity(assessment)
        exploit_score = self._score_exploit_availability(assessment)
        surface_score = self._score_attack_surface(assessment)
        criticality_score = self._score_asset_criticality(assessment)
        exposure_score = self._score_network_exposure(assessment)

        # Store factor breakdown
        self.last_breakdown = {
            "vulnerability_severity": round(vuln_score, 2),
            "exploit_availability": round(exploit_score, 2),
            "attack_surface": round(surface_score, 2),
            "asset_criticality": round(criticality_score, 2),
            "network_exposure": round(exposure_score, 2),
        }

        # Weighted combination
        total = (
            self.weights["vulnerability_severity"] * vuln_score
            + self.weights["exploit_availability"] * exploit_score
            + self.weights["attack_surface"] * surface_score
            + self.weights["asset_criticality"] * criticality_score
            + self.weights["network_exposure"] * exposure_score
        )

        self.last_score = round(min(100.0, max(0.0, total)), 2)

        # Determine risk level
        risk_level = RiskLevel.NEGLIGIBLE
        for threshold, level in self.RISK_THRESHOLDS:
            if self.last_score >= threshold:
                risk_level = level
                break

        # Generate recommendations
        self.last_recommendations = self._generate_recommendations(
            assessment, risk_level
        )

        return risk_level

    # ================================================================== #
    #  Factor Scoring Functions
    # ================================================================== #

    def _score_vulnerability_severity(
        self, assessment: ThreatAssessment
    ) -> float:
        """Score based on maximum CVSS severity among identified CVEs.

        Formula: max(cvss_score) * 10, clamped to [0, 100].

        This uses the highest severity vulnerability as the driving
        factor, following the principle that a single critical
        vulnerability can compromise the entire system.

        Reference:
            FIRST. (2019). CVSS v3.1 Specification, Section 5.

        Args:
            assessment: ThreatAssessment with CVE records.

        Returns:
            Vulnerability severity score (0-100).
        """
        if not assessment.cves:
            return 0.0

        max_cvss = max(cve.cvss_score for cve in assessment.cves)
        return min(100.0, max_cvss * 10.0)

    def _score_exploit_availability(
        self, assessment: ThreatAssessment
    ) -> float:
        """Score based on maximum exploitation probability.

        Formula: max(exploit_probability) * 100, clamped to [0, 100].

        Reference:
            Allodi, L., & Massacci, F. (2014). Comparing Vulnerability
            Severity and Exploits Using Case-Control Studies.

        Args:
            assessment: ThreatAssessment with CVE records.

        Returns:
            Exploit availability score (0-100).
        """
        if not assessment.cves:
            return 0.0

        max_prob = max(cve.exploit_probability for cve in assessment.cves)
        return min(100.0, max_prob * 100.0)

    def _score_attack_surface(self, assessment: ThreatAssessment) -> float:
        """Return the attack surface score from the assessment.

        The attack surface score is pre-computed by the
        AttackSurfaceAnalyzer and stored in the assessment.

        Reference:
            Manadhata, P. K., & Wing, J. M. (2011). An Attack Surface
            Metric. IEEE TSE.

        Args:
            assessment: ThreatAssessment with attack_surface_score.

        Returns:
            Attack surface score (0-100).
        """
        return min(100.0, max(0.0, assessment.attack_surface_score))

    def _score_asset_criticality(
        self, assessment: ThreatAssessment
    ) -> float:
        """Score based on the criticality of affected assets.

        Uses the asset_criticality value from assessment metadata
        if available, otherwise falls back to the default.

        Reference:
            NIST. (2012). SP 800-30 Rev. 1, Table D-6:
            Assessment Scale - Impact of Threat Events.

        Args:
            assessment: ThreatAssessment with metadata.

        Returns:
            Asset criticality score (0-100).
        """
        criticality = assessment.metadata.get(
            "asset_criticality", self.asset_criticality
        )
        return min(100.0, max(0.0, float(criticality)))

    def _score_network_exposure(
        self, assessment: ThreatAssessment
    ) -> float:
        """Score based on network accessibility of vulnerabilities.

        Examines CVSS vectors of identified CVEs to determine the
        proportion that are network-accessible (AV:N). A higher
        proportion of network-accessible vulnerabilities increases
        the exposure score.

        Reference:
            Howard, M., Pincus, J., & Wing, J. M. (2005). Measuring
            Relative Attack Surfaces.

        Args:
            assessment: ThreatAssessment with CVE records.

        Returns:
            Network exposure score (0-100).
        """
        if not assessment.cves:
            return 0.0

        network_count = 0
        total = len(assessment.cves)

        for cve in assessment.cves:
            vector_str = cve.cvss_vector.upper()
            if "AV:N" in vector_str:
                network_count += 1

        if total == 0:
            return 0.0

        ratio = network_count / total
        return min(100.0, ratio * 100.0)

    # ================================================================== #
    #  Recommendation Generation
    # ================================================================== #

    def _generate_recommendations(
        self,
        assessment: ThreatAssessment,
        risk_level: Risk,
    ) -> list[str]:
        """Generate prioritised recommendations based on scoring results.

        Recommendations are ordered by the contributing factor weights,
        focusing on the highest-scoring dimensions first.

        Reference:
            OWASP. (2021). Risk Rating Methodology, Section:
            Deciding What to Fix.

        Args:
            assessment: The scored ThreatAssessment.
            risk_level: Computed risk level.

        Returns:
            List of recommendation strings, ordered by priority.
        """
        recs: list[str] = []

        # Sort factors by score (highest contributing risk first)
        sorted_factors = sorted(
            self.last_breakdown.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        for factor_name, factor_score in sorted_factors:
            if factor_score < 20.0:
                continue

            if factor_name == "vulnerability_severity":
                critical_cves = [
                    cve for cve in assessment.cves
                    if cve.cvss_score >= 9.0
                ]
                high_cves = [
                    cve for cve in assessment.cves
                    if 7.0 <= cve.cvss_score < 9.0
                ]
                if critical_cves:
                    cve_ids = ", ".join(c.cve_id for c in critical_cves[:5])
                    recs.append(
                        f"URGENT: Patch {len(critical_cves)} critical "
                        f"vulnerabilities immediately: {cve_ids}"
                    )
                if high_cves:
                    recs.append(
                        f"Schedule patching for {len(high_cves)} high-severity "
                        f"vulnerabilities within 30 days."
                    )

            elif factor_name == "exploit_availability":
                exploitable = [
                    cve for cve in assessment.cves
                    if cve.exploit_probability > 0.5
                ]
                if exploitable:
                    recs.append(
                        f"Prioritise {len(exploitable)} vulnerabilities with "
                        f"high exploitation probability. Deploy compensating "
                        f"controls (WAF rules, IDS signatures) pending patches."
                    )

                actively_exploited = [
                    cve for cve in assessment.cves
                    if cve.is_actively_exploited
                ]
                if actively_exploited:
                    cve_ids = ", ".join(c.cve_id for c in actively_exploited[:5])
                    recs.append(
                        f"IMMEDIATE: {len(actively_exploited)} vulnerabilities "
                        f"are actively exploited: {cve_ids}. Apply emergency "
                        f"mitigations."
                    )

            elif factor_name == "attack_surface":
                if factor_score >= 60:
                    recs.append(
                        "Reduce attack surface by disabling unnecessary "
                        "services, closing unused ports, and implementing "
                        "network segmentation."
                    )

            elif factor_name == "asset_criticality":
                if factor_score >= 60:
                    recs.append(
                        "Implement enhanced monitoring and access controls "
                        "for critical assets. Consider additional isolation "
                        "through micro-segmentation."
                    )

            elif factor_name == "network_exposure":
                if factor_score >= 60:
                    recs.append(
                        "High proportion of network-accessible vulnerabilities "
                        "detected. Deploy a web application firewall (WAF) and "
                        "restrict network-level access where possible."
                    )

        # IoC-based recommendations
        if assessment.iocs:
            ioc_types = set(ioc.type.value for ioc in assessment.iocs)
            recs.append(
                f"Investigate {len(assessment.iocs)} indicators of compromise "
                f"(types: {', '.join(sorted(ioc_types))}). Block confirmed "
                f"malicious indicators at network perimeter."
            )

        # General risk-level guidance
        if risk_level == RiskLevel.CRITICAL:
            recs.insert(0,
                "CRITICAL RISK: Activate incident response procedures. "
                "Implement emergency mitigations for all identified threats."
            )
        elif risk_level == RiskLevel.HIGH:
            recs.insert(0,
                "HIGH RISK: Escalate to security team for immediate review. "
                "Begin remediation within 48 hours."
            )

        if not recs:
            recs.append(
                "Risk level is acceptable. Continue regular monitoring "
                "and scheduled assessments."
            )

        return recs

    def get_score_details(self) -> dict[str, Any]:
        """Return detailed scoring breakdown from the last computation.

        Returns:
            Dictionary with total_score, risk_level, factor_breakdown,
            weights, and recommendations.
        """
        risk_level = RiskLevel.NEGLIGIBLE
        for threshold, level in self.RISK_THRESHOLDS:
            if self.last_score >= threshold:
                risk_level = level
                break

        return {
            "total_score": self.last_score,
            "risk_level": risk_level.value,
            "factor_breakdown": dict(self.last_breakdown),
            "weights": dict(self.weights),
            "recommendations": list(self.last_recommendations),
        }
