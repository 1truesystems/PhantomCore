"""
CVSS v3.1 Calculator
=====================

Complete implementation of the Common Vulnerability Scoring System
version 3.1 specification, including Base, Temporal, and Environmental
score calculations.

The CVSS v3.1 Base Score is computed from eight metrics that capture
the intrinsic characteristics of a vulnerability. Temporal metrics
adjust the score based on exploit availability and remediation status.
Environmental metrics allow organisations to customise scores based
on their specific infrastructure context.

Algorithm Summary (Base Score):
    1. Impact Sub-Score (ISS) = 1 - [(1-C) * (1-I) * (1-A)]
    2. If Scope Unchanged:
         Impact = 6.42 * ISS
       If Scope Changed:
         Impact = 7.52 * [ISS - 0.029] - 3.25 * [ISS - 0.02]^15
    3. Exploitability = 8.22 * AV * AC * PR * UI
    4. If Impact <= 0: BaseScore = 0
       Else if Scope Unchanged:
         BaseScore = Roundup(min(Impact + Exploitability, 10))
       Else:
         BaseScore = Roundup(min(1.08 * (Impact + Exploitability), 10))

Roundup function:
    The smallest number, specified to one decimal place, that is equal
    to or higher than its input. For example, Roundup(4.02) = 4.1;
    Roundup(4.00) = 4.0.

References:
    - FIRST. (2019). Common Vulnerability Scoring System v3.1:
      Specification Document.
      https://www.first.org/cvss/v3.1/specification-document
    - FIRST. (2019). CVSS v3.1 Calculator.
      https://www.first.org/cvss/calculator/3.1
    - Mell, P., Scarfone, K., & Romanosky, S. (2007). A Complete Guide
      to the Common Vulnerability Scoring System Version 2.0. NIST.
"""

from __future__ import annotations

import math
from typing import Optional

from nexus.core.models import (
    AttackComplexity,
    AttackVector,
    CVSSVector,
    ExploitMaturity,
    Impact,
    PrivilegesRequired,
    RemediationLevel,
    ReportConfidence,
    Scope,
    UserInteraction,
)


class CVSSCalculator:
    """Full CVSS v3.1 score calculator.

    Implements all three metric groups (Base, Temporal, Environmental)
    with exact adherence to the FIRST specification. All numeric
    constants and the Roundup function follow the published standard.

    Usage::

        calc = CVSSCalculator()
        vector = calc.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        base = calc.calculate_base(vector)
        print(f"Base Score: {base}")  # 9.8
    """

    # ================================================================== #
    #  CVSS v3.1 Metric Value Mappings (Table 15-19 in specification)
    # ================================================================== #

    # Attack Vector (AV)
    AV_VALUES: dict[AttackVector, float] = {
        AttackVector.NETWORK: 0.85,
        AttackVector.ADJACENT: 0.62,
        AttackVector.LOCAL: 0.55,
        AttackVector.PHYSICAL: 0.20,
    }

    # Attack Complexity (AC)
    AC_VALUES: dict[AttackComplexity, float] = {
        AttackComplexity.LOW: 0.77,
        AttackComplexity.HIGH: 0.44,
    }

    # Privileges Required (PR) -- depends on Scope
    PR_VALUES_UNCHANGED: dict[PrivilegesRequired, float] = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.62,
        PrivilegesRequired.HIGH: 0.27,
    }

    PR_VALUES_CHANGED: dict[PrivilegesRequired, float] = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.68,
        PrivilegesRequired.HIGH: 0.50,
    }

    # User Interaction (UI)
    UI_VALUES: dict[UserInteraction, float] = {
        UserInteraction.NONE: 0.85,
        UserInteraction.REQUIRED: 0.62,
    }

    # Confidentiality (C), Integrity (I), Availability (A)
    CIA_VALUES: dict[Impact, float] = {
        Impact.HIGH: 0.56,
        Impact.LOW: 0.22,
        Impact.NONE: 0.0,
    }

    # Exploit Code Maturity (E) -- Temporal
    EXPLOIT_MATURITY_VALUES: dict[ExploitMaturity, float] = {
        ExploitMaturity.NOT_DEFINED: 1.0,
        ExploitMaturity.HIGH: 1.0,
        ExploitMaturity.FUNCTIONAL: 0.97,
        ExploitMaturity.PROOF_OF_CONCEPT: 0.94,
        ExploitMaturity.UNPROVEN: 0.91,
    }

    # Remediation Level (RL) -- Temporal
    REMEDIATION_LEVEL_VALUES: dict[RemediationLevel, float] = {
        RemediationLevel.NOT_DEFINED: 1.0,
        RemediationLevel.UNAVAILABLE: 1.0,
        RemediationLevel.WORKAROUND: 0.97,
        RemediationLevel.TEMPORARY_FIX: 0.96,
        RemediationLevel.OFFICIAL_FIX: 0.95,
    }

    # Report Confidence (RC) -- Temporal
    REPORT_CONFIDENCE_VALUES: dict[ReportConfidence, float] = {
        ReportConfidence.NOT_DEFINED: 1.0,
        ReportConfidence.CONFIRMED: 1.0,
        ReportConfidence.REASONABLE: 0.96,
        ReportConfidence.UNKNOWN: 0.92,
    }

    # Metric abbreviation to enum class mapping for vector parsing
    _METRIC_PARSERS: dict[str, tuple[str, dict[str, object]]] = {
        "AV": ("attack_vector", {
            "N": AttackVector.NETWORK,
            "A": AttackVector.ADJACENT,
            "L": AttackVector.LOCAL,
            "P": AttackVector.PHYSICAL,
        }),
        "AC": ("attack_complexity", {
            "L": AttackComplexity.LOW,
            "H": AttackComplexity.HIGH,
        }),
        "PR": ("privileges_required", {
            "N": PrivilegesRequired.NONE,
            "L": PrivilegesRequired.LOW,
            "H": PrivilegesRequired.HIGH,
        }),
        "UI": ("user_interaction", {
            "N": UserInteraction.NONE,
            "R": UserInteraction.REQUIRED,
        }),
        "S": ("scope", {
            "U": Scope.UNCHANGED,
            "C": Scope.CHANGED,
        }),
        "C": ("confidentiality", {
            "H": Impact.HIGH,
            "L": Impact.LOW,
            "N": Impact.NONE,
        }),
        "I": ("integrity", {
            "H": Impact.HIGH,
            "L": Impact.LOW,
            "N": Impact.NONE,
        }),
        "A": ("availability", {
            "H": Impact.HIGH,
            "L": Impact.LOW,
            "N": Impact.NONE,
        }),
        "E": ("exploit_maturity", {
            "X": ExploitMaturity.NOT_DEFINED,
            "H": ExploitMaturity.HIGH,
            "F": ExploitMaturity.FUNCTIONAL,
            "P": ExploitMaturity.PROOF_OF_CONCEPT,
            "U": ExploitMaturity.UNPROVEN,
        }),
        "RL": ("remediation_level", {
            "X": RemediationLevel.NOT_DEFINED,
            "U": RemediationLevel.UNAVAILABLE,
            "W": RemediationLevel.WORKAROUND,
            "T": RemediationLevel.TEMPORARY_FIX,
            "O": RemediationLevel.OFFICIAL_FIX,
        }),
        "RC": ("report_confidence", {
            "X": ReportConfidence.NOT_DEFINED,
            "C": ReportConfidence.CONFIRMED,
            "R": ReportConfidence.REASONABLE,
            "U": ReportConfidence.UNKNOWN,
        }),
    }

    # ================================================================== #
    #  Roundup function (per CVSS v3.1 specification)
    # ================================================================== #

    @staticmethod
    def roundup(value: float) -> float:
        """CVSS v3.1 Roundup function.

        Returns the smallest number, specified to one decimal place,
        that is equal to or higher than its input.

        Examples:
            Roundup(4.02) = 4.1
            Roundup(4.00) = 4.0
            Roundup(4.10) = 4.1

        This is NOT standard mathematical rounding. It is a ceiling
        operation on the first decimal place.

        Reference:
            FIRST. (2019). CVSS v3.1 Specification, Appendix A.

        Args:
            value: Input floating-point value.

        Returns:
            The Roundup result as a float with one decimal place.
        """
        return math.ceil(value * 10) / 10

    # ================================================================== #
    #  Base Score Calculation
    # ================================================================== #

    def calculate_base(self, vector: CVSSVector) -> float:
        """Calculate the CVSS v3.1 Base Score.

        Implements the complete base score algorithm:
          1. Compute Impact Sub-Score (ISS)
          2. Compute Impact score (depends on Scope)
          3. Compute Exploitability score
          4. Combine into Base Score with Roundup

        Reference:
            FIRST. (2019). CVSS v3.1 Specification, Section 5.

        Args:
            vector: Parsed CVSSVector with all base metrics.

        Returns:
            Base Score in the range [0.0, 10.0].
        """
        # Look up numeric values for each metric
        av = self.AV_VALUES[vector.attack_vector]
        ac = self.AC_VALUES[vector.attack_complexity]
        ui = self.UI_VALUES[vector.user_interaction]

        # Privileges Required depends on Scope
        if vector.scope == Scope.CHANGED:
            pr = self.PR_VALUES_CHANGED[vector.privileges_required]
        else:
            pr = self.PR_VALUES_UNCHANGED[vector.privileges_required]

        c = self.CIA_VALUES[vector.confidentiality]
        i = self.CIA_VALUES[vector.integrity]
        a = self.CIA_VALUES[vector.availability]

        # Step 1: Impact Sub-Score
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # Step 2: Impact
        if vector.scope == Scope.UNCHANGED:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Step 3: Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Step 4: Base Score
        if impact <= 0:
            return 0.0

        if vector.scope == Scope.UNCHANGED:
            base_score = self.roundup(min(impact + exploitability, 10.0))
        else:
            base_score = self.roundup(
                min(1.08 * (impact + exploitability), 10.0)
            )

        return base_score

    # ================================================================== #
    #  Temporal Score Calculation
    # ================================================================== #

    def calculate_temporal(
        self,
        base_score: float,
        vector: CVSSVector,
    ) -> float:
        """Calculate the CVSS v3.1 Temporal Score.

        TemporalScore = Roundup(BaseScore * ExploitCodeMaturity
                                * RemediationLevel * ReportConfidence)

        Temporal metrics adjust the Base Score based on factors that
        change over time: availability of exploits, vendor response,
        and confidence in the vulnerability report.

        Reference:
            FIRST. (2019). CVSS v3.1 Specification, Section 6.

        Args:
            base_score: Pre-computed CVSS v3.1 Base Score.
            vector: CVSSVector containing temporal metric values.

        Returns:
            Temporal Score in the range [0.0, 10.0].
        """
        e = self.EXPLOIT_MATURITY_VALUES[vector.exploit_maturity]
        rl = self.REMEDIATION_LEVEL_VALUES[vector.remediation_level]
        rc = self.REPORT_CONFIDENCE_VALUES[vector.report_confidence]

        temporal = self.roundup(base_score * e * rl * rc)
        return temporal

    # ================================================================== #
    #  Environmental Score Calculation
    # ================================================================== #

    def calculate_environmental(
        self,
        base_score: float,
        vector: CVSSVector,
        *,
        confidentiality_requirement: float = 1.0,
        integrity_requirement: float = 1.0,
        availability_requirement: float = 1.0,
    ) -> float:
        """Calculate the CVSS v3.1 Environmental Score.

        The Environmental Score uses Modified Base metrics and Security
        Requirements to customise the score for a specific environment.

        When no modified metrics are specified (i.e. all requirements
        are 1.0), this produces the same result as the Temporal Score
        (or Base Score if temporal metrics are not defined).

        The security requirement values follow the specification:
          - Low:    0.5
          - Medium: 1.0
          - High:   1.5

        Reference:
            FIRST. (2019). CVSS v3.1 Specification, Section 7.

        Args:
            base_score: Pre-computed CVSS v3.1 Base Score.
            vector: CVSSVector with all metric values.
            confidentiality_requirement: CR weight (0.5, 1.0, or 1.5).
            integrity_requirement: IR weight (0.5, 1.0, or 1.5).
            availability_requirement: AR weight (0.5, 1.0, or 1.5).

        Returns:
            Environmental Score in the range [0.0, 10.0].
        """
        # Use same base metrics (Modified metrics default to base)
        av = self.AV_VALUES[vector.attack_vector]
        ac = self.AC_VALUES[vector.attack_complexity]
        ui = self.UI_VALUES[vector.user_interaction]

        if vector.scope == Scope.CHANGED:
            pr = self.PR_VALUES_CHANGED[vector.privileges_required]
        else:
            pr = self.PR_VALUES_UNCHANGED[vector.privileges_required]

        c = self.CIA_VALUES[vector.confidentiality]
        i = self.CIA_VALUES[vector.integrity]
        a = self.CIA_VALUES[vector.availability]

        # Modified Impact Sub-Score with security requirements
        # ISCModified = min(1 - [(1-CR*MC)*(1-IR*MI)*(1-AR*MA)], 0.915)
        isc_modified = min(
            1.0 - (
                (1.0 - confidentiality_requirement * c)
                * (1.0 - integrity_requirement * i)
                * (1.0 - availability_requirement * a)
            ),
            0.915,
        )

        # Modified Impact
        if vector.scope == Scope.UNCHANGED:
            modified_impact = 6.42 * isc_modified
        else:
            modified_impact = (
                7.52 * (isc_modified - 0.029)
                - 3.25 * ((isc_modified * 0.9731 - 0.02) ** 13)
            )

        # Modified Exploitability
        modified_exploitability = 8.22 * av * ac * pr * ui

        # Environmental Base Score
        if modified_impact <= 0:
            return 0.0

        if vector.scope == Scope.UNCHANGED:
            env_base = self.roundup(
                min(modified_impact + modified_exploitability, 10.0)
            )
        else:
            env_base = self.roundup(
                min(
                    1.08 * (modified_impact + modified_exploitability),
                    10.0,
                )
            )

        # Apply temporal metrics
        e = self.EXPLOIT_MATURITY_VALUES[vector.exploit_maturity]
        rl = self.REMEDIATION_LEVEL_VALUES[vector.remediation_level]
        rc = self.REPORT_CONFIDENCE_VALUES[vector.report_confidence]

        environmental = self.roundup(env_base * e * rl * rc)
        return environmental

    # ================================================================== #
    #  Vector String Parsing
    # ================================================================== #

    def parse_vector(self, vector_string: str) -> CVSSVector:
        """Parse a CVSS v3.1 vector string into a CVSSVector model.

        Accepts vector strings in the standard format:
            CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

        Also supports CVSS:3.0 prefix (same calculation engine).

        Reference:
            FIRST. (2019). CVSS v3.1 Specification, Appendix A.

        Args:
            vector_string: CVSS v3.1 vector string.

        Returns:
            Parsed CVSSVector instance.

        Raises:
            ValueError: If the vector string is malformed or contains
                       invalid metric values.
        """
        vector_string = vector_string.strip()
        kwargs: dict[str, object] = {"vector_string": vector_string}

        # Remove prefix
        body = vector_string
        if body.startswith("CVSS:3.1/"):
            body = body[len("CVSS:3.1/"):]
        elif body.startswith("CVSS:3.0/"):
            body = body[len("CVSS:3.0/"):]
        elif body.startswith("CVSS:"):
            # Try to handle other versions gracefully
            slash_idx = body.find("/")
            if slash_idx >= 0:
                body = body[slash_idx + 1:]

        # Parse metric:value pairs
        parts = body.split("/")
        for part in parts:
            if ":" not in part:
                continue

            metric_key, metric_val = part.split(":", 1)
            metric_key = metric_key.strip().upper()
            metric_val = metric_val.strip().upper()

            if metric_key in self._METRIC_PARSERS:
                field_name, value_map = self._METRIC_PARSERS[metric_key]
                if metric_val in value_map:
                    kwargs[field_name] = value_map[metric_val]
                else:
                    raise ValueError(
                        f"Invalid value '{metric_val}' for CVSS metric "
                        f"'{metric_key}'. Valid values: "
                        f"{list(value_map.keys())}"
                    )

        return CVSSVector(**kwargs)  # type: ignore[arg-type]

    # ================================================================== #
    #  Convenience: full calculation from vector string
    # ================================================================== #

    def score_from_vector(
        self, vector_string: str
    ) -> dict[str, float]:
        """Calculate all scores from a CVSS v3.1 vector string.

        Convenience method that parses the vector and computes Base,
        Temporal, and Environmental scores in one call.

        Args:
            vector_string: CVSS v3.1 vector string.

        Returns:
            Dictionary with keys 'base', 'temporal', 'environmental'
            mapping to their respective score values.
        """
        vector = self.parse_vector(vector_string)
        base = self.calculate_base(vector)
        temporal = self.calculate_temporal(base, vector)
        environmental = self.calculate_environmental(base, vector)

        return {
            "base": base,
            "temporal": temporal,
            "environmental": environmental,
        }

    @staticmethod
    def severity_from_score(score: float) -> str:
        """Map a CVSS score to its qualitative severity rating.

        Reference:
            FIRST. (2019). CVSS v3.1 Specification, Section 5.

        Score ranges:
            0.0       -> None
            0.1 - 3.9 -> Low
            4.0 - 6.9 -> Medium
            7.0 - 8.9 -> High
            9.0 - 10.0 -> Critical

        Args:
            score: Numeric CVSS score (0.0 to 10.0).

        Returns:
            Qualitative severity string.
        """
        if score == 0.0:
            return "none"
        elif score <= 3.9:
            return "low"
        elif score <= 6.9:
            return "medium"
        elif score <= 8.9:
            return "high"
        else:
            return "critical"

    def get_metric_breakdown(self, vector: CVSSVector) -> dict[str, Any]:
        """Return a detailed breakdown of all metric values and sub-scores.

        Useful for display purposes, providing human-readable labels
        and numeric values for each CVSS metric.

        Args:
            vector: Parsed CVSSVector.

        Returns:
            Dictionary with metric names, values, labels, and sub-scores.
        """
        av = self.AV_VALUES[vector.attack_vector]
        ac = self.AC_VALUES[vector.attack_complexity]
        ui = self.UI_VALUES[vector.user_interaction]

        if vector.scope == Scope.CHANGED:
            pr = self.PR_VALUES_CHANGED[vector.privileges_required]
        else:
            pr = self.PR_VALUES_UNCHANGED[vector.privileges_required]

        c = self.CIA_VALUES[vector.confidentiality]
        i = self.CIA_VALUES[vector.integrity]
        a = self.CIA_VALUES[vector.availability]

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if vector.scope == Scope.UNCHANGED:
            impact_score = 6.42 * iss
        else:
            impact_score = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        av_labels = {
            AttackVector.NETWORK: "Network",
            AttackVector.ADJACENT: "Adjacent",
            AttackVector.LOCAL: "Local",
            AttackVector.PHYSICAL: "Physical",
        }

        ac_labels = {
            AttackComplexity.LOW: "Low",
            AttackComplexity.HIGH: "High",
        }

        pr_labels = {
            PrivilegesRequired.NONE: "None",
            PrivilegesRequired.LOW: "Low",
            PrivilegesRequired.HIGH: "High",
        }

        ui_labels = {
            UserInteraction.NONE: "None",
            UserInteraction.REQUIRED: "Required",
        }

        scope_labels = {
            Scope.UNCHANGED: "Unchanged",
            Scope.CHANGED: "Changed",
        }

        impact_labels = {
            Impact.HIGH: "High",
            Impact.LOW: "Low",
            Impact.NONE: "None",
        }

        return {
            "metrics": {
                "attack_vector": {
                    "label": av_labels.get(vector.attack_vector, "Unknown"),
                    "value": av,
                },
                "attack_complexity": {
                    "label": ac_labels.get(vector.attack_complexity, "Unknown"),
                    "value": ac,
                },
                "privileges_required": {
                    "label": pr_labels.get(vector.privileges_required, "Unknown"),
                    "value": pr,
                },
                "user_interaction": {
                    "label": ui_labels.get(vector.user_interaction, "Unknown"),
                    "value": ui,
                },
                "scope": {
                    "label": scope_labels.get(vector.scope, "Unknown"),
                },
                "confidentiality": {
                    "label": impact_labels.get(vector.confidentiality, "Unknown"),
                    "value": c,
                },
                "integrity": {
                    "label": impact_labels.get(vector.integrity, "Unknown"),
                    "value": i,
                },
                "availability": {
                    "label": impact_labels.get(vector.availability, "Unknown"),
                    "value": a,
                },
            },
            "sub_scores": {
                "impact_sub_score": round(iss, 4),
                "impact": round(impact_score, 4),
                "exploitability": round(exploitability, 4),
            },
        }


# Convenience alias for type hints
Any = object
