"""
PhantomCore Data Models
========================

Pydantic v2 models shared across all PhantomCore toolkit modules.
These models enforce strict validation, serialisation, and documentation
for every finding, risk assessment, and scan result the toolkit produces.

Design follows OWASP Risk Rating Methodology for severity/risk
classification, and SARIF (Static Analysis Results Interchange Format)
for finding structure inspiration.

References:
    - OWASP Risk Rating Methodology.
      https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
    - SARIF v2.1.0 Specification (OASIS, 2020).
    - FIRST. (2019). Common Vulnerability Scoring System v3.1.
      https://www.first.org/cvss/v3.1/specification-document
    - Pydantic v2 documentation. https://docs.pydantic.dev/latest/
"""

from __future__ import annotations

import datetime as _dt
import json as _json
from enum import Enum
from typing import Any, ClassVar, Optional

from pydantic import (
    BaseModel,
    Field,
    ConfigDict,
    field_validator,
    model_validator,
)


# ========================== Enumerations ===================================


class Severity(str, Enum):
    """Finding severity level.

    Aligned with CVSS v3.1 qualitative severity ratings
    (FIRST.org, 2019).

    Attributes:
        CRITICAL: Critical -- Immediate exploitation likely; catastrophic impact.
        HIGH:     High     -- Serious vulnerability; significant impact.
        MEDIUM:   Medium   -- Moderate risk; limited impact without chaining.
        LOW:      Low      -- Minor issue; minimal direct impact.
        INFO:     Informational -- Informational observation; no direct risk.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def label_ka(self) -> str:
        """Return the localized label for this severity."""
        _map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Informational",
        }
        return _map[self.value]

    @property
    def css_class(self) -> str:
        """Return a CSS class name for severity-based styling."""
        return f"severity-{self.value.lower()}"


class RiskLevel(str, Enum):
    """Qualitative risk level derived from a numeric risk score.

    Based on OWASP Risk Rating Methodology (OWASP, 2021) and
    NIST SP 800-30 Rev. 1 risk assessment methodology.

    Attributes:
        CRITICAL:   Critical   -- Score 90-100.
        HIGH:       High       -- Score 70-89.
        MEDIUM:     Medium     -- Score 40-69.
        LOW:        Low        -- Score 10-39.
        NEGLIGIBLE: Negligible -- Score 0-9.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"

    @property
    def label_ka(self) -> str:
        """Return the localized label for this risk level."""
        _map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "NEGLIGIBLE": "Negligible",
        }
        return _map[self.value]

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        """Derive the qualitative level from a 0-100 numeric score.

        Score ranges follow OWASP Risk Rating Methodology:
          - 90-100 : CRITICAL
          - 70-89  : HIGH
          - 40-69  : MEDIUM
          - 10-39  : LOW
          - 0-9    : NEGLIGIBLE

        Args:
            score: Numeric risk score in the range [0, 100].

        Returns:
            Corresponding :class:`RiskLevel` enum member.
        """
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 10:
            return cls.LOW
        return cls.NEGLIGIBLE


# ========================== Core Models ====================================


class Finding(BaseModel):
    """A single security finding produced by any PhantomCore tool.

    Follows a structure inspired by SARIF result objects (OASIS, 2020),
    extended with Georgian-language support and academic references.

    Attributes:
        severity:       Severity       -- Qualitative severity rating.
        title:          Title          -- Short, descriptive finding title.
        description:    Description    -- Detailed explanation of the finding.
        evidence:       Evidence       -- Raw data or snippet supporting the finding.
        recommendation: Recommendation -- Suggested remediation action.
        references:     References     -- List of external reference URLs or citations.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        use_enum_values=False,
        extra="ignore",
        json_schema_extra={
            "examples": [
                {
                    "severity": "HIGH",
                    "title": "Weak entropy detected in TLS session",
                    "description": (
                        "Shannon entropy of the observed random bytes is 4.2 bits, "
                        "well below the 7.5-bit threshold for cryptographic randomness."
                    ),
                    "evidence": "Entropy: 4.21 bits/byte over 1024-byte sample",
                    "recommendation": "Ensure CSPRNG is used for session token generation.",
                    "references": [
                        "Shannon, C. E. (1948). A Mathematical Theory of Communication.",
                        "NIST SP 800-90B: Recommendation for the Entropy Sources.",
                    ],
                }
            ]
        },
    )

    severity: Severity = Field(
        ...,
        description="Severity level of this finding",
    )
    title: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Short descriptive title",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Detailed explanation",
    )
    evidence: str = Field(
        default="",
        description="Supporting evidence or raw data",
    )
    recommendation: str = Field(
        default="",
        description="Suggested remediation",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Academic or technical references",
    )

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v: Any) -> str:
        """Auto-convert non-string evidence (dict, list) to JSON string."""
        if isinstance(v, str):
            return v
        if isinstance(v, (dict, list)):
            return _json.dumps(v, ensure_ascii=False, default=str)
        return str(v)


class Risk(BaseModel):
    """Quantitative + qualitative risk assessment.

    The numeric *score* (0-100) is the canonical value; the qualitative
    *level* is derived automatically if not provided.

    The risk model follows OWASP Risk Rating Methodology, combining
    likelihood and impact factors into a single composite score.

    Attributes:
        score:   Score   -- Numeric risk score in [0, 100].
        level:   Level   -- Qualitative risk classification.
        factors: Factors -- Contributing risk factors.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=False,
    )

    # Convenience class-level constants so callers can write Risk.CRITICAL etc.
    CRITICAL: ClassVar[RiskLevel] = RiskLevel.CRITICAL
    HIGH: ClassVar[RiskLevel] = RiskLevel.HIGH
    MEDIUM: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    LOW: ClassVar[RiskLevel] = RiskLevel.LOW
    NEGLIGIBLE: ClassVar[RiskLevel] = RiskLevel.NEGLIGIBLE

    score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Numeric risk score (0-100)",
    )
    level: RiskLevel = Field(
        default=None,  # type: ignore[assignment]
        description="Qualitative risk level",
    )
    factors: list[str] = Field(
        default_factory=list,
        description="Contributing risk factors",
    )

    @model_validator(mode="after")
    def _derive_level(self) -> Risk:
        """Automatically derive *level* from *score* when not explicitly set."""
        if self.level is None:
            self.level = RiskLevel.from_score(self.score)
        return self


class ScanResult(BaseModel):
    """Aggregated result of a single scan/analysis run.

    This is the top-level output model emitted by every PhantomCore tool.
    It bundles metadata, findings, risk summary, and timing information
    into a single serialisable object suitable for report generation.

    Attributes:
        tool_name:  Tool name    -- Name of the PhantomCore tool.
        target:     Target       -- Target that was scanned / analysed.
        start_time: Start time   -- UTC timestamp when the scan started.
        end_time:   End time     -- UTC timestamp when the scan ended.
        findings:   Findings     -- List of individual findings.
        risk:       Risk         -- Overall risk assessment (optional).
        summary:    Summary      -- Human-readable summary text.
        metadata:   Metadata     -- Arbitrary extra metadata dict.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=False,
        extra="ignore",
    )

    tool_name: str = Field(
        ...,
        min_length=1,
        description="Tool name",
    )
    target: str = Field(
        ...,
        min_length=1,
        description="Scan target (IP, domain, file path, etc.)",
    )
    start_time: _dt.datetime = Field(
        default_factory=_dt.datetime.utcnow,
        description="Scan start timestamp (UTC)",
    )
    end_time: Optional[_dt.datetime] = Field(
        default=None,
        description="Scan end timestamp (UTC)",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of security findings",
    )
    risk: Optional[Risk] = Field(
        default=None,
        description="Overall risk assessment",
    )
    summary: str = Field(
        default="",
        description="Human-readable result summary",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    # ------------------------------------------------------------------ #
    #  Derived properties
    # ------------------------------------------------------------------ #

    @property
    def duration_seconds(self) -> float | None:
        """Elapsed scan time in seconds, or ``None`` if *end_time* is unset."""
        if self.end_time is None or self.start_time is None:
            return None
        return (self.end_time - self.start_time).total_seconds()

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count of findings grouped by severity.

        Returns:
            Dict mapping severity name to occurrence count, e.g.
            ``{"CRITICAL": 1, "HIGH": 3, "MEDIUM": 0, ...}``.
        """
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.findings:
            key = (
                finding.severity.value
                if isinstance(finding.severity, Severity)
                else str(finding.severity)
            )
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        """The most severe finding, or ``None`` when the list is empty."""
        if not self.findings:
            return None
        order = list(Severity)
        return min(
            (f.severity for f in self.findings),
            key=lambda s: order.index(s),
        )

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    # ------------------------------------------------------------------ #
    #  Mutating helpers
    # ------------------------------------------------------------------ #

    def add_finding(self, finding: Finding) -> None:
        """Append a finding to the scan result."""
        self.findings.append(finding)

    def finalize(self, summary: str | None = None) -> ScanResult:
        """Mark the scan as complete by setting *end_time* and *summary*.

        If *summary* is ``None`` a default is generated from severity counts.

        Returns:
            ``self`` for fluent chaining.
        """
        self.end_time = _dt.datetime.utcnow()
        if summary is not None:
            self.summary = summary
        else:
            counts = self.severity_counts
            parts = [f"{sev}: {cnt}" for sev, cnt in counts.items() if cnt > 0]
            self.summary = (
                f"Scan complete. "
                f"Findings: {len(self.findings)} "
                f"({', '.join(parts) if parts else 'none'})"
            )
        return self
