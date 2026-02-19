"""
Nexus Core Data Models
=======================

Pydantic-based domain models for the Nexus Threat Intelligence Correlator.
These models represent CVE records, CVSS vectors, Indicators of Compromise (IoCs),
threat assessments, attack surface graphs, and MITRE ATT&CK technique mappings.

Design follows domain-driven design principles (Evans, 2003) with value objects
for immutable measurement data and entities for mutable threat intelligence state.

References:
    - Evans, E. (2003). Domain-Driven Design. Addison-Wesley.
    - FIRST. (2019). Common Vulnerability Scoring System v3.1 Specification.
      https://www.first.org/cvss/v3.1/specification-document
    - MITRE Corporation. (2023). ATT&CK Framework.
      https://attack.mitre.org/
    - Pydantic v2 Documentation. https://docs.pydantic.dev/latest/
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class IoCType(str, enum.Enum):
    """Classification of Indicator of Compromise types.

    Covers the primary observable types used in threat intelligence
    sharing standards such as STIX/TAXII (OASIS, 2017).

    Reference:
        OASIS. (2017). STIX Version 2.0. Part 4: Cyber Observable Objects.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"


class AttackVector(str, enum.Enum):
    """CVSS v3.1 Attack Vector metric values."""

    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, enum.Enum):
    """CVSS v3.1 Attack Complexity metric values."""

    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(str, enum.Enum):
    """CVSS v3.1 Privileges Required metric values."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, enum.Enum):
    """CVSS v3.1 User Interaction metric values."""

    NONE = "N"
    REQUIRED = "R"


class Scope(str, enum.Enum):
    """CVSS v3.1 Scope metric values."""

    UNCHANGED = "U"
    CHANGED = "C"


class Impact(str, enum.Enum):
    """CVSS v3.1 Confidentiality/Integrity/Availability impact values."""

    HIGH = "H"
    LOW = "L"
    NONE = "N"


class ExploitMaturity(str, enum.Enum):
    """CVSS v3.1 Temporal Exploit Code Maturity values."""

    NOT_DEFINED = "X"
    HIGH = "H"
    FUNCTIONAL = "F"
    PROOF_OF_CONCEPT = "P"
    UNPROVEN = "U"


class RemediationLevel(str, enum.Enum):
    """CVSS v3.1 Temporal Remediation Level values."""

    NOT_DEFINED = "X"
    UNAVAILABLE = "U"
    WORKAROUND = "W"
    TEMPORARY_FIX = "T"
    OFFICIAL_FIX = "O"


class ReportConfidence(str, enum.Enum):
    """CVSS v3.1 Temporal Report Confidence values."""

    NOT_DEFINED = "X"
    CONFIRMED = "C"
    REASONABLE = "R"
    UNKNOWN = "U"


# ---------------------------------------------------------------------------
# CVSS Vector Model
# ---------------------------------------------------------------------------


class CVSSVector(BaseModel):
    """Parsed CVSS v3.1 vector string components.

    Represents all base, temporal, and environmental metric values from
    a CVSS v3.1 vector string such as:
        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

    Reference:
        FIRST. (2019). Common Vulnerability Scoring System v3.1 Specification.
        Section 2: Base Metrics.
    """

    # Base metrics (required)
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.NONE
    integrity: Impact = Impact.NONE
    availability: Impact = Impact.NONE

    # Temporal metrics (optional -- default to Not Defined)
    exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    remediation_level: RemediationLevel = RemediationLevel.NOT_DEFINED
    report_confidence: ReportConfidence = ReportConfidence.NOT_DEFINED

    # Raw vector string for reference
    vector_string: str = ""


# ---------------------------------------------------------------------------
# Indicator of Compromise
# ---------------------------------------------------------------------------


class IoC(BaseModel):
    """An Indicator of Compromise (IoC) extracted from threat data.

    Represents a single observable artifact -- IP address, domain, hash,
    URL, email, CVE identifier, or filename -- along with contextual
    metadata for triage and correlation.

    Reference:
        Mandiant. (2013). APT1: Exposing One of China's Cyber Espionage
        Units. Appendix C: Digital Indicators.
    """

    id: UUID = Field(default_factory=uuid4)
    type: IoCType
    value: str
    context: str = ""
    defanged_value: str = ""
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    tags: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)

    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
# CVE Record
# ---------------------------------------------------------------------------


class CVERecord(BaseModel):
    """A Common Vulnerabilities and Exposures (CVE) record.

    Captures vulnerability metadata following the CVE JSON 5.0 schema
    used by the NVD (NIST National Vulnerability Database).

    Reference:
        NIST. (2023). National Vulnerability Database.
        https://nvd.nist.gov/
    """

    cve_id: str
    description: str = ""
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = ""
    severity: str = "unknown"
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)

    # Enrichment data (populated by analyzers)
    exploit_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    has_public_exploit: bool = False
    is_actively_exploited: bool = False

    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
# Attack Surface Node
# ---------------------------------------------------------------------------


class AttackSurfaceNode(BaseModel):
    """A node in the attack surface graph.

    Represents an asset, service, interface, or component that forms
    part of the organisation's attack surface. Nodes are connected
    by edges representing network paths, trust relationships, or
    data flows.

    Reference:
        Manadhata, P. K., & Wing, J. M. (2011). An Attack Surface
        Metric. IEEE Transactions on Software Engineering, 37(3), 371-386.
    """

    id: str
    type: str = "generic"
    name: str = ""
    vulnerabilities: list[str] = Field(default_factory=list)
    connections: list[str] = Field(default_factory=list)
    criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    is_entry_point: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique
# ---------------------------------------------------------------------------


class MITRETechnique(BaseModel):
    """A MITRE ATT&CK technique or sub-technique.

    Maps to the ATT&CK Enterprise matrix technique schema with
    fields for identification, classification, detection guidance,
    and platform applicability.

    Reference:
        MITRE Corporation. (2023). MITRE ATT&CK.
        https://attack.mitre.org/
    """

    technique_id: str
    name: str
    tactic: str = ""
    description: str = ""
    detection: str = ""
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    url: str = ""


# ---------------------------------------------------------------------------
# Threat Assessment (aggregate)
# ---------------------------------------------------------------------------


class ThreatAssessment(BaseModel):
    """Aggregate threat assessment combining all analysis dimensions.

    Synthesises vulnerability data (CVEs), indicators of compromise,
    attack surface analysis, and risk scoring into a unified assessment
    suitable for executive reporting and remediation prioritisation.

    Reference:
        NIST. (2012). SP 800-30 Rev. 1: Guide for Conducting
        Risk Assessments.
    """

    id: UUID = Field(default_factory=uuid4)
    overall_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_level: str = "info"
    findings: list[dict[str, Any]] = Field(default_factory=list)
    iocs: list[IoC] = Field(default_factory=list)
    cves: list[CVERecord] = Field(default_factory=list)
    attack_surface_score: float = Field(default=0.0, ge=0.0, le=100.0)
    recommendations: list[str] = Field(default_factory=list)
    mitre_techniques: list[MITRETechnique] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat(),
        }
