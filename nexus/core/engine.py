"""
Nexus Engine
=============

Central orchestration engine for the Nexus Threat Intelligence Correlator.
Coordinates all analysis sub-systems (CVE lookup, IoC extraction, CVSS
calculation, exploit probability, attack surface analysis, risk scoring,
and MITRE ATT&CK mapping) into a unified threat assessment pipeline.

Architecture follows the Mediator pattern (Gamma et al., 1994) where
the engine acts as the central coordinator, reducing coupling between
individual analyzers and collectors.

Pipeline:
    1. Input acquisition (CVE lookup, IoC extraction, config parsing)
    2. Enrichment (CVSS scoring, exploit probability, MITRE mapping)
    3. Correlation (attack surface analysis, cross-referencing)
    4. Scoring (multi-factor risk assessment)
    5. Output (findings, recommendations, report generation)

References:
    - Gamma, E., Helm, R., Johnson, R., & Vlissides, J. (1994).
      Design Patterns. Addison-Wesley. (Mediator Pattern)
    - NIST. (2023). National Vulnerability Database.
    - MITRE Corporation. (2023). ATT&CK Framework.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from shared.config import PhantomConfig
from shared.models import Finding, Risk, ScanResult, Severity

from nexus.analyzers.attack_surface import AttackSurfaceAnalyzer
from nexus.analyzers.cvss import CVSSCalculator
from nexus.analyzers.exploit_prob import ExploitProbabilityModel
from nexus.analyzers.mitre import MITREMapper
from nexus.analyzers.risk_scorer import RiskScorer
from nexus.collectors.cve_search import CVESearchCollector
from nexus.collectors.ioc_extractor import IoCExtractor
from nexus.core.database import CVEDatabase
from nexus.core.models import (
    AttackSurfaceNode,
    CVERecord,
    IoC,
    MITRETechnique,
    ThreatAssessment,
)

logger = logging.getLogger("nexus.engine")


class NexusEngine:
    """Central orchestration engine for Nexus threat intelligence.

    Coordinates CVE lookups, IoC extraction, CVSS calculation,
    exploitation probability estimation, attack surface analysis,
    risk scoring, and MITRE ATT&CK mapping.

    Usage::

        engine = NexusEngine(db_path="nexus.db")
        result = await engine.lookup_cve("CVE-2021-44228")
        print(result.summary)

    Attributes:
        config: PhantomConfig instance.
        db: CVEDatabase for local caching.
        cvss: CVSSCalculator instance.
        exploit_model: ExploitProbabilityModel instance.
        mitre: MITREMapper instance.
        ioc_extractor: IoCExtractor instance.
        surface_analyzer: AttackSurfaceAnalyzer instance.
        risk_scorer: RiskScorer instance.
    """

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        config: Optional[PhantomConfig] = None,
    ) -> None:
        """Initialise the Nexus engine with all sub-systems.

        Args:
            db_path: Path to the SQLite CVE database file.
            config: PhantomConfig instance. Loaded from defaults if None.
        """
        self.config = config or PhantomConfig()

        # Database
        self.db = CVEDatabase(
            db_path=db_path or "nexus_cves.db",
            cache_ttl=86400,
        )
        self.db.create_tables()

        # Analyzers
        self.cvss = CVSSCalculator()
        self.exploit_model = ExploitProbabilityModel()
        self.mitre = MITREMapper()
        self.ioc_extractor = IoCExtractor()
        self.surface_analyzer = AttackSurfaceAnalyzer(
            damping=self.config.nexus.pagerank_damping,
            max_iterations=self.config.nexus.pagerank_iterations,
        )
        self.risk_scorer = RiskScorer()

    # ================================================================== #
    #  CVE Lookup
    # ================================================================== #

    async def lookup_cve(self, cve_id: str) -> ScanResult:
        """Look up a CVE and produce an enriched analysis result.

        Pipeline:
          1. Search local cache, then online NVD API
          2. Parse and validate CVSS vector
          3. Calculate CVSS base, temporal, environmental scores
          4. Estimate exploitation probability
          5. Map to MITRE ATT&CK techniques via CWE
          6. Generate findings and recommendations

        Args:
            cve_id: CVE identifier (e.g. "CVE-2021-44228").

        Returns:
            ScanResult containing findings, scores, and recommendations.
        """
        started = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="nexus",
            target=cve_id.upper(),
        )

        cve_id = cve_id.upper().strip()
        record: Optional[CVERecord] = None

        # Step 1: Local lookup
        record = self.db.get_by_id(cve_id)

        # Step 2: Online lookup if not cached
        if record is None:
            try:
                async with CVESearchCollector(db=self.db) as collector:
                    record = await collector.search_online(cve_id)
            except Exception as exc:
                logger.warning("Online CVE lookup failed: %s", exc)

        if record is None:
            result.add_finding(Finding(
                title=f"CVE Not Found: {cve_id}",
                description=f"The CVE identifier {cve_id} was not found in local cache or online databases.",
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
            ))
            result.summary = f"CVE {cve_id} not found."
            result.end_time = datetime.now(timezone.utc)
            return result

        # Step 3: CVSS calculation
        cvss_details: Optional[dict[str, Any]] = None
        parsed_vector = None

        if record.cvss_vector:
            try:
                parsed_vector = self.cvss.parse_vector(record.cvss_vector)
                base = self.cvss.calculate_base(parsed_vector)
                temporal = self.cvss.calculate_temporal(base, parsed_vector)
                cvss_details = self.cvss.get_metric_breakdown(parsed_vector)
                cvss_details["scores"] = {
                    "base": base,
                    "temporal": temporal,
                }
                record.cvss_score = base
                record.severity = self.cvss.severity_from_score(base)
            except ValueError as exc:
                logger.warning("CVSS vector parse error: %s", exc)

        # Step 4: Exploitation probability
        exploit_prob = self.exploit_model.calculate(record, parsed_vector)
        record.exploit_probability = exploit_prob
        exploit_explanation = self.exploit_model.explain(record, parsed_vector)

        # Step 5: MITRE ATT&CK mapping
        mitre_techniques: list[MITRETechnique] = []
        if record.cwe_ids:
            mitre_techniques = self.mitre.map_cwe_list_to_techniques(record.cwe_ids)

        # Step 6: Generate findings
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        finding_severity = severity_map.get(
            record.severity.lower(), Severity.INFO
        )

        risk_map = {
            "critical": Risk.CRITICAL,
            "high": Risk.HIGH,
            "medium": Risk.MEDIUM,
            "low": Risk.LOW,
        }
        finding_risk = risk_map.get(record.severity.lower(), Risk.NEGLIGIBLE)

        result.add_finding(Finding(
            title=f"{record.cve_id}: {record.severity.upper()} severity vulnerability",
            description=record.description,
            severity=finding_severity,
            risk=finding_risk,
            confidence=1.0,
            evidence={
                "cve_id": record.cve_id,
                "cvss_score": record.cvss_score,
                "cvss_vector": record.cvss_vector,
                "exploit_probability": exploit_prob,
                "cwe_ids": record.cwe_ids,
            },
            recommendation=self._generate_cve_recommendation(record),
            references=[
                f"https://nvd.nist.gov/vuln/detail/{record.cve_id}",
            ] + record.references[:3],
        ))

        if exploit_prob > 0.5:
            result.add_finding(Finding(
                title=f"High exploitation probability for {record.cve_id}",
                description=(
                    f"The exploitation probability model estimates a "
                    f"{exploit_prob:.1%} chance of exploitation. "
                    f"Factors: {exploit_explanation.get('factor_count', 0)} "
                    f"contributing evidence factors."
                ),
                severity=Severity.HIGH,
                risk=Risk.HIGH,
                confidence=exploit_prob,
                evidence=exploit_explanation,
                recommendation="Prioritise patching and deploy compensating controls immediately.",
            ))

        if mitre_techniques:
            technique_names = ", ".join(
                f"{t.technique_id} ({t.name})" for t in mitre_techniques[:5]
            )
            result.add_finding(Finding(
                title=f"MITRE ATT&CK mapping for {record.cve_id}",
                description=f"Mapped to {len(mitre_techniques)} technique(s): {technique_names}",
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
                evidence={
                    "techniques": [
                        {"id": t.technique_id, "name": t.name, "tactic": t.tactic}
                        for t in mitre_techniques
                    ],
                },
            ))

        # Store rich data
        result.metadata = {
            "cve_record": record.model_dump(),
            "cvss_details": cvss_details,
            "exploit_probability": exploit_explanation,
            "mitre_techniques": [t.model_dump() for t in mitre_techniques],
        }

        result.summary = (
            f"{record.cve_id}: CVSS {record.cvss_score:.1f} "
            f"({record.severity.upper()}), "
            f"Exploit Probability: {exploit_prob:.1%}, "
            f"{len(mitre_techniques)} ATT&CK techniques mapped."
        )

        # Cache the enriched record
        self.db.insert_cve(record)

        result.end_time = datetime.now(timezone.utc)
        return result

    # ================================================================== #
    #  IoC Extraction
    # ================================================================== #

    async def extract_iocs(self, file_path: str) -> ScanResult:
        """Extract Indicators of Compromise from a file.

        Pipeline:
          1. Read file and extract IoCs via regex patterns
          2. Map IoCs to MITRE ATT&CK techniques
          3. Generate findings for each IoC type
          4. Produce summary statistics

        Args:
            file_path: Path to the file to scan for IoCs.

        Returns:
            ScanResult containing extracted IoCs and findings.
        """
        started = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="nexus",
            target=file_path,
        )

        path = Path(file_path)
        if not path.exists():
            result.add_finding(Finding(
                title=f"File not found: {file_path}",
                description=f"The specified file does not exist: {file_path}",
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
            ))
            result.summary = f"File not found: {file_path}"
            result.end_time = datetime.now(timezone.utc)
            return result

        # Step 1: Extract IoCs
        try:
            iocs = self.ioc_extractor.extract_from_file(file_path)
        except Exception as exc:
            result.add_finding(Finding(
                title=f"IoC extraction error: {file_path}",
                description=str(exc),
                severity=Severity.LOW,
                risk=Risk.LOW,
            ))
            result.summary = f"Error extracting IoCs from {file_path}: {exc}"
            result.end_time = datetime.now(timezone.utc)
            return result

        if not iocs:
            result.add_finding(Finding(
                title="No indicators of compromise found",
                description=f"No IoCs were extracted from {path.name}.",
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
            ))
            result.summary = f"No IoCs found in {path.name}."
            result.end_time = datetime.now(timezone.utc)
            return result

        # Step 2: Map to MITRE ATT&CK
        all_techniques: dict[str, MITRETechnique] = {}
        for ioc in iocs:
            techniques = self.mitre.map_ioc_to_technique(ioc)
            for tech in techniques:
                all_techniques[tech.technique_id] = tech

        # Step 3: Generate findings by type
        from collections import Counter
        type_counts = Counter(ioc.type for ioc in iocs)

        for ioc_type, count in type_counts.most_common():
            severity = Severity.MEDIUM
            if ioc_type.value in ("ipv4", "ipv6", "domain", "url"):
                severity = Severity.HIGH
            elif ioc_type.value in ("md5", "sha1", "sha256"):
                severity = Severity.MEDIUM
            elif ioc_type.value == "cve":
                severity = Severity.HIGH

            examples = [
                ioc.value for ioc in iocs
                if ioc.type == ioc_type
            ][:3]

            result.add_finding(Finding(
                title=f"{count} {ioc_type.value.upper()} indicator(s) found",
                description=f"Extracted {count} {ioc_type.value} indicators. Examples: {', '.join(examples)}",
                severity=severity,
                risk=Risk.MEDIUM if severity in (Severity.HIGH, Severity.MEDIUM) else Risk.LOW,
                evidence={
                    "type": ioc_type.value,
                    "count": count,
                    "examples": examples,
                },
                recommendation=f"Investigate and validate {ioc_type.value} indicators against threat intelligence feeds.",
            ))

        # Store data
        result.metadata = {
            "iocs": [ioc.model_dump() for ioc in iocs],
            "type_summary": {k.value: v for k, v in type_counts.items()},
            "mitre_techniques": [t.model_dump() for t in all_techniques.values()],
        }

        result.summary = (
            f"Extracted {len(iocs)} IoCs from {path.name}: "
            + ", ".join(f"{v} {k.value}" for k, v in type_counts.most_common())
        )

        result.end_time = datetime.now(timezone.utc)
        return result

    # ================================================================== #
    #  Risk Assessment
    # ================================================================== #

    async def assess_risk(self, config_path: str) -> ScanResult:
        """Assess risk from a configuration or scan results file.

        Reads a JSON configuration file containing:
          - CVE identifiers to analyse
          - IoC data to extract and correlate
          - Attack surface node definitions
          - Asset criticality settings

        Pipeline:
          1. Parse configuration file
          2. Look up and enrich all CVEs
          3. Extract IoCs if text/file data provided
          4. Build and analyse attack surface graph
          5. Compute multi-factor risk score
          6. Generate comprehensive threat assessment

        Args:
            config_path: Path to the JSON configuration file.

        Returns:
            ScanResult containing the full threat assessment.
        """
        started = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="nexus",
            target=config_path,
        )

        path = Path(config_path)
        if not path.exists():
            result.add_finding(Finding(
                title=f"Configuration file not found: {config_path}",
                description=f"The specified file does not exist.",
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
            ))
            result.summary = f"Config file not found: {config_path}"
            result.end_time = datetime.now(timezone.utc)
            return result

        # Parse config
        try:
            with open(path, "r", encoding="utf-8") as fh:
                config_data = json.load(fh)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            result.add_finding(Finding(
                title=f"Configuration parse error: {config_path}",
                description=str(exc),
                severity=Severity.LOW,
                risk=Risk.LOW,
            ))
            result.summary = f"Error parsing config: {exc}"
            result.end_time = datetime.now(timezone.utc)
            return result

        # Step 1: CVE analysis
        cve_ids = config_data.get("cve_ids", [])
        cve_records: list[CVERecord] = []

        for cve_id in cve_ids:
            cve_result = await self.lookup_cve(cve_id)
            if cve_result.metadata and "cve_record" in cve_result.metadata:
                record_data = cve_result.metadata["cve_record"]
                cve_records.append(CVERecord(**record_data))

        # Also handle inline CVE records
        for cve_data in config_data.get("cve_records", []):
            record = CVERecord(**cve_data)
            if record.cvss_vector:
                try:
                    parsed = self.cvss.parse_vector(record.cvss_vector)
                    record.cvss_score = self.cvss.calculate_base(parsed)
                    record.severity = self.cvss.severity_from_score(record.cvss_score)
                    record.exploit_probability = self.exploit_model.calculate(
                        record, parsed
                    )
                except ValueError:
                    pass
            cve_records.append(record)

        # Step 2: IoC extraction
        all_iocs: list[IoC] = []
        ioc_text = config_data.get("ioc_text", "")
        if ioc_text:
            all_iocs.extend(self.ioc_extractor.extract_from_text(ioc_text))

        for ioc_file in config_data.get("ioc_files", []):
            try:
                file_iocs = self.ioc_extractor.extract_from_file(ioc_file)
                all_iocs.extend(file_iocs)
            except Exception as exc:
                logger.warning("IoC extraction failed for %s: %s", ioc_file, exc)

        # Step 3: Attack surface analysis
        surface_score = 0.0
        surface_analysis: Optional[dict[str, Any]] = None
        nodes_data = config_data.get("attack_surface_nodes", [])

        if nodes_data:
            nodes = [AttackSurfaceNode(**node) for node in nodes_data]
            graph = self.surface_analyzer.build_graph(nodes)
            surface_analysis = self.surface_analyzer.analyze(graph)
            surface_score = surface_analysis.get("total_score", 0.0)

        # Step 4: MITRE mapping
        all_techniques: dict[str, MITRETechnique] = {}
        for record in cve_records:
            if record.cwe_ids:
                for tech in self.mitre.map_cwe_list_to_techniques(record.cwe_ids):
                    all_techniques[tech.technique_id] = tech
        for ioc in all_iocs:
            for tech in self.mitre.map_ioc_to_technique(ioc):
                all_techniques[tech.technique_id] = tech

        # Step 5: Build threat assessment
        assessment = ThreatAssessment(
            cves=cve_records,
            iocs=all_iocs,
            attack_surface_score=surface_score,
            mitre_techniques=list(all_techniques.values()),
            metadata={
                "asset_criticality": config_data.get("asset_criticality", 50.0),
                "config_file": str(path),
            },
        )

        # Step 6: Risk scoring
        risk_level = self.risk_scorer.score(assessment)
        risk_details = self.risk_scorer.get_score_details()
        assessment.overall_risk = risk_details["total_score"]
        assessment.risk_level = risk_level.value
        assessment.recommendations = risk_details.get("recommendations", [])

        # Step 7: Generate findings from assessment
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "negligible": Severity.INFO,
        }
        risk_to_model_risk = {
            "critical": Risk.CRITICAL,
            "high": Risk.HIGH,
            "medium": Risk.MEDIUM,
            "low": Risk.LOW,
            "negligible": Risk.NEGLIGIBLE,
        }

        result.add_finding(Finding(
            title=f"Overall Risk: {risk_level.value.upper()} ({assessment.overall_risk:.1f}/100)",
            description=(
                f"Multi-factor risk assessment: "
                f"{len(cve_records)} CVEs, {len(all_iocs)} IoCs, "
                f"Attack Surface Score: {surface_score:.1f}, "
                f"{len(all_techniques)} ATT&CK techniques."
            ),
            severity=severity_map.get(risk_level.value, Severity.INFO),
            risk=risk_to_model_risk.get(risk_level.value, Risk.NEGLIGIBLE),
            evidence=risk_details,
        ))

        for rec in assessment.recommendations:
            result.add_finding(Finding(
                title="Recommendation",
                description=rec,
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
            ))

        result.metadata = {
            "assessment": assessment.model_dump(),
            "risk_details": risk_details,
            "surface_analysis": surface_analysis,
        }

        result.summary = (
            f"Risk Assessment: {risk_level.value.upper()} "
            f"({assessment.overall_risk:.1f}/100) - "
            f"{len(cve_records)} CVEs, {len(all_iocs)} IoCs, "
            f"{len(all_techniques)} ATT&CK techniques."
        )

        result.end_time = datetime.now(timezone.utc)
        return result

    # ================================================================== #
    #  CVE Search
    # ================================================================== #

    async def search_cves(self, query: str) -> list[CVERecord]:
        """Search the local CVE database by keyword.

        Uses FTS5 full-text search for fast, BM25-ranked results.

        Args:
            query: Search query string.

        Returns:
            List of matching CVERecord instances.
        """
        return self.db.search(query)

    # ================================================================== #
    #  MITRE ATT&CK Lookup
    # ================================================================== #

    async def lookup_mitre(self, technique_id: str) -> ScanResult:
        """Look up a MITRE ATT&CK technique by its identifier.

        Args:
            technique_id: ATT&CK technique ID (e.g. "T1190").

        Returns:
            ScanResult with technique details.
        """
        started = datetime.now(timezone.utc)
        result = ScanResult(
            tool_name="nexus",
            target=technique_id,
        )

        technique = self.mitre.get_technique(technique_id)

        if technique is None:
            # Try search
            matches = self.mitre.search_techniques(technique_id)
            if matches:
                technique = matches[0]

        if technique is None:
            result.add_finding(Finding(
                title=f"Technique not found: {technique_id}",
                description=f"MITRE ATT&CK technique {technique_id} was not found in the local database.",
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
            ))
            result.summary = f"Technique {technique_id} not found."
        else:
            result.add_finding(Finding(
                title=f"{technique.technique_id}: {technique.name}",
                description=technique.description,
                severity=Severity.INFO,
                risk=Risk.NEGLIGIBLE,
                evidence={
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                    "platforms": technique.platforms,
                    "data_sources": technique.data_sources,
                    "detection": technique.detection,
                },
                references=[technique.url] if technique.url else [],
            ))
            result.metadata = {"technique": technique.model_dump()}
            result.summary = f"{technique.technique_id}: {technique.name} ({technique.tactic})"

        result.end_time = datetime.now(timezone.utc)
        return result

    # ================================================================== #
    #  Helper Methods
    # ================================================================== #

    def _generate_cve_recommendation(self, record: CVERecord) -> str:
        """Generate a recommendation string for a CVE.

        Args:
            record: CVERecord instance.

        Returns:
            Recommendation string.
        """
        parts: list[str] = []

        if record.severity.lower() == "critical":
            parts.append("Apply patches immediately.")
        elif record.severity.lower() == "high":
            parts.append("Schedule urgent patching within 48 hours.")
        elif record.severity.lower() == "medium":
            parts.append("Plan remediation within 30 days.")
        else:
            parts.append("Monitor and address as part of regular maintenance.")

        if record.is_actively_exploited:
            parts.insert(0, "ACTIVELY EXPLOITED - Deploy emergency mitigations.")

        if record.has_public_exploit:
            parts.append("Public exploit available - heightened risk of attack.")

        if record.cwe_ids:
            parts.append(f"Related weaknesses: {', '.join(record.cwe_ids)}.")

        return " ".join(parts)

    def close(self) -> None:
        """Close the engine and release database resources."""
        self.db.close()
