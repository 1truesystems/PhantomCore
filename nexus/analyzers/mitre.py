"""
MITRE ATT&CK Mapper
=====================

Maps vulnerabilities (via CWE identifiers) and indicators of compromise
to MITRE ATT&CK techniques, enabling threat-informed defence prioritisation.

The mapper loads technique data from a local JSON database and provides
lookup, search, and mapping functions for integrating ATT&CK intelligence
into the Nexus threat correlation pipeline.

CWE-to-ATT&CK Mapping Rationale:
    CWE (Common Weakness Enumeration) describes software weaknesses,
    while ATT&CK describes adversary behaviours. The mapping connects
    exploitable weaknesses to the tactics/techniques adversaries use
    to exploit them, based on published threat intelligence and
    vulnerability research.

References:
    - MITRE Corporation. (2023). MITRE ATT&CK.
      https://attack.mitre.org/
    - MITRE Corporation. (2023). Common Weakness Enumeration.
      https://cwe.mitre.org/
    - Strom, B. E., et al. (2018). MITRE ATT&CK: Design and Philosophy.
      MITRE Technical Report MTR180314.
    - CISA. (2023). Known Exploited Vulnerabilities Catalog.
      https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from nexus.core.models import IoC, IoCType, MITRETechnique


class MITREMapper:
    """MITRE ATT&CK technique mapper and lookup engine.

    Loads technique definitions from a local JSON database and provides
    methods to map CWE identifiers, IoC types, and free-text queries
    to relevant ATT&CK techniques.

    Attributes:
        techniques: List of all loaded MITRETechnique instances.
        technique_index: Mapping from technique_id to MITRETechnique.

    Usage::

        mapper = MITREMapper()
        techs = mapper.map_cwe_to_technique("CWE-79")
        for t in techs:
            print(f"{t.technique_id}: {t.name}")
    """

    # ================================================================== #
    #  CWE-to-ATT&CK Mapping Table
    # ================================================================== #
    #
    #  Maps Common Weakness Enumeration IDs to relevant ATT&CK technique
    #  IDs. Based on analysis of exploitation patterns documented in
    #  CISA KEV catalog and MITRE CVE/CWE databases.

    CWE_TO_ATTACK: dict[str, list[str]] = {
        # Injection Weaknesses
        "CWE-79": ["T1059.007"],       # XSS -> JavaScript execution
        "CWE-89": ["T1190"],            # SQL Injection -> Exploit Public App
        "CWE-78": ["T1059"],            # OS Command Injection -> Command Execution
        "CWE-77": ["T1059"],            # Command Injection -> Command Execution
        "CWE-94": ["T1059"],            # Code Injection -> Command Execution
        "CWE-917": ["T1059"],           # Expression Language Injection

        # Authentication / Authorization Weaknesses
        "CWE-287": ["T1078"],           # Auth Bypass -> Valid Accounts
        "CWE-306": ["T1078"],           # Missing Auth -> Valid Accounts
        "CWE-862": ["T1078"],           # Missing Authorization -> Valid Accounts
        "CWE-863": ["T1078"],           # Incorrect Authorization -> Valid Accounts
        "CWE-798": ["T1078"],           # Hard-coded Credentials -> Valid Accounts
        "CWE-522": ["T1110"],           # Weak Credentials -> Brute Force
        "CWE-521": ["T1110"],           # Weak Password Requirements -> Brute Force
        "CWE-307": ["T1110"],           # Brute Force -> Brute Force

        # Deserialization / Code Execution
        "CWE-502": ["T1059", "T1203"],  # Deserialization -> Command Exec + Exploit
        "CWE-20": ["T1190", "T1059"],   # Improper Input Validation
        "CWE-434": ["T1190", "T1105"],  # Unrestricted Upload -> Exploit + Ingress Tool

        # Memory Corruption
        "CWE-119": ["T1203"],           # Buffer Overflow -> Exploit for Client Exec
        "CWE-120": ["T1203"],           # Classic Buffer Overflow
        "CWE-125": ["T1203"],           # Out-of-bounds Read
        "CWE-787": ["T1203"],           # Out-of-bounds Write
        "CWE-416": ["T1203"],           # Use After Free
        "CWE-190": ["T1203"],           # Integer Overflow

        # Privilege Escalation
        "CWE-269": ["T1068"],           # Improper Privilege Mgmt -> Exploitation for PE
        "CWE-250": ["T1068"],           # Execute with Unnecessary Privileges
        "CWE-732": ["T1068", "T1548"],  # Incorrect Permissions -> PE + Abuse Elevation

        # Information Disclosure
        "CWE-200": ["T1005"],           # Information Exposure -> Data from Local System
        "CWE-209": ["T1005"],           # Error Message Info Disclosure
        "CWE-532": ["T1005"],           # Info Exposure Through Log Files

        # Path Traversal / File Access
        "CWE-22": ["T1005"],            # Path Traversal -> Data from Local System
        "CWE-23": ["T1005"],            # Relative Path Traversal
        "CWE-36": ["T1005"],            # Absolute Path Traversal

        # Cryptographic Weaknesses
        "CWE-327": ["T1040"],           # Weak Crypto -> Network Sniffing
        "CWE-326": ["T1040"],           # Inadequate Encryption Strength
        "CWE-295": ["T1557"],           # Improper Cert Validation -> Adversary-in-the-Middle

        # SSRF / Request Forgery
        "CWE-918": ["T1190"],           # SSRF -> Exploit Public-Facing App
        "CWE-352": ["T1190"],           # CSRF -> Exploit Public-Facing App

        # XML / XXE
        "CWE-611": ["T1059", "T1005"],  # XXE -> Command Exec + Data Collection

        # Configuration
        "CWE-16": ["T1190"],            # Configuration -> Exploit Public App
        "CWE-1188": ["T1190"],          # Default Initialisation of Resource
    }

    # IoC type to likely ATT&CK technique mapping
    IOC_TYPE_TO_ATTACK: dict[IoCType, list[str]] = {
        IoCType.IPV4: ["T1071", "T1105"],      # C2 comm + ingress tool
        IoCType.IPV6: ["T1071", "T1105"],
        IoCType.DOMAIN: ["T1071", "T1105"],     # C2 comm + ingress tool
        IoCType.URL: ["T1071", "T1105", "T1566"],  # C2 + phishing
        IoCType.MD5: ["T1027"],                  # Obfuscated files
        IoCType.SHA1: ["T1027"],
        IoCType.SHA256: ["T1027"],
        IoCType.EMAIL: ["T1566"],                # Phishing
        IoCType.CVE: ["T1190", "T1203"],         # Exploits
        IoCType.FILENAME: ["T1059", "T1105"],    # Execution + ingress
        IoCType.REGISTRY_KEY: ["T1547"],         # Boot/Logon Autostart
        IoCType.FILE_PATH: ["T1005", "T1059"],   # Data collection + exec
    }

    def __init__(
        self,
        data_path: Optional[str | Path] = None,
    ) -> None:
        """Initialise the MITRE ATT&CK mapper.

        Loads technique data from the JSON database file. If the file
        is not found, the mapper initialises with an empty technique
        set but remains functional for CWE/IoC mapping using the
        built-in mapping tables.

        Args:
            data_path: Path to the mitre_attack.json data file.
                      Defaults to nexus/data/mitre_attack.json.
        """
        self.techniques: list[MITRETechnique] = []
        self.technique_index: dict[str, MITRETechnique] = {}

        if data_path is None:
            data_path = (
                Path(__file__).resolve().parent.parent / "data" / "mitre_attack.json"
            )
        else:
            data_path = Path(data_path)

        self._load_techniques(data_path)

    def _load_techniques(self, data_path: Path) -> None:
        """Load technique definitions from the JSON data file.

        Args:
            data_path: Path to the JSON file.
        """
        if not data_path.exists():
            return

        try:
            with open(data_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            techniques_data = data if isinstance(data, list) else data.get("techniques", [])

            for entry in techniques_data:
                technique = MITRETechnique(
                    technique_id=entry.get("technique_id", ""),
                    name=entry.get("name", ""),
                    tactic=entry.get("tactic", ""),
                    description=entry.get("description", ""),
                    detection=entry.get("detection", ""),
                    platforms=entry.get("platforms", []),
                    data_sources=entry.get("data_sources", []),
                    url=entry.get(
                        "url",
                        f"https://attack.mitre.org/techniques/"
                        f"{entry.get('technique_id', '').replace('.', '/')}/",
                    ),
                )
                self.techniques.append(technique)
                self.technique_index[technique.technique_id] = technique

        except (json.JSONDecodeError, KeyError, TypeError):
            # If data file is malformed, continue with empty techniques
            pass

    # ================================================================== #
    #  Lookup Methods
    # ================================================================== #

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Look up a specific ATT&CK technique by its identifier.

        Args:
            technique_id: ATT&CK technique ID (e.g. "T1190").

        Returns:
            MITRETechnique if found, None otherwise.
        """
        return self.technique_index.get(technique_id)

    def map_cwe_to_technique(self, cwe_id: str) -> list[MITRETechnique]:
        """Map a CWE identifier to relevant ATT&CK techniques.

        Uses the built-in CWE-to-ATT&CK mapping table to find
        techniques that adversaries commonly use when exploiting
        the given weakness type.

        Reference:
            MITRE. (2023). ATT&CK and CWE Mapping Methodology.

        Args:
            cwe_id: CWE identifier (e.g. "CWE-79" or "79").

        Returns:
            List of mapped MITRETechnique instances. Returns techniques
            from the index when available, otherwise constructs minimal
            stubs from the mapping table.
        """
        # Normalise CWE ID format
        cwe_id = cwe_id.upper().strip()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        technique_ids = self.CWE_TO_ATTACK.get(cwe_id, [])
        results: list[MITRETechnique] = []

        for tid in technique_ids:
            technique = self.technique_index.get(tid)
            if technique is not None:
                results.append(technique)
            else:
                # Create minimal stub if not in loaded data
                results.append(MITRETechnique(
                    technique_id=tid,
                    name=f"Technique {tid}",
                    url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                ))

        return results

    def map_cwe_list_to_techniques(
        self, cwe_ids: list[str]
    ) -> list[MITRETechnique]:
        """Map multiple CWE identifiers to ATT&CK techniques.

        Deduplicates results across all CWE mappings.

        Args:
            cwe_ids: List of CWE identifiers.

        Returns:
            Deduplicated list of MITRETechnique instances.
        """
        seen: set[str] = set()
        results: list[MITRETechnique] = []

        for cwe_id in cwe_ids:
            for technique in self.map_cwe_to_technique(cwe_id):
                if technique.technique_id not in seen:
                    seen.add(technique.technique_id)
                    results.append(technique)

        return results

    def map_ioc_to_technique(self, ioc: IoC) -> list[MITRETechnique]:
        """Map an IoC to relevant ATT&CK techniques based on its type.

        Different IoC types suggest different adversary behaviours.
        For example, IP/domain IoCs suggest C2 communication (T1071),
        while email IoCs suggest phishing (T1566).

        Reference:
            Strom, B. E., et al. (2018). MITRE ATT&CK: Design and
            Philosophy. Section 3: Technique Abstraction.

        Args:
            ioc: Indicator of Compromise instance.

        Returns:
            List of relevant MITRETechnique instances.
        """
        technique_ids = self.IOC_TYPE_TO_ATTACK.get(ioc.type, [])
        results: list[MITRETechnique] = []

        for tid in technique_ids:
            technique = self.technique_index.get(tid)
            if technique is not None:
                results.append(technique)
            else:
                results.append(MITRETechnique(
                    technique_id=tid,
                    name=f"Technique {tid}",
                    url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                ))

        return results

    def search_techniques(self, query: str) -> list[MITRETechnique]:
        """Search loaded techniques by keyword.

        Performs case-insensitive substring matching against technique
        names, descriptions, tactics, and IDs.

        Args:
            query: Search query string.

        Returns:
            List of matching MITRETechnique instances.
        """
        query_lower = query.lower().strip()
        if not query_lower:
            return []

        results: list[MITRETechnique] = []

        for technique in self.techniques:
            searchable = " ".join([
                technique.technique_id.lower(),
                technique.name.lower(),
                technique.tactic.lower(),
                technique.description.lower(),
            ])
            if query_lower in searchable:
                results.append(technique)

        return results

    def get_techniques_by_tactic(self, tactic: str) -> list[MITRETechnique]:
        """Retrieve all techniques for a given tactic.

        Args:
            tactic: ATT&CK tactic name (e.g. "initial-access",
                   "execution", "persistence").

        Returns:
            List of techniques belonging to the specified tactic.
        """
        tactic_lower = tactic.lower().strip()
        return [
            t for t in self.techniques
            if t.tactic.lower() == tactic_lower
        ]

    def get_all_tactics(self) -> list[str]:
        """Return a sorted list of all unique tactics in the loaded data.

        Returns:
            Sorted list of tactic name strings.
        """
        return sorted(set(t.tactic for t in self.techniques if t.tactic))
