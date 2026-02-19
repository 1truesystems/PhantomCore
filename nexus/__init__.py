"""
PhantomCore Nexus -- Threat Intelligence Correlator
=====================================================

Nexus is a comprehensive threat intelligence analysis tool that correlates
vulnerability data (CVEs), indicators of compromise (IoCs), CVSS scoring,
exploitation probability estimation, attack surface analysis, and MITRE
ATT&CK mapping into unified threat assessments.

Modules:
    core/       - Engine, data models, and database
    analyzers/  - CVSS calculator, exploit probability, attack surface, risk scorer, MITRE mapper
    collectors/ - CVE search, IoC extraction
    output/     - Console display and report generation
    data/       - MITRE ATT&CK technique data

References:
    - FIRST. (2019). Common Vulnerability Scoring System v3.1 Specification.
    - MITRE Corporation. (2023). MITRE ATT&CK Framework.
    - NIST. (2023). National Vulnerability Database.
    - Allodi, L., & Massacci, F. (2014). Comparing Vulnerability Severity
      and Exploits Using Case-Control Studies.
"""

from nexus.core.engine import NexusEngine

__all__ = ["NexusEngine"]
__version__ = "1.0.0"
