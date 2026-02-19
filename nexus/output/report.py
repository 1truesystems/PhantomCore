"""
Nexus Report Generator
=======================

Generates HTML and JSON reports from Nexus threat intelligence analysis
results. Reports include CVE details, IoC listings, risk assessments,
MITRE ATT&CK mappings, and actionable recommendations.

HTML reports use a self-contained template with embedded CSS for
professional presentation without external dependencies.

References:
    - NIST SP 800-115: Technical Guide to Information Security Testing
      and Assessment. Section 7: Reporting.
    - OWASP Testing Guide: Reporting section.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from shared.models import Risk, ScanResult

from nexus.core.models import (
    CVERecord,
    IoC,
    MITRETechnique,
    ThreatAssessment,
)


class _NexusJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder handling UUID, datetime, and enum types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "value"):
            return obj.value
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        return super().default(obj)


class NexusReportGenerator:
    """Generate HTML and JSON reports from Nexus analysis results.

    Supports generating reports from ScanResult, ThreatAssessment,
    or raw dictionaries. All reports are self-contained with no
    external dependencies.

    Usage::

        gen = NexusReportGenerator()
        gen.generate_html(scan_result, "/path/to/report.html")
        gen.generate_json(scan_result, "/path/to/report.json")
    """

    def __init__(self) -> None:
        """Initialise the report generator."""
        pass

    # ================================================================== #
    #  JSON Report
    # ================================================================== #

    def generate_json(
        self,
        result: ScanResult | ThreatAssessment | dict[str, Any],
        output_path: str | Path,
    ) -> Path:
        """Generate a JSON report from analysis results.

        Serialises the result to a formatted JSON file with proper
        handling of UUID, datetime, and Pydantic model types.

        Args:
            result: Analysis result (ScanResult, ThreatAssessment, or dict).
            output_path: Path to write the JSON report.

        Returns:
            Path to the generated report file.
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        if hasattr(result, "model_dump"):
            data = result.model_dump()
        elif isinstance(result, dict):
            data = result
        else:
            data = {"result": str(result)}

        # Add metadata
        report_data = {
            "report": {
                "tool": "PhantomCore Nexus",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "format_version": "1.0",
            },
            "data": data,
        }

        with open(output, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2, cls=_NexusJSONEncoder, ensure_ascii=False)

        return output

    # ================================================================== #
    #  HTML Report
    # ================================================================== #

    def generate_html(
        self,
        result: ScanResult | ThreatAssessment | dict[str, Any],
        output_path: str | Path,
    ) -> Path:
        """Generate a self-contained HTML report from analysis results.

        Creates a professional HTML report with embedded CSS styling,
        tables, severity badges, and interactive sections. No external
        CSS/JS dependencies required.

        Args:
            result: Analysis result (ScanResult, ThreatAssessment, or dict).
            output_path: Path to write the HTML report.

        Returns:
            Path to the generated report file.
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict for uniform processing
        if hasattr(result, "model_dump"):
            data = result.model_dump()
        elif isinstance(result, dict):
            data = result
        else:
            data = {"result": str(result)}

        html = self._build_html(data, result)

        with open(output, "w", encoding="utf-8") as fh:
            fh.write(html)

        return output

    def _build_html(
        self,
        data: dict[str, Any],
        original: Any,
    ) -> str:
        """Build the complete HTML document.

        Args:
            data: Serialised result data as a dictionary.
            original: Original result object for type-specific rendering.

        Returns:
            Complete HTML document string.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Determine what type of result we're rendering
        sections_html = ""

        if isinstance(original, ThreatAssessment):
            sections_html = self._render_assessment_html(original)
        elif isinstance(original, ScanResult):
            sections_html = self._render_scan_result_html(original, data)
        else:
            sections_html = self._render_generic_html(data)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomCore Nexus Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-cyan: #58a6ff;
            --accent-magenta: #bc8cff;
            --severity-critical: #f85149;
            --severity-high: #da3633;
            --severity-medium: #d29922;
            --severity-low: #58a6ff;
            --severity-info: #8b949e;
            --border-color: #30363d;
            --success: #3fb950;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .header {{
            text-align: center;
            padding: 2rem;
            border: 1px solid var(--accent-cyan);
            border-radius: 8px;
            margin-bottom: 2rem;
            background: var(--bg-secondary);
        }}

        .header h1 {{
            color: var(--accent-cyan);
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}

        .header .subtitle {{
            color: var(--accent-magenta);
            font-size: 1.1rem;
        }}

        .header .meta {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }}

        .section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}

        .section h2 {{
            color: var(--accent-magenta);
            font-size: 1.4rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .section h3 {{
            color: var(--accent-cyan);
            font-size: 1.1rem;
            margin: 1rem 0 0.5rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}

        th, td {{
            padding: 0.6rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: var(--bg-tertiary);
            color: var(--accent-magenta);
            font-weight: 600;
        }}

        tr:hover {{
            background: var(--bg-tertiary);
        }}

        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: var(--severity-critical); color: white; }}
        .badge-high {{ background: var(--severity-high); color: white; }}
        .badge-medium {{ background: var(--severity-medium); color: black; }}
        .badge-low {{ background: var(--severity-low); color: black; }}
        .badge-info {{ background: var(--severity-info); color: white; }}
        .badge-none {{ background: var(--border-color); color: var(--text-secondary); }}

        .score-bar {{
            width: 100%;
            height: 24px;
            background: var(--bg-tertiary);
            border-radius: 12px;
            overflow: hidden;
            margin: 0.5rem 0;
        }}

        .score-fill {{
            height: 100%;
            border-radius: 12px;
            transition: width 0.3s;
        }}

        .score-low {{ background: linear-gradient(90deg, var(--success), var(--success)); }}
        .score-medium {{ background: linear-gradient(90deg, var(--success), var(--severity-medium)); }}
        .score-high {{ background: linear-gradient(90deg, var(--severity-medium), var(--severity-high)); }}
        .score-critical {{ background: linear-gradient(90deg, var(--severity-high), var(--severity-critical)); }}

        .recommendation {{
            padding: 0.8rem 1rem;
            margin: 0.5rem 0;
            border-left: 3px solid var(--accent-cyan);
            background: var(--bg-tertiary);
            border-radius: 0 4px 4px 0;
        }}

        .recommendation.urgent {{
            border-left-color: var(--severity-critical);
        }}

        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }}

        .stat-card {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}

        .stat-card .value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-cyan);
        }}

        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 2rem;
        }}

        pre {{
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Cascadia Code', 'Fira Code', monospace;
            font-size: 0.85rem;
        }}

        code {{
            font-family: 'Cascadia Code', 'Fira Code', monospace;
            background: var(--bg-tertiary);
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PhantomCore Nexus</h1>
            <div class="subtitle">Threat Intelligence Correlator Report</div>
            <div class="meta">Generated: {now}</div>
        </div>

        {sections_html}

        <div class="footer">
            <p>PhantomCore Nexus &mdash; Threat Intelligence Correlator</p>
            <p>Educational Cybersecurity Toolkit &bull; Report generated automatically</p>
        </div>
    </div>
</body>
</html>"""

    # ================================================================== #
    #  ThreatAssessment HTML Rendering
    # ================================================================== #

    def _render_assessment_html(self, assessment: ThreatAssessment) -> str:
        """Render ThreatAssessment-specific HTML sections.

        Args:
            assessment: ThreatAssessment instance.

        Returns:
            HTML string for assessment sections.
        """
        sections: list[str] = []

        # Risk Overview
        risk_class = "score-low"
        badge_class = "badge-info"
        if assessment.overall_risk >= 80:
            risk_class = "score-critical"
            badge_class = "badge-critical"
        elif assessment.overall_risk >= 60:
            risk_class = "score-high"
            badge_class = "badge-high"
        elif assessment.overall_risk >= 40:
            risk_class = "score-medium"
            badge_class = "badge-medium"
        elif assessment.overall_risk >= 20:
            risk_class = "score-low"
            badge_class = "badge-low"

        sections.append(f"""
        <div class="section">
            <h2>Risk Assessment</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="value">{assessment.overall_risk:.1f}</div>
                    <div class="label">Risk Score (0-100)</div>
                </div>
                <div class="stat-card">
                    <div class="value"><span class="{badge_class}">{assessment.risk_level.upper()}</span></div>
                    <div class="label">Risk Level</div>
                </div>
                <div class="stat-card">
                    <div class="value">{len(assessment.cves)}</div>
                    <div class="label">CVEs Identified</div>
                </div>
                <div class="stat-card">
                    <div class="value">{len(assessment.iocs)}</div>
                    <div class="label">IoCs Extracted</div>
                </div>
            </div>
            <div class="score-bar">
                <div class="score-fill {risk_class}" style="width: {assessment.overall_risk}%"></div>
            </div>
        </div>
        """)

        # CVE Table
        if assessment.cves:
            cve_rows = ""
            for cve in sorted(assessment.cves, key=lambda c: c.cvss_score, reverse=True):
                sev_class = f"badge-{cve.severity.lower()}" if cve.severity.lower() in ("critical", "high", "medium", "low") else "badge-info"
                prob = f"{cve.exploit_probability:.1%}" if cve.exploit_probability > 0 else "-"
                desc = cve.description
                if len(desc) > 120:
                    desc = desc[:117] + "..."
                desc = desc.replace("<", "&lt;").replace(">", "&gt;")
                cve_rows += f"""
                <tr>
                    <td><code>{cve.cve_id}</code></td>
                    <td>{cve.cvss_score:.1f}</td>
                    <td><span class="badge {sev_class}">{cve.severity.upper()}</span></td>
                    <td>{prob}</td>
                    <td>{desc}</td>
                </tr>"""

            sections.append(f"""
            <div class="section">
                <h2>Vulnerabilities ({len(assessment.cves)})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>CVSS</th>
                            <th>Severity</th>
                            <th>Exploit Prob.</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>{cve_rows}
                    </tbody>
                </table>
            </div>
            """)

        # IoC Table
        if assessment.iocs:
            ioc_rows = ""
            for ioc in assessment.iocs:
                value_escaped = ioc.value.replace("<", "&lt;").replace(">", "&gt;")
                defanged_escaped = ioc.defanged_value.replace("<", "&lt;").replace(">", "&gt;") if ioc.defanged_value else ""
                ioc_rows += f"""
                <tr>
                    <td><span class="badge badge-info">{ioc.type.value.upper()}</span></td>
                    <td><code>{value_escaped}</code></td>
                    <td><code>{defanged_escaped}</code></td>
                </tr>"""

            sections.append(f"""
            <div class="section">
                <h2>Indicators of Compromise ({len(assessment.iocs)})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Value</th>
                            <th>Defanged</th>
                        </tr>
                    </thead>
                    <tbody>{ioc_rows}
                    </tbody>
                </table>
            </div>
            """)

        # MITRE ATT&CK
        if assessment.mitre_techniques:
            mitre_rows = ""
            for tech in assessment.mitre_techniques:
                platforms = ", ".join(tech.platforms) if tech.platforms else "-"
                detection = tech.detection
                if len(detection) > 150:
                    detection = detection[:147] + "..."
                detection = detection.replace("<", "&lt;").replace(">", "&gt;")
                mitre_rows += f"""
                <tr>
                    <td><code>{tech.technique_id}</code></td>
                    <td>{tech.name}</td>
                    <td>{tech.tactic.replace('-', ' ').title()}</td>
                    <td>{platforms}</td>
                    <td>{detection}</td>
                </tr>"""

            sections.append(f"""
            <div class="section">
                <h2>MITRE ATT&CK Mapping ({len(assessment.mitre_techniques)})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Technique ID</th>
                            <th>Name</th>
                            <th>Tactic</th>
                            <th>Platforms</th>
                            <th>Detection</th>
                        </tr>
                    </thead>
                    <tbody>{mitre_rows}
                    </tbody>
                </table>
            </div>
            """)

        # Recommendations
        if assessment.recommendations:
            rec_html = ""
            for rec in assessment.recommendations:
                is_urgent = any(
                    word in rec
                    for word in ("CRITICAL", "IMMEDIATE", "URGENT")
                )
                cls = "recommendation urgent" if is_urgent else "recommendation"
                rec_escaped = rec.replace("<", "&lt;").replace(">", "&gt;")
                rec_html += f'<div class="{cls}">{rec_escaped}</div>\n'

            sections.append(f"""
            <div class="section">
                <h2>Recommendations</h2>
                {rec_html}
            </div>
            """)

        return "\n".join(sections)

    # ================================================================== #
    #  ScanResult HTML Rendering
    # ================================================================== #

    def _render_scan_result_html(
        self, result: ScanResult, data: dict[str, Any]
    ) -> str:
        """Render ScanResult-specific HTML sections.

        Args:
            result: ScanResult instance.
            data: Serialised result data.

        Returns:
            HTML string for scan result sections.
        """
        sections: list[str] = []

        # Overview
        sections.append(f"""
        <div class="section">
            <h2>Scan Overview</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="value">{result.tool}</div>
                    <div class="label">Tool</div>
                </div>
                <div class="stat-card">
                    <div class="value">{result.finding_count}</div>
                    <div class="label">Findings</div>
                </div>
                <div class="stat-card">
                    <div class="value">{result.critical_count}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="value">{result.duration_seconds:.1f}s</div>
                    <div class="label">Duration</div>
                </div>
            </div>
            <p><strong>Target:</strong> <code>{result.target}</code></p>
            {f'<p><strong>Summary:</strong> {result.summary}</p>' if result.summary else ''}
        </div>
        """)

        # Findings table
        if result.findings:
            findings_rows = ""
            for finding in result.findings:
                sev = finding.severity.value.lower()
                sev_class = f"badge-{sev}" if sev in ("critical", "high", "medium", "low") else "badge-info"
                desc = finding.description
                if len(desc) > 120:
                    desc = desc[:117] + "..."
                desc = desc.replace("<", "&lt;").replace(">", "&gt;")
                title_escaped = finding.title.replace("<", "&lt;").replace(">", "&gt;")
                findings_rows += f"""
                <tr>
                    <td><span class="badge {sev_class}">{sev.upper()}</span></td>
                    <td>{title_escaped}</td>
                    <td>{desc}</td>
                    <td>{finding.confidence:.0%}</td>
                </tr>"""

            sections.append(f"""
            <div class="section">
                <h2>Findings ({len(result.findings)})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Description</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>{findings_rows}
                    </tbody>
                </table>
            </div>
            """)

        # Raw data section
        if result.raw_data:
            raw_json = json.dumps(result.raw_data, indent=2, cls=_NexusJSONEncoder)
            raw_escaped = raw_json.replace("<", "&lt;").replace(">", "&gt;")
            sections.append(f"""
            <div class="section">
                <h2>Raw Data</h2>
                <pre>{raw_escaped}</pre>
            </div>
            """)

        return "\n".join(sections)

    # ================================================================== #
    #  Generic HTML Rendering
    # ================================================================== #

    def _render_generic_html(self, data: dict[str, Any]) -> str:
        """Render a generic dictionary as formatted HTML.

        Args:
            data: Dictionary of results.

        Returns:
            HTML string.
        """
        raw_json = json.dumps(data, indent=2, cls=_NexusJSONEncoder, ensure_ascii=False)
        raw_escaped = raw_json.replace("<", "&lt;").replace(">", "&gt;")
        return f"""
        <div class="section">
            <h2>Analysis Results</h2>
            <pre>{raw_escaped}</pre>
        </div>
        """
