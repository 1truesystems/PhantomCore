"""
Cipher Report Generator
========================

Generates HTML and JSON reports from Cipher analysis results.
The HTML report uses inline CSS for portability (no external dependencies)
and includes colour-coded tables, grade badges, and entropy visualisations.

The JSON report provides machine-readable structured output suitable for
integration with SIEM systems, CI/CD pipelines, and other tools.

References:
    - Jinja2 Template Documentation. https://jinja.palletsprojects.com/
    - OWASP Reporting Guidelines. https://owasp.org/www-community/
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from shared.models import ScanResult


# ===================================================================== #
#  HTML Template (Inline -- no Jinja2 dependency required)
# ===================================================================== #

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomCore Cipher Report - {title}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-cyan: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-purple: #bc8cff;
            --border: #30363d;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
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
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        .section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .section h2 {{
            color: var(--accent-purple);
            font-size: 1.4rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border: 1px solid var(--border);
        }}
        th {{
            background: var(--bg-tertiary);
            color: var(--accent-cyan);
            font-weight: 600;
        }}
        tr:nth-child(even) {{ background: var(--bg-tertiary); }}
        tr:hover {{ background: rgba(88, 166, 255, 0.05); }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.85rem;
        }}
        .badge-info {{ background: rgba(88, 166, 255, 0.2); color: var(--accent-cyan); }}
        .badge-low {{ background: rgba(63, 185, 80, 0.2); color: var(--accent-green); }}
        .badge-medium {{ background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); }}
        .badge-high {{ background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }}
        .badge-critical {{ background: rgba(248, 81, 73, 0.4); color: #ff7b72; }}
        .grade-badge {{
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 8px;
            font-size: 2rem;
            font-weight: 800;
        }}
        .grade-a-plus {{ background: rgba(63, 185, 80, 0.3); color: var(--accent-green); border: 2px solid var(--accent-green); }}
        .grade-a {{ background: rgba(63, 185, 80, 0.2); color: var(--accent-green); border: 2px solid var(--accent-green); }}
        .grade-b {{ background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); border: 2px solid var(--accent-yellow); }}
        .grade-c {{ background: rgba(210, 153, 34, 0.3); color: var(--accent-yellow); border: 2px solid var(--accent-yellow); }}
        .grade-d {{ background: rgba(248, 81, 73, 0.2); color: var(--accent-red); border: 2px solid var(--accent-red); }}
        .grade-f {{ background: rgba(248, 81, 73, 0.4); color: #ff7b72; border: 2px solid var(--accent-red); }}
        .meter {{
            height: 24px;
            background: var(--bg-tertiary);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        .meter-fill {{
            height: 100%;
            border-radius: 12px;
            transition: width 0.3s ease;
        }}
        .finding {{
            padding: 1rem;
            margin: 0.5rem 0;
            border-left: 4px solid var(--border);
            background: var(--bg-tertiary);
            border-radius: 0 4px 4px 0;
        }}
        .finding-critical {{ border-left-color: var(--accent-red); }}
        .finding-high {{ border-left-color: #ff7b72; }}
        .finding-medium {{ border-left-color: var(--accent-yellow); }}
        .finding-low {{ border-left-color: var(--accent-cyan); }}
        .finding-info {{ border-left-color: var(--accent-green); }}
        .finding h3 {{
            font-size: 1rem;
            margin-bottom: 0.5rem;
        }}
        .finding p {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        .footer {{
            text-align: center;
            padding: 1.5rem;
            color: var(--text-secondary);
            font-size: 0.8rem;
            border-top: 1px solid var(--border);
            margin-top: 2rem;
        }}
        .entropy-bar {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .entropy-bar .bar {{
            flex: 1;
            height: 16px;
            background: var(--bg-tertiary);
            border-radius: 8px;
            overflow: hidden;
        }}
        .entropy-bar .fill {{
            height: 100%;
            border-radius: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PhantomCore :: Cipher</h1>
            <div class="subtitle">
                Cryptographic Analysis Report | {target}<br>
                Generated: {timestamp}
            </div>
        </div>

        <div class="section">
            <h2>Summary</h2>
            <p>{summary}</p>
            <table>
                <tr>
                    <th>Tool</th><td>{tool}</td>
                    <th>Target</th><td>{target}</td>
                </tr>
                <tr>
                    <th>Duration</th><td>{duration:.3f}s</td>
                    <th>Findings</th><td>{finding_count}</td>
                </tr>
            </table>
        </div>

        <div class="section">
            <h2>Findings</h2>
            {findings_html}
        </div>

        {raw_data_section}

        <div class="footer">
            PhantomCore Cipher v1.0.0 | Cryptographic Analysis Framework<br>
            Report generated {timestamp}
        </div>
    </div>
</body>
</html>
"""


class CipherReportGenerator:
    """Generates HTML and JSON reports from Cipher analysis results.

    Supports two output formats:
    - HTML: Styled report with inline CSS, suitable for browsers
    - JSON: Machine-readable structured output

    Usage::

        generator = CipherReportGenerator()
        generator.generate_html(scan_result, Path("report.html"))
        generator.generate_json(scan_result, Path("report.json"))
    """

    def generate_html(
        self,
        result: ScanResult,
        output_path: Path,
        title: Optional[str] = None,
    ) -> Path:
        """Generate an HTML report from a ScanResult.

        Args:
            result: ScanResult containing findings and raw data.
            output_path: Path to write the HTML file.
            title: Optional report title override.

        Returns:
            Path to the generated HTML file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        report_title = title or f"Analysis of {result.target}"

        # Build findings HTML
        findings_html = self._build_findings_html(result)

        # Build raw data section
        raw_data_section = self._build_raw_data_section(result)

        html_content = _HTML_TEMPLATE.format(
            title=self._escape_html(report_title),
            target=self._escape_html(result.target),
            timestamp=timestamp,
            summary=self._escape_html(result.summary),
            tool=self._escape_html(result.tool),
            duration=result.duration_seconds,
            finding_count=result.finding_count,
            findings_html=findings_html,
            raw_data_section=raw_data_section,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")

        return output_path

    def generate_json(
        self,
        result: ScanResult,
        output_path: Path,
    ) -> Path:
        """Generate a JSON report from a ScanResult.

        The JSON output includes all findings, raw analysis data, and
        metadata in a structured format suitable for automated processing.

        Args:
            result: ScanResult containing findings and raw data.
            output_path: Path to write the JSON file.

        Returns:
            Path to the generated JSON file.
        """
        report_data: dict[str, Any] = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tool": result.tool,
                "target": result.target,
                "version": "1.0.0",
            },
            "summary": {
                "total_findings": result.finding_count,
                "critical_findings": result.critical_count,
                "high_findings": result.high_count,
                "duration_seconds": result.duration_seconds,
                "description": result.summary,
            },
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "risk": f.risk.value,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "references": f.references,
                    "metadata": f.metadata,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in result.findings
            ],
            "raw_data": result.raw_data,
            "metadata": result.metadata,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

        return output_path

    # ------------------------------------------------------------------ #
    #  Private HTML Builders
    # ------------------------------------------------------------------ #

    def _build_findings_html(self, result: ScanResult) -> str:
        """Build the HTML for the findings section.

        Args:
            result: ScanResult with findings.

        Returns:
            HTML string for the findings section.
        """
        if not result.findings:
            return '<p style="color: var(--text-secondary);">No findings.</p>'

        html_parts: list[str] = []
        for finding in result.findings:
            severity = finding.severity.value
            badge_class = f"badge-{severity}"
            finding_class = f"finding-{severity}"

            html_parts.append(
                f'<div class="finding {finding_class}">'
                f'  <h3><span class="badge {badge_class}">{severity.upper()}</span> '
                f'  {self._escape_html(finding.title)}</h3>'
                f'  <p>{self._escape_html(finding.description)}</p>'
            )

            if finding.recommendation:
                html_parts.append(
                    f'  <p><strong>Recommendation:</strong> '
                    f'{self._escape_html(finding.recommendation)}</p>'
                )

            if finding.references:
                refs = ", ".join(self._escape_html(r) for r in finding.references)
                html_parts.append(
                    f'  <p style="font-size: 0.8rem; color: var(--text-secondary);">'
                    f'References: {refs}</p>'
                )

            html_parts.append("</div>")

        return "\n".join(html_parts)

    def _build_raw_data_section(self, result: ScanResult) -> str:
        """Build the HTML for the raw data section.

        Renders raw_data as a formatted JSON block if present.

        Args:
            result: ScanResult with raw data.

        Returns:
            HTML string for the raw data section.
        """
        if not result.raw_data:
            return ""

        json_str = json.dumps(result.raw_data, indent=2, ensure_ascii=False, default=str)
        escaped = self._escape_html(json_str)

        return (
            '<div class="section">'
            "  <h2>Raw Analysis Data</h2>"
            f'  <pre style="background: var(--bg-tertiary); padding: 1rem; '
            f'border-radius: 4px; overflow-x: auto; font-size: 0.85rem; '
            f'color: var(--text-secondary);">{escaped}</pre>'
            "</div>"
        )

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters.

        Args:
            text: Raw text to escape.

        Returns:
            HTML-safe string.
        """
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
