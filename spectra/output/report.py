"""
Spectra Report Generator
=========================

Generates HTML and JSON reports from Spectra analysis results.
HTML reports are standalone files with embedded CSS for portability.
JSON reports follow a structured schema for machine consumption.

References:
    - PhantomCore Shared Models: shared.models.ScanResult
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from shared.logger import PhantomLogger
from shared.models import ScanResult

logger = PhantomLogger("spectra.report")


class _SpectraJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for Spectra data types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return sorted(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


class SpectraReportGenerator:
    """Generates HTML and JSON reports from Spectra analysis results.

    Usage::

        generator = SpectraReportGenerator()
        generator.generate_html(result, "report.html")
        generator.generate_json(result, "report.json")
    """

    # ================================================================== #
    #  JSON Report
    # ================================================================== #

    def generate_json(
        self,
        result: ScanResult,
        output_path: str,
    ) -> str:
        """Generate a JSON report from analysis results.

        Args:
            result: ScanResult from the Spectra engine.
            output_path: Output file path for the JSON report.

        Returns:
            Absolute path to the generated report.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        report_data = {
            "report_type": "spectra_network_intelligence",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": result.tool,
            "target": result.target,
            "scan_id": str(result.id),
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "duration_seconds": result.duration_seconds,
            "summary": result.summary,
            "metadata": result.metadata,
            "statistics": {
                "total_findings": result.finding_count,
                "critical_findings": result.critical_count,
                "high_findings": result.high_count,
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
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in result.findings
            ],
            "raw_data": result.raw_data,
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, cls=_SpectraJSONEncoder, indent=2, ensure_ascii=False)

        logger.info(f"JSON report generated: {path.resolve()}")
        return str(path.resolve())

    # ================================================================== #
    #  HTML Report
    # ================================================================== #

    def generate_html(
        self,
        result: ScanResult,
        output_path: str,
    ) -> str:
        """Generate a standalone HTML report from analysis results.

        Produces a self-contained HTML file with embedded CSS styling.
        No external dependencies are required to view the report.

        Args:
            result: ScanResult from the Spectra engine.
            output_path: Output file path for the HTML report.

        Returns:
            Absolute path to the generated report.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        html = self._build_html(result)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info(f"HTML report generated: {path.resolve()}")
        return str(path.resolve())

    def _build_html(self, result: ScanResult) -> str:
        """Build the complete HTML document."""
        meta = result.metadata
        raw = result.raw_data

        findings_html = self._build_findings_html(result)
        hosts_html = self._build_hosts_html(raw.get("hosts", {}))
        anomalies_html = self._build_anomalies_html(raw.get("anomaly_alerts", []))
        beacons_html = self._build_beacons_html(raw.get("beacon_results", []))
        lateral_html = self._build_lateral_html(raw.get("lateral_movements", []))
        graph_html = self._build_graph_html(
            raw.get("graph_analysis", {}),
            raw.get("graph_key_nodes", {}),
        )
        services_html = self._build_services_html(raw.get("service_fingerprints", {}))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Spectra Network Intelligence Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-cyan: #58a6ff;
            --accent-magenta: #bc8cff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
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

        h1 {{
            color: var(--accent-cyan);
            font-size: 2rem;
            margin-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent-magenta);
            padding-bottom: 0.5rem;
        }}

        h2 {{
            color: var(--accent-magenta);
            font-size: 1.4rem;
            margin: 2rem 0 1rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.3rem;
        }}

        h3 {{
            color: var(--accent-cyan);
            font-size: 1.1rem;
            margin: 1rem 0 0.5rem;
        }}

        .subtitle {{
            color: var(--text-secondary);
            font-style: italic;
            margin-bottom: 1rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }}

        .summary-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }}

        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-cyan);
        }}

        .summary-card .label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: var(--bg-secondary);
            border-radius: 6px;
            overflow: hidden;
        }}

        th {{
            background: var(--bg-tertiary);
            color: var(--accent-magenta);
            padding: 0.75rem 1rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--border);
        }}

        td {{
            padding: 0.5rem 1rem;
            border-bottom: 1px solid var(--border);
        }}

        tr:hover {{ background: var(--bg-tertiary); }}

        .severity-critical {{ color: #fff; background: var(--accent-red); padding: 2px 8px; border-radius: 3px; font-weight: bold; }}
        .severity-high {{ color: var(--accent-red); font-weight: bold; }}
        .severity-medium {{ color: var(--accent-yellow); font-weight: bold; }}
        .severity-low {{ color: var(--accent-cyan); }}
        .severity-info {{ color: var(--text-secondary); }}

        .panel {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
        }}

        .panel.warning {{ border-left: 4px solid var(--accent-yellow); }}
        .panel.danger {{ border-left: 4px solid var(--accent-red); }}
        .panel.info {{ border-left: 4px solid var(--accent-cyan); }}

        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .badge-red {{ background: rgba(248,81,73,0.2); color: var(--accent-red); }}
        .badge-yellow {{ background: rgba(210,153,34,0.2); color: var(--accent-yellow); }}
        .badge-green {{ background: rgba(63,185,80,0.2); color: var(--accent-green); }}

        footer {{
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-align: center;
        }}

        code {{
            background: var(--bg-tertiary);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SPECTRA Network Intelligence Report</h1>
        <p class="subtitle">
            PhantomCore Cybersecurity Educational Toolkit --
            Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
        </p>

        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">{meta.get('host_count', 0)}</div>
                <div class="label">Hosts</div>
            </div>
            <div class="summary-card">
                <div class="value">{meta.get('flow_count', 0)}</div>
                <div class="label">Flows</div>
            </div>
            <div class="summary-card">
                <div class="value">{result.finding_count}</div>
                <div class="label">Findings</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: var(--accent-red)">{result.critical_count}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: var(--accent-yellow)">{meta.get('anomaly_count', 0)}</div>
                <div class="label">Anomalies</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: var(--accent-red)">{meta.get('beacon_count', 0)}</div>
                <div class="label">Beacons</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: var(--accent-red)">{meta.get('lateral_count', 0)}</div>
                <div class="label">Lateral Movement</div>
            </div>
            <div class="summary-card">
                <div class="value">{meta.get('community_count', 0)}</div>
                <div class="label">Communities</div>
            </div>
        </div>

        <div class="panel info">
            <strong>Target:</strong> {result.target}<br>
            <strong>Duration:</strong> {result.duration_seconds:.2f}s<br>
            <strong>Scan ID:</strong> <code>{result.id}</code>
        </div>

        {hosts_html}
        {services_html}
        {anomalies_html}
        {graph_html}
        {beacons_html}
        {lateral_html}
        {findings_html}

        <footer>
            <p>
                PhantomCore SPECTRA -- Network Intelligence Engine<br>
                Educational cybersecurity toolkit. Generated by PhantomCore v1.0.0.
            </p>
        </footer>
    </div>
</body>
</html>"""

    # ------------------------------------------------------------------ #
    #  Section Builders
    # ------------------------------------------------------------------ #

    def _build_hosts_html(self, hosts_data: dict[str, Any]) -> str:
        """Build the hosts section HTML."""
        if not hosts_data:
            return ""

        rows = ""
        sorted_hosts = sorted(
            hosts_data.items(),
            key=lambda x: x[1].get("bytes_sent", 0) + x[1].get("bytes_recv", 0),
            reverse=True,
        )

        for ip, hdata in sorted_hosts[:50]:
            ports = hdata.get("ports", [])
            ports_str = ", ".join(str(p) for p in ports[:8])
            if len(ports) > 8:
                ports_str += f" (+{len(ports) - 8})"

            rows += f"""<tr>
                <td><code>{ip}</code></td>
                <td>{hdata.get('mac', '') or '-'}</td>
                <td>{ports_str or '-'}</td>
                <td style="text-align:right">{self._fmt_bytes(hdata.get('bytes_sent', 0))}</td>
                <td style="text-align:right">{self._fmt_bytes(hdata.get('bytes_recv', 0))}</td>
                <td style="text-align:right">{hdata.get('packet_count', 0):,}</td>
            </tr>"""

        return f"""<h2>Network Hosts ({len(hosts_data)})</h2>
        <table>
            <thead><tr>
                <th>IP Address</th><th>MAC</th><th>Ports</th>
                <th>Sent</th><th>Received</th><th>Packets</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _build_services_html(self, services_data: dict[str, Any]) -> str:
        """Build the services section HTML."""
        if not services_data:
            return ""

        rows = ""
        for ip, port_map in services_data.items():
            for port, info in port_map.items():
                conf = info.get("confidence", 0.0)
                conf_class = "badge-green" if conf > 0.7 else "badge-yellow" if conf > 0.4 else ""
                rows += f"""<tr>
                    <td><code>{ip}</code></td>
                    <td>{port}</td>
                    <td><strong>{info.get('service', 'Unknown')}</strong></td>
                    <td><span class="badge {conf_class}">{conf:.1%}</span></td>
                    <td>{info.get('description', '')}</td>
                </tr>"""

        return f"""<h2>Identified Services</h2>
        <table>
            <thead><tr>
                <th>Host</th><th>Port</th><th>Service</th>
                <th>Confidence</th><th>Description</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _build_anomalies_html(self, alerts_data: list[dict]) -> str:
        """Build the anomalies section HTML."""
        if not alerts_data:
            return ""

        rows = ""
        for alert in alerts_data:
            sev = alert.get("severity", "medium")
            sev_class = f"severity-{sev}"
            rows += f"""<tr>
                <td><span class="{sev_class}">{sev.upper()}</span></td>
                <td>{alert.get('type', '').replace('_', ' ').title()}</td>
                <td><code>{alert.get('source', '-')}</code></td>
                <td><code>{alert.get('target', '') or '-'}</code></td>
                <td>{alert.get('description', '')[:150]}</td>
            </tr>"""

        return f"""<h2>Anomaly Alerts ({len(alerts_data)})</h2>
        <table>
            <thead><tr>
                <th>Severity</th><th>Type</th><th>Source</th>
                <th>Target</th><th>Description</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _build_beacons_html(self, beacon_data: list[dict]) -> str:
        """Build the beacons section HTML."""
        if not beacon_data:
            return ""

        rows = ""
        for b in beacon_data:
            is_beacon = b.get("is_beacon", False)
            beacon_badge = '<span class="badge badge-red">BEACON</span>' if is_beacon else '<span class="badge">No</span>'
            rows += f"""<tr>
                <td><code>{b.get('src', '-')}</code></td>
                <td><code>{b.get('dst', '-')}</code></td>
                <td style="text-align:right">{b.get('interval_mean', 0.0):.1f}s</td>
                <td style="text-align:right">{b.get('cv', 0.0):.4f}</td>
                <td style="text-align:right">{b.get('entropy', 0.0):.2f}</td>
                <td style="text-align:right">{b.get('confidence', 0.0):.2f}</td>
                <td>{beacon_badge}</td>
            </tr>"""

        return f"""<h2>C2 Beacon Detection</h2>
        <table>
            <thead><tr>
                <th>Source</th><th>Destination</th><th>Interval</th>
                <th>CV</th><th>Entropy</th><th>Confidence</th><th>Beacon</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _build_lateral_html(self, lateral_data: list[dict]) -> str:
        """Build the lateral movement section HTML."""
        if not lateral_data:
            return ""

        panels = ""
        for i, m in enumerate(lateral_data, 1):
            path = " &#8594; ".join(m.get("path", []))
            conf = m.get("confidence", 0.0)
            panel_class = "danger" if conf > 0.7 else "warning"

            evidence_html = ""
            for ev in m.get("evidence", []):
                evidence_html += f"<li>{ev}</li>"

            panels += f"""<div class="panel {panel_class}">
                <h3>Lateral Movement #{i}: {m.get('technique', 'Unknown')}</h3>
                <p><strong>Path:</strong> <code>{path}</code></p>
                <p><strong>Confidence:</strong> {conf:.2f} |
                   <strong>Duration:</strong> {m.get('timespan_seconds', 0.0):.1f}s |
                   <strong>Ports:</strong> {m.get('ports_used', [])}</p>
                <p><strong>Evidence:</strong></p>
                <ul>{evidence_html}</ul>
            </div>"""

        return f"""<h2>Lateral Movement Detection ({len(lateral_data)})</h2>
        {panels}"""

    def _build_graph_html(
        self,
        graph_data: dict[str, Any],
        key_nodes: dict[str, Any],
    ) -> str:
        """Build the graph analysis section HTML."""
        if not graph_data and not key_nodes:
            return ""

        topology = graph_data.get("topology", {})

        topo_html = ""
        if topology:
            topo_html = f"""<div class="panel info">
                <h3>Topology Metrics</h3>
                <p>
                    <strong>Nodes:</strong> {graph_data.get('node_count', 0)} |
                    <strong>Edges:</strong> {graph_data.get('edge_count', 0)} |
                    <strong>Density:</strong> {topology.get('density', 0.0):.4f} |
                    <strong>Diameter:</strong> {topology.get('diameter', 'N/A')} |
                    <strong>Avg Path:</strong> {topology.get('avg_path_length', 'N/A')} |
                    <strong>Clustering:</strong> {topology.get('avg_clustering', 'N/A')}
                </p>
            </div>"""

        key_nodes_html = ""
        if key_nodes:
            rows = ""
            metric_labels = {
                "betweenness": "Betweenness",
                "eigenvector": "Eigenvector",
                "pagerank": "PageRank",
                "in_degree": "In-Degree",
                "out_degree": "Out-Degree",
            }
            for metric, label in metric_labels.items():
                nodes = key_nodes.get(metric, [])
                for node, score in nodes[:3]:
                    rows += f"""<tr>
                        <td>{label}</td>
                        <td><code>{node}</code></td>
                        <td style="text-align:right">{score:.6f}</td>
                    </tr>"""

            key_nodes_html = f"""<table>
                <thead><tr><th>Metric</th><th>Node</th><th>Score</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>"""

        return f"""<h2>Graph Analysis</h2>
        {topo_html}
        <h3>Key Network Nodes</h3>
        {key_nodes_html}"""

    def _build_findings_html(self, result: ScanResult) -> str:
        """Build the findings section HTML."""
        if not result.findings:
            return "<h2>Findings</h2><p>No findings detected.</p>"

        rows = ""
        for i, f in enumerate(result.findings, 1):
            sev = f.severity.value
            sev_class = f"severity-{sev}"
            rows += f"""<tr>
                <td>{i}</td>
                <td><span class="{sev_class}">{sev.upper()}</span></td>
                <td><strong>{f.title}</strong></td>
                <td>{f.description[:200]}</td>
                <td>{f.confidence:.2f}</td>
                <td>{f.recommendation[:150]}</td>
            </tr>"""

        return f"""<h2>Findings ({result.finding_count})</h2>
        <table>
            <thead><tr>
                <th>#</th><th>Severity</th><th>Title</th>
                <th>Description</th><th>Confidence</th><th>Recommendation</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    # ------------------------------------------------------------------ #
    #  Utility
    # ------------------------------------------------------------------ #

    @staticmethod
    def _fmt_bytes(n: int | float) -> str:
        """Format byte count as human-readable."""
        n = float(n)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(n) < 1024.0:
                return f"{n:.1f} {unit}"
            n /= 1024.0
        return f"{n:.1f} PB"
