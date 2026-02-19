"""
Pulse Report Generator
========================

Generates HTML and JSON reports from Pulse wireless analysis results.
Produces self-contained HTML reports with embedded CSS for offline
viewing, and structured JSON for integration with other tools.

References:
    - PhantomCore Shared Models: shared.models.ScanResult
    - OWASP. (2023). Testing Guide v4: Reporting.
"""

from __future__ import annotations

import json
import html as html_module
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from shared.logger import PhantomLogger
from shared.models import ScanResult

from pulse.core.models import (
    AccessPoint,
    BLEDevice,
    ChannelInfo,
    SecurityGrade,
    WifiClient,
    WirelessFinding,
)

logger = PhantomLogger("pulse.output.report")


# ---------------------------------------------------------------------------
# Custom JSON encoder
# ---------------------------------------------------------------------------


class _PulseJSONEncoder(json.JSONEncoder):
    """JSON encoder handling Pulse model serialization."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, UUID):
            return str(obj)
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if hasattr(obj, "dict"):
            return obj.dict()
        if hasattr(obj, "value"):  # Enum
            return obj.value
        return super().default(obj)


# ---------------------------------------------------------------------------
# HTML Report CSS
# ---------------------------------------------------------------------------

_HTML_CSS = """
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #0d1117;
    color: #c9d1d9;
    margin: 0;
    padding: 20px;
    line-height: 1.6;
}
.container {
    max-width: 1200px;
    margin: 0 auto;
}
h1, h2, h3 {
    color: #58a6ff;
    border-bottom: 1px solid #21262d;
    padding-bottom: 8px;
}
h1 { font-size: 2em; text-align: center; }
.banner {
    text-align: center;
    padding: 20px;
    background: linear-gradient(135deg, #161b22, #0d1117);
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-bottom: 24px;
}
.banner h1 { border: none; margin: 0; }
.banner .subtitle {
    color: #8b949e;
    font-style: italic;
}
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.summary-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}
.summary-card .value {
    font-size: 2em;
    font-weight: bold;
    color: #58a6ff;
}
.summary-card .label {
    color: #8b949e;
    font-size: 0.9em;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 24px;
    background: #161b22;
    border-radius: 8px;
    overflow: hidden;
}
th {
    background: #21262d;
    color: #58a6ff;
    padding: 10px 12px;
    text-align: left;
    font-weight: 600;
}
td {
    padding: 8px 12px;
    border-bottom: 1px solid #21262d;
}
tr:hover { background: #1c2128; }
.grade-A { color: #3fb950; font-weight: bold; }
.grade-B { color: #56d364; font-weight: bold; }
.grade-C { color: #d29922; font-weight: bold; }
.grade-D { color: #f85149; font-weight: bold; }
.grade-F { color: #fff; background: #da3633; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
.severity-CRITICAL { color: #fff; background: #da3633; padding: 2px 8px; border-radius: 4px; }
.severity-HIGH { color: #f85149; font-weight: bold; }
.severity-MEDIUM { color: #d29922; font-weight: bold; }
.severity-LOW { color: #58a6ff; }
.severity-INFO { color: #8b949e; }
.enc-WPA3 { color: #3fb950; }
.enc-WPA2 { color: #d29922; }
.enc-WPA { color: #f85149; }
.enc-WEP { color: #da3633; }
.enc-Open { color: #fff; background: #da3633; padding: 2px 6px; border-radius: 4px; }
.finding-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
}
.finding-card.critical { border-left: 4px solid #da3633; }
.finding-card.high { border-left: 4px solid #f85149; }
.finding-card.medium { border-left: 4px solid #d29922; }
.finding-card.low { border-left: 4px solid #58a6ff; }
.finding-card.info { border-left: 4px solid #8b949e; }
.recommendation {
    background: #1c2128;
    border-left: 3px solid #3fb950;
    padding: 8px 12px;
    margin-top: 8px;
    font-size: 0.9em;
}
footer {
    text-align: center;
    color: #8b949e;
    margin-top: 40px;
    padding: 20px;
    border-top: 1px solid #21262d;
}
"""


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------


class PulseReportGenerator:
    """Generates HTML and JSON reports from Pulse analysis results.

    Usage::

        generator = PulseReportGenerator()
        generator.generate_html(scan_result, "report.html")
        generator.generate_json(scan_result, "report.json")
    """

    def generate_html(
        self,
        result: ScanResult,
        output_path: str,
        *,
        aps: Optional[dict[str, AccessPoint]] = None,
        clients: Optional[list[WifiClient]] = None,
        grades: Optional[list[tuple[AccessPoint, SecurityGrade]]] = None,
        channels: Optional[list[ChannelInfo]] = None,
        ble_devices: Optional[list[BLEDevice]] = None,
        wireless_findings: Optional[list[WirelessFinding]] = None,
    ) -> str:
        """Generate a self-contained HTML report.

        Args:
            result: ScanResult with findings.
            output_path: Path for the HTML output file.
            aps: Access points dictionary.
            clients: Client stations list.
            grades: Security grade tuples.
            channels: Channel analysis results.
            ble_devices: BLE device list.
            wireless_findings: Wireless-specific findings.

        Returns:
            Absolute path to the generated report.
        """
        now = datetime.now(timezone.utc)
        e = html_module.escape

        parts: list[str] = []

        # Document header
        parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pulse Wireless Analysis Report</title>
    <style>{_HTML_CSS}</style>
</head>
<body>
<div class="container">
""")

        # Banner
        parts.append(f"""
<div class="banner">
    <h1>PULSE - Wireless Protocol Analyzer</h1>
    <div class="subtitle">PhantomCore Cybersecurity Educational Toolkit</div>
    <div class="subtitle">Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
    <div class="subtitle">Target: {e(result.target)}</div>
</div>
""")

        # Summary cards
        finding_count = len(result.findings)
        critical_count = result.critical_count
        high_count = result.high_count
        ap_count = len(aps) if aps else 0
        client_count = len(clients) if clients else 0

        parts.append("""<h2>Summary</h2>
<div class="summary-grid">""")

        cards = [
            (str(ap_count), "Access Points"),
            (str(client_count), "Client Devices"),
            (str(finding_count), "Total Findings"),
            (str(critical_count), "Critical"),
            (str(high_count), "High"),
            (f"{result.duration_seconds:.1f}s", "Scan Duration"),
        ]
        for value, label in cards:
            parts.append(f"""
    <div class="summary-card">
        <div class="value">{value}</div>
        <div class="label">{label}</div>
    </div>""")

        parts.append("</div>")

        # Access Points table
        if aps:
            grade_lookup = {}
            if grades:
                for ap, grade in grades:
                    grade_lookup[ap.bssid] = grade

            parts.append("<h2>Access Points</h2>")
            parts.append("""<table>
<tr><th>BSSID</th><th>SSID</th><th>CH</th><th>Signal</th>
<th>Encryption</th><th>Cipher</th><th>Auth</th><th>WPS</th>
<th>PMF</th><th>Grade</th><th>Vendor</th><th>Clients</th></tr>""")

            for ap in sorted(aps.values(), key=lambda a: a.signal_dbm, reverse=True):
                ssid_display = e(ap.ssid) if ap.ssid else "<em>&lt;hidden&gt;</em>"
                enc_class = f"enc-{ap.encryption.value.replace('/', '')}"

                grade = grade_lookup.get(ap.bssid)
                if grade:
                    grade_letter = grade.grade
                    grade_class = f"grade-{grade_letter[0]}"
                    grade_str = f'<span class="{grade_class}">{e(grade_letter)}</span>'
                else:
                    grade_str = "-"

                wps_str = '<span style="color:#da3633">YES</span>' if ap.wps_enabled else "No"
                pmf_str = '<span style="color:#3fb950">YES</span>' if ap.pmf else "No"

                parts.append(f"""<tr>
<td>{e(ap.bssid)}</td>
<td>{ssid_display}</td>
<td>{ap.channel}</td>
<td>{ap.signal_dbm} dBm</td>
<td><span class="{enc_class}">{e(ap.encryption.value)}</span></td>
<td>{e(ap.cipher.value)}</td>
<td>{e(ap.auth.value)}</td>
<td>{wps_str}</td>
<td>{pmf_str}</td>
<td>{grade_str}</td>
<td>{e(ap.vendor[:16])}</td>
<td>{len(ap.clients)}</td>
</tr>""")

            parts.append("</table>")

        # Clients table
        if clients:
            parts.append("<h2>Client Devices</h2>")
            parts.append("""<table>
<tr><th>MAC</th><th>Vendor</th><th>Signal</th><th>Associated AP</th>
<th>Randomized</th><th>Probes</th></tr>""")

            for client in sorted(clients, key=lambda c: c.signal_dbm, reverse=True):
                rand_str = (
                    '<span style="color:#3fb950">Yes</span>'
                    if client.is_randomized_mac
                    else '<span style="color:#f85149">No</span>'
                )
                probes = e(", ".join(client.probe_requests[:5]))
                if len(client.probe_requests) > 5:
                    probes += f" (+{len(client.probe_requests) - 5} more)"

                parts.append(f"""<tr>
<td>{e(client.mac)}</td>
<td>{e(client.vendor)}</td>
<td>{client.signal_dbm} dBm</td>
<td>{e(client.associated_ap or '-')}</td>
<td>{rand_str}</td>
<td>{probes or '-'}</td>
</tr>""")

            parts.append("</table>")

        # BLE Devices
        if ble_devices:
            parts.append("<h2>BLE Devices</h2>")
            parts.append("""<table>
<tr><th>Address</th><th>Name</th><th>RSSI</th><th>Type</th>
<th>Company</th><th>Connectable</th><th>Services</th></tr>""")

            for dev in sorted(ble_devices, key=lambda d: d.rssi, reverse=True):
                name = e(dev.name) if dev.name else "<em>&lt;unnamed&gt;</em>"
                conn = "Yes" if dev.connectable else "No"
                svcs = e(", ".join(dev.services[:3]))
                if len(dev.services) > 3:
                    svcs += f" (+{len(dev.services) - 3})"

                parts.append(f"""<tr>
<td>{e(dev.address)}</td>
<td>{name}</td>
<td>{dev.rssi} dBm</td>
<td>{e(dev.address_type.value)}</td>
<td>{e(dev.company or '-')}</td>
<td>{conn}</td>
<td>{svcs or '-'}</td>
</tr>""")

            parts.append("</table>")

        # Channels
        if channels:
            parts.append("<h2>Channel Analysis</h2>")
            parts.append("""<table>
<tr><th>Channel</th><th>Band</th><th>Freq</th><th>Networks</th>
<th>Utilization</th><th>Interference</th><th>DFS</th><th>Recommendation</th></tr>""")

            for ch in sorted(channels, key=lambda c: (c.band, c.channel)):
                int_color = "#3fb950" if ch.interference_score < 0.3 else (
                    "#d29922" if ch.interference_score < 0.6 else "#da3633"
                )
                parts.append(f"""<tr>
<td>{ch.channel}</td>
<td>{e(ch.band)}</td>
<td>{ch.frequency} MHz</td>
<td>{ch.networks_count}</td>
<td>{ch.utilization:.0%}</td>
<td style="color:{int_color}">{ch.interference_score:.0%}</td>
<td>{"Yes" if ch.is_dfs else "No"}</td>
<td>{e(ch.recommendation[:80])}</td>
</tr>""")

            parts.append("</table>")

        # Findings
        all_findings = wireless_findings or []
        if all_findings:
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_findings = sorted(
                all_findings,
                key=lambda f: severity_order.get(f.severity.upper(), 5),
            )

            parts.append("<h2>Security Findings</h2>")

            for finding in sorted_findings:
                sev = finding.severity.upper()
                sev_class = sev.lower()

                parts.append(f"""
<div class="finding-card {sev_class}">
    <strong><span class="severity-{sev}">{sev}</span></strong> &mdash;
    <strong>{e(finding.type.value)}</strong>
    {f' | BSSID: {e(finding.ap_bssid)}' if finding.ap_bssid else ''}
    {f' | Client: {e(finding.client_mac)}' if finding.client_mac else ''}
    <p>{e(finding.description)}</p>
    <div class="recommendation">
        <strong>Recommendation:</strong> {e(finding.recommendation)}
    </div>
    <div style="color:#8b949e;font-size:0.8em;margin-top:8px">
        Confidence: {finding.confidence:.0%}
    </div>
</div>""")

        # Footer
        parts.append(f"""
<footer>
    <p>Generated by <strong>Pulse</strong> - PhantomCore Wireless Protocol Analyzer</p>
    <p>For educational and authorized security assessment purposes only.</p>
    <p>{now.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
</footer>
</div>
</body>
</html>""")

        html_content = "\n".join(parts)

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html_content, encoding="utf-8")

        logger.info(f"HTML report generated: {output}")
        return str(output.resolve())

    def generate_json(
        self,
        result: ScanResult,
        output_path: str,
        *,
        aps: Optional[dict[str, AccessPoint]] = None,
        clients: Optional[list[WifiClient]] = None,
        grades: Optional[list[tuple[AccessPoint, SecurityGrade]]] = None,
        channels: Optional[list[ChannelInfo]] = None,
        ble_devices: Optional[list[BLEDevice]] = None,
        wireless_findings: Optional[list[WirelessFinding]] = None,
    ) -> str:
        """Generate a JSON report.

        Args:
            result: ScanResult with findings.
            output_path: Path for the JSON output file.
            aps: Access points dictionary.
            clients: Client stations list.
            grades: Security grade tuples.
            channels: Channel analysis results.
            ble_devices: BLE device list.
            wireless_findings: Wireless-specific findings.

        Returns:
            Absolute path to the generated report.
        """
        report_data: dict[str, Any] = {
            "tool": "pulse",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": result.target,
            "duration_seconds": result.duration_seconds,
            "summary": {
                "total_findings": len(result.findings),
                "critical_findings": result.critical_count,
                "high_findings": result.high_count,
                "access_points": len(aps) if aps else 0,
                "clients": len(clients) if clients else 0,
                "ble_devices": len(ble_devices) if ble_devices else 0,
            },
        }

        if aps:
            grade_lookup = {}
            if grades:
                for ap, grade in grades:
                    grade_lookup[ap.bssid] = grade

            report_data["access_points"] = []
            for ap in aps.values():
                ap_dict = ap.model_dump()
                grade = grade_lookup.get(ap.bssid)
                if grade:
                    ap_dict["security_grade"] = grade.model_dump()
                report_data["access_points"].append(ap_dict)

        if clients:
            report_data["clients"] = [c.model_dump() for c in clients]

        if ble_devices:
            report_data["ble_devices"] = [d.model_dump() for d in ble_devices]

        if channels:
            report_data["channels"] = [c.model_dump() for c in channels]

        if wireless_findings:
            report_data["wireless_findings"] = [
                f.model_dump() for f in wireless_findings
            ]

        report_data["findings"] = [f.model_dump() for f in result.findings]

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report_data, cls=_PulseJSONEncoder, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        logger.info(f"JSON report generated: {output}")
        return str(output.resolve())
