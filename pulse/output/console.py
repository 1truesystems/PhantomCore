"""
Pulse Console Output
======================

Rich-based console output for the Pulse Wireless Protocol Analyzer.
Provides formatted tables, panels, and colour-coded displays for
WiFi scan results, BLE devices, channel analysis, security grades,
deauth alerts, and IDS monitoring.

References:
    - Rich library: https://github.com/Textualize/rich
    - PhantomCore Console: shared.console.PhantomConsole
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from shared.console import PhantomConsole

from pulse.core.models import (
    AccessPoint,
    BLEDevice,
    ChannelInfo,
    SecurityGrade,
    SignalQuality,
    WifiClient,
    WirelessFinding,
)
from pulse.analyzers.signal import classify_signal_quality, signal_quality_to_percentage


# ---------------------------------------------------------------------------
# Colour mappings
# ---------------------------------------------------------------------------

_GRADE_COLORS: dict[str, str] = {
    "A+": "bold bright_green",
    "A": "bold bright_green",
    "A-": "bold green",
    "B+": "bold green",
    "B": "bold green",
    "B-": "bold yellow",
    "C+": "bold yellow",
    "C": "bold yellow",
    "C-": "bold bright_yellow",
    "D+": "bold bright_red",
    "D": "bold bright_red",
    "D-": "bold red",
    "F": "bold white on red",
}

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold bright_cyan",
    "INFO": "bold bright_blue",
}

_SIGNAL_COLORS: dict[str, str] = {
    "Excellent": "bold bright_green",
    "Good": "bold green",
    "Fair": "bold yellow",
    "Weak": "bold bright_red",
    "Very Weak": "bold red",
}

_ENCRYPTION_COLORS: dict[str, str] = {
    "WPA3": "bold bright_green",
    "WPA2/WPA3": "bold green",
    "WPA2": "bold yellow",
    "WPA": "bold bright_red",
    "WEP": "bold red",
    "Open": "bold white on red",
    "Unknown": "dim",
}


# ---------------------------------------------------------------------------
# Console Output
# ---------------------------------------------------------------------------


class PulseConsoleOutput:
    """Rich-based console output for Pulse wireless analysis results.

    Provides formatted display methods for all Pulse analysis outputs
    including WiFi scans, BLE scans, channel analysis, security grades,
    deauthentication alerts, and IDS monitoring.

    Usage::

        output = PulseConsoleOutput()
        output.display_scan(aps, clients)
        output.display_ap_table(aps, grades)
        output.display_channels(channels)
    """

    def __init__(self, console: Optional[PhantomConsole] = None) -> None:
        """Initialize the console output.

        Args:
            console: PhantomConsole instance. Creates a new one if None.
        """
        self._console = console or PhantomConsole()

    def display_banner(self) -> None:
        """Display the Pulse tool banner."""
        banner_text = """
[bright_cyan]  ██████╗ ██╗   ██╗██╗     ███████╗███████╗
  ██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
  ██████╔╝██║   ██║██║     ███████╗█████╗
  ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝
  ██║     ╚██████╔╝███████╗███████║███████╗
  ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝[/bright_cyan]
[bright_magenta]  Wireless Protocol Analyzer[/bright_magenta]
[dim]  Wireless Protocol Analyzer[/dim]
"""
        panel = Panel(
            Align.center(Text.from_markup(banner_text)),
            border_style="bright_cyan",
            padding=(0, 2),
        )
        self._console.print(panel)

    def display_scan(
        self,
        aps: dict[str, AccessPoint],
        clients: list[WifiClient],
    ) -> None:
        """Display a scan overview summary.

        Args:
            aps: Discovered access points.
            clients: Discovered client stations.
        """
        self._console.section(
            "Scan Overview"
        )

        # Summary statistics
        total_aps = len(aps)
        hidden_aps = sum(1 for ap in aps.values() if ap.hidden)
        total_clients = len(clients)
        randomized = sum(1 for c in clients if c.is_randomized_mac)

        # Encryption breakdown
        enc_counts: dict[str, int] = {}
        for ap in aps.values():
            enc = ap.encryption.value
            enc_counts[enc] = enc_counts.get(enc, 0) + 1

        # Band breakdown
        band_24 = sum(1 for ap in aps.values() if 1 <= ap.channel <= 14)
        band_5 = sum(1 for ap in aps.values() if ap.channel > 14)

        summary_table = Table(
            title="Scan Summary",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=False,
            padding=(0, 2),
        )
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value", style="bright_white")

        summary_table.add_row("Access Points", str(total_aps))
        summary_table.add_row("  Hidden SSIDs", str(hidden_aps))
        summary_table.add_row("  2.4 GHz Networks", str(band_24))
        summary_table.add_row("  5 GHz Networks", str(band_5))
        summary_table.add_row("Client Stations", str(total_clients))
        summary_table.add_row("  Randomized MACs", str(randomized))
        summary_table.add_row("  Real MACs", str(total_clients - randomized))

        for enc_name, count in sorted(enc_counts.items()):
            color = _ENCRYPTION_COLORS.get(enc_name, "")
            summary_table.add_row(
                f"  [{color}]{enc_name}[/{color}]",
                str(count),
            )

        self._console.rich.print(summary_table)
        self._console.blank()

    def display_ap_table(
        self,
        aps: dict[str, AccessPoint],
        grades: Optional[list[tuple[AccessPoint, SecurityGrade]]] = None,
    ) -> None:
        """Display the access point listing with security grades.

        Args:
            aps: Discovered access points.
            grades: Optional list of (AP, grade) tuples.
        """
        self._console.section(
            "Access Points"
        )

        # Build grade lookup
        grade_lookup: dict[str, SecurityGrade] = {}
        if grades:
            for ap, grade in grades:
                grade_lookup[ap.bssid] = grade

        table = Table(
            title="Discovered Networks",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )

        table.add_column("BSSID", style="bright_white", width=19)
        table.add_column("SSID", style="bold")
        table.add_column("CH", justify="center", width=4)
        table.add_column("Signal", justify="center", width=10)
        table.add_column("Encryption", width=12)
        table.add_column("Cipher", width=10)
        table.add_column("Auth", width=8)
        table.add_column("WPS", justify="center", width=5)
        table.add_column("PMF", justify="center", width=5)
        table.add_column("Grade", justify="center", width=6)
        table.add_column("Vendor", width=14)
        table.add_column("Clients", justify="center", width=7)

        # Sort APs: by grade score (worst first), then by signal
        sorted_aps = sorted(
            aps.values(),
            key=lambda a: (
                grade_lookup.get(a.bssid, SecurityGrade()).score,
                a.signal_dbm,
            ),
        )

        for ap in sorted_aps:
            # SSID display
            ssid_display = ap.ssid if ap.ssid else "[dim italic]<hidden>[/dim italic]"

            # Signal with quality indicator
            quality = classify_signal_quality(ap.signal_dbm)
            sig_color = _SIGNAL_COLORS.get(quality.value, "")
            signal_str = f"[{sig_color}]{ap.signal_dbm} dBm[/{sig_color}]"

            # Encryption colour
            enc_color = _ENCRYPTION_COLORS.get(ap.encryption.value, "")
            enc_str = f"[{enc_color}]{ap.encryption.value}[/{enc_color}]"

            # WPS indicator
            wps_str = "[bold red]YES[/bold red]" if ap.wps_enabled else "[green]No[/green]"

            # PMF indicator
            pmf_str = "[green]YES[/green]" if ap.pmf else "[dim]No[/dim]"

            # Grade
            grade = grade_lookup.get(ap.bssid)
            if grade:
                g_color = _GRADE_COLORS.get(grade.grade, "")
                grade_str = f"[{g_color}]{grade.grade}[/{g_color}]"
            else:
                grade_str = "[dim]-[/dim]"

            table.add_row(
                ap.bssid,
                ssid_display,
                str(ap.channel),
                signal_str,
                enc_str,
                ap.cipher.value,
                ap.auth.value,
                wps_str,
                pmf_str,
                grade_str,
                ap.vendor[:14],
                str(len(ap.clients)),
            )

        self._console.rich.print(table)
        self._console.blank()

    def display_clients(self, clients: list[WifiClient]) -> None:
        """Display the client devices table.

        Args:
            clients: List of detected WiFi clients.
        """
        self._console.section(
            "Client Devices"
        )

        table = Table(
            title="Discovered Clients",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )

        table.add_column("MAC Address", style="bright_white", width=19)
        table.add_column("Vendor", width=16)
        table.add_column("Signal", justify="center", width=10)
        table.add_column("Associated AP", width=19)
        table.add_column("Randomized", justify="center", width=10)
        table.add_column("Probes", width=30)
        table.add_column("Packets", justify="right", width=8)

        sorted_clients = sorted(clients, key=lambda c: c.signal_dbm, reverse=True)

        for client in sorted_clients:
            # Signal
            quality = classify_signal_quality(client.signal_dbm)
            sig_color = _SIGNAL_COLORS.get(quality.value, "")
            signal_str = f"[{sig_color}]{client.signal_dbm} dBm[/{sig_color}]"

            # MAC randomization
            if client.is_randomized_mac:
                rand_str = "[green]Yes[/green]"
            else:
                rand_str = "[bold red]No[/bold red]"

            # Probes
            if client.probe_requests:
                probes = ", ".join(client.probe_requests[:4])
                if len(client.probe_requests) > 4:
                    probes += f" (+{len(client.probe_requests) - 4} more)"
            else:
                probes = "[dim]-[/dim]"

            # Associated AP
            ap_str = client.associated_ap if client.associated_ap else "[dim]-[/dim]"

            table.add_row(
                client.mac,
                client.vendor[:16],
                signal_str,
                ap_str,
                rand_str,
                probes,
                str(client.packets),
            )

        self._console.rich.print(table)
        self._console.blank()

    def display_channels(self, channels: list[ChannelInfo]) -> None:
        """Display channel utilization analysis.

        Args:
            channels: List of channel analysis results.
        """
        self._console.section(
            "Channel Analysis"
        )

        # Separate by band
        channels_24 = [c for c in channels if c.band == "2.4GHz"]
        channels_5 = [c for c in channels if c.band == "5GHz"]

        if channels_24:
            table_24 = Table(
                title="2.4 GHz Channels",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
                padding=(0, 1),
            )

            table_24.add_column("Channel", justify="center", width=8)
            table_24.add_column("Freq (MHz)", justify="center", width=10)
            table_24.add_column("Networks", justify="center", width=9)
            table_24.add_column("Utilization", justify="center", width=12)
            table_24.add_column("Interference", justify="center", width=12)
            table_24.add_column("Recommendation", width=50)

            for ch in sorted(channels_24, key=lambda c: c.channel):
                # Colour interference score
                if ch.interference_score < 0.3:
                    int_color = "green"
                elif ch.interference_score < 0.6:
                    int_color = "yellow"
                else:
                    int_color = "red"

                util_bar = self._make_bar(ch.utilization, 10)
                int_bar = self._make_bar(ch.interference_score, 10)

                table_24.add_row(
                    str(ch.channel),
                    str(ch.frequency),
                    str(ch.networks_count),
                    f"{util_bar} {ch.utilization:.0%}",
                    f"[{int_color}]{int_bar} {ch.interference_score:.0%}[/{int_color}]",
                    ch.recommendation[:50],
                )

            self._console.rich.print(table_24)
            self._console.blank()

        if channels_5:
            table_5 = Table(
                title="5 GHz Channels",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
                padding=(0, 1),
            )

            table_5.add_column("Channel", justify="center", width=8)
            table_5.add_column("Freq (MHz)", justify="center", width=10)
            table_5.add_column("Networks", justify="center", width=9)
            table_5.add_column("DFS", justify="center", width=5)
            table_5.add_column("Interference", justify="center", width=12)
            table_5.add_column("Recommendation", width=50)

            for ch in sorted(channels_5, key=lambda c: c.channel):
                if ch.interference_score < 0.3:
                    int_color = "green"
                elif ch.interference_score < 0.6:
                    int_color = "yellow"
                else:
                    int_color = "red"

                int_bar = self._make_bar(ch.interference_score, 10)
                dfs_str = "[yellow]Yes[/yellow]" if ch.is_dfs else "[green]No[/green]"

                table_5.add_row(
                    str(ch.channel),
                    str(ch.frequency),
                    str(ch.networks_count),
                    dfs_str,
                    f"[{int_color}]{int_bar} {ch.interference_score:.0%}[/{int_color}]",
                    ch.recommendation[:50],
                )

            self._console.rich.print(table_5)
            self._console.blank()

    def display_deauth(self, findings: list[WirelessFinding]) -> None:
        """Display deauthentication attack alerts.

        Args:
            findings: Deauth-related wireless findings.
        """
        self._console.section(
            "Deauthentication Alerts"
        )

        if not findings:
            self._console.info("No deauthentication attacks detected.")
            return

        for finding in findings:
            sev = finding.severity.upper()
            sev_color = _SEVERITY_COLORS.get(sev, "")

            panel_content = (
                f"[{sev_color}][{sev}][/{sev_color}]\n\n"
                f"{finding.description}\n\n"
                f"[bold]Recommendation:[/bold]\n"
                f"{finding.recommendation}"
            )

            if finding.evidence:
                ev = finding.evidence
                if "src_mac" in ev:
                    panel_content += f"\n\n[dim]Source: {ev.get('src_mac', 'N/A')}"
                    panel_content += f" -> Target: {ev.get('dst_mac', 'N/A')}"
                    panel_content += f" | BSSID: {ev.get('bssid', 'N/A')}"
                    panel_content += f" | Count: {ev.get('count', 'N/A')}[/dim]"

            border_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
            panel = Panel(
                panel_content,
                title=f"Deauth Alert - {finding.type.value}",
                border_style=border_color,
                padding=(1, 2),
            )
            self._console.rich.print(panel)
            self._console.blank()

    def display_ble(self, devices: list[BLEDevice]) -> None:
        """Display BLE device listing.

        Args:
            devices: List of detected BLE devices.
        """
        self._console.section(
            "BLE Devices"
        )

        table = Table(
            title="Discovered BLE Devices",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )

        table.add_column("Address", style="bright_white", width=19)
        table.add_column("Name", width=20)
        table.add_column("RSSI", justify="center", width=8)
        table.add_column("Type", width=15)
        table.add_column("Company", width=18)
        table.add_column("Connectable", justify="center", width=11)
        table.add_column("Services", width=30)

        sorted_devices = sorted(devices, key=lambda d: d.rssi, reverse=True)

        for device in sorted_devices:
            # Name
            name = device.name if device.name else "[dim italic]<unnamed>[/dim italic]"

            # RSSI color
            quality = classify_signal_quality(device.rssi)
            sig_color = _SIGNAL_COLORS.get(quality.value, "")
            rssi_str = f"[{sig_color}]{device.rssi}[/{sig_color}]"

            # Connectable
            conn_str = "[green]Yes[/green]" if device.connectable else "[dim]No[/dim]"

            # Services
            if device.services:
                svc_list = ", ".join(device.services[:3])
                if len(device.services) > 3:
                    svc_list += f" (+{len(device.services) - 3})"
            else:
                svc_list = "[dim]-[/dim]"

            table.add_row(
                device.address,
                name,
                rssi_str,
                device.address_type.value,
                device.company[:18] if device.company else "[dim]-[/dim]",
                conn_str,
                svc_list,
            )

        self._console.rich.print(table)
        self._console.blank()

    def display_ids(self, alerts: list[WirelessFinding]) -> None:
        """Display IDS alert feed.

        Args:
            alerts: List of IDS alerts as wireless findings.
        """
        self._console.section(
            "IDS Alerts"
        )

        if not alerts:
            self._console.success(
                "No threats detected"
            )
            return

        # Summary counts
        severity_counts: dict[str, int] = {}
        for alert in alerts:
            sev = alert.severity.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary = " | ".join(
            f"[{_SEVERITY_COLORS.get(s, '')}]{s}: {c}[/{_SEVERITY_COLORS.get(s, '')}]"
            for s, c in sorted(severity_counts.items())
        )
        self._console.print(f"  Alert Summary: {summary}")
        self._console.blank()

        # Alert table
        table = Table(
            title="IDS Alert Log",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )

        table.add_column("#", justify="right", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=18)
        table.add_column("Description", width=60)
        table.add_column("BSSID", width=19)

        for idx, alert in enumerate(alerts, 1):
            sev = alert.severity.upper()
            sev_color = _SEVERITY_COLORS.get(sev, "")

            table.add_row(
                str(idx),
                f"[{sev_color}]{sev}[/{sev_color}]",
                alert.type.value,
                alert.description[:60],
                alert.ap_bssid or "[dim]-[/dim]",
            )

        self._console.rich.print(table)
        self._console.blank()

    def display_findings(self, findings: list[WirelessFinding]) -> None:
        """Display all wireless security findings.

        Args:
            findings: List of wireless findings.
        """
        self._console.section(
            "Security Findings"
        )

        if not findings:
            self._console.success(
                "No issues found"
            )
            return

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.severity.upper(), 5),
        )

        table = Table(
            title="Findings",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )

        table.add_column("#", justify="right", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=18)
        table.add_column("Description", ratio=2)
        table.add_column("Confidence", justify="center", width=10)

        for idx, finding in enumerate(sorted_findings, 1):
            sev = finding.severity.upper()
            sev_color = _SEVERITY_COLORS.get(sev, "")

            table.add_row(
                str(idx),
                f"[{sev_color}]{sev}[/{sev_color}]",
                finding.type.value,
                finding.description[:120],
                f"{finding.confidence:.0%}",
            )

        self._console.rich.print(table)
        self._console.blank()

    @staticmethod
    def _make_bar(value: float, width: int = 10) -> str:
        """Create a simple text-based progress bar.

        Args:
            value: Value in [0.0, 1.0].
            width: Bar width in characters.

        Returns:
            String bar like "[#####     ]".
        """
        filled = int(value * width)
        empty = width - filled
        return f"[{'#' * filled}{'.' * empty}]"
