"""
Spectra Console Output
=======================

Rich-based console presentation layer for Spectra analysis results.
Renders network topology, anomaly alerts, beacon detections, lateral
movement paths, and graph analysis as formatted tables, panels, and
tree views using the PhantomConsole abstraction.

References:
    - Rich library: https://github.com/Textualize/rich
    - PhantomCore Console: shared.console.PhantomConsole
"""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from shared.console import PhantomConsole
from shared.models import ScanResult

from spectra.core.models import (
    AnomalyAlert,
    BeaconResult,
    CommunityResult,
    LateralMovement,
    NetworkHost,
)


class SpectraConsoleOutput:
    """Console output renderer for Spectra analysis results.

    Provides formatted display of all analysis outputs using Rich
    tables, panels, and tree views through the PhantomConsole.

    Usage::

        output = SpectraConsoleOutput()
        output.display(scan_result)
    """

    def __init__(self, console: PhantomConsole | None = None) -> None:
        """Initialise the console output renderer.

        Args:
            console: PhantomConsole instance. Creates a new one if None.
        """
        self.console = console or PhantomConsole()

    # ================================================================== #
    #  Full Display
    # ================================================================== #

    def display(self, result: ScanResult) -> None:
        """Display a complete Spectra analysis result.

        Renders all sections: summary, hosts, anomalies, graph analysis,
        beacons, lateral movements, and findings.

        Args:
            result: Complete ScanResult from the Spectra engine.
        """
        self.console.banner()
        self.console.print(
            Panel(
                "[bright_cyan]SPECTRA[/bright_cyan] -- "
                "[bright_magenta]Network Intelligence Engine[/bright_magenta]\n"
                "[dim]Network Intelligence Engine[/dim]",
                border_style="bright_cyan",
            )
        )
        self.console.blank()

        raw = result.raw_data

        # Summary panel
        self._display_summary(result)

        # Hosts table
        hosts_data = raw.get("hosts", {})
        if hosts_data:
            self.display_hosts_raw(hosts_data)

        # Service fingerprints
        services_data = raw.get("service_fingerprints", {})
        if services_data:
            self._display_services(services_data)

        # Anomaly alerts
        alerts_data = raw.get("anomaly_alerts", [])
        if alerts_data:
            self.display_anomalies_raw(alerts_data)

        # Graph analysis
        graph_data = raw.get("graph_analysis", {})
        key_nodes = raw.get("graph_key_nodes", {})
        if graph_data or key_nodes:
            self.display_graph_raw(graph_data, key_nodes)

        # Beacon results
        beacon_data = raw.get("beacon_results", [])
        if beacon_data:
            self.display_beacons_raw(beacon_data)

        # Lateral movements
        lateral_data = raw.get("lateral_movements", [])
        if lateral_data:
            self.display_lateral_raw(lateral_data)

        # Findings table
        if result.findings:
            self.console.section("Findings")
            self.console.findings_table(result.findings)

        self.console.blank()
        self.console.divider()
        self.console.success(
            f"Analysis complete. "
            f"{result.finding_count} findings. "
            f"Duration: {result.duration_seconds:.2f}s"
        )

    # ================================================================== #
    #  Summary
    # ================================================================== #

    def _display_summary(self, result: ScanResult) -> None:
        """Display analysis summary panel."""
        self.console.section("Summary")

        meta = result.metadata
        summary_text = (
            f"[bright_white]Target:[/bright_white] {result.target}\n"
            f"[bright_white]Hosts:[/bright_white] {meta.get('host_count', 0)}\n"
            f"[bright_white]Flows:[/bright_white] {meta.get('flow_count', 0)}\n"
            f"[bright_white]Anomalies:[/bright_white] {meta.get('anomaly_count', 0)}\n"
            f"[bright_white]Beacons:[/bright_white] {meta.get('beacon_count', 0)}\n"
            f"[bright_white]Lateral:[/bright_white] {meta.get('lateral_count', 0)}\n"
            f"[bright_white]Communities:[/bright_white] {meta.get('community_count', 0)}\n"
            f"[bright_white]Findings:[/bright_white] "
            f"{result.finding_count} (Critical: {result.critical_count}, "
            f"High: {result.high_count})"
        )

        self.console.print(Panel(
            summary_text,
            title="Analysis Summary",
            border_style="bright_cyan",
        ))

    # ================================================================== #
    #  Hosts Display
    # ================================================================== #

    def display_hosts(self, hosts: dict[str, NetworkHost]) -> None:
        """Display host table with traffic statistics.

        Args:
            hosts: Dictionary of IP -> NetworkHost.
        """
        self.console.section("Network Hosts")

        tbl = Table(
            title="Discovered Hosts",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )

        tbl.add_column("IP", style="bright_white")
        tbl.add_column("MAC", style="dim")
        tbl.add_column("Ports", style="bright_cyan", max_width=30)
        tbl.add_column("Sent", style="bright_green", justify="right")
        tbl.add_column("Recv", style="bright_yellow", justify="right")
        tbl.add_column("Packets", style="bright_blue", justify="right")
        tbl.add_column("Services", style="bright_magenta", max_width=30)

        # Sort by total bytes descending
        sorted_hosts = sorted(
            hosts.values(),
            key=lambda h: h.total_bytes,
            reverse=True,
        )

        for host in sorted_hosts[:30]:  # Limit display
            ports_str = ", ".join(str(p) for p in sorted(host.ports)[:10])
            if len(host.ports) > 10:
                ports_str += f" (+{len(host.ports) - 10})"

            services_str = ", ".join(
                f"{p}:{s}" for p, s in sorted(host.services.items())[:5]
            )

            tbl.add_row(
                host.ip,
                host.mac or "-",
                ports_str or "-",
                self._format_bytes(host.bytes_sent),
                self._format_bytes(host.bytes_recv),
                f"{host.packet_count:,}",
                services_str or "-",
            )

        self.console.print(tbl)

    def display_hosts_raw(self, hosts_data: dict[str, Any]) -> None:
        """Display host table from raw data dict."""
        self.console.section("Network Hosts")

        tbl = Table(
            title="Discovered Hosts",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )

        tbl.add_column("IP", style="bright_white")
        tbl.add_column("MAC", style="dim")
        tbl.add_column("Ports", style="bright_cyan", max_width=30)
        tbl.add_column("Sent", style="bright_green", justify="right")
        tbl.add_column("Recv", style="bright_yellow", justify="right")
        tbl.add_column("Packets", style="bright_blue", justify="right")

        sorted_hosts = sorted(
            hosts_data.items(),
            key=lambda x: x[1].get("bytes_sent", 0) + x[1].get("bytes_recv", 0),
            reverse=True,
        )

        for ip, hdata in sorted_hosts[:30]:
            ports = hdata.get("ports", [])
            ports_str = ", ".join(str(p) for p in ports[:10])
            if len(ports) > 10:
                ports_str += f" (+{len(ports) - 10})"

            tbl.add_row(
                ip,
                hdata.get("mac", "") or "-",
                ports_str or "-",
                self._format_bytes(hdata.get("bytes_sent", 0)),
                self._format_bytes(hdata.get("bytes_recv", 0)),
                f"{hdata.get('packet_count', 0):,}",
            )

        self.console.print(tbl)

    # ================================================================== #
    #  Services Display
    # ================================================================== #

    def _display_services(self, services_data: dict[str, Any]) -> None:
        """Display identified services."""
        self.console.section("Identified Services")

        tbl = Table(
            title="Service Identification",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )

        tbl.add_column("Host", style="bright_white")
        tbl.add_column("Port", style="bright_cyan", justify="right")
        tbl.add_column("Service", style="bright_green")
        tbl.add_column("Confidence", style="bright_yellow", justify="right")
        tbl.add_column("Description", style="dim")

        for ip, port_map in services_data.items():
            for port, info in port_map.items():
                conf = info.get("confidence", 0.0)
                conf_style = "bright_green" if conf > 0.7 else "bright_yellow" if conf > 0.4 else "dim"
                tbl.add_row(
                    ip,
                    str(port),
                    info.get("service", "Unknown"),
                    f"[{conf_style}]{conf:.1%}[/{conf_style}]",
                    info.get("description", ""),
                )

        self.console.print(tbl)

    # ================================================================== #
    #  Anomalies Display
    # ================================================================== #

    def display_anomalies(self, alerts: list[AnomalyAlert]) -> None:
        """Display anomaly alerts with severity colouring.

        Args:
            alerts: List of AnomalyAlert objects.
        """
        self.console.section("Anomaly Alerts")

        tbl = Table(
            title="Anomaly Alerts",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )

        tbl.add_column("Type", style="bright_white")
        tbl.add_column("Severity", width=10)
        tbl.add_column("Source", style="bright_cyan")
        tbl.add_column("Target", style="bright_yellow")
        tbl.add_column("Description", ratio=2)

        severity_styles = {
            "critical": "bold white on red",
            "high": "bold red",
            "medium": "bold yellow",
            "low": "bold bright_cyan",
        }

        for alert in alerts:
            sev_style = severity_styles.get(alert.severity, "dim")
            tbl.add_row(
                alert.type.value.replace("_", " ").title(),
                f"[{sev_style}]{alert.severity.upper()}[/{sev_style}]",
                alert.source,
                alert.target or "-",
                alert.description[:120],
            )

        self.console.print(tbl)

    def display_anomalies_raw(self, alerts_data: list[dict]) -> None:
        """Display anomaly alerts from raw data."""
        self.console.section("Anomaly Alerts")

        tbl = Table(
            title="Anomaly Alerts",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )

        tbl.add_column("Type", style="bright_white")
        tbl.add_column("Severity", width=10)
        tbl.add_column("Source", style="bright_cyan")
        tbl.add_column("Target", style="bright_yellow")
        tbl.add_column("Description", ratio=2)

        severity_styles = {
            "critical": "bold white on red",
            "high": "bold red",
            "medium": "bold yellow",
            "low": "bold bright_cyan",
        }

        for alert in alerts_data:
            sev = alert.get("severity", "medium")
            sev_style = severity_styles.get(sev, "dim")
            atype = alert.get("type", "unknown").replace("_", " ").title()
            tbl.add_row(
                atype,
                f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                alert.get("source", "-"),
                alert.get("target", "") or "-",
                alert.get("description", "")[:120],
            )

        self.console.print(tbl)

    # ================================================================== #
    #  Graph Analysis Display
    # ================================================================== #

    def display_graph(self, analysis: dict[str, Any]) -> None:
        """Display graph analysis results with centrality rankings.

        Args:
            analysis: Dictionary from GraphAnalyzer.analyze().
        """
        key_nodes = analysis.get("key_nodes", {})
        topology = analysis.get("topology", {})
        self.display_graph_raw(analysis, key_nodes)

    def display_graph_raw(
        self,
        graph_data: dict[str, Any],
        key_nodes: dict[str, Any],
    ) -> None:
        """Display graph analysis from raw data."""
        self.console.section("Graph Analysis")

        # Topology metrics
        topology = graph_data.get("topology", {})
        if topology:
            metrics_text = (
                f"[bright_white]Nodes:[/bright_white] "
                f"{graph_data.get('node_count', 0)}\n"
                f"[bright_white]Edges:[/bright_white] "
                f"{graph_data.get('edge_count', 0)}\n"
                f"[bright_white]Density:[/bright_white] "
                f"{topology.get('density', 0.0):.4f}\n"
                f"[bright_white]Diameter:[/bright_white] "
                f"{topology.get('diameter', 'N/A')}\n"
                f"[bright_white]Avg Path:[/bright_white] "
                f"{topology.get('avg_path_length', 'N/A')}\n"
                f"[bright_white]Clustering:[/bright_white] "
                f"{topology.get('avg_clustering', 'N/A')}\n"
                f"[bright_white]Reciprocity:[/bright_white] "
                f"{topology.get('reciprocity', 'N/A')}"
            )
            self.console.print(Panel(
                metrics_text,
                title="Topology Metrics",
                border_style="bright_magenta",
            ))

        # Key nodes table
        if key_nodes:
            tbl = Table(
                title="Key Network Nodes",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
            )

            tbl.add_column("Metric", style="bright_white")
            tbl.add_column("Node (IP)", style="bright_cyan")
            tbl.add_column("Score", style="bright_green", justify="right")

            metric_labels = {
                "betweenness": "Betweenness (Bridge)",
                "eigenvector": "Eigenvector (Influence)",
                "pagerank": "PageRank (Importance)",
                "in_degree": "In-Degree (Server)",
                "out_degree": "Out-Degree (Client)",
            }

            for metric, label in metric_labels.items():
                nodes = key_nodes.get(metric, [])
                for node, score in nodes[:3]:
                    tbl.add_row(label, str(node), f"{score:.6f}")

            self.console.print(tbl)

        # Communities
        communities = graph_data.get("communities", [])
        if communities:
            self.console.print()
            tree = Tree("[bright_magenta]Communities[/bright_magenta]")

            for comm in communities:
                if isinstance(comm, dict):
                    cid = comm.get("community_id", 0)
                    members = comm.get("members", [])
                    density = comm.get("density", 0.0)
                elif isinstance(comm, CommunityResult):
                    cid = comm.community_id
                    members = comm.members
                    density = comm.density
                else:
                    continue

                branch = tree.add(
                    f"[bright_cyan]Community {cid}[/bright_cyan] "
                    f"({len(members)} members, density: {density:.3f})"
                )
                member_str = ", ".join(str(m) for m in members[:8])
                if len(members) > 8:
                    member_str += f" (+{len(members) - 8} more)"
                branch.add(f"[dim]{member_str}[/dim]")

            self.console.print(tree)

    # ================================================================== #
    #  Beacons Display
    # ================================================================== #

    def display_beacons(self, beacons: list[BeaconResult]) -> None:
        """Display beacon detection results.

        Args:
            beacons: List of BeaconResult objects.
        """
        self.console.section("Beacon Detection")

        tbl = Table(
            title="C2 Beacon Detection",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )

        tbl.add_column("Source", style="bright_cyan")
        tbl.add_column("Destination", style="bright_yellow")
        tbl.add_column("Interval", style="bright_white", justify="right")
        tbl.add_column("CV", style="bright_green", justify="right")
        tbl.add_column("Entropy", style="bright_blue", justify="right")
        tbl.add_column("Confidence", justify="right")
        tbl.add_column("Beacon?", justify="center")

        for b in beacons:
            conf_style = "bold red" if b.confidence > 0.7 else "bold yellow" if b.confidence > 0.4 else "dim"
            beacon_mark = "[bold red]YES[/bold red]" if b.is_beacon else "[dim]no[/dim]"

            tbl.add_row(
                b.src,
                b.dst,
                f"{b.interval_mean:.1f}s",
                f"{b.coefficient_of_variation:.4f}",
                f"{b.entropy:.2f}",
                f"[{conf_style}]{b.confidence:.2f}[/{conf_style}]",
                beacon_mark,
            )

        self.console.print(tbl)

    def display_beacons_raw(self, beacon_data: list[dict]) -> None:
        """Display beacons from raw data."""
        self.console.section("Beacon Detection")

        tbl = Table(
            title="C2 Beacon Detection",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )

        tbl.add_column("Source", style="bright_cyan")
        tbl.add_column("Destination", style="bright_yellow")
        tbl.add_column("Interval", style="bright_white", justify="right")
        tbl.add_column("CV", style="bright_green", justify="right")
        tbl.add_column("Entropy", style="bright_blue", justify="right")
        tbl.add_column("Confidence", justify="right")
        tbl.add_column("Beacon?", justify="center")

        for b in beacon_data:
            conf = b.get("confidence", 0.0)
            is_b = b.get("is_beacon", False)
            conf_style = "bold red" if conf > 0.7 else "bold yellow" if conf > 0.4 else "dim"
            beacon_mark = "[bold red]YES[/bold red]" if is_b else "[dim]no[/dim]"

            tbl.add_row(
                b.get("src", "-"),
                b.get("dst", "-"),
                f"{b.get('interval_mean', 0.0):.1f}s",
                f"{b.get('cv', 0.0):.4f}",
                f"{b.get('entropy', 0.0):.2f}",
                f"[{conf_style}]{conf:.2f}[/{conf_style}]",
                beacon_mark,
            )

        self.console.print(tbl)

    # ================================================================== #
    #  Lateral Movement Display
    # ================================================================== #

    def display_lateral(self, movements: list[LateralMovement]) -> None:
        """Display lateral movement findings.

        Args:
            movements: List of LateralMovement objects.
        """
        self.console.section("Lateral Movement")

        for i, m in enumerate(movements, 1):
            path_str = " -> ".join(m.path)
            conf_style = "bold red" if m.confidence > 0.7 else "bold yellow"

            panel_content = (
                f"[bright_white]Technique:[/bright_white] {m.technique}\n"
                f"[bright_white]Path:[/bright_white] {path_str}\n"
                f"[bright_white]Confidence:[/bright_white] "
                f"[{conf_style}]{m.confidence:.2f}[/{conf_style}]\n"
                f"[bright_white]Ports:[/bright_white] {m.ports_used}\n"
                f"[bright_white]Duration:[/bright_white] "
                f"{m.timespan_seconds:.1f}s\n"
                f"\n[bright_white]Evidence:[/bright_white]"
            )

            for ev in m.evidence:
                panel_content += f"\n  - {ev}"

            self.console.print(Panel(
                panel_content,
                title=f"Lateral Movement #{i}",
                border_style="red" if m.confidence > 0.7 else "yellow",
            ))

    def display_lateral_raw(self, lateral_data: list[dict]) -> None:
        """Display lateral movements from raw data."""
        self.console.section("Lateral Movement")

        for i, m in enumerate(lateral_data, 1):
            path = m.get("path", [])
            path_str = " -> ".join(path)
            conf = m.get("confidence", 0.0)
            conf_style = "bold red" if conf > 0.7 else "bold yellow"

            panel_content = (
                f"[bright_white]Technique:[/bright_white] "
                f"{m.get('technique', 'Unknown')}\n"
                f"[bright_white]Path:[/bright_white] {path_str}\n"
                f"[bright_white]Confidence:[/bright_white] "
                f"[{conf_style}]{conf:.2f}[/{conf_style}]\n"
                f"[bright_white]Ports:[/bright_white] "
                f"{m.get('ports_used', [])}\n"
                f"[bright_white]Duration:[/bright_white] "
                f"{m.get('timespan_seconds', 0.0):.1f}s"
            )

            evidence = m.get("evidence", [])
            if evidence:
                panel_content += "\n\n[bright_white]Evidence:[/bright_white]"
                for ev in evidence:
                    panel_content += f"\n  - {ev}"

            self.console.print(Panel(
                panel_content,
                title=f"Lateral Movement #{i}",
                border_style="red" if conf > 0.7 else "yellow",
            ))

    # ================================================================== #
    #  Utility
    # ================================================================== #

    @staticmethod
    def _format_bytes(n: int | float) -> str:
        """Format a byte count as human-readable string."""
        n = float(n)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(n) < 1024.0:
                return f"{n:.1f} {unit}"
            n /= 1024.0
        return f"{n:.1f} PB"
