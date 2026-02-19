"""
Nexus Console Output
=====================

Rich-based console display module for the Nexus Threat Intelligence
Correlator. Provides formatted output for CVE records, IoC tables,
risk assessments, MITRE ATT&CK mappings, and threat assessment
summaries.

Uses the PhantomCore shared console infrastructure for consistent
styling across all toolkit modules.

References:
    - Rich library: https://github.com/Textualize/rich
    - FIRST. (2019). CVSS v3.1 Specification (severity colours).
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from shared.console import PhantomConsole
from shared.models import Risk

from nexus.core.models import (
    CVERecord,
    IoC,
    IoCType,
    MITRETechnique,
    ThreatAssessment,
)


class NexusConsoleOutput:
    """Formatted console output for Nexus analysis results.

    Wraps PhantomConsole with Nexus-specific display methods for
    CVEs, IoCs, risk scores, MITRE ATT&CK techniques, and
    comprehensive threat assessments.

    Usage::

        output = NexusConsoleOutput()
        output.display_cve(cve_record, cvss_details)
        output.display_iocs(ioc_list)
        output.display_risk(risk_level, score, details)
    """

    # Severity colour mapping
    SEVERITY_COLOURS: dict[str, str] = {
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold cyan",
        "none": "dim white",
        "unknown": "dim white",
        "info": "bold blue",
    }

    # IoC type display names
    IOC_TYPE_NAMES: dict[IoCType, str] = {
        IoCType.IPV4: "IPv4 Address",
        IoCType.IPV6: "IPv6 Address",
        IoCType.DOMAIN: "Domain",
        IoCType.URL: "URL",
        IoCType.MD5: "MD5 Hash",
        IoCType.SHA1: "SHA-1 Hash",
        IoCType.SHA256: "SHA-256 Hash",
        IoCType.EMAIL: "Email",
        IoCType.CVE: "CVE ID",
        IoCType.FILENAME: "Filename",
        IoCType.REGISTRY_KEY: "Registry Key",
        IoCType.FILE_PATH: "File Path",
    }

    def __init__(
        self,
        console: Optional[PhantomConsole] = None,
    ) -> None:
        """Initialise the console output module.

        Args:
            console: PhantomConsole instance. Created if not provided.
        """
        self.console = console or PhantomConsole()

    # ================================================================== #
    #  CVE Display
    # ================================================================== #

    def display_cve(
        self,
        record: CVERecord,
        cvss_details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Display a CVE record with detailed CVSS breakdown.

        Renders a rich panel with the CVE identifier, description,
        severity badge, CVSS scores, and CVSS metric breakdown.

        Args:
            record: CVERecord to display.
            cvss_details: Optional CVSS metric breakdown from
                         CVSSCalculator.get_metric_breakdown().
        """
        severity_style = self.SEVERITY_COLOURS.get(
            record.severity.lower(), "dim white"
        )

        # Header with severity badge
        header = Text()
        header.append(f"  {record.cve_id}  ", style="bold bright_white")
        header.append(
            f"  {record.severity.upper()}  ",
            style=severity_style,
        )

        # Build content sections
        content_parts: list[str] = []

        # Description
        if record.description:
            desc = record.description
            if len(desc) > 500:
                desc = desc[:497] + "..."
            content_parts.append(f"[bold]Description:[/bold]\n{desc}")

        # CVSS Score
        content_parts.append(
            f"\n[bold]CVSS Score:[/bold] "
            f"[{severity_style}]{record.cvss_score:.1f}[/{severity_style}]"
        )

        # CVSS Vector
        if record.cvss_vector:
            content_parts.append(
                f"[bold]CVSS Vector:[/bold] [dim]{record.cvss_vector}[/dim]"
            )

        # Dates
        if record.published_date:
            content_parts.append(
                f"[bold]Published:[/bold] {record.published_date}"
            )
        if record.modified_date:
            content_parts.append(
                f"[bold]Modified:[/bold] {record.modified_date}"
            )

        # CWE IDs
        if record.cwe_ids:
            cwe_str = ", ".join(record.cwe_ids)
            content_parts.append(f"[bold]CWE IDs:[/bold] {cwe_str}")

        # Exploit status
        if record.has_public_exploit:
            content_parts.append(
                "[bold red]Public Exploit Available[/bold red]"
            )
        if record.is_actively_exploited:
            content_parts.append(
                "[bold white on red] ACTIVELY EXPLOITED [/bold white on red]"
            )

        # Exploitation probability
        if record.exploit_probability > 0:
            prob_pct = record.exploit_probability * 100
            content_parts.append(
                f"[bold]Exploitation Probability:[/bold] {prob_pct:.1f}%"
            )

        # CVSS Metric Breakdown
        if cvss_details:
            content_parts.append("\n[bold]CVSS Metric Breakdown:[/bold]")
            metrics = cvss_details.get("metrics", {})
            for metric_name, metric_data in metrics.items():
                label = metric_data.get("label", "Unknown")
                value = metric_data.get("value", "")
                display_name = metric_name.replace("_", " ").title()
                if value != "":
                    content_parts.append(
                        f"  {display_name}: {label} ({value})"
                    )
                else:
                    content_parts.append(f"  {display_name}: {label}")

            sub_scores = cvss_details.get("sub_scores", {})
            if sub_scores:
                content_parts.append("\n[bold]Sub-Scores:[/bold]")
                for name, value in sub_scores.items():
                    display_name = name.replace("_", " ").title()
                    content_parts.append(f"  {display_name}: {value:.4f}")

        # References
        if record.references:
            content_parts.append("\n[bold]References:[/bold]")
            for ref in record.references[:5]:
                content_parts.append(f"  [link={ref}]{ref}[/link]")
            if len(record.references) > 5:
                content_parts.append(
                    f"  ... and {len(record.references) - 5} more"
                )

        # Affected Products
        if record.affected_products:
            content_parts.append("\n[bold]Affected Products:[/bold]")
            for product in record.affected_products[:10]:
                content_parts.append(f"  {product}")
            if len(record.affected_products) > 10:
                content_parts.append(
                    f"  ... and {len(record.affected_products) - 10} more"
                )

        content = "\n".join(content_parts)

        panel = Panel(
            content,
            title=str(header),
            border_style="bright_cyan",
            padding=(1, 2),
        )
        self.console.print(panel)

    # ================================================================== #
    #  IoC Display
    # ================================================================== #

    def display_iocs(self, iocs: list[IoC]) -> None:
        """Display extracted IoCs in a table grouped by type.

        Renders separate tables for each IoC type present in the
        results, with columns for value, defanged form, and context.

        Args:
            iocs: List of IoC instances to display.
        """
        if not iocs:
            self.console.info(
                "No indicators of compromise found."
            )
            return

        # Group IoCs by type
        grouped: dict[IoCType, list[IoC]] = {}
        for ioc in iocs:
            grouped.setdefault(ioc.type, []).append(ioc)

        # Summary
        self.console.section(
            "Indicators of Compromise (IoC)"
        )

        summary_table = Table(
            title="IoC Summary",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=False,
        )
        summary_table.add_column("Type", style="bold")
        summary_table.add_column("Count", justify="right")

        for ioc_type, ioc_list in sorted(
            grouped.items(), key=lambda x: len(x[1]), reverse=True
        ):
            type_name = self.IOC_TYPE_NAMES.get(ioc_type, ioc_type.value)
            summary_table.add_row(type_name, str(len(ioc_list)))

        summary_table.add_row(
            "[bold]Total[/bold]",
            f"[bold]{len(iocs)}[/bold]",
        )
        self.console.print(summary_table)
        self.console.print()

        # Detail tables per type
        for ioc_type, ioc_list in sorted(
            grouped.items(), key=lambda x: len(x[1]), reverse=True
        ):
            type_name = self.IOC_TYPE_NAMES.get(ioc_type, ioc_type.value)

            detail_table = Table(
                title=f"{type_name} ({len(ioc_list)})",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
                padding=(0, 1),
            )
            detail_table.add_column("#", style="dim", width=4, justify="right")
            detail_table.add_column("Value", style="bold bright_white")
            detail_table.add_column("Defanged", style="dim")
            detail_table.add_column(
                "Context", max_width=60, overflow="fold"
            )

            for idx, ioc in enumerate(ioc_list, 1):
                context = ioc.context
                if len(context) > 100:
                    context = context[:97] + "..."

                detail_table.add_row(
                    str(idx),
                    ioc.value,
                    ioc.defanged_value or "",
                    context,
                )

            self.console.print(detail_table)
            self.console.print()

    # ================================================================== #
    #  Risk Display
    # ================================================================== #

    def display_risk(
        self,
        risk_level: Risk,
        score: float,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Display risk assessment with score visualisation.

        Renders a panel with the overall risk score, a visual score
        bar, factor breakdown, and recommendations.

        Args:
            risk_level: Qualitative risk level.
            score: Numeric risk score (0-100).
            details: Optional scoring details from RiskScorer.get_score_details().
        """
        # Determine colour based on risk level
        risk_colours: dict[str, str] = {
            "critical": "bold white on red",
            "high": "bold red",
            "medium": "bold yellow",
            "low": "bold cyan",
            "negligible": "bold green",
        }
        colour = risk_colours.get(risk_level.value, "dim white")

        # Build score bar
        bar_width = 40
        filled = int((score / 100.0) * bar_width)
        bar = "[bold green]" + "=" * min(filled, 8)
        if filled > 8:
            bar += "[bold yellow]" + "=" * min(filled - 8, 12)
        if filled > 20:
            bar += "[bold bright_red]" + "=" * min(filled - 20, 12)
        if filled > 32:
            bar += "[bold red]" + "=" * min(filled - 32, 8)
        remaining = bar_width - filled
        bar += "[dim]" + "-" * remaining + "[/dim]"

        content_parts: list[str] = []
        content_parts.append(
            f"[bold]Overall Risk Score:[/bold] "
            f"[{colour}]{score:.1f}/100[/{colour}]"
        )
        content_parts.append(
            f"[bold]Risk Level:[/bold] [{colour}]{risk_level.value.upper()}[/{colour}]"
        )
        content_parts.append(f"\n{bar}")

        # Factor breakdown
        if details:
            breakdown = details.get("factor_breakdown", {})
            weights = details.get("weights", {})

            if breakdown:
                content_parts.append("\n[bold]Factor Breakdown:[/bold]")

                factor_table = Table(
                    show_header=True,
                    header_style="bold",
                    border_style="dim",
                    show_lines=False,
                    padding=(0, 1),
                )
                factor_table.add_column("Factor")
                factor_table.add_column("Score", justify="right")
                factor_table.add_column("Weight", justify="right")
                factor_table.add_column("Contribution", justify="right")

                for factor_name, factor_score in sorted(
                    breakdown.items(),
                    key=lambda x: x[1],
                    reverse=True,
                ):
                    weight = weights.get(factor_name, 0.0)
                    contribution = factor_score * weight
                    display_name = factor_name.replace("_", " ").title()

                    # Colour code the factor score
                    if factor_score >= 80:
                        score_style = "bold red"
                    elif factor_score >= 60:
                        score_style = "bold bright_red"
                    elif factor_score >= 40:
                        score_style = "bold yellow"
                    else:
                        score_style = "bold green"

                    factor_table.add_row(
                        display_name,
                        f"[{score_style}]{factor_score:.1f}[/{score_style}]",
                        f"{weight:.2f}",
                        f"{contribution:.1f}",
                    )

                content_parts.append("")
                # We'll print the table separately

            # Recommendations
            recommendations = details.get("recommendations", [])
            if recommendations:
                content_parts.append("\n[bold]Recommendations:[/bold]")
                for idx, rec in enumerate(recommendations, 1):
                    content_parts.append(f"  {idx}. {rec}")

        content = "\n".join(content_parts)

        panel = Panel(
            content,
            title="[bold bright_white]  Risk Assessment  [/bold bright_white]",
            border_style=colour.replace("bold ", "").replace(" on red", ""),
            padding=(1, 2),
        )
        self.console.print(panel)

        # Print factor table separately if available
        if details and details.get("factor_breakdown"):
            breakdown = details["factor_breakdown"]
            weights = details.get("weights", {})

            factor_table = Table(
                title="Factor Scores",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
                padding=(0, 1),
            )
            factor_table.add_column("Factor")
            factor_table.add_column("Score", justify="right")
            factor_table.add_column("Weight", justify="right")
            factor_table.add_column("Weighted", justify="right")

            for factor_name, factor_score in sorted(
                breakdown.items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                weight = weights.get(factor_name, 0.0)
                contribution = factor_score * weight
                display_name = factor_name.replace("_", " ").title()

                if factor_score >= 80:
                    score_style = "bold red"
                elif factor_score >= 60:
                    score_style = "bold bright_red"
                elif factor_score >= 40:
                    score_style = "bold yellow"
                else:
                    score_style = "bold green"

                factor_table.add_row(
                    display_name,
                    f"[{score_style}]{factor_score:.1f}[/{score_style}]",
                    f"{weight:.2f}",
                    f"{contribution:.1f}",
                )

            self.console.print(factor_table)

    # ================================================================== #
    #  MITRE ATT&CK Display
    # ================================================================== #

    def display_mitre(
        self,
        techniques: list[MITRETechnique],
        title: str = "MITRE ATT&CK Mapping",
    ) -> None:
        """Display MITRE ATT&CK techniques in a matrix-like layout.

        Groups techniques by tactic and displays them in a tree view
        with detection guidance and platform information.

        Args:
            techniques: List of MITRETechnique instances to display.
            title: Display title.
        """
        if not techniques:
            self.console.info("No MITRE ATT&CK techniques mapped.")
            return

        self.console.section(title)

        # Group by tactic
        by_tactic: dict[str, list[MITRETechnique]] = {}
        for tech in techniques:
            tactic = tech.tactic or "unknown"
            by_tactic.setdefault(tactic, []).append(tech)

        # Tactic display order
        tactic_order = [
            "initial-access", "execution", "persistence",
            "privilege-escalation", "defense-evasion", "credential-access",
            "discovery", "lateral-movement", "collection",
            "command-and-control", "exfiltration", "impact",
        ]

        # Build tree
        tree = Tree(
            f"[bold bright_cyan]MITRE ATT&CK Enterprise[/bold bright_cyan]",
            guide_style="bright_cyan",
        )

        # Process in tactic order, then remaining
        displayed_tactics: set[str] = set()
        for tactic in tactic_order:
            if tactic in by_tactic:
                self._add_tactic_branch(tree, tactic, by_tactic[tactic])
                displayed_tactics.add(tactic)

        for tactic in sorted(by_tactic.keys()):
            if tactic not in displayed_tactics:
                self._add_tactic_branch(tree, tactic, by_tactic[tactic])

        self.console.print(tree)
        self.console.print()

        # Detailed technique table
        tech_table = Table(
            title="Technique Details",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )
        tech_table.add_column("ID", style="bold")
        tech_table.add_column("Name")
        tech_table.add_column("Tactic")
        tech_table.add_column("Platforms", max_width=30)
        tech_table.add_column("Detection", max_width=50, overflow="fold")

        for tech in techniques:
            platforms = ", ".join(tech.platforms) if tech.platforms else "-"
            detection = tech.detection if tech.detection else "-"
            if len(detection) > 100:
                detection = detection[:97] + "..."

            tech_table.add_row(
                tech.technique_id,
                tech.name,
                tech.tactic.replace("-", " ").title(),
                platforms,
                detection,
            )

        self.console.print(tech_table)

    def _add_tactic_branch(
        self,
        tree: Tree,
        tactic: str,
        techniques: list[MITRETechnique],
    ) -> None:
        """Add a tactic branch with its techniques to the tree.

        Args:
            tree: Rich Tree to add the branch to.
            tactic: Tactic name.
            techniques: Techniques belonging to this tactic.
        """
        display_tactic = tactic.replace("-", " ").title()
        branch = tree.add(
            f"[bold bright_magenta]{display_tactic}[/bold bright_magenta] "
            f"[dim]({len(techniques)} techniques)[/dim]"
        )
        for tech in techniques:
            branch.add(
                f"[bold]{tech.technique_id}[/bold] - {tech.name}"
            )

    # ================================================================== #
    #  Assessment Summary Display
    # ================================================================== #

    def display_assessment(
        self,
        assessment: ThreatAssessment,
        risk_details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Display a complete threat assessment summary.

        Renders all components of the assessment: risk score, CVEs,
        IoCs, MITRE techniques, and recommendations.

        Args:
            assessment: Complete ThreatAssessment instance.
            risk_details: Optional scoring details.
        """
        self.console.section(
            "Threat Assessment Summary"
        )

        # Overview panel
        overview_parts: list[str] = []
        overview_parts.append(
            f"[bold]Assessment ID:[/bold] {assessment.id}"
        )
        overview_parts.append(
            f"[bold]Timestamp:[/bold] {assessment.timestamp.isoformat()}"
        )
        overview_parts.append(
            f"[bold]CVEs Identified:[/bold] {len(assessment.cves)}"
        )
        overview_parts.append(
            f"[bold]IoCs Extracted:[/bold] {len(assessment.iocs)}"
        )
        overview_parts.append(
            f"[bold]MITRE Techniques:[/bold] {len(assessment.mitre_techniques)}"
        )

        overview = Panel(
            "\n".join(overview_parts),
            title="[bold bright_white]  Overview  [/bold bright_white]",
            border_style="bright_cyan",
            padding=(1, 2),
        )
        self.console.print(overview)
        self.console.print()

        # Risk display
        risk_level = Risk.NEGLIGIBLE
        risk_score = assessment.overall_risk
        risk_thresholds = [
            (80.0, Risk.CRITICAL),
            (60.0, Risk.HIGH),
            (40.0, Risk.MEDIUM),
            (20.0, Risk.LOW),
            (0.0, Risk.NEGLIGIBLE),
        ]
        for threshold, level in risk_thresholds:
            if risk_score >= threshold:
                risk_level = level
                break

        self.display_risk(risk_level, risk_score, risk_details)
        self.console.print()

        # CVE summary table
        if assessment.cves:
            cve_table = Table(
                title=f"CVE Summary ({len(assessment.cves)})",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
            )
            cve_table.add_column("CVE ID", style="bold")
            cve_table.add_column("CVSS", justify="right")
            cve_table.add_column("Severity")
            cve_table.add_column("Exploit Prob", justify="right")
            cve_table.add_column("Description", max_width=50, overflow="fold")

            for cve in sorted(
                assessment.cves,
                key=lambda c: c.cvss_score,
                reverse=True,
            ):
                sev_style = self.SEVERITY_COLOURS.get(
                    cve.severity.lower(), "dim"
                )
                prob_str = f"{cve.exploit_probability:.1%}" if cve.exploit_probability > 0 else "-"
                desc = cve.description
                if len(desc) > 80:
                    desc = desc[:77] + "..."

                cve_table.add_row(
                    cve.cve_id,
                    f"{cve.cvss_score:.1f}",
                    f"[{sev_style}]{cve.severity.upper()}[/{sev_style}]",
                    prob_str,
                    desc,
                )

            self.console.print(cve_table)
            self.console.print()

        # IoC summary
        if assessment.iocs:
            self.display_iocs(assessment.iocs)

        # MITRE techniques
        if assessment.mitre_techniques:
            self.display_mitre(assessment.mitre_techniques)

        # Recommendations
        if assessment.recommendations:
            self.console.section("Recommendations")
            for idx, rec in enumerate(assessment.recommendations, 1):
                if "CRITICAL" in rec or "IMMEDIATE" in rec or "URGENT" in rec:
                    self.console.print(
                        f"  [bold red]{idx}. {rec}[/bold red]"
                    )
                else:
                    self.console.print(f"  {idx}. {rec}")
