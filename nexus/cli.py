"""
Nexus CLI
==========

Click-based command-line interface for the Nexus Threat Intelligence
Correlator. Provides commands for CVE lookup, IoC extraction, risk
assessment, CVE database search, and MITRE ATT&CK technique lookup.

Commands:
    nexus cve CVE_ID         - Look up CVE details and calculate CVSS
    nexus ioc FILE           - Extract IoCs from a file or text
    nexus assess CONFIG_FILE - Assess risk from configuration/scan results
    nexus search QUERY       - Search the local CVE database
    nexus mitre TECHNIQUE_ID - Look up a MITRE ATT&CK technique

Global Options:
    --output, -o    Output file path for report generation
    --format, -f    Output format: json or html (default: json)
    --verbose, -v   Enable verbose (debug) logging
    --db-path       Path to the SQLite CVE database

References:
    - Click documentation: https://click.palletsprojects.com/
    - NIST NVD: https://nvd.nist.gov/
    - MITRE ATT&CK: https://attack.mitre.org/
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click

from shared.config import PhantomConfig
from shared.console import PhantomConsole
from shared.logger import PhantomLogger
from shared.models import Risk

from nexus.core.engine import NexusEngine
from nexus.core.models import CVERecord, MITRETechnique, ThreatAssessment
from nexus.output.console import NexusConsoleOutput
from nexus.output.report import NexusReportGenerator


# ================================================================== #
#  Async runner helper
# ================================================================== #

def _run_async(coro):
    """Run an async coroutine in the current or new event loop.

    Handles compatibility across Python versions and existing event
    loop scenarios.

    Args:
        coro: Coroutine to execute.

    Returns:
        The coroutine's return value.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We're inside an existing event loop (e.g. Jupyter)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)


# ================================================================== #
#  CLI Group
# ================================================================== #

@click.group()
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file path for report generation.",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["json", "html"], case_sensitive=False),
    default="json",
    help="Output format (json or html). Default: json.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose (debug) logging.",
)
@click.option(
    "--db-path",
    type=click.Path(),
    default=None,
    help="Path to the SQLite CVE database file.",
)
@click.pass_context
def nexus(
    ctx: click.Context,
    output: Optional[str],
    output_format: str,
    verbose: bool,
    db_path: Optional[str],
) -> None:
    """Nexus -- Threat Intelligence Correlator.

    PhantomCore's threat intelligence analysis tool. Provides CVE
    lookup, IoC extraction, risk assessment, CVE search, and
    MITRE ATT&CK mapping capabilities.
    """
    ctx.ensure_object(dict)

    # Configure logging
    log_level = "DEBUG" if verbose else "INFO"
    logger = PhantomLogger("nexus", log_level=log_level)

    # Initialise shared objects
    config = PhantomConfig()
    console = PhantomConsole()
    display = NexusConsoleOutput(console=console)
    report_gen = NexusReportGenerator()
    engine = NexusEngine(db_path=db_path, config=config)

    # Store in context
    ctx.obj["engine"] = engine
    ctx.obj["console"] = console
    ctx.obj["display"] = display
    ctx.obj["report_gen"] = report_gen
    ctx.obj["logger"] = logger
    ctx.obj["output"] = output
    ctx.obj["output_format"] = output_format
    ctx.obj["verbose"] = verbose


# ================================================================== #
#  CVE Lookup Command
# ================================================================== #

@nexus.command()
@click.argument("cve_id")
@click.pass_context
def cve(ctx: click.Context, cve_id: str) -> None:
    """Look up CVE details and calculate CVSS scores.

    Searches local cache and online NVD API for the specified CVE,
    calculates CVSS v3.1 scores, estimates exploitation probability,
    and maps to MITRE ATT&CK techniques.

    Example:
        nexus cve CVE-2021-44228
    """
    engine: NexusEngine = ctx.obj["engine"]
    console: PhantomConsole = ctx.obj["console"]
    display: NexusConsoleOutput = ctx.obj["display"]
    report_gen: NexusReportGenerator = ctx.obj["report_gen"]

    console.banner()
    console.section("CVE Lookup")
    console.info(f"Looking up {cve_id.upper()}...")

    try:
        result = _run_async(engine.lookup_cve(cve_id))
    except Exception as exc:
        console.error(f"CVE lookup failed: {exc}")
        engine.close()
        sys.exit(1)

    # Display results
    if result.metadata and "cve_record" in result.metadata:
        record = CVERecord(**result.metadata["cve_record"])
        cvss_details = result.metadata.get("cvss_details")
        display.display_cve(record, cvss_details)

        # Display MITRE techniques
        techniques_data = result.metadata.get("mitre_techniques", [])
        if techniques_data:
            techniques = [MITRETechnique(**t) for t in techniques_data]
            display.display_mitre(techniques)

        # Exploitation probability
        exploit_data = result.metadata.get("exploit_probability", {})
        if exploit_data:
            console.section("Exploitation Probability Analysis")
            console.print(f"  [bold]Prior:[/bold] {exploit_data.get('prior', 0):.4f}")
            console.print(f"  [bold]Posterior:[/bold] {exploit_data.get('posterior', 0):.4f}")
            console.print(f"  [bold]Severity:[/bold] {exploit_data.get('severity', 'unknown')}")
            factors = exploit_data.get("factors", [])
            if factors:
                console.print(f"\n  [bold]Contributing Factors ({len(factors)}):[/bold]")
                for factor in factors:
                    console.print(
                        f"    - {factor['name']}: "
                        f"LR={factor['likelihood_ratio']}x "
                        f"({factor['description']})"
                    )
    else:
        console.findings_table(result.findings)

    console.print()
    console.info(result.summary)

    # Generate report if output specified
    _write_report(ctx, result)

    engine.close()


# ================================================================== #
#  IoC Extraction Command
# ================================================================== #

@nexus.command()
@click.argument("file", type=click.Path(exists=True))
@click.pass_context
def ioc(ctx: click.Context, file: str) -> None:
    """Extract Indicators of Compromise from a file.

    Scans the specified file for IP addresses, domains, URLs,
    hashes (MD5/SHA1/SHA256), email addresses, CVE identifiers,
    file paths, and registry keys.

    Example:
        nexus ioc threat_report.txt
    """
    engine: NexusEngine = ctx.obj["engine"]
    console: PhantomConsole = ctx.obj["console"]
    display: NexusConsoleOutput = ctx.obj["display"]

    console.banner()
    console.section("IoC Extraction")
    console.info(f"Scanning {file} for indicators of compromise...")

    try:
        result = _run_async(engine.extract_iocs(file))
    except Exception as exc:
        console.error(f"IoC extraction failed: {exc}")
        engine.close()
        sys.exit(1)

    # Display IoCs
    if result.metadata and "iocs" in result.metadata:
        from nexus.core.models import IoC
        iocs_data = result.metadata["iocs"]
        iocs = [IoC(**ioc_data) for ioc_data in iocs_data]
        display.display_iocs(iocs)

        # Display MITRE techniques
        techniques_data = result.metadata.get("mitre_techniques", [])
        if techniques_data:
            techniques = [MITRETechnique(**t) for t in techniques_data]
            display.display_mitre(techniques, title="IoC-to-ATT&CK Mapping")
    else:
        console.findings_table(result.findings)

    console.print()
    console.info(result.summary)

    _write_report(ctx, result)
    engine.close()


# ================================================================== #
#  Risk Assessment Command
# ================================================================== #

@nexus.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.pass_context
def assess(ctx: click.Context, config_file: str) -> None:
    """Assess risk from a configuration/scan results file.

    Reads a JSON configuration file specifying CVEs to analyse,
    IoC data, attack surface nodes, and asset criticality settings.
    Produces a comprehensive threat assessment with risk scoring.

    Configuration file format (JSON):
        {
            "cve_ids": ["CVE-2021-44228", "CVE-2023-0001"],
            "ioc_text": "suspicious text with 192.168.1.1...",
            "ioc_files": ["/path/to/ioc_report.txt"],
            "attack_surface_nodes": [...],
            "asset_criticality": 75.0
        }

    Example:
        nexus assess config.json
    """
    engine: NexusEngine = ctx.obj["engine"]
    console: PhantomConsole = ctx.obj["console"]
    display: NexusConsoleOutput = ctx.obj["display"]

    console.banner()
    console.section("Risk Assessment")
    console.info(f"Assessing risk from {config_file}...")

    try:
        result = _run_async(engine.assess_risk(config_file))
    except Exception as exc:
        console.error(f"Risk assessment failed: {exc}")
        engine.close()
        sys.exit(1)

    # Display assessment
    if result.metadata and "assessment" in result.metadata:
        assessment_data = result.metadata["assessment"]
        assessment = ThreatAssessment(**assessment_data)
        risk_details = result.metadata.get("risk_details")

        display.display_assessment(assessment, risk_details)
    else:
        console.findings_table(result.findings)

    console.print()
    console.info(result.summary)

    _write_report(ctx, result)
    engine.close()


# ================================================================== #
#  CVE Search Command
# ================================================================== #

@nexus.command()
@click.argument("query")
@click.pass_context
def search(ctx: click.Context, query: str) -> None:
    """Search the local CVE database.

    Performs a full-text search across CVE descriptions, identifiers,
    and affected products using FTS5 with BM25 ranking.

    Example:
        nexus search "remote code execution"
        nexus search "Apache Log4j"
    """
    engine: NexusEngine = ctx.obj["engine"]
    console: PhantomConsole = ctx.obj["console"]
    display: NexusConsoleOutput = ctx.obj["display"]

    console.banner()
    console.section("CVE Database Search")
    console.info(f"Searching for: {query}")

    try:
        results = _run_async(engine.search_cves(query))
    except Exception as exc:
        console.error(f"Search failed: {exc}")
        engine.close()
        sys.exit(1)

    if not results:
        console.warning(
            f"No results found for '{query}'. "
            f"The local database may be empty. Use 'nexus cve <CVE_ID>' "
            f"to populate it."
        )
        engine.close()
        return

    console.success(f"Found {len(results)} result(s)")
    console.print()

    # Display as table
    from rich.table import Table
    table = Table(
        title=f"Search Results: '{query}'",
        border_style="bright_cyan",
        header_style="bold bright_magenta",
        show_lines=True,
    )
    table.add_column("CVE ID", style="bold")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Description", max_width=60, overflow="fold")

    for record in results:
        sev_style = display.SEVERITY_COLOURS.get(
            record.severity.lower(), "dim"
        )
        desc = record.description
        if len(desc) > 100:
            desc = desc[:97] + "..."

        table.add_row(
            record.cve_id,
            f"{record.cvss_score:.1f}",
            f"[{sev_style}]{record.severity.upper()}[/{sev_style}]",
            desc,
        )

    console.print(table)

    # Write report if requested
    if ctx.obj.get("output"):
        from shared.models import ScanResult
        scan_result = ScanResult(
            tool_name="nexus",
            target=f"search:{query}",
            summary=f"Found {len(results)} CVEs matching '{query}'",
            metadata={
                "query": query,
                "results": [r.model_dump() for r in results],
            },
        )
        _write_report(ctx, scan_result)

    engine.close()


# ================================================================== #
#  MITRE ATT&CK Lookup Command
# ================================================================== #

@nexus.command()
@click.argument("technique_id")
@click.pass_context
def mitre(ctx: click.Context, technique_id: str) -> None:
    """Look up a MITRE ATT&CK technique.

    Retrieves technique details including description, tactic,
    platforms, data sources, and detection guidance.

    Example:
        nexus mitre T1190
        nexus mitre T1059.001
    """
    engine: NexusEngine = ctx.obj["engine"]
    console: PhantomConsole = ctx.obj["console"]
    display: NexusConsoleOutput = ctx.obj["display"]

    console.banner()
    console.section("MITRE ATT&CK Lookup")
    console.info(f"Looking up technique {technique_id}...")

    try:
        result = _run_async(engine.lookup_mitre(technique_id))
    except Exception as exc:
        console.error(f"MITRE lookup failed: {exc}")
        engine.close()
        sys.exit(1)

    # Display technique
    if result.metadata and "technique" in result.metadata:
        technique = MITRETechnique(**result.metadata["technique"])
        display.display_mitre([technique], title=f"Technique: {technique_id}")

        # Additional detail panel
        from rich.panel import Panel
        detail_parts = []
        if technique.description:
            detail_parts.append(f"[bold]Description:[/bold]\n{technique.description}")
        if technique.detection:
            detail_parts.append(f"\n[bold]Detection:[/bold]\n{technique.detection}")
        if technique.platforms:
            detail_parts.append(
                f"\n[bold]Platforms:[/bold] {', '.join(technique.platforms)}"
            )
        if technique.data_sources:
            detail_parts.append(
                f"[bold]Data Sources:[/bold] {', '.join(technique.data_sources)}"
            )
        if technique.url:
            detail_parts.append(
                f"[bold]Reference:[/bold] [link={technique.url}]{technique.url}[/link]"
            )

        if detail_parts:
            panel = Panel(
                "\n".join(detail_parts),
                title=f"[bold]{technique.technique_id}: {technique.name}[/bold]",
                border_style="bright_cyan",
                padding=(1, 2),
            )
            console.print(panel)
    else:
        console.findings_table(result.findings)

    console.print()
    console.info(result.summary)

    _write_report(ctx, result)
    engine.close()


# ================================================================== #
#  Report Writer Helper
# ================================================================== #

def _write_report(ctx: click.Context, result) -> None:
    """Write a report if an output path is specified.

    Args:
        ctx: Click context with output settings.
        result: Analysis result to write.
    """
    output_path = ctx.obj.get("output")
    if not output_path:
        return

    console: PhantomConsole = ctx.obj["console"]
    report_gen: NexusReportGenerator = ctx.obj["report_gen"]
    output_format = ctx.obj.get("output_format", "json")

    try:
        if output_format == "html":
            path = report_gen.generate_html(result, output_path)
        else:
            path = report_gen.generate_json(result, output_path)

        console.success(f"Report written to {path}")
    except Exception as exc:
        console.error(f"Failed to write report: {exc}")


# ================================================================== #
#  Entry Point
# ================================================================== #

def main() -> None:
    """Main entry point for the Nexus CLI."""
    nexus(obj={})


if __name__ == "__main__":
    main()
