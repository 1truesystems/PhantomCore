"""
Morph CLI -- Binary Analysis Framework
========================================

Click-based command-line interface for the Morph binary analysis tool.
Provides access to all analysis capabilities through a single command
with configurable options for format selection, output control, and
analysis scope.

Usage::

    # Full analysis
    morph /path/to/binary

    # Force ELF format
    morph /path/to/binary --format elf

    # Strings-only extraction
    morph /path/to/binary --strings-only

    # Entropy-only analysis
    morph /path/to/binary --entropy-only

    # Generate HTML report
    morph /path/to/binary --output report.html

    # Verbose output
    morph /path/to/binary --verbose

References:
    - Click documentation: https://click.palletsprojects.com/
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from shared.config import PhantomConfig
from shared.console import PhantomConsole
from shared.logger import PhantomLogger

from morph.core.engine import MorphEngine
from morph.core.models import BinaryAnalysisResult
from morph.output.console import MorphConsoleOutput
from morph.output.report import MorphReportGenerator


# ---------------------------------------------------------------------------
# CLI group / commands
# ---------------------------------------------------------------------------

@click.command("morph")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    "file_format",
    type=click.Choice(["auto", "elf", "pe", "dex"], case_sensitive=False),
    default="auto",
    help="Binary format override.  Default: auto-detect.",
)
@click.option(
    "--output", "-o",
    "output_path",
    type=click.Path(),
    default=None,
    help="Output report path (.html or .json).",
)
@click.option(
    "--strings-only", "-s",
    is_flag=True,
    default=False,
    help="Only extract and classify strings.",
)
@click.option(
    "--entropy-only", "-e",
    is_flag=True,
    default=False,
    help="Only compute entropy analysis.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose/debug output.",
)
@click.option(
    "--min-string-length",
    type=int,
    default=4,
    help="Minimum string length for extraction (default: 4).",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    default=False,
    help="Output results as JSON to stdout.",
)
def morph_cli(
    path: str,
    file_format: str,
    output_path: str | None,
    strings_only: bool,
    entropy_only: bool,
    verbose: bool,
    min_string_length: int,
    json_output: bool,
) -> None:
    """Morph -- Binary Analysis Framework.

    Analyse a binary executable file (ELF, PE, DEX) for security-relevant
    properties including imports, strings, entropy, shellcode patterns,
    and control flow complexity.

    PATH is the path to the binary file to analyse.

    Examples:

    \b
        # Full analysis of an ELF binary
        python -m morph.cli /usr/bin/ls

    \b
        # Strings-only extraction
        python -m morph.cli malware.exe --strings-only

    \b
        # Generate HTML report
        python -m morph.cli sample.elf --output report.html
    """
    console = PhantomConsole()
    log_level = "DEBUG" if verbose else "INFO"
    logger = PhantomLogger("morph.cli", log_level=log_level)

    try:
        config = PhantomConfig.load()
    except Exception:
        config = PhantomConfig()

    # Validate mutually exclusive options
    if strings_only and entropy_only:
        console.error("Cannot use --strings-only and --entropy-only together.")
        sys.exit(1)

    # Run analysis
    engine = MorphEngine(config=config, logger=logger)

    try:
        scan_result = asyncio.run(
            engine.analyze(
                file_path=path,
                format=file_format,
                strings_only=strings_only,
                entropy_only=entropy_only,
            )
        )
    except KeyboardInterrupt:
        console.warning("Analysis interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        console.error(f"Analysis failed: {exc}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Extract the BinaryAnalysisResult from raw_data
    raw = scan_result.metadata.get("binary_analysis")
    if raw:
        analysis_result = BinaryAnalysisResult.model_validate(raw)
    else:
        # Fallback: create minimal result
        analysis_result = BinaryAnalysisResult()
        console.warning("Analysis produced no detailed results.")

    # JSON output mode
    if json_output:
        report_gen = MorphReportGenerator()
        import json as json_module
        import io
        report_data = {
            "scan": scan_result.model_dump(mode="json"),
        }
        click.echo(json_module.dumps(report_data, indent=2, default=str))
        return

    # Console display
    output_display = MorphConsoleOutput(console=console)
    output_display.display(analysis_result)

    # Display findings
    if scan_result.findings:
        console.section("Findings")
        console.findings_table(scan_result.findings)

    # Summary
    console.blank()
    console.info(f"Scan Duration: {scan_result.duration_seconds:.2f}s")
    console.info(f"Findings: {scan_result.finding_count}")
    if scan_result.critical_count > 0:
        console.critical(
            f"Critical findings: {scan_result.critical_count}"
        )

    # Generate report if output path specified
    if output_path:
        report_gen = MorphReportGenerator()
        output_ext = Path(output_path).suffix.lower()

        if output_ext == ".json":
            report_path = report_gen.generate_json(analysis_result, output_path)
            console.success(f"JSON report saved: {report_path}")
        else:
            # Default to HTML
            report_path = report_gen.generate_html(analysis_result, output_path)
            console.success(f"HTML report saved: {report_path}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point for ``python -m morph.cli``."""
    morph_cli()


if __name__ == "__main__":
    main()
