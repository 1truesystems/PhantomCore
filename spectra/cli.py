"""
Spectra CLI -- Network Intelligence Engine Command-Line Interface
==================================================================

Click-based CLI for the Spectra Network Intelligence Engine.
Provides packet capture analysis (PCAP files and live capture),
anomaly detection, graph analysis, beacon detection, and lateral
movement detection.

Usage:
    spectra -i CAPTURE.pcap                    # Analyse PCAP file
    spectra -i CAPTURE.pcap -o report.html     # With HTML report
    spectra --live -d 60                       # Live capture (60s, needs root)
    spectra --live --interface eth0 -d 120     # Specific interface
    spectra -i CAPTURE.pcap --format json      # JSON output
    spectra -i CAPTURE.pcap --anomaly-threshold 3.0 --top-n 15

References:
    - Click Documentation: https://click.palletsprojects.com/
    - PhantomCore Shared Config: shared.config.PhantomConfig
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import click

from shared.config import PhantomConfig
from shared.console import PhantomConsole
from shared.logger import PhantomLogger

from spectra.core.engine import SpectraEngine
from spectra.output.console import SpectraConsoleOutput
from spectra.output.report import SpectraReportGenerator

logger = PhantomLogger("spectra.cli")


def _get_event_loop() -> asyncio.AbstractEventLoop:
    """Get or create an asyncio event loop."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop


@click.command(
    name="spectra",
    help=(
        "SPECTRA -- Network Intelligence Engine\n\n"
        "Analyses PCAP files or performs live network capture to detect "
        "anomalies, beacon patterns, lateral movement, and map network "
        "topology using graph analysis and Markov chain modelling."
    ),
)
@click.option(
    "-i", "--input",
    "input_file",
    type=click.Path(exists=False),
    default=None,
    help="Path to PCAP/PCAPNG file for offline analysis.",
)
@click.option(
    "--live",
    is_flag=True,
    default=False,
    help="Enable live packet capture mode (requires root).",
)
@click.option(
    "-d", "--duration",
    type=int,
    default=60,
    show_default=True,
    help="Duration in seconds for live capture.",
)
@click.option(
    "--interface",
    type=str,
    default=None,
    help="Network interface for live capture (e.g., eth0, wlan0).",
)
@click.option(
    "-o", "--output",
    type=click.Path(),
    default=None,
    help="Output file path for report (HTML or JSON based on --format).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["console", "html", "json", "all"], case_sensitive=False),
    default="console",
    show_default=True,
    help="Output format for analysis results.",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose output with detailed logging.",
)
@click.option(
    "--anomaly-threshold",
    type=float,
    default=2.5,
    show_default=True,
    help="Z-score threshold for anomaly detection (Grubbs test).",
)
@click.option(
    "--top-n",
    type=int,
    default=10,
    show_default=True,
    help="Number of top nodes to report per centrality metric.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to PhantomCore configuration file (TOML).",
)
def main(
    input_file: Optional[str],
    live: bool,
    duration: int,
    interface: Optional[str],
    output: Optional[str],
    output_format: str,
    verbose: bool,
    anomaly_threshold: float,
    top_n: int,
    config_path: Optional[str],
) -> None:
    """SPECTRA Network Intelligence Engine entry point."""
    console = PhantomConsole()

    # Validate arguments
    if not input_file and not live:
        console.error(
            "Please specify a PCAP file (-i) or live mode (--live)"
        )
        sys.exit(1)

    if input_file and live:
        console.error(
            "Cannot use both PCAP file and live mode simultaneously"
        )
        sys.exit(1)

    if input_file and not Path(input_file).exists():
        console.error(
            f"PCAP file not found: {input_file}"
        )
        sys.exit(1)

    if live and os.geteuid() != 0:
        console.warning(
            "Live capture requires root privileges. "
            "Run with sudo if capture fails."
        )

    # Load configuration
    try:
        config = PhantomConfig.load(config_path) if config_path else PhantomConfig()
    except FileNotFoundError as exc:
        console.error(str(exc))
        sys.exit(1)

    # Resolve interface
    if live and interface is None:
        interface = config.spectra.interface
        console.info(
            f"Interface: {interface} "
            f"(from config)"
        )

    # Initialise engine
    engine = SpectraEngine(
        config=config,
        anomaly_threshold=anomaly_threshold,
        top_n=top_n,
        verbose=verbose,
    )

    # Run analysis
    loop = _get_event_loop()

    try:
        if input_file:
            console.info(
                f"Analysing PCAP: {input_file}"
            )
            with console.status(
                "Analysing PCAP file..."
            ):
                result = loop.run_until_complete(
                    engine.analyze_pcap(input_file)
                )

        else:
            assert live and interface is not None
            console.info(
                f"Live capture: {interface}, "
                f"{duration}s"
            )
            with console.status(
                f"Capturing on {interface} "
                f"({duration}s)..."
            ):
                result = loop.run_until_complete(
                    engine.analyze_live(interface, duration)
                )

    except FileNotFoundError as exc:
        console.error(str(exc))
        sys.exit(1)
    except PermissionError as exc:
        console.error(str(exc))
        sys.exit(1)
    except OSError as exc:
        console.error(f"OS error: {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.warning("Interrupted by user")
        sys.exit(130)
    except Exception as exc:
        console.error(f"Unexpected error: {exc}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Output results
    _output_results(
        result=result,
        output_format=output_format,
        output_path=output,
        console=console,
        verbose=verbose,
    )


def _output_results(
    result: "ScanResult",
    output_format: str,
    output_path: Optional[str],
    console: PhantomConsole,
    verbose: bool,
) -> None:
    """Render analysis results in the requested format.

    Args:
        result: ScanResult from the engine.
        output_format: One of "console", "html", "json", "all".
        output_path: Optional output file path.
        console: PhantomConsole for display.
        verbose: Whether verbose mode is enabled.
    """
    from shared.models import ScanResult as _SR

    report_gen = SpectraReportGenerator()
    console_output = SpectraConsoleOutput(console=console)

    # Console output (always shown unless format is json-only)
    if output_format in ("console", "all"):
        console_output.display(result)

    # HTML report
    if output_format in ("html", "all"):
        html_path = output_path or _default_output_path("html")
        generated = report_gen.generate_html(result, html_path)
        console.success(
            f"HTML report: {generated}"
        )

    # JSON report
    if output_format in ("json", "all"):
        json_path = output_path or _default_output_path("json")
        generated = report_gen.generate_json(result, json_path)
        console.success(
            f"JSON report: {generated}"
        )

    # If format is json/html only and no console output was shown,
    # print a brief summary
    if output_format in ("json", "html"):
        console.blank()
        console.info(
            f"Analysis complete: "
            f"{result.finding_count} findings "
            f"({result.critical_count} critical, {result.high_count} high)"
        )


def _default_output_path(ext: str) -> str:
    """Generate a default output file path with timestamp."""
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    return str(output_dir / f"spectra_report_{timestamp}.{ext}")


if __name__ == "__main__":
    main()
