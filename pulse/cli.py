"""
Pulse CLI
==========

Click-based command-line interface for the Pulse Wireless Protocol
Analyzer. Provides commands for WiFi scanning, BLE device discovery,
wireless IDS monitoring, and PCAP file analysis.

Commands:
    pulse scan --interface IFACE     Scan WiFi networks
    pulse ble                         Scan BLE devices
    pulse ids --interface IFACE      Wireless IDS mode
    pulse analyze PCAP_FILE          Analyze wireless capture

Common options:
    --output PATH       Output report file path
    --duration SECS     Scan/capture duration
    --channel NUM       Specific WiFi channel to monitor
    --verbose           Enable verbose output

References:
    - Click Documentation: https://click.palletsprojects.com/
    - IEEE. (2020). IEEE Std 802.11-2020.
    - Bluetooth SIG. (2023). Bluetooth Core Specification v5.4.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Optional

import click

from shared.config import PhantomConfig
from shared.console import PhantomConsole


# ---------------------------------------------------------------------------
# Async helper
# ---------------------------------------------------------------------------


def _run_async(coro):
    """Run an async coroutine from synchronous Click commands.

    Handles event loop creation and cleanup for both standard
    Python and environments with existing event loops.

    Args:
        coro: Coroutine to execute.

    Returns:
        The coroutine's return value.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already in an async context -- use nest_asyncio or run in thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# CLI Group
# ---------------------------------------------------------------------------


@click.group(
    name="pulse",
    help=(
        "PULSE - Wireless Protocol Analyzer\n\n"
        "Wireless Protocol Analyzer\n\n"
        "PhantomCore Tool 5/5: Analyse WiFi networks, BLE devices, "
        "detect wireless attacks, and assess wireless security posture."
    ),
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=False),
    default=None,
    help="Path to PhantomCore configuration file (TOML).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress console output (report only).",
)
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[str], quiet: bool) -> None:
    """Pulse Wireless Protocol Analyzer - main CLI entry point."""
    ctx.ensure_object(dict)

    # Load configuration
    try:
        config = PhantomConfig.load(config_path) if config_path else PhantomConfig()
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    console = PhantomConsole(quiet=quiet)

    ctx.obj["config"] = config
    ctx.obj["console"] = console
    ctx.obj["quiet"] = quiet


# ---------------------------------------------------------------------------
# WiFi Scan Command
# ---------------------------------------------------------------------------


@cli.command(
    name="scan",
    help=(
        "Scan WiFi networks.\n\n"
        "Scan WiFi networks.\n\n"
        "Captures 802.11 frames to enumerate access points, client "
        "stations, and security configurations. Assigns security grades "
        "(A-F), analyses channel utilization, and detects deauth attacks.\n\n"
        "Requires a wireless interface in monitor mode for live capture. "
        "Falls back to simulated data for educational demonstration."
    ),
)
@click.option(
    "--interface", "-i",
    required=True,
    type=str,
    help="Wireless interface in monitor mode (e.g., wlan0mon).",
)
@click.option(
    "--duration", "-d",
    type=int,
    default=30,
    show_default=True,
    help="Scan duration in seconds.",
)
@click.option(
    "--channel", "-c",
    type=int,
    default=None,
    help="Specific channel to monitor (omit for all channels).",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output report file path (generates .html and .json).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output.",
)
@click.pass_context
def scan_wifi(
    ctx: click.Context,
    interface: str,
    duration: int,
    channel: Optional[int],
    output: Optional[str],
    verbose: bool,
) -> None:
    """Scan WiFi networks and assess security."""
    config = ctx.obj["config"]
    console = ctx.obj["console"]

    from pulse.core.engine import PulseEngine

    engine = PulseEngine(config=config, console=console)
    result = _run_async(
        engine.scan_wifi(
            interface=interface,
            duration=duration,
            channel=channel,
            output_path=output,
            verbose=verbose,
        )
    )

    if result.critical_count > 0 or result.high_count > 0:
        sys.exit(1)


# ---------------------------------------------------------------------------
# BLE Scan Command
# ---------------------------------------------------------------------------


@cli.command(
    name="ble",
    help=(
        "Scan BLE devices.\n\n"
        "Scan BLE devices.\n\n"
        "Discovers Bluetooth Low Energy devices in the vicinity, "
        "extracting device names, service UUIDs, manufacturer data, "
        "and address types. Identifies trackable devices and "
        "assesses BLE privacy."
    ),
)
@click.option(
    "--duration", "-d",
    type=int,
    default=10,
    show_default=True,
    help="Scan duration in seconds.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output report file path.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output.",
)
@click.pass_context
def scan_ble(
    ctx: click.Context,
    duration: int,
    output: Optional[str],
    verbose: bool,
) -> None:
    """Scan for Bluetooth Low Energy devices."""
    config = ctx.obj["config"]
    console = ctx.obj["console"]

    from pulse.core.engine import PulseEngine

    engine = PulseEngine(config=config, console=console)
    _run_async(
        engine.scan_ble(
            duration=duration,
            output_path=output,
            verbose=verbose,
        )
    )


# ---------------------------------------------------------------------------
# Wireless IDS Command
# ---------------------------------------------------------------------------


@cli.command(
    name="ids",
    help=(
        "Wireless IDS monitoring mode.\n\n"
        "Wireless IDS monitoring.\n\n"
        "Continuously monitors the wireless medium for security threats "
        "including deauthentication flood attacks, rogue access points, "
        "weak encryption usage, and suspicious client behaviour.\n\n"
        "Designed for extended monitoring periods."
    ),
)
@click.option(
    "--interface", "-i",
    required=True,
    type=str,
    help="Wireless interface in monitor mode.",
)
@click.option(
    "--duration", "-d",
    type=int,
    default=300,
    show_default=True,
    help="Monitoring duration in seconds.",
)
@click.option(
    "--channel", "-c",
    type=int,
    default=None,
    help="Specific channel to monitor.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output report file path.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output.",
)
@click.pass_context
def run_ids(
    ctx: click.Context,
    interface: str,
    duration: int,
    channel: Optional[int],
    output: Optional[str],
    verbose: bool,
) -> None:
    """Run wireless Intrusion Detection System monitoring."""
    config = ctx.obj["config"]
    console = ctx.obj["console"]

    from pulse.core.engine import PulseEngine

    engine = PulseEngine(config=config, console=console)
    result = _run_async(
        engine.run_ids(
            interface=interface,
            duration=duration,
            channel=channel,
            output_path=output,
            verbose=verbose,
        )
    )

    if result.critical_count > 0:
        sys.exit(2)
    elif result.high_count > 0:
        sys.exit(1)


# ---------------------------------------------------------------------------
# PCAP Analysis Command
# ---------------------------------------------------------------------------


@cli.command(
    name="analyze",
    help=(
        "Analyze a wireless PCAP capture file.\n\n"
        "Wireless PCAP file analysis.\n\n"
        "Reads a PCAP or PCAPNG file containing 802.11 wireless frames "
        "and performs full security analysis: AP enumeration, security "
        "grading, channel analysis, probe request analysis, deauth "
        "detection, and hidden SSID discovery.\n\n"
        "Supports both libpcap (.pcap) and PCAPNG (.pcapng) formats "
        "with RadioTap link-layer headers."
    ),
)
@click.argument(
    "pcap_file",
    type=click.Path(exists=True),
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output report file path.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output.",
)
@click.pass_context
def analyze_pcap(
    ctx: click.Context,
    pcap_file: str,
    output: Optional[str],
    verbose: bool,
) -> None:
    """Analyze a wireless PCAP/PCAPNG capture file."""
    config = ctx.obj["config"]
    console = ctx.obj["console"]

    from pulse.core.engine import PulseEngine

    engine = PulseEngine(config=config, console=console)
    result = _run_async(
        engine.analyze_pcap(
            file_path=pcap_file,
            output_path=output,
            verbose=verbose,
        )
    )

    if result.critical_count > 0 or result.high_count > 0:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the Pulse CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
