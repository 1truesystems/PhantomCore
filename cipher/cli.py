"""
Cipher CLI
===========

Click-based command-line interface for the Cipher cryptographic analysis
framework. Provides subcommands for entropy analysis, hash identification,
TLS cipher suite evaluation, password strength assessment, frequency
analysis, key strength estimation, and RNG statistical testing.

Usage::

    python -m cipher entropy /path/to/file
    python -m cipher hash-id "5d41402abc4b2a76b9719d911017c592"
    python -m cipher tls example.com
    python -m cipher password "MyP@ssw0rd!"
    python -m cipher frequency /path/to/file
    python -m cipher key-strength --algorithm RSA --key-size 2048
    python -m cipher rng /path/to/random_data

References:
    - Click Documentation. https://click.palletsprojects.com/
    - PhantomCore Architecture Guide.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click

from shared.config import PhantomConfig
from shared.console import PhantomConsole
from shared.models import ScanResult

from cipher.core.engine import CipherEngine
from cipher.output.console import CipherConsoleOutput
from cipher.output.report import CipherReportGenerator


# ===================================================================== #
#  Async Runner Helper
# ===================================================================== #

def _run_async(coro):
    """Run an async coroutine from synchronous Click handlers.

    Handles event loop creation for both Python 3.10+ and older versions.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already in an async context (shouldn't happen from CLI)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)


# ===================================================================== #
#  CLI Group
# ===================================================================== #

@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to PhantomCore configuration file (TOML).",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["console", "json", "html"]),
    default="console",
    help="Output format.",
)
@click.option(
    "--output-file", "-f",
    type=click.Path(dir_okay=False),
    default=None,
    help="Output file path (for JSON/HTML output).",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress banner and informational output.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    config: Optional[str],
    output: str,
    output_file: Optional[str],
    quiet: bool,
) -> None:
    """PhantomCore Cipher -- Cryptographic Analysis Framework.

    Analyse entropy, identify hashes, evaluate TLS configurations,
    assess password strength, and test random number generators.
    """
    ctx.ensure_object(dict)

    # Load configuration
    phantom_config = PhantomConfig.load(config) if config else PhantomConfig()
    ctx.obj["config"] = phantom_config
    ctx.obj["output_format"] = output
    ctx.obj["output_file"] = output_file
    ctx.obj["quiet"] = quiet

    # Create shared instances
    console = PhantomConsole(quiet=quiet)
    ctx.obj["console"] = console
    ctx.obj["engine"] = CipherEngine(phantom_config)
    ctx.obj["display"] = CipherConsoleOutput(console)
    ctx.obj["reporter"] = CipherReportGenerator()

    if not quiet:
        console.banner(version="1.0.0")


def _handle_output(ctx: click.Context, result: ScanResult) -> None:
    """Handle output based on the selected format.

    Args:
        ctx: Click context containing configuration.
        result: ScanResult to output.
    """
    output_format = ctx.obj["output_format"]
    output_file = ctx.obj["output_file"]
    reporter: CipherReportGenerator = ctx.obj["reporter"]
    console: PhantomConsole = ctx.obj["console"]

    if output_format == "json":
        if output_file:
            path = reporter.generate_json(result, Path(output_file))
            console.success(f"JSON report saved to: {path}")
        else:
            # Output JSON to stdout
            import json
            click.echo(json.dumps(
                result.model_dump(),
                indent=2,
                ensure_ascii=False,
                default=str,
            ))
    elif output_format == "html":
        if output_file:
            path = reporter.generate_html(result, Path(output_file))
            console.success(f"HTML report saved to: {path}")
        else:
            # Default HTML file name
            default_name = f"cipher_report_{result.tool}.html"
            path = reporter.generate_html(result, Path(default_name))
            console.success(f"HTML report saved to: {path}")


# ===================================================================== #
#  Subcommands
# ===================================================================== #

@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def entropy(ctx: click.Context, file: str) -> None:
    """Analyse file entropy (Shannon, Min, Renyi, block entropy).

    Reads the file and computes multiple entropy measures to classify
    the data as plaintext, structured, compressed, or encrypted.
    """
    engine: CipherEngine = ctx.obj["engine"]
    display: CipherConsoleOutput = ctx.obj["display"]

    result = _run_async(engine.analyze_entropy(Path(file)))

    if ctx.obj["output_format"] == "console":
        # Display entropy-specific output
        raw = result.metadata
        if raw:
            from cipher.core.models import EntropyResult
            entropy_result = EntropyResult(**raw)
            display.display_entropy(entropy_result)

        # Display findings
        ctx.obj["console"].findings_table(result.findings)
    else:
        _handle_output(ctx, result)


@cli.command("hash-id")
@click.argument("hash_value")
@click.pass_context
def hash_id(ctx: click.Context, hash_value: str) -> None:
    """Identify hash type from a hash string.

    Analyses the structure, length, and character set of the hash
    to identify the most likely algorithm(s).
    """
    engine: CipherEngine = ctx.obj["engine"]
    display: CipherConsoleOutput = ctx.obj["display"]

    result = _run_async(engine.analyze_hash(hash_value))

    if ctx.obj["output_format"] == "console":
        raw = result.metadata
        if raw:
            from cipher.core.models import HashIdentification
            hash_result = HashIdentification(**raw)
            display.display_hash_id([hash_result])
        ctx.obj["console"].findings_table(result.findings)
    else:
        _handle_output(ctx, result)


@cli.command()
@click.argument("host")
@click.option(
    "--port", "-p",
    type=int,
    default=443,
    help="Target port (default 443).",
)
@click.pass_context
def tls(ctx: click.Context, host: str, port: int) -> None:
    """Analyse TLS cipher suites of a remote host.

    Connects to the host and evaluates protocol version, cipher suites,
    certificate details, and overall security configuration.
    """
    engine: CipherEngine = ctx.obj["engine"]
    display: CipherConsoleOutput = ctx.obj["display"]

    result = _run_async(engine.analyze_tls(host, port))

    if ctx.obj["output_format"] == "console":
        raw = result.metadata
        if raw:
            from cipher.core.models import CipherSuiteResult
            tls_result = CipherSuiteResult(**raw)
            display.display_tls(tls_result)
        ctx.obj["console"].findings_table(result.findings)
    else:
        _handle_output(ctx, result)


@cli.command()
@click.argument("password")
@click.pass_context
def password(ctx: click.Context, password: str) -> None:
    """Analyse password strength and entropy.

    Computes entropy, detects patterns, estimates crack times, and
    checks NIST SP 800-63B compliance.
    """
    engine: CipherEngine = ctx.obj["engine"]
    display: CipherConsoleOutput = ctx.obj["display"]

    result = _run_async(engine.analyze_password(password))

    if ctx.obj["output_format"] == "console":
        raw = result.metadata
        if raw:
            from cipher.core.models import PasswordAnalysis
            pw_result = PasswordAnalysis(**raw)
            display.display_password(pw_result)
        ctx.obj["console"].findings_table(result.findings)
    else:
        _handle_output(ctx, result)


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def frequency(ctx: click.Context, file: str) -> None:
    """Perform frequency analysis on file data.

    Computes byte frequency distribution, chi-squared test, Index of
    Coincidence, and Kasiski examination.
    """
    engine: CipherEngine = ctx.obj["engine"]
    display: CipherConsoleOutput = ctx.obj["display"]

    result = _run_async(engine.analyze_frequency(Path(file)))

    if ctx.obj["output_format"] == "console":
        raw = result.metadata
        if raw:
            from cipher.core.models import FrequencyResult
            freq_result = FrequencyResult(**raw)
            display.display_frequency(freq_result)
        ctx.obj["console"].findings_table(result.findings)
    else:
        _handle_output(ctx, result)


@cli.command("key-strength")
@click.option(
    "--algorithm", "-a",
    required=True,
    help="Algorithm name (e.g. RSA, AES, ECDSA, ChaCha20).",
)
@click.option(
    "--key-size", "-k",
    type=int,
    required=True,
    help="Key size in bits.",
)
@click.pass_context
def key_strength(ctx: click.Context, algorithm: str, key_size: int) -> None:
    """Evaluate cryptographic key strength.

    Assesses the security of a given algorithm and key size against
    NIST recommendations, including quantum resistance estimation.
    """
    engine: CipherEngine = ctx.obj["engine"]
    display: CipherConsoleOutput = ctx.obj["display"]

    result = _run_async(engine.analyze_key_strength(algorithm, key_size))

    if ctx.obj["output_format"] == "console":
        raw = result.metadata
        if raw:
            from cipher.core.models import KeyStrengthResult
            ks_result = KeyStrengthResult(**raw)
            display.display_key_strength(ks_result)
        ctx.obj["console"].findings_table(result.findings)
    else:
        _handle_output(ctx, result)


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def rng(ctx: click.Context, file: str) -> None:
    """Run NIST SP 800-22 statistical tests on file data.

    Tests the randomness quality of the data using seven standard
    statistical tests. Minimum 100 bits of data required.
    """
    engine: CipherEngine = ctx.obj["engine"]
    display: CipherConsoleOutput = ctx.obj["display"]

    result = _run_async(engine.analyze_rng(Path(file)))

    if ctx.obj["output_format"] == "console":
        raw = result.metadata
        if raw:
            from cipher.core.models import RNGSuiteResult
            rng_result = RNGSuiteResult(**raw)
            display.display_rng(rng_result)
        ctx.obj["console"].findings_table(result.findings)
    else:
        _handle_output(ctx, result)


# ===================================================================== #
#  Entry Point
# ===================================================================== #

def main() -> None:
    """Main entry point for the Cipher CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
