"""
Cipher Console Output
======================

Rich-based console output formatters for the Cipher cryptographic
analysis framework. Provides colour-coded displays for entropy analysis,
hash identification, TLS grading, password strength meters, and
statistical test results.

Uses the PhantomCore shared console infrastructure for consistent
styling across all toolkit modules.

References:
    - Rich Library Documentation. https://rich.readthedocs.io/
"""

from __future__ import annotations

from typing import Optional

from rich.bar import Bar
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from shared.console import PhantomConsole
from cipher.core.models import (
    CipherGrade,
    CipherSuiteResult,
    DataType,
    EntropyResult,
    FrequencyResult,
    HashIdentification,
    KeyStrengthResult,
    PasswordAnalysis,
    PasswordStrength,
    RNGSuiteResult,
)


# ===================================================================== #
#  Colour Maps
# ===================================================================== #

_GRADE_COLOURS: dict[str, str] = {
    "A+": "bold bright_green",
    "A": "green",
    "B": "yellow",
    "C": "dark_orange",
    "D": "red",
    "F": "bold white on red",
}

_STRENGTH_COLOURS: dict[str, str] = {
    "very_weak": "bold white on red",
    "weak": "bold red",
    "fair": "bold yellow",
    "strong": "bold green",
    "very_strong": "bold bright_green",
}

_DATA_TYPE_COLOURS: dict[str, str] = {
    "empty_uniform": "dim white",
    "plain_text": "bright_blue",
    "structured_data": "cyan",
    "compressed_text": "yellow",
    "encoded_data": "dark_orange",
    "compressed": "bright_magenta",
    "encrypted_random": "bright_red",
}


class CipherConsoleOutput:
    """Console output formatters for Cipher analysis results.

    Uses Rich tables, panels, and progress bars to display analysis
    results in a visually informative format.

    Usage::

        console = PhantomConsole()
        output = CipherConsoleOutput(console)
        output.display_entropy(entropy_result)
        output.display_hash_id(hash_identifications)
        output.display_tls(tls_result)
        output.display_password(password_result)
    """

    def __init__(self, console: Optional[PhantomConsole] = None) -> None:
        """Initialise the console output formatter.

        Args:
            console: PhantomConsole instance. Creates one if not provided.
        """
        self.console = console or PhantomConsole()
        self._rich = self.console.rich

    # ------------------------------------------------------------------ #
    #  Entropy Display
    # ------------------------------------------------------------------ #

    def display_entropy(self, result: EntropyResult) -> None:
        """Display entropy analysis results with colour-coded bars.

        Shows Shannon, min-entropy, and Renyi values with visual bars,
        data type classification, and a block-level entropy heatmap.

        Args:
            result: EntropyResult from the entropy analyzer.
        """
        self.console.section("Entropy Analysis")

        # Summary panel
        data_colour = _DATA_TYPE_COLOURS.get(result.data_type.value, "white")
        data_label = result.data_type.value.replace("_", " ").title()

        summary_text = Text()
        summary_text.append("Data Size: ", style="bold")
        summary_text.append(f"{result.data_size:,} bytes\n")
        summary_text.append("Unique Bytes: ", style="bold")
        summary_text.append(f"{result.unique_bytes}/256\n")
        summary_text.append("Classification: ", style="bold")
        summary_text.append(data_label, style=data_colour)

        self._rich.print(Panel(summary_text, title="Overview", border_style="cyan"))

        # Entropy values table
        tbl = Table(
            title="Entropy Measures",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )
        tbl.add_column("Measure", style="bold")
        tbl.add_column("Value (bits/byte)", justify="right")
        tbl.add_column("Bar", width=40)
        tbl.add_column("Interpretation")

        # Shannon entropy
        shannon_bar = self._entropy_bar(result.shannon)
        tbl.add_row(
            "Shannon H(X)",
            f"{result.shannon:.4f}",
            shannon_bar,
            self._entropy_interpretation(result.shannon),
        )

        # Min-entropy
        min_bar = self._entropy_bar(result.min_entropy)
        tbl.add_row(
            "Min-Entropy H_inf",
            f"{result.min_entropy:.4f}",
            min_bar,
            "Worst-case guessing difficulty",
        )

        # Renyi entropy (alpha=2)
        renyi_bar = self._entropy_bar(result.renyi)
        tbl.add_row(
            "Renyi H_2 (collision)",
            f"{result.renyi:.4f}",
            renyi_bar,
            "Collision probability measure",
        )

        self._rich.print(tbl)

        # Block entropy heatmap (if available)
        if result.entropy_map and len(result.entropy_map) > 1:
            self._display_entropy_map(result.entropy_map)

    def _display_entropy_map(self, entropy_map: list[float]) -> None:
        """Display a text-based entropy heatmap.

        Uses coloured block characters to represent per-block entropy
        values, providing a visual overview of entropy distribution.

        Args:
            entropy_map: List of per-block entropy values.
        """
        self._rich.print()
        self._rich.print("[bold]Block Entropy Map:[/bold]")

        # Create a visual representation using coloured blocks
        # Each character represents one block
        chars_per_line = 64
        lines: list[Text] = []
        current_line = Text()

        for i, entropy in enumerate(entropy_map):
            if i > 0 and i % chars_per_line == 0:
                lines.append(current_line)
                current_line = Text()

            # Map entropy to colour
            if entropy < 1.0:
                colour = "bright_blue"
                char = "\u2591"  # Light shade
            elif entropy < 3.0:
                colour = "cyan"
                char = "\u2592"  # Medium shade
            elif entropy < 5.0:
                colour = "green"
                char = "\u2592"
            elif entropy < 7.0:
                colour = "yellow"
                char = "\u2593"  # Dark shade
            elif entropy < 7.5:
                colour = "dark_orange"
                char = "\u2593"
            else:
                colour = "red"
                char = "\u2588"  # Full block

            current_line.append(char, style=colour)

        if current_line:
            lines.append(current_line)

        for line in lines:
            self._rich.print(line)

        # Legend
        legend = Text()
        legend.append("  Legend: ", style="dim")
        legend.append("\u2591", style="bright_blue")
        legend.append("=low ", style="dim")
        legend.append("\u2592", style="green")
        legend.append("=medium ", style="dim")
        legend.append("\u2593", style="yellow")
        legend.append("=high ", style="dim")
        legend.append("\u2588", style="red")
        legend.append("=encrypted/random", style="dim")
        self._rich.print(legend)

    @staticmethod
    def _entropy_bar(value: float, max_value: float = 8.0) -> str:
        """Create a text-based entropy bar.

        Args:
            value: Entropy value.
            max_value: Maximum value (8.0 for byte entropy).

        Returns:
            String representation of the bar.
        """
        bar_width = 32
        filled = int((value / max_value) * bar_width)
        filled = max(0, min(bar_width, filled))

        if value < 3.0:
            fill_char = "\u2588"
            colour = "blue"
        elif value < 5.0:
            fill_char = "\u2588"
            colour = "green"
        elif value < 7.0:
            fill_char = "\u2588"
            colour = "yellow"
        elif value < 7.5:
            fill_char = "\u2588"
            colour = "dark_orange"
        else:
            fill_char = "\u2588"
            colour = "red"

        bar = f"[{colour}]{fill_char * filled}[/{colour}]{'.' * (bar_width - filled)}"
        return bar

    @staticmethod
    def _entropy_interpretation(entropy: float) -> str:
        """Provide a human-readable interpretation of an entropy value."""
        if entropy < 1.0:
            return "Empty/uniform (single repeated value)"
        elif entropy < 3.0:
            return "Plain text (natural language)"
        elif entropy < 5.0:
            return "Structured data (XML, JSON)"
        elif entropy < 6.0:
            return "Compressed text"
        elif entropy < 7.0:
            return "Encoded data (Base64, hex)"
        elif entropy < 7.5:
            return "Compressed data"
        else:
            return "Encrypted or random"

    # ------------------------------------------------------------------ #
    #  Hash Identification Display
    # ------------------------------------------------------------------ #

    def display_hash_id(self, results: list[HashIdentification]) -> None:
        """Display hash identification results in a ranked table.

        Args:
            results: List of HashIdentification results.
        """
        self.console.section("Hash Identification")

        for ident in results:
            # Hash properties panel
            props = Text()
            props.append("Hash: ", style="bold")
            props.append(f"{ident.hash_value}\n")
            props.append("Length: ", style="bold")
            props.append(f"{ident.length} characters\n")
            props.append("Charset: ", style="bold")
            props.append(f"{ident.charset}\n")
            if ident.prefix:
                props.append("Prefix: ", style="bold")
                props.append(f"{ident.prefix}\n")
            props.append("Salted: ", style="bold")
            props.append("Yes" if ident.is_salted else "No")

            self._rich.print(Panel(props, title="Hash Properties", border_style="cyan"))

            # Candidate table
            if ident.possible_types:
                tbl = Table(
                    title="Possible Hash Types (ranked by confidence)",
                    border_style="bright_cyan",
                    header_style="bold bright_magenta",
                    show_lines=True,
                )
                tbl.add_column("#", style="dim", width=4, justify="right")
                tbl.add_column("Algorithm", style="bold")
                tbl.add_column("Confidence", justify="right")
                tbl.add_column("Description")
                tbl.add_column("Hashcat", justify="center")
                tbl.add_column("John", justify="center")

                for idx, ht in enumerate(ident.possible_types[:15], start=1):
                    conf_pct = f"{ht.confidence:.0%}"
                    if ht.confidence >= 0.8:
                        conf_style = "bold green"
                    elif ht.confidence >= 0.5:
                        conf_style = "yellow"
                    else:
                        conf_style = "dim"

                    tbl.add_row(
                        str(idx),
                        ht.name,
                        f"[{conf_style}]{conf_pct}[/{conf_style}]",
                        ht.description[:60] + ("..." if len(ht.description) > 60 else ""),
                        str(ht.hashcat_mode) if ht.hashcat_mode is not None else "-",
                        ht.john_format or "-",
                    )

                self._rich.print(tbl)
            else:
                self.console.warning("No matching hash types found.")

    # ------------------------------------------------------------------ #
    #  TLS Display
    # ------------------------------------------------------------------ #

    def display_tls(self, result: CipherSuiteResult) -> None:
        """Display TLS cipher suite analysis with grade badge.

        Args:
            result: CipherSuiteResult from the cipher suite analyzer.
        """
        self.console.section("TLS Analysis")

        # Grade badge
        grade_colour = _GRADE_COLOURS.get(result.grade.value, "white")
        grade_text = Text()
        grade_text.append("  ", style="bold")
        grade_text.append(f" {result.grade.value} ", style=grade_colour)
        grade_text.append(f"  {result.host}:{result.port}", style="bold")

        self._rich.print(Panel(
            grade_text,
            title="TLS Grade",
            border_style=grade_colour.split()[-1] if " " in grade_colour else grade_colour,
        ))

        # Protocol and features
        features = Text()
        features.append("Protocol: ", style="bold")
        features.append(f"{result.protocol}\n")
        features.append("TLS 1.3: ", style="bold")
        features.append(
            "Supported" if result.supports_tls_13 else "Not Supported",
            style="green" if result.supports_tls_13 else "red",
        )
        features.append("\n")
        features.append("Forward Secrecy: ", style="bold")
        features.append(
            "Available" if result.supports_forward_secrecy else "Not Available",
            style="green" if result.supports_forward_secrecy else "red",
        )
        features.append("\n")
        features.append("Weak Ciphers: ", style="bold")
        features.append(
            "Detected" if result.has_weak_ciphers else "None",
            style="red" if result.has_weak_ciphers else "green",
        )

        self._rich.print(Panel(features, title="Features", border_style="cyan"))

        # Cipher suites table
        if result.suites:
            tbl = Table(
                title=f"Cipher Suites ({len(result.suites)})",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
            )
            tbl.add_column("Suite Name", style="bold")
            tbl.add_column("Protocol")
            tbl.add_column("KEX")
            tbl.add_column("Cipher")
            tbl.add_column("Bits", justify="right")
            tbl.add_column("Grade", justify="center")

            for suite in result.suites:
                suite_grade_colour = _GRADE_COLOURS.get(suite.grade.value, "white")
                tbl.add_row(
                    suite.name,
                    suite.protocol,
                    suite.key_exchange,
                    suite.encryption,
                    str(suite.bits),
                    f"[{suite_grade_colour}]{suite.grade.value}[/{suite_grade_colour}]",
                )

            self._rich.print(tbl)

        # Certificate info
        if result.certificate:
            cert = result.certificate
            cert_text = Text()
            cert_text.append("Subject: ", style="bold")
            cert_text.append(f"{cert.subject}\n")
            cert_text.append("Issuer: ", style="bold")
            cert_text.append(f"{cert.issuer}\n")
            cert_text.append("Valid Until: ", style="bold")
            cert_text.append(f"{cert.not_after}\n")
            if cert.san:
                cert_text.append("SANs: ", style="bold")
                cert_text.append(", ".join(cert.san[:5]))

            self._rich.print(Panel(cert_text, title="Certificate", border_style="cyan"))

        # Recommendations
        if result.recommendations:
            self._rich.print()
            self._rich.print("[bold]Recommendations:[/bold]")
            for rec in result.recommendations:
                self._rich.print(f"  [bright_cyan]\u2022[/bright_cyan] {rec}")

    # ------------------------------------------------------------------ #
    #  Password Display
    # ------------------------------------------------------------------ #

    def display_password(self, result: PasswordAnalysis) -> None:
        """Display password strength analysis with visual meter.

        Args:
            result: PasswordAnalysis from the password analyzer.
        """
        self.console.section("Password Analysis")

        # Strength meter
        strength_colour = _STRENGTH_COLOURS.get(result.strength.value, "white")
        strength_label = result.strength.value.replace("_", " ").upper()

        # Visual meter (0-100)
        meter_width = 40
        filled = int((result.score / 100) * meter_width)
        filled = max(0, min(meter_width, filled))

        meter = Text()
        meter.append("Score: ", style="bold")
        meter.append(f"{result.score}/100  ")
        meter.append("[", style="dim")

        # Colour segments
        for i in range(meter_width):
            if i < filled:
                if i < meter_width * 0.25:
                    meter.append("\u2588", style="red")
                elif i < meter_width * 0.50:
                    meter.append("\u2588", style="yellow")
                elif i < meter_width * 0.75:
                    meter.append("\u2588", style="green")
                else:
                    meter.append("\u2588", style="bright_green")
            else:
                meter.append("\u2591", style="dim")

        meter.append("]", style="dim")
        meter.append(f"  [{strength_colour}]{strength_label}[/{strength_colour}]")

        self._rich.print(Panel(meter, title="Strength Meter", border_style="cyan"))

        # Details table
        tbl = Table(
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
        )
        tbl.add_column("Property", style="bold")
        tbl.add_column("Value")

        tbl.add_row("Password", result.password_masked)
        tbl.add_row("Length", str(result.length))
        tbl.add_row("Entropy", f"{result.entropy:.2f} bits")
        tbl.add_row("Character Pool", str(result.char_pool_size))
        tbl.add_row("NIST Compliant", "Yes" if result.nist_compliant else "No")

        self._rich.print(tbl)

        # Crack time estimates
        if result.crack_time_estimates:
            crack_tbl = Table(
                title="Crack Time Estimates",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
            )
            crack_tbl.add_column("Attack Scenario", style="bold")
            crack_tbl.add_column("Speed", justify="right")
            crack_tbl.add_column("Estimated Time", justify="right")

            for estimate in result.crack_time_estimates:
                crack_tbl.add_row(
                    estimate.scenario,
                    f"{estimate.guesses_per_second:.0e} g/s",
                    estimate.display,
                )

            self._rich.print(crack_tbl)

        # Patterns detected
        if result.patterns_detected:
            self._rich.print()
            self._rich.print("[bold]Patterns Detected:[/bold]")
            for pattern in result.patterns_detected:
                self._rich.print(
                    f"  [yellow]\u26A0[/yellow] [{pattern.pattern_type}] "
                    f"'{pattern.value}' at position {pattern.position} "
                    f"(penalty: -{pattern.penalty:.1f} bits)"
                )

        # Suggestions
        if result.suggestions:
            self._rich.print()
            self._rich.print("[bold]Suggestions:[/bold]")
            for suggestion in result.suggestions:
                self._rich.print(
                    f"  [bright_cyan]\u2022[/bright_cyan] {suggestion}"
                )

    # ------------------------------------------------------------------ #
    #  Frequency Analysis Display
    # ------------------------------------------------------------------ #

    def display_frequency(self, result: FrequencyResult) -> None:
        """Display frequency analysis results.

        Args:
            result: FrequencyResult from the frequency analyzer.
        """
        self.console.section("Frequency Analysis")

        # Summary
        summary = Text()
        summary.append("Bytes Analysed: ", style="bold")
        summary.append(f"{result.byte_count:,}\n")
        summary.append("Chi-Squared: ", style="bold")
        summary.append(f"{result.chi_squared:.4f}")
        summary.append(f" (p={result.chi_squared_p_value:.6f})\n")
        summary.append("Index of Coincidence: ", style="bold")
        summary.append(f"{result.ic:.6f}\n")
        summary.append("Likely Cipher Type: ", style="bold")
        summary.append(result.likely_cipher_type.value.replace("_", " ").title())

        self._rich.print(Panel(summary, title="Summary", border_style="cyan"))

        # Most common bytes
        if result.most_common_bytes:
            tbl = Table(
                title="Most Common Bytes",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
            )
            tbl.add_column("Byte (hex)", justify="center")
            tbl.add_column("Byte (dec)", justify="center")
            tbl.add_column("Char", justify="center")
            tbl.add_column("Frequency", justify="right")

            for byte_val, freq in result.most_common_bytes:
                char = chr(byte_val) if 32 <= byte_val < 127 else "."
                tbl.add_row(
                    f"0x{byte_val:02x}",
                    str(byte_val),
                    char,
                    f"{freq:.6f}",
                )

            self._rich.print(tbl)

        # Kasiski key lengths
        if result.kasiski_key_lengths:
            self._rich.print()
            self._rich.print("[bold]Kasiski Examination - Likely Key Lengths:[/bold]")
            for kl in result.kasiski_key_lengths[:10]:
                self._rich.print(f"  [bright_cyan]\u2022[/bright_cyan] {kl}")

    # ------------------------------------------------------------------ #
    #  Key Strength Display
    # ------------------------------------------------------------------ #

    def display_key_strength(self, result: KeyStrengthResult) -> None:
        """Display key strength analysis results.

        Args:
            result: KeyStrengthResult from the key strength analyzer.
        """
        self.console.section("Key Strength")

        status_colours = {
            "strong": "bold bright_green",
            "acceptable": "green",
            "legacy": "yellow",
            "deprecated": "red",
            "weak": "bold white on red",
            "unknown": "dim",
        }
        status_colour = status_colours.get(result.status, "white")

        summary = Text()
        summary.append(f"{result.algorithm}-{result.key_size}\n", style="bold bright_cyan")
        summary.append("Status: ", style="bold")
        summary.append(
            result.status.upper(),
            style=status_colour,
        )
        summary.append(f"\nEffective Strength: ", style="bold")
        summary.append(f"{result.effective_strength} bits\n")
        summary.append("Quantum-Safe: ", style="bold")
        summary.append(
            "Yes" if result.quantum_safe else "No",
            style="green" if result.quantum_safe else "red",
        )
        if not result.quantum_safe:
            summary.append(f" (post-quantum: {result.quantum_strength} bits)")
        summary.append(f"\nNIST Level: ", style="bold")
        summary.append(str(result.nist_level) if result.nist_level else "N/A")

        self._rich.print(Panel(summary, title="Key Strength Assessment", border_style="cyan"))

        # Recommendation
        if result.recommendation:
            self._rich.print()
            self._rich.print(f"[bold]Recommendation:[/bold] {result.recommendation}")

    # ------------------------------------------------------------------ #
    #  RNG Test Display
    # ------------------------------------------------------------------ #

    def display_rng(self, result: RNGSuiteResult) -> None:
        """Display RNG statistical test results.

        Args:
            result: RNGSuiteResult from the RNG tester.
        """
        self.console.section("RNG Statistical Tests")

        # Overall result
        overall_colour = "bold bright_green" if result.overall_pass else "bold red"
        overall_text = "PASS" if result.overall_pass else "FAIL"

        summary = Text()
        summary.append("Overall: ", style="bold")
        summary.append(overall_text, style=overall_colour)
        summary.append(f"\nTests: {result.tests_passed}/{result.total_tests} passed\n")
        summary.append(f"Data Size: {result.data_size_bits:,} bits\n")
        summary.append(result.assessment)

        self._rich.print(Panel(summary, title="RNG Test Suite Results", border_style="cyan"))

        # Individual test results
        if result.tests:
            tbl = Table(
                title="Individual Test Results (NIST SP 800-22)",
                border_style="bright_cyan",
                header_style="bold bright_magenta",
                show_lines=True,
            )
            tbl.add_column("#", style="dim", width=3, justify="right")
            tbl.add_column("Test Name", style="bold")
            tbl.add_column("p-value", justify="right")
            tbl.add_column("Statistic", justify="right")
            tbl.add_column("Result", justify="center")

            for idx, test in enumerate(result.tests, start=1):
                result_colour = "green" if test.passed else "red"
                result_text = "PASS" if test.passed else "FAIL"

                tbl.add_row(
                    str(idx),
                    test.test_name,
                    f"{test.p_value:.6f}",
                    f"{test.statistic:.6f}",
                    f"[{result_colour}]{result_text}[/{result_colour}]",
                )

            self._rich.print(tbl)
