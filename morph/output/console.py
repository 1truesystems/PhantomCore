"""
Morph Console Output
=====================

Rich-powered terminal display for Morph binary analysis results.
Produces colour-coded tables, entropy visualisations, import highlights,
and shellcode detection summaries.

Uses the PhantomConsole abstraction for consistent styling across
all PhantomCore modules.

References:
    - Rich library: https://github.com/Textualize/rich
"""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from shared.console import PhantomConsole

from morph.core.models import (
    BinaryAnalysisResult,
    BinaryInfo,
    CFGResult,
    ImportCategory,
    ImportInfo,
    SectionInfo,
    ShellcodeIndicator,
    StringCategory,
    StringResult,
)


# ---------------------------------------------------------------------------
# Severity colour helpers
# ---------------------------------------------------------------------------

_ENTROPY_COLOUR_THRESHOLDS: list[tuple[float, str]] = [
    (1.0, "bright_green"),
    (4.5, "green"),
    (6.5, "yellow"),
    (7.0, "bright_yellow"),
    (7.5, "red"),
    (8.1, "bright_red"),
]

_CATEGORY_COLOURS: dict[str, str] = {
    ImportCategory.PROCESS_INJECTION.value: "bright_red",
    ImportCategory.CODE_INJECTION.value: "red",
    ImportCategory.KEYLOGGING.value: "bright_red",
    ImportCategory.ANTI_DEBUG.value: "yellow",
    ImportCategory.ANTI_VM.value: "yellow",
    ImportCategory.FILE_OPERATIONS.value: "bright_cyan",
    ImportCategory.NETWORK.value: "bright_magenta",
    ImportCategory.REGISTRY.value: "bright_yellow",
    ImportCategory.CRYPTO.value: "bright_blue",
    ImportCategory.PRIVILEGE.value: "red",
    ImportCategory.GENERAL.value: "dim",
}

_STRING_CATEGORY_COLOURS: dict[str, str] = {
    StringCategory.URL.value: "bright_cyan",
    StringCategory.IP_ADDRESS.value: "bright_magenta",
    StringCategory.FILE_PATH.value: "bright_blue",
    StringCategory.REGISTRY.value: "bright_yellow",
    StringCategory.EMAIL.value: "bright_cyan",
    StringCategory.CRYPTO.value: "bright_red",
    StringCategory.SUSPICIOUS.value: "bright_red",
    StringCategory.DOMAIN.value: "bright_magenta",
    StringCategory.BASE64.value: "yellow",
    StringCategory.GENERAL.value: "dim",
}


def _entropy_colour(entropy: float) -> str:
    """Return a Rich colour name for the given entropy value."""
    for threshold, colour in _ENTROPY_COLOUR_THRESHOLDS:
        if entropy < threshold:
            return colour
    return "bright_red"


def _entropy_bar(entropy: float, width: int = 20) -> str:
    """Render a text-based entropy bar.

    Args:
        entropy: Entropy value in [0.0, 8.0].
        width: Character width of the bar.

    Returns:
        Coloured bar string with Rich markup.
    """
    fraction = min(entropy / 8.0, 1.0)
    filled = int(fraction * width)
    empty = width - filled
    colour = _entropy_colour(entropy)
    bar = f"[{colour}]{'#' * filled}[/{colour}][dim]{'.' * empty}[/dim]"
    return bar


def _risk_colour(score: float) -> str:
    """Return a colour for the overall risk score."""
    if score >= 75.0:
        return "bright_red"
    elif score >= 50.0:
        return "red"
    elif score >= 25.0:
        return "yellow"
    elif score >= 10.0:
        return "bright_cyan"
    return "bright_green"


# ---------------------------------------------------------------------------
# MorphConsoleOutput
# ---------------------------------------------------------------------------

class MorphConsoleOutput:
    """Rich terminal display for Morph binary analysis results.

    Renders comprehensive, colour-coded output including binary metadata,
    section tables with entropy bars, categorised strings, import analysis,
    shellcode indicators, and CFG statistics.

    Usage::

        output = MorphConsoleOutput()
        output.display(analysis_result)
    """

    def __init__(self, console: PhantomConsole | None = None) -> None:
        """Initialise the output renderer.

        Args:
            console: Optional PhantomConsole instance.  A new one is
                     created if not provided.
        """
        self._console: PhantomConsole = console or PhantomConsole()

    def display(self, result: BinaryAnalysisResult) -> None:
        """Display the complete analysis result.

        Args:
            result: The BinaryAnalysisResult to render.
        """
        self._console.banner()
        self._console.section("MORPH -- Binary Analysis Framework")
        self._console.section(
            "Binary Analysis Results"
        )

        self.display_header(result.info)
        self.display_risk_score(result.risk_score, result.packer_detected)

        if result.sections:
            self.display_sections(result.sections)

        if result.imports:
            self.display_imports(result.imports)

        if result.strings:
            self.display_strings(result.strings)

        if result.shellcode_indicators:
            self.display_shellcode(result.shellcode_indicators)

        if result.cfg:
            self.display_cfg_summary(result.cfg)

        if result.symbols:
            self.display_symbols_summary(result.symbols)

        self._console.divider()

    def display_header(self, info: BinaryInfo) -> None:
        """Display binary metadata panel.

        Args:
            info: BinaryInfo model.
        """
        lines: list[str] = [
            f"[bold]File:[/bold]        {info.path}",
            f"[bold]Size:[/bold]         {info.size:,} bytes ({info.size / 1024:.1f} KiB)",
            f"[bold]Format:[/bold]    {info.format.value.upper()}",
            f"[bold]Arch:[/bold] {info.arch} ({info.bits}-bit, {info.endian})",
            f"[bold]Entry Point:[/bold]          0x{info.entry_point:x}",
        ]
        if info.md5:
            lines.append(f"[bold]MD5:[/bold]                 {info.md5}")
        if info.sha256:
            lines.append(f"[bold]SHA-256:[/bold]             {info.sha256}")

        panel = Panel(
            "\n".join(lines),
            title="[bold bright_cyan]Binary Information[/bold bright_cyan]",
            border_style="bright_cyan",
            padding=(1, 2),
        )
        self._console.rich.print(panel)
        self._console.blank()

    def display_risk_score(self, score: float, packer: str) -> None:
        """Display the overall risk score.

        Args:
            score: Risk score in [0.0, 100.0].
            packer: Detected packer name, or empty string.
        """
        colour = _risk_colour(score)
        bar_width = 40
        filled = int(score / 100.0 * bar_width)
        bar = f"[{colour}]{'#' * filled}[/{colour}][dim]{'.' * (bar_width - filled)}[/dim]"

        lines: list[str] = [
            f"[bold]Risk Score:[/bold]  [{colour}]{score:.1f}/100.0[/{colour}]",
            f"  {bar}",
        ]
        if packer:
            lines.append(f"[bold bright_red]Packer Detected:[/bold bright_red] {packer}")

        panel = Panel(
            "\n".join(lines),
            title="[bold bright_cyan]Risk Assessment[/bold bright_cyan]",
            border_style=colour,
            padding=(0, 2),
        )
        self._console.rich.print(panel)
        self._console.blank()

    def display_sections(self, sections: list[SectionInfo]) -> None:
        """Display section table with entropy visualisation.

        Args:
            sections: List of SectionInfo models with entropy values.
        """
        self._console.section("Sections")

        tbl = Table(
            title="",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )
        tbl.add_column("#", style="dim", width=4, justify="right")
        tbl.add_column("Name", style="bold", min_width=12)
        tbl.add_column("Offset", justify="right")
        tbl.add_column("Size", justify="right")
        tbl.add_column("VAddr", justify="right")
        tbl.add_column("Flags")
        tbl.add_column("Entropy", justify="right")
        tbl.add_column("Entropy Bar", min_width=22)
        tbl.add_column("Type")

        for i, sec in enumerate(sections, 1):
            ent_colour = _entropy_colour(sec.entropy)
            tbl.add_row(
                str(i),
                sec.name or "<unnamed>",
                f"0x{sec.offset:x}",
                f"{sec.size:,}",
                f"0x{sec.vaddr:x}",
                sec.flags,
                f"[{ent_colour}]{sec.entropy:.3f}[/{ent_colour}]",
                _entropy_bar(sec.entropy),
                sec.type_guess,
            )

        self._console.rich.print(tbl)
        self._console.blank()

    def display_strings(
        self,
        strings: list[StringResult],
        max_display: int = 100,
    ) -> None:
        """Display categorised extracted strings.

        Args:
            strings: List of StringResult models.
            max_display: Maximum number of strings to display.
        """
        self._console.section("Strings")

        # Summary by category
        category_counts: dict[str, int] = {}
        for s in strings:
            cat = s.category.value if isinstance(s.category, StringCategory) else str(s.category)
            category_counts[cat] = category_counts.get(cat, 0) + 1

        summary_parts: list[str] = [
            f"[bold]Total:[/bold] {len(strings)}"
        ]
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            colour = _STRING_CATEGORY_COLOURS.get(cat, "dim")
            summary_parts.append(f"[{colour}]{cat}: {count}[/{colour}]")

        self._console.rich.print("  ".join(summary_parts))
        self._console.blank()

        # Show non-general strings first, then general
        interesting = [s for s in strings if s.category != StringCategory.GENERAL]
        general = [s for s in strings if s.category == StringCategory.GENERAL]

        display_list = interesting[:max_display]
        remaining = max_display - len(display_list)
        if remaining > 0:
            display_list.extend(general[:remaining])

        tbl = Table(
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=False,
            padding=(0, 1),
        )
        tbl.add_column("Offset", style="dim", justify="right", width=10)
        tbl.add_column("Enc", width=10)
        tbl.add_column("Category", width=14)
        tbl.add_column("Value", ratio=1, overflow="ellipsis", no_wrap=True)

        for s in display_list:
            cat = s.category.value if isinstance(s.category, StringCategory) else str(s.category)
            colour = _STRING_CATEGORY_COLOURS.get(cat, "dim")
            # Truncate very long strings for display
            display_val = s.value[:120] + "..." if len(s.value) > 120 else s.value
            tbl.add_row(
                f"0x{s.offset:x}",
                s.encoding,
                f"[{colour}]{cat}[/{colour}]",
                display_val,
            )

        self._console.rich.print(tbl)

        if len(strings) > max_display:
            self._console.info(
                f"Showing {max_display} of {len(strings)} strings. "
                f"Use --output to export all strings to a report."
            )
        self._console.blank()

    def display_imports(self, imports: list[ImportInfo]) -> None:
        """Display import table with category highlights.

        Args:
            imports: List of ImportInfo models.
        """
        self._console.section("Imports")

        # Summary
        category_counts: dict[str, int] = {}
        for imp in imports:
            cat = imp.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        summary_parts: list[str] = [f"[bold]Total:[/bold] {len(imports)}"]
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            colour = _CATEGORY_COLOURS.get(cat, "dim")
            summary_parts.append(f"[{colour}]{cat}: {count}[/{colour}]")

        self._console.rich.print("  ".join(summary_parts))
        self._console.blank()

        # Only show non-GENERAL imports in the table (to reduce noise)
        interesting_imports = [
            imp for imp in imports
            if imp.category != ImportCategory.GENERAL
        ]

        if not interesting_imports:
            self._console.info("No suspicious imports detected.")
            self._console.blank()
            return

        tbl = Table(
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=False,
            padding=(0, 1),
        )
        tbl.add_column("Library", style="bold", min_width=16)
        tbl.add_column("Function", min_width=24)
        tbl.add_column("Category", min_width=18)
        tbl.add_column("Address", justify="right", width=12)

        for imp in interesting_imports[:200]:
            cat = imp.category.value
            colour = _CATEGORY_COLOURS.get(cat, "dim")
            tbl.add_row(
                imp.library,
                imp.function,
                f"[{colour}]{cat}[/{colour}]",
                f"0x{imp.address:x}" if imp.address else "-",
            )

        self._console.rich.print(tbl)
        self._console.blank()

    def display_shellcode(self, indicators: list[ShellcodeIndicator]) -> None:
        """Display shellcode detection results.

        Args:
            indicators: List of ShellcodeIndicator models.
        """
        self._console.section("Shellcode Indicators")

        if not indicators:
            self._console.success("No shellcode indicators detected.")
            self._console.blank()
            return

        tbl = Table(
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )
        tbl.add_column("#", style="dim", width=4, justify="right")
        tbl.add_column("Offset", justify="right", width=12)
        tbl.add_column("Pattern", min_width=24)
        tbl.add_column("Confidence", justify="right", width=12)
        tbl.add_column("Description", ratio=1)

        for i, ind in enumerate(indicators, 1):
            conf = ind.confidence
            if conf >= 0.8:
                conf_colour = "bright_red"
            elif conf >= 0.6:
                conf_colour = "yellow"
            else:
                conf_colour = "dim"

            tbl.add_row(
                str(i),
                f"0x{ind.offset:x}",
                ind.pattern_name,
                f"[{conf_colour}]{conf:.0%}[/{conf_colour}]",
                ind.description[:200],
            )

        self._console.rich.print(tbl)
        self._console.blank()

    def display_cfg_summary(self, cfg: CFGResult) -> None:
        """Display Control Flow Graph statistics.

        Args:
            cfg: CFGResult model.
        """
        self._console.section(
            "Control Flow Graph"
        )

        lines: list[str] = [
            f"[bold]Basic Blocks:[/bold]         {len(cfg.blocks)}",
            f"[bold]Edges:[/bold]                {len(cfg.edges)}",
            f"[bold]Cyclomatic Complexity:[/bold]  {cfg.cyclomatic_complexity}",
            f"[bold]Functions:[/bold]           {len(cfg.entry_points)}",
        ]

        # Complexity assessment
        cc = cfg.cyclomatic_complexity
        if cc <= 10:
            complexity_label = "[bright_green]Simple[/bright_green]"
        elif cc <= 20:
            complexity_label = "[yellow]Moderate[/yellow]"
        elif cc <= 50:
            complexity_label = "[bright_yellow]Complex[/bright_yellow]"
        else:
            complexity_label = "[bright_red]Very Complex[/bright_red]"

        lines.append(f"[bold]Complexity:[/bold]   {complexity_label}")

        panel = Panel(
            "\n".join(lines),
            title="[bold bright_cyan]CFG Statistics[/bold bright_cyan]",
            border_style="bright_cyan",
            padding=(1, 2),
        )
        self._console.rich.print(panel)
        self._console.blank()

    def display_symbols_summary(
        self,
        symbols: list[Any],
        max_display: int = 30,
    ) -> None:
        """Display a summary of symbols.

        Args:
            symbols: List of SymbolInfo models.
            max_display: Maximum symbols to show.
        """
        if not symbols:
            return

        self._console.section("Symbols")
        self._console.info(f"Total symbols: {len(symbols)}")

        # Show only named, non-trivial symbols
        named = [s for s in symbols if getattr(s, "name", "") and getattr(s, "name", "") != ""]
        if not named:
            self._console.blank()
            return

        tbl = Table(
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=False,
            padding=(0, 1),
        )
        tbl.add_column("Name", min_width=30)
        tbl.add_column("Value", justify="right", width=16)
        tbl.add_column("Type", width=10)
        tbl.add_column("Bind", width=10)
        tbl.add_column("Section", width=12)

        for sym in named[:max_display]:
            tbl.add_row(
                str(getattr(sym, "name", "")),
                f"0x{getattr(sym, 'value', 0):x}",
                str(getattr(sym, "type", "")),
                str(getattr(sym, "bind", "")),
                str(getattr(sym, "section", "")),
            )

        self._console.rich.print(tbl)
        if len(named) > max_display:
            self._console.info(f"Showing {max_display} of {len(named)} named symbols.")
        self._console.blank()
