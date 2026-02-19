"""
PhantomCore Console Interface
==============================

Rich-powered console abstraction providing a unified, Georgian-localised
presentation layer for every PhantomCore module.

The class wraps :class:`rich.console.Console` and adds convenience methods
for banners, section headers, severity-coloured messages, progress bars,
tables, and status spinners -- all with consistent styling.

References:
    - Rich library: https://github.com/Textualize/rich
    - Unicode CLDR Georgian locale data.
"""

from __future__ import annotations

import datetime as _dt
from contextlib import contextmanager
from typing import Any, Generator, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TaskProgressColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.style import Style
from rich.align import Align

# ---------------------------------------------------------------------------
# Theme -- consistent palette across all PhantomCore output
# ---------------------------------------------------------------------------
_PHANTOM_THEME = Theme(
    {
        "phantom.banner": "bold bright_cyan",
        "phantom.section": "bold bright_magenta",
        "phantom.success": "bold green",
        "phantom.warning": "bold yellow",
        "phantom.error": "bold red",
        "phantom.info": "bold bright_blue",
        "phantom.dim": "dim white",
        "phantom.highlight": "bold bright_white",
        "phantom.critical": "bold white on red",
        "phantom.high": "bold red",
        "phantom.medium": "bold yellow",
        "phantom.low": "bold bright_cyan",
        "phantom.informational": "bold bright_blue",
        "phantom.label_ka": "bold bright_green",
        "phantom.label_en": "dim italic bright_white",
    }
)

# ---------------------------------------------------------------------------
# ASCII banner art
# ---------------------------------------------------------------------------
_BANNER_ART = r"""
[bright_cyan]
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bright_cyan][bright_magenta]
   ██████╗ ██████╗ ██████╗ ███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██║     ██║   ██║██████╔╝█████╗
  ██║     ██║   ██║██╔══██╗██╔══╝
  ╚██████╗╚██████╔╝██║  ██║███████╗
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
[/bright_magenta]"""

_TAGLINE_KA = "Cybersecurity Educational Toolkit"
_TAGLINE_EN = "Cybersecurity Educational Toolkit"


class PhantomConsole:
    """Unified console interface for all PhantomCore modules.

    Wraps :pyclass:`rich.console.Console` with Georgian-localised helpers
    for every presentation need the toolkit has.

    Usage::

        con = PhantomConsole()
        con.banner()
        con.section("Scan Results")
        con.success("Scan complete")
    """

    # ------------------------------------------------------------------ #
    #  Construction
    # ------------------------------------------------------------------ #

    def __init__(self, *, quiet: bool = False, record: bool = False) -> None:
        """Initialise the console.

        Args:
            quiet:  Suppress all output (useful in library / test mode).
            record: Enable Rich recording for SVG / HTML export.
        """
        self._console = Console(
            theme=_PHANTOM_THEME,
            quiet=quiet,
            record=record,
            highlight=False,
        )

    # ------------------------------------------------------------------ #
    #  Properties
    # ------------------------------------------------------------------ #

    @property
    def rich(self) -> Console:
        """Direct access to the underlying Rich Console instance."""
        return self._console

    # ------------------------------------------------------------------ #
    #  Banner
    # ------------------------------------------------------------------ #

    def banner(self, version: str = "1.0.0") -> None:
        """Display the PhantomCore ASCII-art banner.

        Args:
            version: Version string shown beneath the logo.
        """
        now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subtitle = (
            f"[phantom.label_ka]{_TAGLINE_KA}[/phantom.label_ka]\n"
            f"[phantom.label_en]{_TAGLINE_EN}[/phantom.label_en]\n"
            f"[phantom.dim]Version: {version}  |  {now}[/phantom.dim]"
        )
        panel = Panel(
            Align.center(Text.from_markup(_BANNER_ART + "\n" + subtitle)),
            border_style="bright_cyan",
            padding=(1, 2),
        )
        self._console.print(panel)

    # ------------------------------------------------------------------ #
    #  Section header
    # ------------------------------------------------------------------ #

    def section(self, title: str) -> None:
        """Print a prominent section header.

        Args:
            title: Section title (may contain Georgian + English text).
        """
        rule_text = f"  {title}  "
        self._console.rule(
            rule_text,
            style="phantom.section",
            characters="\u2500",
        )
        self._console.print()

    # ------------------------------------------------------------------ #
    #  Message helpers (severity-coloured)
    # ------------------------------------------------------------------ #

    def success(self, message: str) -> None:
        """Print a success message.

        Prefix: Success.
        """
        self._console.print(
            f"[phantom.success][\u2714] SUCCESS:[/phantom.success] {message}"
        )

    def warning(self, message: str) -> None:
        """Print a warning message.

        Prefix: Warning.
        """
        self._console.print(
            f"[phantom.warning][\u26A0] WARNING:[/phantom.warning] {message}"
        )

    def error(self, message: str) -> None:
        """Print an error message.

        Prefix: Error.
        """
        self._console.print(
            f"[phantom.error][\u2718] ERROR:[/phantom.error] {message}"
        )

    def info(self, message: str) -> None:
        """Print an informational message.

        Prefix: Info.
        """
        self._console.print(
            f"[phantom.info][\u2139] INFO:[/phantom.info] {message}"
        )

    def critical(self, message: str) -> None:
        """Print a critical-severity message with high-visibility styling.

        Prefix: Critical.
        """
        self._console.print(
            f"[phantom.critical][\u2620] CRITICAL: {message}[/phantom.critical]"
        )

    # ------------------------------------------------------------------ #
    #  Progress bar
    # ------------------------------------------------------------------ #

    @contextmanager
    def progress(
        self,
        description: str = "Processing...",
        total: float | None = None,
    ) -> Generator[Progress, None, None]:
        """Context-manager wrapping a Rich progress bar.

        Args:
            description: Description shown beside the bar.
            total: Total number of steps (``None`` for indeterminate).

        Yields:
            A :class:`rich.progress.Progress` instance. Call
            ``progress.update(task, advance=1)`` inside the loop.

        Example::

            with con.progress("Analyzing", total=100) as (prog, task):
                for i in range(100):
                    prog.update(task, advance=1)
        """
        progress_bar = Progress(
            SpinnerColumn("dots", style="bright_cyan"),
            TextColumn("[phantom.info]{task.description}"),
            BarColumn(bar_width=40, style="bright_cyan", complete_style="bright_green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self._console,
            transient=False,
        )
        with progress_bar:
            task_id = progress_bar.add_task(description, total=total)
            # Yield both progress and task_id as a tuple for convenience
            yield progress_bar  # type: ignore[misc]
            # Ensure the bar reaches 100 % if total was specified
            if total is not None:
                progress_bar.update(task_id, completed=total)

    def progress_task(
        self,
        description: str = "Processing...",
        total: float | None = None,
    ) -> tuple[Progress, int]:
        """Create a progress bar and return ``(progress, task_id)``.

        Unlike :meth:`progress` (a context manager), this gives the caller
        full control over the lifecycle.  The caller must call
        ``progress.stop()`` when finished.
        """
        progress_bar = Progress(
            SpinnerColumn("dots", style="bright_cyan"),
            TextColumn("[phantom.info]{task.description}"),
            BarColumn(bar_width=40, style="bright_cyan", complete_style="bright_green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self._console,
            transient=False,
        )
        task_id = progress_bar.add_task(description, total=total)
        progress_bar.start()
        return progress_bar, task_id

    # ------------------------------------------------------------------ #
    #  Table display
    # ------------------------------------------------------------------ #

    def table(
        self,
        title: str,
        columns: Sequence[str],
        rows: Sequence[Sequence[Any]],
        *,
        caption: str | None = None,
        styles: Sequence[str] | None = None,
    ) -> None:
        """Render a styled Rich table.

        Args:
            title:    Table title.
            columns:  Column header labels.
            rows:     Iterable of row tuples; each element is stringified.
            caption:  Optional footer caption.
            styles:   Optional per-column Rich style strings.
        """
        tbl = Table(
            title=title,
            caption=caption,
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )
        for idx, col_name in enumerate(columns):
            style = styles[idx] if styles and idx < len(styles) else ""
            tbl.add_column(col_name, style=style)

        for row in rows:
            tbl.add_row(*(str(cell) for cell in row))

        self._console.print(tbl)

    def findings_table(
        self,
        findings: Sequence[Any],
    ) -> None:
        """Render a findings table with automatic severity colouring.

        Expects objects with ``severity``, ``title``, and ``description``
        attributes (e.g., :class:`~phantomcore.shared.models.Finding`).
        """
        severity_style_map: dict[str, str] = {
            "CRITICAL": "phantom.critical",
            "HIGH": "phantom.high",
            "MEDIUM": "phantom.medium",
            "LOW": "phantom.low",
            "INFO": "phantom.informational",
        }

        tbl = Table(
            title="Findings",
            border_style="bright_cyan",
            header_style="bold bright_magenta",
            show_lines=True,
            padding=(0, 1),
        )
        tbl.add_column("#", style="dim", width=4, justify="right")
        tbl.add_column("Severity", width=12)
        tbl.add_column("Title")
        tbl.add_column("Description", ratio=2)

        for idx, finding in enumerate(findings, start=1):
            sev = getattr(finding, "severity", "INFO")
            sev_name = sev.value if hasattr(sev, "value") else str(sev).upper()
            sev_style = severity_style_map.get(sev_name, "")
            sev_cell = (
                f"[{sev_style}]{sev_name}[/{sev_style}]"
                if sev_style
                else sev_name
            )
            tbl.add_row(
                str(idx),
                sev_cell,
                str(getattr(finding, "title", "")),
                str(getattr(finding, "description", "")),
            )

        self._console.print(tbl)

    # ------------------------------------------------------------------ #
    #  Status spinner
    # ------------------------------------------------------------------ #

    @contextmanager
    def status(
        self, message: str = "Working..."
    ) -> Generator[Any, None, None]:
        """Context-manager showing a spinner with a status message.

        Args:
            message: Text displayed next to the spinner.

        Example::

            with con.status("Resolving DNS..."):
                result = await resolve(domain)
        """
        with self._console.status(
            f"[phantom.info]{message}[/phantom.info]",
            spinner="dots",
            spinner_style="bright_cyan",
        ) as status_obj:
            yield status_obj

    # ------------------------------------------------------------------ #
    #  Utility
    # ------------------------------------------------------------------ #

    def print(self, *args: Any, **kwargs: Any) -> None:
        """Proxy to :meth:`rich.console.Console.print`."""
        self._console.print(*args, **kwargs)

    def blank(self, count: int = 1) -> None:
        """Print *count* blank lines."""
        for _ in range(count):
            self._console.print()

    def divider(self, style: str = "dim") -> None:
        """Print a thin horizontal rule."""
        self._console.rule(style=style)

    def export_html(self) -> str:
        """Export recorded console output as HTML (requires ``record=True``)."""
        return self._console.export_html()

    def export_svg(self, title: str = "PhantomCore") -> str:
        """Export recorded console output as SVG (requires ``record=True``)."""
        return self._console.export_svg(title=title)
