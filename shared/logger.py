"""
PhantomCore Structured Logger
==============================

Provides :class:`PhantomLogger`, a structured logging facade that emits
both human-friendly Rich console output and machine-parseable JSON logs
to rotating log files.

Design follows structured-logging best practices for observability:

References:
    - Turnbull, J. (2014). The Art of Monitoring. James Turnbull.
    - Python logging HOWTO. https://docs.python.org/3/howto/logging.html
    - Rich library. https://github.com/Textualize/rich
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Rich theme consistent with PhantomConsole colour palette
# ---------------------------------------------------------------------------
_LOG_THEME = Theme(
    {
        "log.level.debug": "dim cyan",
        "log.level.info": "bold bright_blue",
        "log.level.warning": "bold yellow",
        "log.level.error": "bold red",
        "log.level.critical": "bold white on red",
    }
)


# ========================== JSON Formatter =================================


class _JSONFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object.

    Output fields::

        {
          "timestamp": "...",
          "level": "INFO",
          "logger": "phantomcore.spectra",
          "message": "...",
          "tool_name": "spectra",
          "operation": "entropy_analysis",
          "extra": { ... },
          "exc_info": "..."
        }

    This format is optimised for ingestion by log-aggregation systems
    (ELK, Splunk, Grafana Loki, etc.).
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # PhantomCore-specific context fields
        for attr in ("tool_name", "operation"):
            val = getattr(record, attr, None)
            if val is not None:
                entry[attr] = val

        # Arbitrary extra data from keyword arguments
        extra = getattr(record, "phantom_extra", None)
        if extra is not None:
            entry["extra"] = extra

        # Exception traceback
        if record.exc_info and record.exc_info[1] is not None:
            entry["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(entry, ensure_ascii=False, default=str)


# ========================== Rich Console Handler ===========================


class _ColorConsoleHandler(RichHandler):
    """Thin wrapper over :class:`rich.logging.RichHandler` applying the
    PhantomCore theme with Georgian-friendly console output.
    """

    def __init__(self, **kwargs: Any) -> None:
        console = Console(theme=_LOG_THEME, stderr=True)
        super().__init__(
            console=console,
            show_path=False,
            show_time=True,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
            markup=True,
            **kwargs,
        )


# ========================== PhantomLogger ==================================


class PhantomLogger:
    """Structured, context-aware logger for PhantomCore tools.

    Each instance is bound to a *tool_name* (e.g. ``"spectra"``) and
    can carry a temporary *operation* context via a context manager.

    Features:
      - Colour-coded Rich console output.
      - Optional JSON-lines file logging with rotation.
      - Context-aware (tool_name, operation) fields in every record.
      - Timing helper for measuring operation duration.

    Usage::

        log = PhantomLogger("spectra", log_file="spectra.log", json_logs=True)
        log.info("Scan started")
        with log.operation("dns_resolution"):
            log.debug("Resolving %s", domain)
        log.error("Connection failed", exc_info=True)

    Args:
        tool_name:       Identifying name for the PhantomCore module.
        log_level:       Minimum severity (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file:        Path to the rotating log file. ``None`` disables file logging.
        json_logs:       If ``True`` the file handler emits JSON lines.
        max_bytes:       Maximum log-file size before rotation (default 10 MiB).
        backup_count:    Number of rotated backup files to keep.
        console_output:  If ``True`` attach a colour Rich console handler.
    """

    def __init__(
        self,
        tool_name: str,
        *,
        log_level: str = "INFO",
        log_file: str | Path | None = None,
        json_logs: bool = False,
        max_bytes: int = 10_485_760,
        backup_count: int = 5,
        console_output: bool = True,
    ) -> None:
        self._tool_name = tool_name
        self._operation: str | None = None

        # Underlying stdlib logger
        self._logger = logging.getLogger(f"phantomcore.{tool_name}")
        self._logger.setLevel(
            getattr(logging, log_level.upper(), logging.INFO)
        )
        self._logger.propagate = False

        # Prevent duplicate handlers on re-instantiation
        self._logger.handlers.clear()

        # -- Console handler (Rich colour-coded) --
        if console_output:
            ch = _ColorConsoleHandler(level=log_level.upper())
            self._logger.addHandler(ch)

        # -- File handler (plain text or JSON lines, with rotation) --
        if log_file is not None:
            file_path = Path(log_file)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(
                filename=str(file_path),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            fh.setLevel(getattr(logging, log_level.upper(), logging.INFO))
            if json_logs:
                fh.setFormatter(_JSONFormatter())
            else:
                fh.setFormatter(
                    logging.Formatter(
                        fmt=(
                            "%(asctime)s | %(levelname)-8s | "
                            "%(name)s | %(message)s"
                        ),
                        datefmt="%Y-%m-%dT%H:%M:%S%z",
                    )
                )
            self._logger.addHandler(fh)

    # ------------------------------------------------------------------ #
    #  Context management -- operation scope
    # ------------------------------------------------------------------ #

    class _OperationContext:
        """Context manager that temporarily binds an operation name."""

        def __init__(self, parent: PhantomLogger, operation: str) -> None:
            self._parent = parent
            self._operation = operation
            self._prev: str | None = None

        def __enter__(self) -> PhantomLogger:
            self._prev = self._parent._operation
            self._parent._operation = self._operation
            return self._parent

        def __exit__(self, *exc: Any) -> None:
            self._parent._operation = self._prev

    def operation(self, name: str) -> _OperationContext:
        """Return a context manager that sets the *operation* field.

        While active, every log record will include ``operation=<name>``.

        Usage::

            with log.operation("entropy_analysis"):
                log.info("Running Shannon entropy")
        """
        return self._OperationContext(self, name)

    # ------------------------------------------------------------------ #
    #  Log methods
    # ------------------------------------------------------------------ #

    def _enrich(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Inject PhantomCore context into the log record via *extra*."""
        extra = kwargs.pop("extra", {}) or {}

        # Collect non-standard keyword args as phantom_extra
        phantom_extra_data: dict[str, Any] = {}
        standard_keys = {"exc_info", "stack_info", "stacklevel"}
        for key in list(kwargs):
            if key not in standard_keys:
                phantom_extra_data[key] = kwargs.pop(key)

        extra["tool_name"] = self._tool_name
        extra["operation"] = self._operation
        if phantom_extra_data:
            extra["phantom_extra"] = phantom_extra_data

        kwargs["extra"] = extra
        return kwargs

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log a DEBUG-level message."""
        kwargs = self._enrich(kwargs)
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log an INFO-level message."""
        kwargs = self._enrich(kwargs)
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log a WARNING-level message."""
        kwargs = self._enrich(kwargs)
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log an ERROR-level message."""
        kwargs = self._enrich(kwargs)
        self._logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log a CRITICAL-level message."""
        kwargs = self._enrich(kwargs)
        self._logger.critical(msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log an ERROR-level message with full exception traceback."""
        kwargs["exc_info"] = kwargs.get("exc_info", True)
        kwargs = self._enrich(kwargs)
        self._logger.error(msg, *args, **kwargs)

    # ------------------------------------------------------------------ #
    #  Timing helper
    # ------------------------------------------------------------------ #

    class _TimingContext:
        """Context manager for measuring and logging elapsed time."""

        def __init__(self, logger_inst: PhantomLogger, label: str) -> None:
            self._logger = logger_inst
            self._label = label
            self._start: float = 0.0

        def __enter__(self) -> PhantomLogger._TimingContext:
            self._start = time.perf_counter()
            self._logger.debug(
                "Started: %s", self._label
            )
            return self

        def __exit__(self, *exc: Any) -> None:
            elapsed = time.perf_counter() - self._start
            self._logger.info(
                "Completed: %s (%.3f sec)",
                self._label,
                elapsed,
            )

        @property
        def elapsed(self) -> float:
            """Seconds elapsed since entering the context."""
            return time.perf_counter() - self._start

    def timed(self, label: str) -> _TimingContext:
        """Context manager that logs start / finish and elapsed time.

        Usage::

            with log.timed("entropy calculation"):
                result = shannon_entropy(data)
        """
        return self._TimingContext(self, label)

    # ------------------------------------------------------------------ #
    #  Properties
    # ------------------------------------------------------------------ #

    @property
    def tool_name(self) -> str:
        """Name of the PhantomCore tool this logger is bound to."""
        return self._tool_name

    @property
    def underlying(self) -> logging.Logger:
        """Direct access to the stdlib :class:`logging.Logger`."""
        return self._logger
