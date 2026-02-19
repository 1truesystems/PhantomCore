"""
Pulse Output
=============

Output generation modules for the Pulse Wireless Protocol Analyzer.

Modules:
    console  -- Rich-based console display
    report   -- HTML and JSON report generation
"""

from pulse.output.console import PulseConsoleOutput
from pulse.output.report import PulseReportGenerator

__all__ = [
    "PulseConsoleOutput",
    "PulseReportGenerator",
]
