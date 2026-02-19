"""
Nexus Output Module
====================

Output formatting and report generation for Nexus analysis results.
Supports Rich console display, HTML reports, and JSON export.
"""

from nexus.output.console import NexusConsoleOutput
from nexus.output.report import NexusReportGenerator

__all__ = [
    "NexusConsoleOutput",
    "NexusReportGenerator",
]
