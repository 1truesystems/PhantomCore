"""
Spectra Output
===============

Output rendering modules for analysis results.

- ``console`` -- Rich-based console display
- ``report``  -- HTML and JSON report generation
"""

from spectra.output.console import SpectraConsoleOutput
from spectra.output.report import SpectraReportGenerator

__all__ = [
    "SpectraConsoleOutput",
    "SpectraReportGenerator",
]
