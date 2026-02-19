"""
Spectra Core Module
====================

Contains the main analysis engine and data models.
"""

from spectra.core.engine import SpectraEngine
from spectra.core.models import (
    AnomalyAlert,
    AnomalyType,
    BeaconResult,
    CommunicationGraph,
    CommunityResult,
    LateralMovement,
    NetworkFlow,
    NetworkHost,
    Protocol,
)

__all__ = [
    "SpectraEngine",
    "AnomalyAlert",
    "AnomalyType",
    "BeaconResult",
    "CommunicationGraph",
    "CommunityResult",
    "LateralMovement",
    "NetworkFlow",
    "NetworkHost",
    "Protocol",
]
