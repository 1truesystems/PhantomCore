"""
Nexus Core Module
==================

Core engine, data models, and database for the Nexus Threat Intelligence
Correlator.
"""

from nexus.core.engine import NexusEngine
from nexus.core.models import (
    AttackSurfaceNode,
    CVERecord,
    CVSSVector,
    IoC,
    IoCType,
    MITRETechnique,
    ThreatAssessment,
)
from nexus.core.database import CVEDatabase

__all__ = [
    "NexusEngine",
    "CVERecord",
    "CVSSVector",
    "IoC",
    "IoCType",
    "MITRETechnique",
    "ThreatAssessment",
    "AttackSurfaceNode",
    "CVEDatabase",
]
