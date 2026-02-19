"""
Spectra Analyzers
==================

Analysis modules for network traffic intelligence:

- ``anomaly``      -- Statistical anomaly detection (z-score, IQR)
- ``graph``        -- Communication graph analysis (centrality, communities)
- ``markov``       -- Markov chain transition analysis
- ``fingerprint``  -- Naive Bayes service fingerprinting
- ``lateral``      -- Lateral movement detection
- ``beacon``       -- C2 beacon detection (timing analysis)
"""

from spectra.analyzers.anomaly import AnomalyDetector
from spectra.analyzers.beacon import BeaconDetector
from spectra.analyzers.fingerprint import ServiceFingerprinter
from spectra.analyzers.graph import GraphAnalyzer
from spectra.analyzers.lateral import LateralMovementDetector
from spectra.analyzers.markov import MarkovAnalyzer

__all__ = [
    "AnomalyDetector",
    "BeaconDetector",
    "ServiceFingerprinter",
    "GraphAnalyzer",
    "LateralMovementDetector",
    "MarkovAnalyzer",
]
