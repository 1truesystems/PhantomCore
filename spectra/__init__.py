"""
Spectra -- Network Intelligence Engine
========================================

Tool 1 of the PhantomCore Cybersecurity Educational Toolkit.

Spectra provides deep network traffic analysis through PCAP file
parsing and live capture, combining statistical anomaly detection,
graph-theoretic analysis, Markov chain modelling, service fingerprinting,
C2 beacon detection, and lateral movement identification.

Modules:
    - ``spectra.core.engine``     -- Four-phase analysis engine
    - ``spectra.core.models``     -- Pydantic data models
    - ``spectra.collectors``      -- Packet capture (Scapy)
    - ``spectra.analyzers``       -- Analysis algorithms
    - ``spectra.output``          -- Console and report output
    - ``spectra.cli``             -- Click CLI entry point
"""

__all__ = [
    "SpectraEngine",
]
