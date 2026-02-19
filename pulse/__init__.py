"""
Pulse -- Wireless Protocol Analyzer
=====================================

Tool 5 of the PhantomCore Cybersecurity Educational Toolkit.

Pulse provides passive wireless network analysis capabilities for
WiFi (802.11) and Bluetooth Low Energy (BLE) environments. It
enumerates access points and client devices, grades security
configurations, analyses channel utilization, detects deauthentication
attacks, and discovers hidden SSIDs.

Modules:
    core.engine     -- Central orchestration engine
    core.models     -- Pydantic domain models
    collectors      -- WiFi, BLE, and PCAP data collectors
    analyzers       -- Security analysis modules
    output          -- Console and report output
    cli             -- Click-based command-line interface

References:
    - IEEE. (2020). IEEE Std 802.11-2020: Wireless LAN MAC and PHY
      Specifications.
    - Bluetooth SIG. (2023). Bluetooth Core Specification v5.4.
    - Wi-Fi Alliance. (2018). WPA3 Specification v1.0.
"""

__version__ = "1.0.0"
__tool__ = "Pulse"
__description__ = "Wireless Protocol Analyzer"
