"""
Spectra Collectors
===================

Packet capture and parsing modules for network data collection.

- ``packet_collector`` -- PCAP reading and live capture via Scapy
"""

from spectra.collectors.packet_collector import PacketCollector

__all__ = ["PacketCollector"]
