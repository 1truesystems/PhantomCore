"""
Spectra Packet Collector
=========================

Packet capture and parsing module for the Spectra Network Intelligence Engine.
Reads PCAP files and performs live network captures using Scapy, extracting
structured host and flow records for downstream analysis.

Supports Ethernet, IP, IPv6, TCP, UDP, ICMP, DNS, ARP, and HTTP packet
dissection with flow aggregation by 5-tuple (src_ip, src_port, dst_ip,
dst_port, protocol).

References:
    - Scapy Documentation. https://scapy.readthedocs.io/
    - Jacobson, V., Leres, C., & McCanne, S. (1989). libpcap: Packet
      Capture Library. Lawrence Berkeley National Laboratory.
    - IETF RFC 791: Internet Protocol (IPv4).
    - IETF RFC 793: Transmission Control Protocol.
    - IETF RFC 768: User Datagram Protocol.
    - IETF RFC 1035: Domain Names - Implementation and Specification.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from shared.logger import PhantomLogger

from spectra.core.models import NetworkFlow, NetworkHost

# Scapy imports -- suppress Scapy's startup warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (  # noqa: E402
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    Ether,
    ICMP,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
    PcapReader,
    AsyncSniffer,
    rdpcap,
    conf,
)

logger = PhantomLogger("spectra.collector")

# ---------------------------------------------------------------------------
#  TCP Flag mappings
# ---------------------------------------------------------------------------
_TCP_FLAGS: dict[int, str] = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


def _decode_tcp_flags(flags_int: int) -> list[str]:
    """Decode TCP flags integer to list of flag names."""
    result: list[str] = []
    for bit, name in _TCP_FLAGS.items():
        if flags_int & bit:
            result.append(name)
    return result


# ---------------------------------------------------------------------------
#  Flow key type
# ---------------------------------------------------------------------------
FlowKey = tuple[str, int, str, int, str]


class PacketCollector:
    """Collects and parses network packets from PCAP files or live capture.

    Extracts structured :class:`~spectra.core.models.NetworkHost` and
    :class:`~spectra.core.models.NetworkFlow` records from raw packet data
    using Scapy's protocol dissection engine.

    Flow aggregation groups packets by 5-tuple (source IP, source port,
    destination IP, destination port, protocol) as per the IETF flow
    definition standard.

    Usage::

        collector = PacketCollector(max_packets=50000)
        hosts, flows = collector.read_pcap("/path/to/capture.pcap")
        hosts, flows = await collector.live_capture("eth0", duration=60)
    """

    def __init__(
        self,
        max_packets: int = 100_000,
        snap_length: int = 65535,
        bpf_filter: str = "",
    ) -> None:
        """Initialise the packet collector.

        Args:
            max_packets: Maximum number of packets to process. Prevents
                memory exhaustion on large captures.
            snap_length: Snapshot length for live captures (bytes per packet).
            bpf_filter: Berkeley Packet Filter expression for capture filtering.
        """
        self.max_packets: int = max_packets
        self.snap_length: int = snap_length
        self.bpf_filter: str = bpf_filter

        # Internal accumulators (reset per collection run)
        self._hosts: dict[str, NetworkHost] = {}
        self._flow_data: dict[FlowKey, dict[str, Any]] = {}
        self._packet_count: int = 0

    # ------------------------------------------------------------------ #
    #  Public API: PCAP reading
    # ------------------------------------------------------------------ #

    def read_pcap(
        self,
        file_path: str,
    ) -> tuple[dict[str, NetworkHost], list[NetworkFlow]]:
        """Read and parse a PCAP file into host and flow records.

        Uses Scapy's :class:`PcapReader` for memory-efficient sequential
        reading of large capture files.

        Args:
            file_path: Filesystem path to the PCAP/PCAPNG file.

        Returns:
            Tuple of (hosts_dict, flows_list) where hosts_dict maps
            IP addresses to NetworkHost objects and flows_list contains
            aggregated NetworkFlow objects.

        Raises:
            FileNotFoundError: If the PCAP file does not exist.
            ValueError: If the file cannot be parsed as PCAP.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(
                f"PCAP file not found: {file_path}"
            )

        self._reset()
        logger.info(f"Reading PCAP file: {file_path}")

        try:
            with PcapReader(str(path)) as reader:
                for pkt in reader:
                    if self._packet_count >= self.max_packets:
                        logger.warning(
                            f"Packet limit reached: "
                            f"{self.max_packets}"
                        )
                        break
                    self._parse_packet(pkt)
                    self._packet_count += 1
        except Exception as exc:
            logger.error(
                f"PCAP read error: {exc}"
            )
            # Try fallback with rdpcap for smaller files
            try:
                packets = rdpcap(str(path), count=self.max_packets)
                for pkt in packets:
                    self._parse_packet(pkt)
                    self._packet_count += 1
            except Exception as exc2:
                raise ValueError(
                    f"Cannot parse PCAP file: {exc2}"
                ) from exc2

        logger.info(
            f"Processed {self._packet_count} packets, "
            f"{len(self._hosts)} hosts, "
            f"{len(self._flow_data)} flows"
        )

        return self._hosts, self._build_flows()

    # ------------------------------------------------------------------ #
    #  Public API: Live capture
    # ------------------------------------------------------------------ #

    async def live_capture(
        self,
        interface: str,
        duration: int,
        callback: Optional[Callable[[int], None]] = None,
    ) -> tuple[dict[str, NetworkHost], list[NetworkFlow]]:
        """Perform live packet capture on a network interface.

        Uses Scapy's :class:`AsyncSniffer` with a timeout for
        non-blocking capture. Requires root/administrator privileges.

        Args:
            interface: Network interface name (e.g., "eth0", "wlan0").
            duration: Capture duration in seconds.
            callback: Optional callback invoked with current packet count
                during capture for progress reporting.

        Returns:
            Tuple of (hosts_dict, flows_list).

        Raises:
            PermissionError: If insufficient privileges for raw capture.
            OSError: If the interface does not exist.
        """
        self._reset()
        logger.info(
            f"Live capture on {interface} "
            f"({duration} seconds)"
        )

        captured_packets: list[Any] = []

        def _packet_handler(pkt: Any) -> None:
            """Process each captured packet."""
            if self._packet_count >= self.max_packets:
                return
            captured_packets.append(pkt)
            self._parse_packet(pkt)
            self._packet_count += 1
            if callback and self._packet_count % 100 == 0:
                callback(self._packet_count)

        sniffer_kwargs: dict[str, Any] = {
            "iface": interface,
            "prn": _packet_handler,
            "timeout": duration,
            "store": False,
        }

        if self.bpf_filter:
            sniffer_kwargs["filter"] = self.bpf_filter

        try:
            sniffer = AsyncSniffer(**sniffer_kwargs)
            sniffer.start()

            # Wait for the capture duration
            await asyncio.sleep(duration)

            sniffer.stop()
        except PermissionError:
            raise PermissionError(
                "Live capture requires root privileges"
            )
        except OSError as exc:
            raise OSError(
                f"Interface error ({interface}): {exc}"
            ) from exc

        logger.info(
            f"Capture complete: {self._packet_count} packets"
        )

        return self._hosts, self._build_flows()

    # ------------------------------------------------------------------ #
    #  Packet parsing
    # ------------------------------------------------------------------ #

    def _parse_packet(self, pkt: Any) -> None:
        """Parse a single packet and update internal host/flow accumulators.

        Supports the following protocol layers:
        - Layer 2: Ethernet (MAC extraction), ARP
        - Layer 3: IP (IPv4), IPv6
        - Layer 4: TCP, UDP, ICMP
        - Layer 7: DNS (queries and responses), HTTP

        Args:
            pkt: Scapy packet object.
        """
        timestamp = float(pkt.time) if hasattr(pkt, "time") else 0.0
        pkt_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        pkt_len = len(pkt)

        # -- Layer 2: Ethernet (MAC addresses) --
        src_mac = ""
        dst_mac = ""
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src or ""
            dst_mac = pkt[Ether].dst or ""

        # -- ARP packets --
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            src_ip = arp.psrc or ""
            dst_ip = arp.pdst or ""
            if src_ip:
                self._update_host(
                    src_ip, src_mac, pkt_time, bytes_sent=pkt_len
                )
            if dst_ip:
                self._update_host(
                    dst_ip, dst_mac, pkt_time, bytes_recv=pkt_len
                )
            if src_ip and dst_ip:
                flow_key: FlowKey = (src_ip, 0, dst_ip, 0, "ARP")
                self._update_flow(
                    flow_key, pkt_len, pkt_time, timestamp, [], [], b""
                )
            return

        # -- Layer 3: IP / IPv6 --
        src_ip = ""
        dst_ip = ""

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        else:
            return  # No IP layer -- skip

        if not src_ip or not dst_ip:
            return

        # Determine protocol and extract port information
        src_port = 0
        dst_port = 0
        protocol = "OTHER"
        tcp_flags: list[str] = []
        dns_queries: list[str] = []
        payload_sample = b""

        # -- Layer 4: TCP --
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol = "TCP"
            tcp_flags = _decode_tcp_flags(int(tcp_layer.flags))

            # Detect HTTP
            if dst_port in (80, 8080, 8000, 8888) or src_port in (80, 8080, 8000, 8888):
                protocol = "HTTP"
            elif dst_port == 443 or src_port == 443:
                protocol = "HTTPS"

            # Extract payload sample
            if pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                payload_sample = raw_data[:256]

        # -- Layer 4: UDP --
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol = "UDP"

            # Extract payload sample
            if pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                payload_sample = raw_data[:256]

        # -- Layer 4: ICMP --
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        # -- Layer 7: DNS --
        if pkt.haslayer(DNS):
            protocol = "DNS"
            dns_layer = pkt[DNS]
            # Extract query names
            if dns_layer.haslayer(DNSQR):
                try:
                    qname = dns_layer[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore").rstrip(".")
                    if qname:
                        dns_queries.append(qname)
                except (AttributeError, UnicodeDecodeError):
                    pass
            # Extract response record names
            if dns_layer.ancount and dns_layer.ancount > 0:
                try:
                    for i in range(dns_layer.ancount):
                        rr = dns_layer.an[i] if hasattr(dns_layer.an, '__getitem__') else dns_layer[DNSRR]
                        rname = getattr(rr, 'rrname', b'')
                        if isinstance(rname, bytes):
                            rname = rname.decode("utf-8", errors="ignore").rstrip(".")
                        if rname and rname not in dns_queries:
                            dns_queries.append(rname)
                except (IndexError, AttributeError, TypeError):
                    pass

        # -- Update host records --
        self._update_host(
            src_ip, src_mac, pkt_time,
            bytes_sent=pkt_len,
            port=src_port,
        )
        self._update_host(
            dst_ip, dst_mac, pkt_time,
            bytes_recv=pkt_len,
            port=dst_port,
        )

        # -- Update flow record --
        flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        self._update_flow(
            flow_key, pkt_len, pkt_time, timestamp,
            tcp_flags, dns_queries, payload_sample,
        )

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    def _update_host(
        self,
        ip: str,
        mac: str,
        timestamp: datetime,
        bytes_sent: int = 0,
        bytes_recv: int = 0,
        port: int = 0,
    ) -> None:
        """Update or create a host record."""
        if ip not in self._hosts:
            self._hosts[ip] = NetworkHost(
                ip=ip,
                mac=mac,
                first_seen=timestamp,
                last_seen=timestamp,
            )

        host = self._hosts[ip]
        if mac and not host.mac:
            host.mac = mac
        host.bytes_sent += bytes_sent
        host.bytes_recv += bytes_recv
        host.packet_count += 1

        if host.first_seen is None or timestamp < host.first_seen:
            host.first_seen = timestamp
        if host.last_seen is None or timestamp > host.last_seen:
            host.last_seen = timestamp

        if port and port > 0:
            host.ports.add(port)

    def _update_flow(
        self,
        flow_key: FlowKey,
        pkt_len: int,
        pkt_time: datetime,
        timestamp: float,
        tcp_flags: list[str],
        dns_queries: list[str],
        payload_sample: bytes,
    ) -> None:
        """Update or create a flow record."""
        if flow_key not in self._flow_data:
            self._flow_data[flow_key] = {
                "packets": 0,
                "bytes_total": 0,
                "start_time": pkt_time,
                "end_time": pkt_time,
                "flags": set(),
                "packet_sizes": [],
                "timestamps": [],
                "dns_queries": [],
                "payload_sample": b"",
            }

        fd = self._flow_data[flow_key]
        fd["packets"] += 1
        fd["bytes_total"] += pkt_len
        fd["packet_sizes"].append(pkt_len)
        fd["timestamps"].append(timestamp)

        if pkt_time < fd["start_time"]:
            fd["start_time"] = pkt_time
        if pkt_time > fd["end_time"]:
            fd["end_time"] = pkt_time

        for flag in tcp_flags:
            fd["flags"].add(flag)

        for query in dns_queries:
            if query not in fd["dns_queries"]:
                fd["dns_queries"].append(query)

        if payload_sample and not fd["payload_sample"]:
            fd["payload_sample"] = payload_sample

    def _build_flows(self) -> list[NetworkFlow]:
        """Convert internal flow data to list of NetworkFlow models."""
        flows: list[NetworkFlow] = []

        for flow_key, fd in self._flow_data.items():
            src_ip, src_port, dst_ip, dst_port, protocol = flow_key
            flow = NetworkFlow(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                packets=fd["packets"],
                bytes_total=fd["bytes_total"],
                start_time=fd["start_time"],
                end_time=fd["end_time"],
                flags=sorted(fd["flags"]),
                packet_sizes=fd["packet_sizes"],
                timestamps=sorted(fd["timestamps"]),
                dns_queries=fd["dns_queries"],
                payload_sample=fd["payload_sample"],
            )
            flows.append(flow)

        # Sort flows by start time
        flows.sort(key=lambda f: f.start_time or datetime.min.replace(tzinfo=timezone.utc))
        return flows

    def _reset(self) -> None:
        """Reset internal state for a new collection run."""
        self._hosts = {}
        self._flow_data = {}
        self._packet_count = 0
