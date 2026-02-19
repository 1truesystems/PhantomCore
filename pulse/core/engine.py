"""
Pulse Engine
==============

Central orchestration engine for the Pulse Wireless Protocol Analyzer.
Coordinates collectors, analyzers, and output generators to perform
WiFi scanning, BLE scanning, wireless IDS monitoring, and PCAP analysis.

The engine follows a pipeline architecture:
    1. Collection: Capture/read wireless frames
    2. Analysis: Run security analyzers on collected data
    3. Synthesis: Aggregate findings into a unified ScanResult
    4. Output: Generate console display and reports

References:
    - IEEE. (2020). IEEE Std 802.11-2020: Wireless LAN MAC and PHY
      Specifications.
    - Bluetooth SIG. (2023). Bluetooth Core Specification v5.4.
    - Evans, E. (2003). Domain-Driven Design. Addison-Wesley.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from shared.config import PhantomConfig
from shared.console import PhantomConsole
from shared.logger import PhantomLogger
from shared.models import Finding, Risk, ScanResult, Severity

from pulse.core.models import (
    AccessPoint,
    BLEDevice,
    ChannelInfo,
    SecurityGrade,
    WifiClient,
    WirelessFinding,
)
from pulse.collectors.wifi_collector import WiFiCollector
from pulse.collectors.ble_collector import BLECollector
from pulse.collectors.pcap_reader import WirelessPCAPReader
from pulse.analyzers.beacon import BeaconAnalyzer
from pulse.analyzers.channel import ChannelAnalyzer
from pulse.analyzers.deauth import DeauthDetector
from pulse.analyzers.hidden_ssid import HiddenSSIDDetector
from pulse.analyzers.probe import ProbeAnalyzer
from pulse.analyzers.signal import SignalAnalyzer
from pulse.output.console import PulseConsoleOutput
from pulse.output.report import PulseReportGenerator

logger = PhantomLogger("pulse.core.engine")


class PulseEngine:
    """Central orchestration engine for Pulse wireless analysis.

    Coordinates all Pulse subsystems to provide four primary operations:
        - WiFi scanning: Enumerate APs and clients, grade security
        - BLE scanning: Discover BLE devices and services
        - Wireless IDS: Monitor for attacks in real-time
        - PCAP analysis: Offline analysis of wireless captures

    Usage::

        engine = PulseEngine()
        result = await engine.scan_wifi("wlan0mon", duration=30)
        result = await engine.scan_ble(duration=10)
        result = await engine.run_ids("wlan0mon", duration=300)
        result = await engine.analyze_pcap("capture.pcap")
    """

    def __init__(
        self,
        config: Optional[PhantomConfig] = None,
        console: Optional[PhantomConsole] = None,
    ) -> None:
        """Initialize the Pulse engine.

        Args:
            config: PhantomCore configuration. Uses defaults if None.
            console: PhantomConsole for output. Creates new if None.
        """
        self._config = config or PhantomConfig()
        self._console = console or PhantomConsole()
        self._output = PulseConsoleOutput(self._console)

        # Collectors
        self._wifi_collector = WiFiCollector()
        self._ble_collector = BLECollector()
        self._pcap_reader = WirelessPCAPReader()

        # Analyzers
        self._beacon_analyzer = BeaconAnalyzer()
        self._channel_analyzer = ChannelAnalyzer()
        self._deauth_detector = DeauthDetector()
        self._hidden_detector = HiddenSSIDDetector()
        self._probe_analyzer = ProbeAnalyzer()
        self._signal_analyzer = SignalAnalyzer()

        # Report generator
        self._report_gen = PulseReportGenerator()

    async def scan_wifi(
        self,
        interface: str,
        duration: int = 30,
        channel: Optional[int] = None,
        output_path: Optional[str] = None,
        verbose: bool = False,
    ) -> ScanResult:
        """Perform a WiFi network scan.

        Captures 802.11 frames from the specified interface, enumerates
        access points and clients, grades security configurations,
        analyses channel utilization, and detects deauthentication attacks.

        Args:
            interface: Wireless interface name (should be in monitor mode).
            duration: Scan duration in seconds.
            channel: Optional specific channel to scan.
            output_path: Optional report output path.
            verbose: Enable verbose output.

        Returns:
            ScanResult with all findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)

        self._output.display_banner()
        self._console.info(
            f"Starting WiFi scan on {interface} "
            f"for {duration}s"
        )

        # Phase 1: Collection
        self._console.info("Phase 1: Data Collection")
        aps, clients, deauths = await self._wifi_collector.capture(
            interface, duration, channel
        )
        raw_frames = self._wifi_collector.raw_frames

        # Phase 2: Analysis
        self._console.info("Phase 2: Analysis")

        # Beacon analysis (security grading)
        grades = self._beacon_analyzer.analyze(aps)
        beacon_findings = self._beacon_analyzer.analyze_to_findings(aps)

        # Channel analysis
        channels = self._channel_analyzer.analyze(aps)

        # Probe analysis
        probe_findings = self._probe_analyzer.analyze(clients)

        # Deauth detection
        deauth_findings = self._deauth_detector.detect(deauths)

        # Hidden SSID detection
        hidden_findings = self._hidden_detector.detect(
            aps, clients, raw_frames
        )

        # Phase 3: Synthesize findings
        all_wireless_findings = (
            beacon_findings + probe_findings + deauth_findings + hidden_findings
        )

        result = self._build_scan_result(
            target=f"wifi://{interface}",
            started_at=started_at,
            start_time=start_time,
            wireless_findings=all_wireless_findings,
            metadata={
                "interface": interface,
                "duration": duration,
                "channel": channel,
                "access_points_count": len(aps),
                "clients_count": len(clients),
                "deauth_events": len(deauths),
            },
        )

        # Phase 4: Output
        self._output.display_scan(aps, clients)
        self._output.display_ap_table(aps, grades)
        self._output.display_clients(clients)
        self._output.display_channels(channels)

        if deauth_findings:
            self._output.display_deauth(deauth_findings)

        self._output.display_findings(all_wireless_findings)

        # Generate reports if output path specified
        if output_path:
            self._generate_reports(
                result=result,
                output_path=output_path,
                aps=aps,
                clients=clients,
                grades=grades,
                channels=channels,
                wireless_findings=all_wireless_findings,
            )

        self._console.success(
            f"WiFi scan complete. "
            f"{len(result.findings)} finding(s) in "
            f"{result.duration_seconds:.1f}s"
        )

        return result

    async def scan_ble(
        self,
        duration: int = 10,
        output_path: Optional[str] = None,
        verbose: bool = False,
    ) -> ScanResult:
        """Perform a BLE device scan.

        Scans for Bluetooth Low Energy devices, extracting names,
        service UUIDs, manufacturer data, and address types.

        Args:
            duration: Scan duration in seconds.
            output_path: Optional report output path.
            verbose: Enable verbose output.

        Returns:
            ScanResult with BLE findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)

        self._output.display_banner()
        self._console.info(
            f"Starting BLE scan for {duration}s"
        )

        # Collection
        devices = await self._ble_collector.scan(duration)

        # Analysis: classify devices and identify tracking risks
        wireless_findings: list[WirelessFinding] = []

        # Check for tracking-capable devices
        trackable_devices = [
            d for d in devices
            if d.address_type.value in ("public", "random_static")
            and d.connectable
        ]
        if trackable_devices:
            from pulse.core.models import WirelessFindingType
            wireless_findings.append(WirelessFinding(
                type=WirelessFindingType.BLE_TRACKING,
                severity="INFO",
                description=(
                    f"{len(trackable_devices)} BLE device(s) detected with "
                    f"stable (trackable) addresses. Devices with public or "
                    f"random-static addresses can be tracked across sessions. "
                    f"Devices: {', '.join(d.name or d.address for d in trackable_devices[:5])}"
                ),
                recommendation=(
                    "BLE devices with stable addresses can be used for "
                    "location tracking. Awareness of nearby BLE devices "
                    "is important for physical security assessments."
                ),
                evidence={
                    "trackable_count": len(trackable_devices),
                    "devices": [
                        {"address": d.address, "name": d.name, "type": d.address_type.value}
                        for d in trackable_devices[:10]
                    ],
                },
                confidence=0.8,
            ))

        result = self._build_scan_result(
            target="ble://local",
            started_at=started_at,
            start_time=start_time,
            wireless_findings=wireless_findings,
            metadata={
                "duration": duration,
                "devices_count": len(devices),
                "connectable_count": sum(1 for d in devices if d.connectable),
            },
        )

        # Output
        self._output.display_ble(devices)

        if wireless_findings:
            self._output.display_findings(wireless_findings)

        if output_path:
            self._generate_reports(
                result=result,
                output_path=output_path,
                ble_devices=devices,
                wireless_findings=wireless_findings,
            )

        self._console.success(
            f"BLE scan complete. "
            f"{len(devices)} device(s) found in "
            f"{result.duration_seconds:.1f}s"
        )

        return result

    async def run_ids(
        self,
        interface: str,
        duration: int = 300,
        channel: Optional[int] = None,
        output_path: Optional[str] = None,
        verbose: bool = False,
    ) -> ScanResult:
        """Run wireless Intrusion Detection System monitoring.

        Continuously monitors the wireless medium for security threats
        including deauthentication attacks, rogue APs, and anomalous
        client behaviour.

        Args:
            interface: Wireless interface in monitor mode.
            duration: Monitoring duration in seconds.
            channel: Optional specific channel to monitor.
            output_path: Optional report output path.
            verbose: Enable verbose output.

        Returns:
            ScanResult with IDS alerts.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)

        self._output.display_banner()
        self._console.info(
            f"Starting IDS monitoring on "
            f"{interface} for {duration}s"
        )

        # IDS mode: capture for the full duration
        aps, clients, deauths = await self._wifi_collector.capture(
            interface, duration, channel
        )
        raw_frames = self._wifi_collector.raw_frames

        # Run all analyzers for comprehensive IDS
        all_findings: list[WirelessFinding] = []

        # Deauth detection (primary IDS function)
        deauth_findings = self._deauth_detector.detect(
            deauths, threshold=5
        )
        all_findings.extend(deauth_findings)

        # Beacon analysis for weak/insecure networks
        beacon_findings = self._beacon_analyzer.analyze_to_findings(aps)
        all_findings.extend(beacon_findings)

        # Probe analysis for privacy issues
        probe_findings = self._probe_analyzer.analyze(clients)
        all_findings.extend(probe_findings)

        # Hidden SSID detection
        hidden_findings = self._hidden_detector.detect(
            aps, clients, raw_frames
        )
        all_findings.extend(hidden_findings)

        result = self._build_scan_result(
            target=f"ids://{interface}",
            started_at=started_at,
            start_time=start_time,
            wireless_findings=all_findings,
            metadata={
                "mode": "ids",
                "interface": interface,
                "duration": duration,
                "channel": channel,
                "access_points_count": len(aps),
                "clients_count": len(clients),
                "deauth_events": len(deauths),
                "total_alerts": len(all_findings),
            },
        )

        # Output
        self._output.display_scan(aps, clients)
        self._output.display_ids(all_findings)

        if output_path:
            grades = self._beacon_analyzer.analyze(aps)
            channels = self._channel_analyzer.analyze(aps)
            self._generate_reports(
                result=result,
                output_path=output_path,
                aps=aps,
                clients=clients,
                grades=grades,
                channels=channels,
                wireless_findings=all_findings,
            )

        self._console.success(
            f"IDS monitoring complete. "
            f"{len(all_findings)} alert(s) in {result.duration_seconds:.1f}s"
        )

        return result

    async def analyze_pcap(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        verbose: bool = False,
    ) -> ScanResult:
        """Analyze a wireless PCAP capture file.

        Parses the PCAP file for 802.11 frames and performs the full
        analysis pipeline: beacon grading, channel analysis, probe
        analysis, deauth detection, and hidden SSID discovery.

        Args:
            file_path: Path to the PCAP/PCAPNG file.
            output_path: Optional report output path.
            verbose: Enable verbose output.

        Returns:
            ScanResult with analysis findings.
        """
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc)

        self._output.display_banner()
        self._console.info(
            f"Starting PCAP analysis: {file_path}"
        )

        # Read PCAP
        aps, clients, deauths, raw_frames = await self._pcap_reader.read(
            file_path
        )

        # Run analysis pipeline
        grades = self._beacon_analyzer.analyze(aps)
        beacon_findings = self._beacon_analyzer.analyze_to_findings(aps)

        channels = self._channel_analyzer.analyze(aps)
        probe_findings = self._probe_analyzer.analyze(clients)
        deauth_findings = self._deauth_detector.detect(deauths)
        hidden_findings = self._hidden_detector.detect(
            aps, clients, raw_frames
        )

        all_findings = (
            beacon_findings + probe_findings + deauth_findings + hidden_findings
        )

        result = self._build_scan_result(
            target=file_path,
            started_at=started_at,
            start_time=start_time,
            wireless_findings=all_findings,
            metadata={
                "mode": "pcap_analysis",
                "file_path": file_path,
                "file_size": Path(file_path).stat().st_size if Path(file_path).exists() else 0,
                "access_points_count": len(aps),
                "clients_count": len(clients),
                "deauth_events": len(deauths),
                "frames_analyzed": len(raw_frames),
            },
        )

        # Output
        self._output.display_scan(aps, clients)
        self._output.display_ap_table(aps, grades)
        self._output.display_clients(clients)
        self._output.display_channels(channels)

        if deauth_findings:
            self._output.display_deauth(deauth_findings)

        self._output.display_findings(all_findings)

        if output_path:
            self._generate_reports(
                result=result,
                output_path=output_path,
                aps=aps,
                clients=clients,
                grades=grades,
                channels=channels,
                wireless_findings=all_findings,
            )

        self._console.success(
            f"PCAP analysis complete. "
            f"{len(result.findings)} finding(s) in "
            f"{result.duration_seconds:.1f}s"
        )

        return result

    def _build_scan_result(
        self,
        target: str,
        started_at: datetime,
        start_time: float,
        wireless_findings: list[WirelessFinding],
        metadata: dict[str, Any],
    ) -> ScanResult:
        """Build a ScanResult from wireless findings.

        Converts WirelessFinding objects to the shared Finding model.

        Args:
            target: Scan target identifier.
            started_at: Scan start timestamp.
            start_time: Monotonic start time for duration calculation.
            wireless_findings: List of wireless findings.
            metadata: Additional metadata.

        Returns:
            ScanResult with converted findings.
        """
        completed_at = datetime.now(timezone.utc)
        duration = time.monotonic() - start_time

        # Map wireless severity strings to shared Severity enum
        severity_map: dict[str, Severity] = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }

        risk_map: dict[str, Risk] = {
            "CRITICAL": Risk.CRITICAL,
            "HIGH": Risk.HIGH,
            "MEDIUM": Risk.MEDIUM,
            "LOW": Risk.LOW,
            "INFO": Risk.NEGLIGIBLE,
        }

        findings: list[Finding] = []
        for wf in wireless_findings:
            sev = severity_map.get(wf.severity.upper(), Severity.INFO)
            risk = risk_map.get(wf.severity.upper(), Risk.NEGLIGIBLE)

            findings.append(Finding(
                title=f"[{wf.type.value}] {wf.severity}",
                description=wf.description,
                severity=sev,
                risk=risk,
                confidence=wf.confidence,
                evidence=wf.evidence,
                recommendation=wf.recommendation,
                metadata={
                    "finding_type": wf.type.value,
                    "ap_bssid": wf.ap_bssid,
                    "client_mac": wf.client_mac,
                },
            ))

        result = ScanResult(
            tool_name="pulse",
            target=target,
            findings=findings,
            summary=(
                f"Pulse wireless analysis: {len(findings)} finding(s) "
                f"({sum(1 for f in findings if f.severity == Severity.CRITICAL)} critical, "
                f"{sum(1 for f in findings if f.severity == Severity.HIGH)} high)"
            ),
            start_time=started_at,
            end_time=completed_at,
            metadata=metadata,
        )

        return result

    def _generate_reports(
        self,
        result: ScanResult,
        output_path: str,
        **kwargs: Any,
    ) -> None:
        """Generate HTML and JSON reports.

        Args:
            result: ScanResult with findings.
            output_path: Base output path (extension will be changed).
            **kwargs: Additional data (aps, clients, grades, etc.).
        """
        base = Path(output_path)
        stem = base.stem
        parent = base.parent

        # HTML report
        html_path = parent / f"{stem}.html"
        try:
            self._report_gen.generate_html(
                result, str(html_path), **kwargs
            )
            self._console.info(f"HTML report: {html_path}")
        except Exception as exc:
            logger.error(f"HTML report error: {exc}")

        # JSON report
        json_path = parent / f"{stem}.json"
        try:
            self._report_gen.generate_json(
                result, str(json_path), **kwargs
            )
            self._console.info(f"JSON report: {json_path}")
        except Exception as exc:
            logger.error(f"JSON report error: {exc}")
