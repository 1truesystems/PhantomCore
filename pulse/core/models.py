"""
Pulse Core Data Models
=======================

Pydantic-based domain models for the Pulse Wireless Protocol Analyzer.
These models represent WiFi access points, clients, BLE devices,
deauthentication events, channel information, signal measurements,
wireless security findings, and security grading.

The 802.11 frame structure and field definitions follow the IEEE 802.11-2020
standard, with security classifications based on Wi-Fi Alliance certification
programmes (WPA2, WPA3).

References:
    - IEEE. (2020). IEEE Std 802.11-2020: Wireless LAN Medium Access Control
      (MAC) and Physical Layer (PHY) Specifications.
    - Wi-Fi Alliance. (2018). WPA3 Specification v1.0.
    - Bluetooth SIG. (2023). Bluetooth Core Specification v5.4.
    - Evans, E. (2003). Domain-Driven Design. Addison-Wesley.
    - Pydantic v2 Documentation. https://docs.pydantic.dev/latest/
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EncryptionType(str, enum.Enum):
    """WiFi encryption protocol classification.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Section 12: Security.
    """

    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA2_WPA3 = "WPA2/WPA3"
    UNKNOWN = "Unknown"


class CipherSuite(str, enum.Enum):
    """Pairwise and group cipher suite identifiers.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Table 9-149.
    """

    CCMP = "CCMP"
    TKIP = "TKIP"
    WEP40 = "WEP-40"
    WEP104 = "WEP-104"
    GCMP = "GCMP"
    GCMP_256 = "GCMP-256"
    CCMP_256 = "CCMP-256"
    BIP_CMAC_128 = "BIP-CMAC-128"
    NONE = "None"


class AuthKeyMgmt(str, enum.Enum):
    """Authentication and Key Management (AKM) suite types.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Table 9-151.
    """

    PSK = "PSK"
    SAE = "SAE"
    IEEE_802_1X = "802.1X"
    FT_PSK = "FT-PSK"
    FT_SAE = "FT-SAE"
    FT_802_1X = "FT-802.1X"
    OWE = "OWE"
    SUITE_B = "Suite-B"
    UNKNOWN = "Unknown"


class WirelessFindingType(str, enum.Enum):
    """Classification of wireless security findings."""

    WEAK_ENCRYPTION = "weak_encryption"
    OPEN_NETWORK = "open_network"
    WPS_ENABLED = "wps_enabled"
    NO_PMF = "no_pmf"
    HIDDEN_SSID = "hidden_ssid"
    DEFAULT_SSID = "default_ssid"
    DEAUTH_ATTACK = "deauth_attack"
    DEAUTH_FLOOD = "deauth_flood"
    PROBE_LEAK = "probe_leak"
    MAC_TRACKING = "mac_tracking"
    ROGUE_AP = "rogue_ap"
    EVIL_TWIN = "evil_twin"
    CHANNEL_CONGESTION = "channel_congestion"
    WEAK_SIGNAL = "weak_signal"
    BLE_TRACKING = "ble_tracking"
    ANOMALOUS_BEACON = "anomalous_beacon"


class SignalQuality(str, enum.Enum):
    """RSSI-based signal quality classification.

    Thresholds based on industry-standard metrics used by
    wireless site survey tools.

    Reference:
        Cisco. (2024). Wireless LAN Design Guide. Signal Strength
        Recommendations.
    """

    EXCELLENT = "Excellent"
    GOOD = "Good"
    FAIR = "Fair"
    WEAK = "Weak"
    VERY_WEAK = "Very Weak"


class BLEAddressType(str, enum.Enum):
    """Bluetooth Low Energy address types.

    Reference:
        Bluetooth SIG. (2023). Core Specification v5.4. Vol 6, Part B,
        Section 1.3.
    """

    PUBLIC = "public"
    RANDOM_STATIC = "random_static"
    RANDOM_PRIVATE_RESOLVABLE = "random_private_resolvable"
    RANDOM_PRIVATE_NON_RESOLVABLE = "random_private_non_resolvable"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# WiFi Access Point
# ---------------------------------------------------------------------------


class AccessPoint(BaseModel):
    """Represents a detected WiFi access point.

    Captures all information elements (IEs) extractable from 802.11
    beacon and probe response management frames.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Section 9.4.2: Information
        Elements.

    Attributes:
        bssid: Basic Service Set Identifier (AP MAC address).
        ssid: Service Set Identifier (network name).
        channel: Operating channel number.
        frequency: Operating frequency in MHz.
        signal_dbm: Signal strength in dBm.
        encryption: Encryption protocol type.
        cipher: Pairwise cipher suite.
        auth: Authentication key management type.
        wps_enabled: Whether Wi-Fi Protected Setup is active.
        pmf: Protected Management Frames status.
        beacon_interval: Beacon interval in TU (1 TU = 1024 microseconds).
        first_seen: Timestamp of first detection.
        last_seen: Timestamp of most recent detection.
        vendor: Vendor name derived from OUI lookup.
        clients: List of associated client MAC addresses.
        hidden: Whether the SSID is hidden (broadcast SSID suppressed).
        supported_rates: Supported data rates in Mbps.
        country: Country code from Country IE if present.
        beacon_count: Number of beacons captured.
    """

    bssid: str
    ssid: str = ""
    channel: int = 0
    frequency: int = 0
    signal_dbm: int = -100
    encryption: EncryptionType = EncryptionType.UNKNOWN
    cipher: CipherSuite = CipherSuite.NONE
    auth: AuthKeyMgmt = AuthKeyMgmt.UNKNOWN
    wps_enabled: bool = False
    pmf: bool = False
    beacon_interval: int = 100
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    vendor: str = "Unknown"
    clients: list[str] = Field(default_factory=list)
    hidden: bool = False
    supported_rates: list[float] = Field(default_factory=list)
    country: str = ""
    beacon_count: int = 0

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
# WiFi Client
# ---------------------------------------------------------------------------


class WifiClient(BaseModel):
    """Represents a detected WiFi client station.

    Client information is derived from probe requests, data frames,
    and association frames observed in the wireless medium.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Section 11.1.3: Scanning.

    Attributes:
        mac: Client MAC address.
        signal_dbm: Signal strength in dBm.
        associated_ap: BSSID of the associated access point, if any.
        probe_requests: List of SSIDs the client has probed.
        vendor: Vendor name from OUI lookup.
        is_randomized_mac: Whether the MAC appears to be locally administered.
        packets: Number of packets observed from this client.
        first_seen: First detection timestamp.
        last_seen: Most recent detection timestamp.
    """

    mac: str
    signal_dbm: int = -100
    associated_ap: Optional[str] = None
    probe_requests: list[str] = Field(default_factory=list)
    vendor: str = "Unknown"
    is_randomized_mac: bool = False
    packets: int = 0
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
# BLE Device
# ---------------------------------------------------------------------------


class BLEDevice(BaseModel):
    """Represents a detected Bluetooth Low Energy device.

    Captures advertisement data from BLE advertising channels
    (channels 37, 38, 39 at 2402, 2426, 2480 MHz respectively).

    Reference:
        Bluetooth SIG. (2023). Core Specification v5.4. Vol 3, Part C:
        Generic Access Profile.

    Attributes:
        address: Device Bluetooth address.
        name: Advertised device name (Complete or Shortened Local Name).
        rssi: Received Signal Strength Indicator in dBm.
        address_type: BLE address type classification.
        services: List of advertised service UUIDs.
        manufacturer_data: Raw manufacturer-specific data as hex string.
        company: Company name from Bluetooth Company ID lookup.
        connectable: Whether the device advertises as connectable.
        tx_power: Advertised TX power level in dBm, if present.
        appearance: GAP Appearance value, if present.
        first_seen: First detection timestamp.
        last_seen: Most recent detection timestamp.
    """

    address: str
    name: str = ""
    rssi: int = -100
    address_type: BLEAddressType = BLEAddressType.UNKNOWN
    services: list[str] = Field(default_factory=list)
    manufacturer_data: str = ""
    company: str = ""
    connectable: bool = False
    tx_power: Optional[int] = None
    appearance: Optional[int] = None
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
# Deauthentication Event
# ---------------------------------------------------------------------------


class DeauthEvent(BaseModel):
    """Represents a captured 802.11 deauthentication frame.

    Deauthentication frames (subtype 12) can indicate legitimate
    disconnections or adversarial deauthentication attacks used in
    denial-of-service or WPA handshake capture scenarios.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Section 9.3.3.12:
        Deauthentication frame format.

    Attributes:
        src_mac: Source MAC address.
        dst_mac: Destination MAC address.
        bssid: BSSID of the affected network.
        reason_code: IEEE 802.11 reason code (Table 9-49).
        timestamp: When the event was captured.
        count: Number of deauth frames observed for this src/dst/bssid tuple.
    """

    src_mac: str
    dst_mac: str
    bssid: str
    reason_code: int = 1
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    count: int = 1

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
# Channel Information
# ---------------------------------------------------------------------------


class ChannelInfo(BaseModel):
    """Channel utilization and interference analysis for a single channel.

    Models the 2.4 GHz (channels 1-14) and 5 GHz (channels 36-165)
    WiFi spectrum bands with congestion and interference scoring.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Annex E: Country
        Information and Operating Classes.

    Attributes:
        channel: Channel number.
        frequency: Centre frequency in MHz.
        utilization: Estimated channel utilization ratio [0.0, 1.0].
        networks_count: Number of networks detected on this channel.
        interference_score: Interference index [0.0, 1.0].
        recommendation: Human-readable recommendation for this channel.
        is_dfs: Whether this is a DFS (Dynamic Frequency Selection) channel.
        band: Frequency band identifier ('2.4GHz' or '5GHz').
    """

    channel: int
    frequency: int = 0
    utilization: float = Field(default=0.0, ge=0.0, le=1.0)
    networks_count: int = 0
    interference_score: float = Field(default=0.0, ge=0.0, le=1.0)
    recommendation: str = ""
    is_dfs: bool = False
    band: str = "2.4GHz"


# ---------------------------------------------------------------------------
# Signal Measurement
# ---------------------------------------------------------------------------


class SignalMeasurement(BaseModel):
    """A single RSSI measurement for signal propagation analysis.

    Used as input for path loss modelling and position estimation
    algorithms.

    Reference:
        Rappaport, T. S. (2002). Wireless Communications: Principles
        and Practice (2nd ed.). Prentice Hall.

    Attributes:
        bssid: BSSID of the measured access point.
        rssi_dbm: Received signal strength in dBm.
        timestamp: Measurement timestamp.
        location_estimate: Optional (x, y) coordinate estimate.
        tx_power_dbm: Transmit power of the AP in dBm, if known.
        frequency_mhz: Operating frequency in MHz.
    """

    bssid: str
    rssi_dbm: int = -70
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    location_estimate: Optional[tuple[float, float]] = None
    tx_power_dbm: int = 20
    frequency_mhz: int = 2437

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
# Wireless Finding
# ---------------------------------------------------------------------------


class WirelessFinding(BaseModel):
    """A security finding from wireless analysis.

    Represents an individual security issue, vulnerability, or anomaly
    detected during wireless scanning and analysis.

    Attributes:
        id: Unique finding identifier.
        type: Classification of the finding.
        severity: Severity level string (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        ap_bssid: BSSID of involved access point, if applicable.
        client_mac: MAC of involved client, if applicable.
        description: Detailed description of the finding.
        recommendation: Suggested remediation action.
        evidence: Supporting evidence data.
        confidence: Confidence in the finding [0.0, 1.0].
        timestamp: When the finding was generated.
    """

    id: UUID = Field(default_factory=uuid4)
    type: WirelessFindingType
    severity: str = "INFO"
    ap_bssid: Optional[str] = None
    client_mac: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat(),
        }


# ---------------------------------------------------------------------------
# Security Grade
# ---------------------------------------------------------------------------


class SecurityGrade(BaseModel):
    """Security grading for a WiFi access point.

    Assigns a letter grade (A through F) based on the encryption
    protocol, cipher suite, PMF status, WPS state, and other
    security-relevant configuration parameters.

    Grading criteria:
        A: WPA3-SAE + PMF + no WPS
        B: WPA2-CCMP + PMF
        C+: WPA2-CCMP without PMF
        C: WPA2-TKIP
        D: WPA (TKIP only)
        F: WEP or Open

    Reference:
        Wi-Fi Alliance. (2018). WPA3 Specification v1.0.
        Wi-Fi Alliance. (2020). WPA3 Security Considerations.

    Attributes:
        grade: Letter grade from A to F.
        protocol: Detected encryption/protocol string.
        issues: List of identified security issues.
        recommendations: List of remediation recommendations.
        score: Numeric score [0, 100] underlying the letter grade.
    """

    grade: str = "F"
    protocol: str = ""
    issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    score: int = Field(default=0, ge=0, le=100)


# ---------------------------------------------------------------------------
# Deauth Reason Codes
# ---------------------------------------------------------------------------


DEAUTH_REASON_CODES: dict[int, str] = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending station is leaving (or has left) IBSS or ESS",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Disassociated because sending station is leaving (or has left) BSS",
    9: "Station requesting (re)association is not authenticated with responding station",
    10: "Disassociated because the information in the Power Capability element is unacceptable",
    11: "Disassociated because the information in the Supported Channels element is unacceptable",
    12: "Disassociated due to BSS Transition Management",
    13: "Invalid information element",
    14: "Message integrity code (MIC) failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "Information element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of the security policy",
    25: "TDLS direct-link teardown due to TDLS peer STA unreachable via the TDLS direct link",
    26: "TDLS direct-link teardown for unspecified reason",
    27: "Disassociated because session terminated by SSP request",
    34: "Disassociated because of lack of QoS facility",
    39: "Requested from peer STA as the STA does not want to use the mechanism",
    45: "Peer STA does not support the requested cipher suite",
    46: "In a Disassociation frame: Disassociated because authorized access limit reached",
}

# Common attack reason codes vs. legitimate codes
ATTACK_REASON_CODES: set[int] = {1, 2, 6, 7}
LEGITIMATE_REASON_CODES: set[int] = {3, 8, 15, 16, 23}


# ---------------------------------------------------------------------------
# OUI Vendor Database (top 120+ prefixes)
# ---------------------------------------------------------------------------

OUI_DATABASE: dict[str, str] = {
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:10:FA": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "00:50:E4": "Apple",
    "00:61:71": "Apple",
    "00:88:65": "Apple",
    "00:B3:62": "Apple",
    "00:C6:10": "Apple",
    "00:CD:FE": "Apple",
    "00:DB:70": "Apple",
    "00:F4:B9": "Apple",
    "00:F7:6F": "Apple",
    "04:0C:CE": "Apple",
    "04:15:52": "Apple",
    "04:26:65": "Apple",
    "04:F7:E4": "Apple",
    "08:00:20": "Oracle/Sun",
    "08:00:27": "Oracle VirtualBox",
    "08:66:98": "Apple",
    "10:DD:B1": "Apple",
    "14:10:9F": "Apple",
    "18:AF:61": "Apple",
    "1C:36:BB": "Apple",
    "20:78:F0": "Apple",
    "24:A0:74": "Apple",
    "28:6A:BA": "Apple",
    "2C:BE:08": "Apple",
    "30:35:AD": "Apple",
    "34:36:3B": "Apple",
    "38:C9:86": "Apple",
    "3C:07:54": "Apple",
    "3C:D0:F8": "Apple",
    "40:33:1A": "Apple",
    "44:2A:60": "Apple",
    "48:60:BC": "Apple",
    "4C:57:CA": "Apple",
    "50:32:37": "Apple",
    "54:26:96": "Apple",
    "54:EA:A8": "Apple",
    "58:55:CA": "Apple",
    "5C:59:48": "Apple",
    "5C:F7:E6": "Apple",
    "60:03:08": "Apple",
    "60:33:4B": "Apple",
    "60:69:44": "Apple",
    "60:FA:CD": "Apple",
    "64:A3:CB": "Apple",
    "68:5B:35": "Apple",
    "68:96:7B": "Apple",
    "68:A8:6D": "Apple",
    "6C:4D:73": "Apple",
    "6C:70:9F": "Apple",
    "6C:94:F8": "Apple",
    "6C:C2:17": "Apple",
    "70:3E:AC": "Apple",
    "70:DE:E2": "Apple",
    "70:EC:E4": "Apple",
    "74:E2:F5": "Apple",
    "78:31:C1": "Apple",
    "78:7E:61": "Apple",
    "78:CA:39": "Apple",
    "7C:6D:62": "Apple",
    "7C:D1:C3": "Apple",
    "80:00:6E": "Apple",
    "80:49:71": "Apple",
    "80:BE:05": "Apple",
    "84:38:35": "Apple",
    "84:78:8B": "Apple",
    "84:FC:FE": "Apple",
    "88:66:A5": "Apple",
    "88:C6:63": "Apple",
    "8C:00:6D": "Apple",
    "8C:29:37": "Apple",
    "8C:85:90": "Apple",
    "8C:FA:BA": "Apple",
    "90:27:E4": "Apple",
    "90:84:0D": "Apple",
    "90:B9:31": "Apple",
    "94:E9:6A": "Apple",
    "98:01:A7": "Apple",
    "98:D6:BB": "Apple",
    "9C:04:EB": "Apple",
    "9C:20:7B": "Apple",
    "9C:35:EB": "Apple",
    "9C:F3:87": "Apple",
    "A0:99:9B": "Apple",
    "A0:D7:95": "Apple",
    "A4:5E:60": "Apple",
    "A4:B1:97": "Apple",
    "A4:D1:8C": "Apple",
    "A8:20:66": "Apple",
    "A8:5C:2C": "Apple",
    "A8:66:7F": "Apple",
    "A8:86:DD": "Apple",
    "A8:96:8A": "Apple",
    "A8:BB:CF": "Apple",
    "AC:29:3A": "Apple",
    "AC:3C:0B": "Apple",
    "AC:61:EA": "Apple",
    "AC:87:A3": "Apple",
    "AC:BC:32": "Apple",
    "AC:FD:EC": "Apple",
    "B0:19:C6": "Apple",
    "B0:34:95": "Apple",
    "B0:65:BD": "Apple",
    "B0:70:2D": "Apple",
    "B4:18:D1": "Apple",
    "B4:F0:AB": "Apple",
    "B8:09:8A": "Apple",
    "B8:17:C2": "Apple",
    "B8:41:A4": "Apple",
    "B8:44:D9": "Apple",
    "B8:53:AC": "Apple",
    "B8:78:2E": "Apple",
    "B8:C1:11": "Apple",
    "B8:E8:56": "Apple",
    "B8:F6:B1": "Apple",
    "B8:FF:61": "Apple",
    "BC:52:B7": "Apple",
    "BC:67:78": "Apple",
    "BC:92:6B": "Apple",
    # Samsung
    "00:07:AB": "Samsung",
    "00:12:47": "Samsung",
    "00:12:FB": "Samsung",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:DB": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung",
    "00:1E:E1": "Samsung",
    "00:1E:E2": "Samsung",
    "00:1F:CC": "Samsung",
    "00:1F:CD": "Samsung",
    "00:21:19": "Samsung",
    "00:21:D1": "Samsung",
    "00:21:D2": "Samsung",
    "00:23:39": "Samsung",
    "00:23:3A": "Samsung",
    "00:23:99": "Samsung",
    "00:23:D6": "Samsung",
    "00:23:D7": "Samsung",
    "00:24:54": "Samsung",
    "00:24:90": "Samsung",
    "00:24:91": "Samsung",
    "00:25:66": "Samsung",
    "00:25:67": "Samsung",
    "00:26:37": "Samsung",
    "00:E0:64": "Samsung",
    "08:37:3D": "Samsung",
    "08:D4:2B": "Samsung",
    "08:EE:8B": "Samsung",
    "08:FC:88": "Samsung",
    "0C:14:20": "Samsung",
    "0C:71:5D": "Samsung",
    "0C:89:10": "Samsung",
    "10:1D:C0": "Samsung",
    "10:30:47": "Samsung",
    "14:49:E0": "Samsung",
    "14:56:8E": "Samsung",
    "18:22:7E": "Samsung",
    "18:3A:2D": "Samsung",
    "18:67:B0": "Samsung",
    "18:E2:C2": "Samsung",
    "1C:5A:3E": "Samsung",
    "1C:62:B8": "Samsung",
    "1C:66:AA": "Samsung",
    "20:13:E0": "Samsung",
    "20:6E:9C": "Samsung",
    # Intel
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:07:E9": "Intel",
    "00:0C:F1": "Intel",
    "00:0E:0C": "Intel",
    "00:0E:35": "Intel",
    "00:11:11": "Intel",
    "00:12:F0": "Intel",
    "00:13:02": "Intel",
    "00:13:20": "Intel",
    "00:13:CE": "Intel",
    "00:13:E8": "Intel",
    "00:15:00": "Intel",
    "00:15:17": "Intel",
    "00:16:6F": "Intel",
    "00:16:76": "Intel",
    "00:16:EA": "Intel",
    "00:16:EB": "Intel",
    "00:18:DE": "Intel",
    "00:19:D1": "Intel",
    "00:19:D2": "Intel",
    "00:1B:21": "Intel",
    "00:1B:77": "Intel",
    "00:1C:BF": "Intel",
    "00:1C:C0": "Intel",
    "00:1D:E0": "Intel",
    "00:1D:E1": "Intel",
    "00:1E:64": "Intel",
    "00:1E:65": "Intel",
    "00:1F:3B": "Intel",
    "00:1F:3C": "Intel",
    "00:20:7B": "Intel",
    "00:21:5C": "Intel",
    "00:21:5D": "Intel",
    "00:21:6A": "Intel",
    "00:21:6B": "Intel",
    "00:22:FA": "Intel",
    "00:22:FB": "Intel",
    "00:23:14": "Intel",
    "00:23:15": "Intel",
    "00:24:D6": "Intel",
    "00:24:D7": "Intel",
    "00:27:10": "Intel",
    # Broadcom
    "00:10:18": "Broadcom",
    "00:0A:F7": "Broadcom",
    "00:05:B5": "Broadcom",
    "00:0A:F7": "Broadcom",
    "00:16:21": "Broadcom",
    "00:1B:E9": "Broadcom",
    "00:1D:D0": "Broadcom",
    "00:1E:BD": "Broadcom",
    "00:22:5F": "Broadcom",
    "00:24:A5": "Broadcom",
    "00:26:86": "Broadcom",
    # Qualcomm / Qualcomm Atheros
    "00:03:7F": "Qualcomm Atheros",
    "00:0B:6B": "Qualcomm Atheros",
    "00:0C:42": "Qualcomm Atheros",
    "00:0E:6D": "Qualcomm Atheros",
    "00:13:74": "Qualcomm Atheros",
    "00:15:AF": "Qualcomm Atheros",
    "00:1A:6B": "Qualcomm Atheros",
    "00:1C:14": "Qualcomm Atheros",
    "00:1F:1F": "Qualcomm Atheros",
    "00:20:A6": "Qualcomm Atheros",
    "00:24:6C": "Qualcomm Atheros",
    "04:F0:21": "Qualcomm Atheros",
    "1C:65:9D": "Qualcomm Atheros",
    "28:C2:DD": "Qualcomm Atheros",
    # Google
    "00:1A:11": "Google",
    "08:9E:08": "Google",
    "14:C1:4E": "Google",
    "18:D6:C7": "Google",
    "30:FD:38": "Google",
    "34:68:95": "Google",
    "3C:5A:B4": "Google",
    "44:07:0B": "Google",
    "48:D6:D5": "Google",
    "54:60:09": "Google",
    "58:CB:52": "Google",
    "5C:E8:83": "Google",
    "6C:AD:F8": "Google",
    "94:EB:2C": "Google",
    "A4:77:33": "Google",
    "F0:EF:86": "Google",
    "F4:F5:D8": "Google",
    "F4:F5:E8": "Google",
    # Amazon
    "00:BB:3A": "Amazon",
    "00:FC:8B": "Amazon",
    "04:E5:98": "Amazon",
    "08:84:9D": "Amazon",
    "0C:47:C9": "Amazon",
    "10:CE:A9": "Amazon",
    "14:91:82": "Amazon",
    "18:74:2E": "Amazon",
    "24:4C:E3": "Amazon",
    "34:D2:70": "Amazon",
    "38:F7:3D": "Amazon",
    "40:A2:DB": "Amazon",
    "44:65:0D": "Amazon",
    "50:DC:E7": "Amazon",
    "68:37:E9": "Amazon",
    "68:54:FD": "Amazon",
    "6C:56:97": "Amazon",
    "74:75:48": "Amazon",
    "74:C2:46": "Amazon",
    "78:E1:03": "Amazon",
    "84:D6:D0": "Amazon",
    "A0:02:DC": "Amazon",
    "AC:63:BE": "Amazon",
    "B4:7C:9C": "Amazon",
    "B4:A2:EB": "Amazon",
    "C8:9F:42": "Amazon",
    "CC:F7:35": "Amazon",
    "F0:27:2D": "Amazon",
    "F0:D2:F1": "Amazon",
    "F0:F0:A4": "Amazon",
    "FC:65:DE": "Amazon",
    # Microsoft
    "00:03:FF": "Microsoft",
    "00:0D:3A": "Microsoft",
    "00:12:5A": "Microsoft",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:17:FA": "Microsoft",
    "00:1D:D8": "Microsoft",
    "00:22:48": "Microsoft",
    "00:25:AE": "Microsoft",
    "00:50:F2": "Microsoft",
    "28:18:78": "Microsoft",
    "30:59:B7": "Microsoft",
    "3C:83:75": "Microsoft",
    "48:50:73": "Microsoft",
    "50:1A:C5": "Microsoft",
    "58:82:A8": "Microsoft",
    "60:45:BD": "Microsoft",
    "7C:1E:52": "Microsoft",
    "7C:ED:8D": "Microsoft",
    "98:5F:D3": "Microsoft",
    "B4:0E:DE": "Microsoft",
    "B8:31:B5": "Microsoft",
    "C4:9D:ED": "Microsoft",
    "C8:3F:26": "Microsoft",
    "DC:B4:C4": "Microsoft",
    # TP-Link
    "00:27:19": "TP-Link",
    "14:CC:20": "TP-Link",
    "18:A6:F7": "TP-Link",
    "1C:3B:F3": "TP-Link",
    "30:B5:C2": "TP-Link",
    "50:C7:BF": "TP-Link",
    "54:C8:0F": "TP-Link",
    "5C:E9:31": "TP-Link",
    "60:E3:27": "TP-Link",
    "64:56:01": "TP-Link",
    "6C:5A:B0": "TP-Link",
    "78:44:76": "TP-Link",
    "90:F6:52": "TP-Link",
    "98:DA:C4": "TP-Link",
    "AC:84:C6": "TP-Link",
    "B0:4E:26": "TP-Link",
    "B0:95:75": "TP-Link",
    "C0:25:E9": "TP-Link",
    "C0:E3:FB": "TP-Link",
    "D8:07:B6": "TP-Link",
    "E8:DE:27": "TP-Link",
    "EC:08:6B": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "F8:D1:11": "TP-Link",
    # Netgear
    "00:09:5B": "Netgear",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear",
    "00:1F:33": "Netgear",
    "00:22:3F": "Netgear",
    "00:24:B2": "Netgear",
    "00:26:F2": "Netgear",
    "08:BD:43": "Netgear",
    "10:0D:7F": "Netgear",
    "10:DA:43": "Netgear",
    "20:0C:C8": "Netgear",
    "28:C6:8E": "Netgear",
    "2C:B0:5D": "Netgear",
    "30:46:9A": "Netgear",
    "3C:37:86": "Netgear",
    "44:94:FC": "Netgear",
    "4C:60:DE": "Netgear",
    "6C:B0:CE": "Netgear",
    "84:1B:5E": "Netgear",
    "8C:3B:AD": "Netgear",
    "9C:3D:CF": "Netgear",
    "A0:04:60": "Netgear",
    "A4:2B:8C": "Netgear",
    "B0:7F:B9": "Netgear",
    "C0:3F:0E": "Netgear",
    "C4:04:15": "Netgear",
    "CC:40:D0": "Netgear",
    "E0:46:9A": "Netgear",
    "E0:91:F5": "Netgear",
    "E4:F4:C6": "Netgear",
    # Cisco / Cisco Meraki
    "00:00:0C": "Cisco",
    "00:01:42": "Cisco",
    "00:01:43": "Cisco",
    "00:01:63": "Cisco",
    "00:01:64": "Cisco",
    "00:01:96": "Cisco",
    "00:01:97": "Cisco",
    "00:01:C7": "Cisco",
    "00:01:C9": "Cisco",
    "00:02:16": "Cisco",
    "00:02:17": "Cisco",
    "00:02:3D": "Cisco",
    "00:02:4A": "Cisco",
    "00:02:4B": "Cisco",
    "00:02:7D": "Cisco",
    "00:02:7E": "Cisco",
    "00:02:B9": "Cisco",
    "00:02:BA": "Cisco",
    "00:02:FC": "Cisco",
    "00:02:FD": "Cisco",
    "00:03:31": "Cisco",
    "00:03:32": "Cisco",
    "00:03:6B": "Cisco",
    "00:18:0A": "Cisco Meraki",
    "00:18:74": "Cisco Meraki",
    "0C:8D:DB": "Cisco Meraki",
    # Huawei
    "00:1E:10": "Huawei",
    "00:18:82": "Huawei",
    "00:25:9E": "Huawei",
    "00:25:68": "Huawei",
    "00:46:4B": "Huawei",
    "00:66:4B": "Huawei",
    "00:E0:FC": "Huawei",
    "04:02:1F": "Huawei",
    "04:BD:70": "Huawei",
    "04:C0:6F": "Huawei",
    "04:F9:38": "Huawei",
    "08:19:A6": "Huawei",
    "08:63:61": "Huawei",
    "0C:37:DC": "Huawei",
    "0C:45:BA": "Huawei",
    "10:1B:54": "Huawei",
    "10:44:00": "Huawei",
    "10:47:80": "Huawei",
    "10:C6:1F": "Huawei",
    # Raspberry Pi Foundation
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    # Espressif (ESP32/ESP8266)
    "24:0A:C4": "Espressif",
    "24:6F:28": "Espressif",
    "24:B2:DE": "Espressif",
    "2C:F4:32": "Espressif",
    "30:AE:A4": "Espressif",
    "3C:61:05": "Espressif",
    "3C:71:BF": "Espressif",
    "40:F5:20": "Espressif",
    "4C:11:AE": "Espressif",
    "54:5A:A6": "Espressif",
    "5C:CF:7F": "Espressif",
    "60:01:94": "Espressif",
    "68:C6:3A": "Espressif",
    "7C:9E:BD": "Espressif",
    "80:7D:3A": "Espressif",
    "84:0D:8E": "Espressif",
    "84:CC:A8": "Espressif",
    "84:F3:EB": "Espressif",
    "8C:AA:B5": "Espressif",
    "90:97:D5": "Espressif",
    "94:B5:55": "Espressif",
    "98:CD:AC": "Espressif",
    "A0:20:A6": "Espressif",
    "A4:7B:9D": "Espressif",
    "A4:CF:12": "Espressif",
    "AC:67:B2": "Espressif",
    "B4:E6:2D": "Espressif",
    "BC:DD:C2": "Espressif",
    "C4:4F:33": "Espressif",
    "C4:5B:BE": "Espressif",
    "CC:50:E3": "Espressif",
    "D8:A0:1D": "Espressif",
    "D8:BF:C0": "Espressif",
    "DC:4F:22": "Espressif",
    "E0:98:06": "Espressif",
    "EC:FA:BC": "Espressif",
    "F0:08:D1": "Espressif",
    "F4:CF:A2": "Espressif",
    # Xiaomi
    "00:9E:C8": "Xiaomi",
    "04:CF:8C": "Xiaomi",
    "0C:1D:AF": "Xiaomi",
    "10:2A:B3": "Xiaomi",
    "14:F6:5A": "Xiaomi",
    "18:59:36": "Xiaomi",
    "20:47:DA": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi",
    "38:A4:ED": "Xiaomi",
    "3C:BD:D8": "Xiaomi",
    "50:64:2B": "Xiaomi",
    "58:44:98": "Xiaomi",
    "64:09:80": "Xiaomi",
    "64:CC:2E": "Xiaomi",
    "68:28:BA": "Xiaomi",
    "74:23:44": "Xiaomi",
    "78:02:F8": "Xiaomi",
    "7C:1D:D9": "Xiaomi",
    "84:F3:EB": "Xiaomi",
    # Ubiquiti
    "00:15:6D": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "04:18:D6": "Ubiquiti",
    "18:E8:29": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti",
    "E0:63:DA": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    # Aruba / HP Enterprise
    "00:0B:86": "Aruba Networks",
    "00:1A:1E": "Aruba Networks",
    "00:24:6C": "Aruba Networks",
    "04:BD:88": "Aruba Networks",
    "18:64:72": "Aruba Networks",
    "20:4C:03": "Aruba Networks",
    "24:DE:C6": "Aruba Networks",
    "40:E3:D6": "Aruba Networks",
    "6C:F3:7F": "Aruba Networks",
    "84:D4:7E": "Aruba Networks",
    "94:B4:0F": "Aruba Networks",
    "9C:1C:12": "Aruba Networks",
    "AC:A3:1E": "Aruba Networks",
    "D8:C7:C8": "Aruba Networks",
    # Linksys
    "00:04:5A": "Linksys",
    "00:06:25": "Linksys",
    "00:0C:41": "Linksys",
    "00:0F:66": "Linksys",
    "00:12:17": "Linksys",
    "00:14:BF": "Linksys",
    "00:16:B6": "Linksys",
    "00:18:39": "Linksys",
    "00:18:F8": "Linksys",
    "00:1A:70": "Linksys",
    "00:1C:10": "Linksys",
    "00:1D:7E": "Linksys",
    "00:1E:E5": "Linksys",
    "00:21:29": "Linksys",
    "00:22:6B": "Linksys",
    "00:23:69": "Linksys",
    "00:25:9C": "Linksys",
    # D-Link
    "00:05:5D": "D-Link",
    "00:0D:88": "D-Link",
    "00:0F:3D": "D-Link",
    "00:11:95": "D-Link",
    "00:13:46": "D-Link",
    "00:15:E9": "D-Link",
    "00:17:9A": "D-Link",
    "00:19:5B": "D-Link",
    "00:1B:11": "D-Link",
    "00:1C:F0": "D-Link",
    "00:1E:58": "D-Link",
    "00:1F:D0": "D-Link",
    "00:21:91": "D-Link",
    "00:22:B0": "D-Link",
    "00:24:01": "D-Link",
    "00:26:5A": "D-Link",
    # VMware
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    # OnePlus
    "94:65:2D": "OnePlus",
    "C0:EE:FB": "OnePlus",
    # Realtek
    "00:E0:4C": "Realtek",
    "52:54:00": "Realtek/QEMU",
    # MediaTek
    "00:02:37": "MediaTek",
    "00:0C:E7": "MediaTek",
    "00:13:13": "MediaTek",
}


# ---------------------------------------------------------------------------
# BLE Known Service UUIDs
# ---------------------------------------------------------------------------

BLE_SERVICE_UUIDS: dict[int, str] = {
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x1802: "Immediate Alert",
    0x1803: "Link Loss",
    0x1804: "Tx Power",
    0x1805: "Current Time",
    0x1806: "Reference Time Update",
    0x1807: "Next DST Change",
    0x1808: "Glucose",
    0x1809: "Health Thermometer",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180E: "Phone Alert Status",
    0x180F: "Battery Service",
    0x1810: "Blood Pressure",
    0x1811: "Alert Notification",
    0x1812: "Human Interface Device (HID)",
    0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence",
    0x1815: "Automation IO",
    0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power",
    0x1819: "Location and Navigation",
    0x181A: "Environmental Sensing",
    0x181B: "Body Composition",
    0x181C: "User Data",
    0x181D: "Weight Scale",
    0x181E: "Bond Management",
    0x181F: "Continuous Glucose Monitoring",
    0x1820: "Internet Protocol Support",
    0x1821: "Indoor Positioning",
    0x1822: "Pulse Oximeter",
    0x1823: "HTTP Proxy",
    0x1824: "Transport Discovery",
    0x1825: "Object Transfer",
    0x1826: "Fitness Machine",
    0x1827: "Mesh Provisioning",
    0x1828: "Mesh Proxy",
    0x1829: "Reconnection Configuration",
    0xFE2C: "Google Nearby",
    0xFD6F: "COVID Exposure Notification",
    0xFE9F: "Google Fast Pair",
    0xFEAA: "Google Eddystone",
    0xFEBB: "Adafruit",
    0xFEE7: "Tencent Holdings",
    0xFFF0: "Custom Service (0xFFF0)",
    0xFFE0: "Custom Service (0xFFE0)",
}

# ---------------------------------------------------------------------------
# BLE Company Identifiers (Bluetooth SIG assigned numbers)
# ---------------------------------------------------------------------------

BLE_COMPANY_IDS: dict[int, str] = {
    0x0000: "Ericsson Technology Licensing",
    0x0001: "Nokia Mobile Phones",
    0x0002: "Intel",
    0x0003: "IBM",
    0x0004: "Toshiba",
    0x0005: "3Com",
    0x0006: "Microsoft",
    0x0007: "Lucent",
    0x0008: "Motorola",
    0x0009: "Infineon Technologies",
    0x000A: "Qualcomm Technologies International",
    0x000B: "Silicon Wave",
    0x000C: "Digianswer",
    0x000D: "Texas Instruments",
    0x000E: "Parthus Technologies",
    0x000F: "Broadcom",
    0x0010: "Mitel Semiconductor",
    0x0011: "Widcomm",
    0x0012: "Zeevo",
    0x0013: "Atmel",
    0x0014: "Mitsubishi Electric",
    0x0015: "RTX Telecom",
    0x0016: "KC Technology",
    0x0017: "NewLogic",
    0x0018: "Transilica",
    0x0019: "Rohde & Schwarz",
    0x001A: "TTPCom",
    0x004C: "Apple",
    0x0059: "Nordic Semiconductor",
    0x005D: "Realtek Semiconductor",
    0x0075: "Samsung Electronics",
    0x0078: "Nike",
    0x0087: "Garmin International",
    0x008A: "Qualcomm Technologies",
    0x00D2: "Dialog Semiconductor",
    0x00E0: "Google",
    0x010F: "Xiaomi",
    0x0131: "Huawei Technologies",
    0x015D: "Espressif",
    0x0171: "Amazon.com Services",
    0x0310: "Tile",
    0x038F: "Bose Corporation",
    0x0499: "Ruuvi Innovations",
    0x02FF: "Sonos",
    0x0600: "Ring",
}

# ---------------------------------------------------------------------------
# WiFi channel to frequency mapping
# ---------------------------------------------------------------------------

CHANNEL_FREQ_MAP_24GHZ: dict[int, int] = {
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
    6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
    11: 2462, 12: 2467, 13: 2472, 14: 2484,
}

CHANNEL_FREQ_MAP_5GHZ: dict[int, int] = {
    36: 5180, 40: 5200, 44: 5220, 48: 5240,
    52: 5260, 56: 5280, 60: 5300, 64: 5320,
    100: 5500, 104: 5520, 108: 5540, 112: 5560,
    116: 5580, 120: 5600, 124: 5620, 128: 5640,
    132: 5660, 136: 5680, 140: 5700, 144: 5720,
    149: 5745, 153: 5765, 157: 5785, 161: 5805,
    165: 5825,
}

# DFS channels in 5 GHz band (require Dynamic Frequency Selection)
DFS_CHANNELS: set[int] = {52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}

# Non-overlapping channels in 2.4 GHz band
NON_OVERLAPPING_24GHZ: set[int] = {1, 6, 11}

# ---------------------------------------------------------------------------
# Default SSID Patterns (indicate unconfigured networks)
# ---------------------------------------------------------------------------

DEFAULT_SSID_PATTERNS: list[str] = [
    "linksys",
    "netgear",
    "default",
    "dlink",
    "tp-link",
    "tplink",
    "asus",
    "belkin",
    "setup",
    "wireless",
    "wifi",
    "home",
    "xfinity",
    "att",
    "spectrum",
    "optimum",
    "verizon",
    "comcast",
    "router",
    "guest",
    "HUAWEI",
    "AndroidAP",
    "Galaxy",
    "iPhone",
    "MikroTik",
    "ZTE",
    "FRITZ!Box",
    "HomeNet",
]
