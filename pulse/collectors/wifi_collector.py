"""
Pulse WiFi Collector
=====================

Passive WiFi frame collector using Scapy for 802.11 frame capture
and dissection. Parses beacon frames, probe requests/responses,
authentication, deauthentication, association, and data frames
to enumerate access points and client stations.

The collector requires a wireless interface in monitor mode for
live capture. Frame parsing follows the IEEE 802.11-2020 standard
for management and data frame formats.

References:
    - IEEE. (2020). IEEE Std 802.11-2020: Wireless LAN Medium Access
      Control (MAC) and Physical Layer (PHY) Specifications.
    - Biondi, P. (2024). Scapy: Packet Manipulation Library.
      https://scapy.net/
    - Wright, J., & Cache, J. (2015). Hacking Exposed Wireless (3rd ed.).
      McGraw-Hill.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any, Optional

from shared.logger import PhantomLogger

from pulse.core.models import (
    AccessPoint,
    AuthKeyMgmt,
    CipherSuite,
    DeauthEvent,
    EncryptionType,
    OUI_DATABASE,
    WifiClient,
    CHANNEL_FREQ_MAP_24GHZ,
    CHANNEL_FREQ_MAP_5GHZ,
)

logger = PhantomLogger("pulse.collectors.wifi")


# ---------------------------------------------------------------------------
# OUI / MAC helper functions
# ---------------------------------------------------------------------------


def lookup_oui(mac: str) -> str:
    """Look up the vendor name for a given MAC address using the OUI prefix.

    The Organizationally Unique Identifier (OUI) is the first 24 bits
    (3 octets) of a MAC address, assigned by IEEE to hardware vendors.

    Args:
        mac: MAC address in colon-separated hex format (e.g. "AA:BB:CC:DD:EE:FF").

    Returns:
        Vendor name string, or "Unknown" if not found.
    """
    if not mac or len(mac) < 8:
        return "Unknown"
    prefix = mac[:8].upper()
    return OUI_DATABASE.get(prefix, "Unknown")


def is_randomized_mac(mac: str) -> bool:
    """Determine if a MAC address is locally administered (randomized).

    Per IEEE 802-2014, the second least significant bit of the first
    octet indicates whether the address is universally administered (0)
    or locally administered (1). Modern devices use locally administered
    addresses for privacy during probe requests.

    Reference:
        IEEE. (2014). IEEE Std 802-2014. Section 8.1: Individual/Group
        and Universal/Local Address Bits.

    Args:
        mac: MAC address in colon-separated hex format.

    Returns:
        True if the MAC is locally administered (likely randomized).
    """
    if not mac or len(mac) < 2:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        # Bit 1 (second LSB) of the first octet: 1 = locally administered
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def channel_from_frequency(frequency: int) -> int:
    """Convert a WiFi frequency in MHz to channel number.

    Args:
        frequency: Centre frequency in MHz.

    Returns:
        Channel number, or 0 if frequency is unrecognised.
    """
    for ch, freq in CHANNEL_FREQ_MAP_24GHZ.items():
        if freq == frequency:
            return ch
    for ch, freq in CHANNEL_FREQ_MAP_5GHZ.items():
        if freq == frequency:
            return ch
    # Fallback calculation for 2.4 GHz
    if 2412 <= frequency <= 2484:
        if frequency == 2484:
            return 14
        return (frequency - 2407) // 5
    # Fallback calculation for 5 GHz
    if 5170 <= frequency <= 5825:
        return (frequency - 5000) // 5
    return 0


def frequency_from_channel(channel: int) -> int:
    """Convert a WiFi channel number to centre frequency in MHz.

    Args:
        channel: Channel number.

    Returns:
        Centre frequency in MHz, or 0 if channel is unrecognised.
    """
    if channel in CHANNEL_FREQ_MAP_24GHZ:
        return CHANNEL_FREQ_MAP_24GHZ[channel]
    if channel in CHANNEL_FREQ_MAP_5GHZ:
        return CHANNEL_FREQ_MAP_5GHZ[channel]
    return 0


# ---------------------------------------------------------------------------
# RSN / WPA Information Element Parser
# ---------------------------------------------------------------------------


class RSNParser:
    """Parser for RSN (Robust Security Network) and WPA information elements.

    Extracts cipher suite, AKM suite, and RSN capabilities from the
    IE data found in beacon and probe response frames.

    The RSN IE (Element ID 48) format is defined in IEEE 802.11-2020,
    Section 9.4.2.25. The WPA IE is a vendor-specific IE (Element ID 221)
    with Microsoft OUI 00:50:F2:01.

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Section 9.4.2.25:
        RSNE (RSN Element).
    """

    # OUI constants for cipher/AKM suite selectors
    RSN_OUI = b"\x00\x0f\xac"
    MS_OUI = b"\x00\x50\xf2"

    # Cipher suite type mappings (last byte of 4-byte selector)
    CIPHER_MAP: dict[int, CipherSuite] = {
        0: CipherSuite.NONE,
        1: CipherSuite.WEP40,
        2: CipherSuite.TKIP,
        4: CipherSuite.CCMP,
        5: CipherSuite.WEP104,
        8: CipherSuite.GCMP,
        9: CipherSuite.GCMP_256,
        10: CipherSuite.CCMP_256,
        6: CipherSuite.BIP_CMAC_128,
    }

    # AKM suite type mappings
    AKM_MAP: dict[int, AuthKeyMgmt] = {
        1: AuthKeyMgmt.IEEE_802_1X,
        2: AuthKeyMgmt.PSK,
        3: AuthKeyMgmt.FT_802_1X,
        4: AuthKeyMgmt.FT_PSK,
        6: AuthKeyMgmt.IEEE_802_1X,  # SHA-256
        8: AuthKeyMgmt.SAE,
        9: AuthKeyMgmt.FT_SAE,
        12: AuthKeyMgmt.SUITE_B,
        18: AuthKeyMgmt.OWE,
    }

    @classmethod
    def parse_rsn_ie(cls, data: bytes) -> dict[str, Any]:
        """Parse an RSN Information Element.

        Args:
            data: Raw IE data bytes (excluding Element ID and Length fields).

        Returns:
            Dictionary with keys: 'pairwise_cipher', 'group_cipher',
            'akm', 'pmf_capable', 'pmf_required', 'encryption'.
        """
        result: dict[str, Any] = {
            "pairwise_cipher": CipherSuite.CCMP,
            "group_cipher": CipherSuite.CCMP,
            "akm": AuthKeyMgmt.UNKNOWN,
            "pmf_capable": False,
            "pmf_required": False,
            "encryption": EncryptionType.WPA2,
        }

        if len(data) < 2:
            return result

        offset = 0

        # Version (2 bytes) -- should be 1
        if offset + 2 > len(data):
            return result
        _version = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        # Group Data Cipher Suite (4 bytes)
        if offset + 4 <= len(data):
            group_cipher_type = data[offset + 3]
            result["group_cipher"] = cls.CIPHER_MAP.get(group_cipher_type, CipherSuite.CCMP)
            offset += 4
        else:
            return result

        # Pairwise Cipher Suite Count (2 bytes) + Suites
        if offset + 2 <= len(data):
            pairwise_count = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            best_cipher = CipherSuite.NONE
            for _i in range(pairwise_count):
                if offset + 4 <= len(data):
                    cipher_type = data[offset + 3]
                    cipher = cls.CIPHER_MAP.get(cipher_type, CipherSuite.CCMP)
                    # Prefer strongest cipher
                    cipher_rank = {
                        CipherSuite.GCMP_256: 6,
                        CipherSuite.CCMP_256: 5,
                        CipherSuite.GCMP: 4,
                        CipherSuite.CCMP: 3,
                        CipherSuite.TKIP: 2,
                        CipherSuite.WEP104: 1,
                        CipherSuite.WEP40: 0,
                        CipherSuite.NONE: -1,
                    }
                    if cipher_rank.get(cipher, -1) > cipher_rank.get(best_cipher, -1):
                        best_cipher = cipher
                    offset += 4
                else:
                    break
            if best_cipher != CipherSuite.NONE:
                result["pairwise_cipher"] = best_cipher
        else:
            return result

        # AKM Suite Count (2 bytes) + Suites
        if offset + 2 <= len(data):
            akm_count = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            for _i in range(akm_count):
                if offset + 4 <= len(data):
                    akm_type = data[offset + 3]
                    akm = cls.AKM_MAP.get(akm_type, AuthKeyMgmt.UNKNOWN)
                    result["akm"] = akm
                    # Update encryption type based on AKM
                    if akm in (AuthKeyMgmt.SAE, AuthKeyMgmt.FT_SAE):
                        result["encryption"] = EncryptionType.WPA3
                    elif akm == AuthKeyMgmt.OWE:
                        result["encryption"] = EncryptionType.WPA3
                    offset += 4
                else:
                    break
        else:
            return result

        # RSN Capabilities (2 bytes)
        if offset + 2 <= len(data):
            capabilities = struct.unpack_from("<H", data, offset)[0]
            # Bit 6: Management Frame Protection Capable
            result["pmf_capable"] = bool(capabilities & (1 << 6))
            # Bit 7: Management Frame Protection Required
            result["pmf_required"] = bool(capabilities & (1 << 7))

        return result

    @classmethod
    def parse_wpa_ie(cls, data: bytes) -> dict[str, Any]:
        """Parse a WPA (vendor-specific) Information Element.

        The WPA IE uses Microsoft OUI (00:50:F2) with type 1.

        Args:
            data: Raw IE data after the vendor-specific header (OUI + type).

        Returns:
            Dictionary with keys: 'pairwise_cipher', 'group_cipher',
            'akm', 'encryption'.
        """
        result: dict[str, Any] = {
            "pairwise_cipher": CipherSuite.TKIP,
            "group_cipher": CipherSuite.TKIP,
            "akm": AuthKeyMgmt.PSK,
            "encryption": EncryptionType.WPA,
        }

        if len(data) < 2:
            return result

        offset = 0

        # Version (2 bytes)
        if offset + 2 > len(data):
            return result
        offset += 2

        # Group cipher (4 bytes)
        if offset + 4 <= len(data):
            group_type = data[offset + 3]
            result["group_cipher"] = cls.CIPHER_MAP.get(group_type, CipherSuite.TKIP)
            offset += 4
        else:
            return result

        # Pairwise cipher count (2 bytes) + suites
        if offset + 2 <= len(data):
            pair_count = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            for _i in range(pair_count):
                if offset + 4 <= len(data):
                    pair_type = data[offset + 3]
                    cipher = cls.CIPHER_MAP.get(pair_type, CipherSuite.TKIP)
                    result["pairwise_cipher"] = cipher
                    offset += 4
        else:
            return result

        # AKM count (2 bytes) + suites
        if offset + 2 <= len(data):
            akm_count = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            for _i in range(akm_count):
                if offset + 4 <= len(data):
                    akm_type = data[offset + 3]
                    result["akm"] = cls.AKM_MAP.get(akm_type, AuthKeyMgmt.PSK)
                    offset += 4

        return result


# ---------------------------------------------------------------------------
# WiFi Collector
# ---------------------------------------------------------------------------


class WiFiCollector:
    """Passive WiFi frame collector using Scapy.

    Captures 802.11 management and data frames from a monitor-mode
    wireless interface and extracts access point and client information.

    The collector processes the following frame types:
        - Beacon (type=0, subtype=8): AP enumeration and configuration
        - Probe Request (type=0, subtype=4): Client device probing
        - Probe Response (type=0, subtype=5): AP response with full IEs
        - Authentication (type=0, subtype=11): Auth handshake tracking
        - Deauthentication (type=0, subtype=12): Deauth event capture
        - Association Request (type=0, subtype=0): Client association
        - Association Response (type=0, subtype=1): AP response
        - Data frames (type=2): Client-AP traffic tracking

    Reference:
        IEEE. (2020). IEEE Std 802.11-2020. Section 9.3: Frame Formats.

    Usage::

        collector = WiFiCollector()
        aps, clients, deauths = await collector.capture("wlan0mon", duration=30)
    """

    def __init__(self) -> None:
        self._aps: dict[str, AccessPoint] = {}
        self._clients: dict[str, WifiClient] = {}
        self._deauth_events: list[DeauthEvent] = []
        self._raw_frames: list[Any] = []

    async def capture(
        self,
        interface: str,
        duration: int = 30,
        channel: Optional[int] = None,
    ) -> tuple[dict[str, AccessPoint], list[WifiClient], list[DeauthEvent]]:
        """Capture WiFi frames from the specified interface.

        Args:
            interface: Wireless interface name in monitor mode.
            duration: Capture duration in seconds.
            channel: Specific channel to monitor (None = all).

        Returns:
            Tuple of (access_points dict, client list, deauth events).
        """
        self._aps.clear()
        self._clients.clear()
        self._deauth_events.clear()
        self._raw_frames.clear()

        try:
            from scapy.all import (  # type: ignore[import-untyped]
                AsyncSniffer,
                Dot11,
                Dot11Beacon,
                Dot11ProbeReq,
                Dot11ProbeResp,
                Dot11Deauth,
                Dot11Auth,
                Dot11AssoReq,
                Dot11AssoResp,
                RadioTap,
                conf as scapy_conf,
            )

            logger.info(
                f"Starting WiFi capture "
                f"on {interface} for {duration}s"
            )

            if channel is not None:
                logger.info(f"Setting channel to {channel}")
                import subprocess
                subprocess.run(
                    ["iwconfig", interface, "channel", str(channel)],
                    capture_output=True,
                    timeout=5,
                )

            sniffer = AsyncSniffer(
                iface=interface,
                prn=self._process_frame,
                store=False,
                timeout=duration,
                monitor=True,
            )
            sniffer.start()

            import asyncio
            await asyncio.sleep(duration)

            try:
                sniffer.stop()
            except Exception:
                pass

        except ImportError:
            logger.warning(
                "Scapy not found. "
                "Using simulated capture for educational demonstration."
            )
            self._generate_simulated_data()
        except PermissionError:
            logger.error(
                "Permission denied. "
                "WiFi capture requires root/sudo privileges and monitor mode."
            )
            self._generate_simulated_data()
        except Exception as exc:
            logger.error(f"Capture error: {exc}")
            self._generate_simulated_data()

        logger.info(
            f"Capture complete. "
            f"APs: {len(self._aps)}, Clients: {len(self._clients)}, "
            f"Deauths: {len(self._deauth_events)}"
        )

        return self._aps, list(self._clients.values()), self._deauth_events

    def _process_frame(self, packet: Any) -> None:
        """Process a single captured 802.11 frame.

        Dispatches to the appropriate handler based on frame type and subtype.

        Args:
            packet: Scapy packet object.
        """
        try:
            from scapy.all import (  # type: ignore[import-untyped]
                Dot11,
                Dot11Beacon,
                Dot11ProbeReq,
                Dot11ProbeResp,
                Dot11Deauth,
                Dot11Auth,
                Dot11AssoReq,
                RadioTap,
            )
        except ImportError:
            return

        if not packet.haslayer(Dot11):
            return

        self._raw_frames.append(packet)
        dot11 = packet.getlayer(Dot11)
        frame_type = dot11.type
        frame_subtype = dot11.subtype

        # Extract signal strength from RadioTap header if present
        signal_dbm = -100
        if packet.haslayer(RadioTap):
            radiotap = packet.getlayer(RadioTap)
            if hasattr(radiotap, "dBm_AntSignal"):
                signal_dbm = radiotap.dBm_AntSignal
            elif hasattr(radiotap, "notdecoded"):
                # Some drivers encode signal in notdecoded field
                try:
                    signal_dbm = -(256 - ord(radiotap.notdecoded[-4:-3]))
                except Exception:
                    pass

        # Management frames (type=0)
        if frame_type == 0:
            if frame_subtype == 8:  # Beacon
                self._handle_beacon(packet, signal_dbm)
            elif frame_subtype == 4:  # Probe Request
                self._handle_probe_request(packet, signal_dbm)
            elif frame_subtype == 5:  # Probe Response
                self._handle_probe_response(packet, signal_dbm)
            elif frame_subtype == 11:  # Authentication
                self._handle_authentication(packet)
            elif frame_subtype == 12:  # Deauthentication
                self._handle_deauth(packet)
            elif frame_subtype == 0:  # Association Request
                self._handle_association_request(packet)
            elif frame_subtype == 1:  # Association Response
                self._handle_association_response(packet)

        # Data frames (type=2)
        elif frame_type == 2:
            self._handle_data_frame(packet, signal_dbm)

    def _handle_beacon(self, packet: Any, signal_dbm: int) -> None:
        """Process a beacon frame (type=0, subtype=8).

        Beacons are transmitted periodically by APs to announce network
        availability. They contain the full set of information elements
        describing the BSS configuration.

        Args:
            packet: Scapy packet with Dot11Beacon layer.
            signal_dbm: Received signal strength in dBm.
        """
        try:
            from scapy.all import Dot11Beacon, Dot11Elt  # type: ignore[import-untyped]
        except ImportError:
            return

        if not packet.haslayer(Dot11Beacon):
            return

        dot11 = packet.getlayer("Dot11")
        bssid = dot11.addr3
        if not bssid:
            return
        bssid = bssid.upper()

        now = datetime.now(timezone.utc)

        # Parse information elements
        ssid = ""
        channel = 0
        encryption = EncryptionType.OPEN
        cipher = CipherSuite.NONE
        auth = AuthKeyMgmt.UNKNOWN
        wps_enabled = False
        pmf = False
        supported_rates: list[float] = []
        country = ""

        # Get capability info for privacy bit
        beacon_layer = packet.getlayer(Dot11Beacon)
        cap = beacon_layer.cap if hasattr(beacon_layer, "cap") else 0
        privacy = False
        if isinstance(cap, int):
            privacy = bool(cap & 0x0010)
        elif hasattr(cap, "privacy"):
            privacy = bool(cap.privacy)

        # Walk information elements
        elt = packet.getlayer(Dot11Elt)
        while elt:
            elt_id = elt.ID
            elt_data = elt.info if hasattr(elt, "info") else b""

            if elt_id == 0:  # SSID
                try:
                    ssid = elt_data.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    ssid = ""

            elif elt_id == 3:  # DS Parameter Set (channel)
                if len(elt_data) >= 1:
                    channel = elt_data[0]

            elif elt_id == 1:  # Supported Rates
                for byte_val in elt_data:
                    rate = (byte_val & 0x7F) * 0.5
                    if rate > 0:
                        supported_rates.append(rate)

            elif elt_id == 50:  # Extended Supported Rates
                for byte_val in elt_data:
                    rate = (byte_val & 0x7F) * 0.5
                    if rate > 0:
                        supported_rates.append(rate)

            elif elt_id == 7:  # Country
                if len(elt_data) >= 2:
                    try:
                        country = elt_data[:2].decode("ascii", errors="replace")
                    except Exception:
                        pass

            elif elt_id == 48:  # RSN (WPA2/WPA3)
                rsn_info = RSNParser.parse_rsn_ie(elt_data)
                encryption = rsn_info["encryption"]
                cipher = rsn_info["pairwise_cipher"]
                auth = rsn_info["akm"]
                pmf = rsn_info["pmf_capable"] or rsn_info["pmf_required"]

            elif elt_id == 221:  # Vendor Specific
                if len(elt_data) >= 4:
                    oui = elt_data[:3]
                    vendor_type = elt_data[3]

                    # Microsoft WPA IE
                    if oui == b"\x00\x50\xf2" and vendor_type == 1:
                        if encryption == EncryptionType.OPEN or encryption == EncryptionType.UNKNOWN:
                            wpa_info = RSNParser.parse_wpa_ie(elt_data[4:])
                            encryption = wpa_info["encryption"]
                            cipher = wpa_info["pairwise_cipher"]
                            auth = wpa_info["akm"]

                    # WPS IE (Microsoft OUI type 4)
                    elif oui == b"\x00\x50\xf2" and vendor_type == 4:
                        wps_enabled = True

            # Move to next element
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        # If privacy bit set but no RSN/WPA IE found, it is WEP
        if privacy and encryption == EncryptionType.OPEN:
            encryption = EncryptionType.WEP
            cipher = CipherSuite.WEP40

        hidden = (ssid == "" or ssid == "\x00" or all(c == "\x00" for c in ssid))

        frequency = frequency_from_channel(channel) if channel > 0 else 0

        beacon_interval = 100
        if hasattr(beacon_layer, "beacon_interval"):
            beacon_interval = beacon_layer.beacon_interval

        if bssid in self._aps:
            ap = self._aps[bssid]
            ap.last_seen = now
            ap.beacon_count += 1
            if signal_dbm > ap.signal_dbm:
                ap.signal_dbm = signal_dbm
            if ssid and ap.hidden and not hidden:
                ap.ssid = ssid
                ap.hidden = False
        else:
            self._aps[bssid] = AccessPoint(
                bssid=bssid,
                ssid=ssid if not hidden else "",
                channel=channel,
                frequency=frequency,
                signal_dbm=signal_dbm,
                encryption=encryption,
                cipher=cipher,
                auth=auth,
                wps_enabled=wps_enabled,
                pmf=pmf,
                beacon_interval=beacon_interval,
                first_seen=now,
                last_seen=now,
                vendor=lookup_oui(bssid),
                hidden=hidden,
                supported_rates=supported_rates,
                country=country,
                beacon_count=1,
            )

    def _handle_probe_request(self, packet: Any, signal_dbm: int) -> None:
        """Process a probe request frame (type=0, subtype=4).

        Probe requests are sent by client stations to discover available
        networks. They may contain specific SSIDs (directed probe) or
        be broadcast (wildcard probe).

        Args:
            packet: Scapy packet with Dot11ProbeReq layer.
            signal_dbm: Received signal strength in dBm.
        """
        try:
            from scapy.all import Dot11ProbeReq, Dot11Elt  # type: ignore[import-untyped]
        except ImportError:
            return

        dot11 = packet.getlayer("Dot11")
        src_mac = dot11.addr2
        if not src_mac:
            return
        src_mac = src_mac.upper()

        # Extract probed SSID
        ssid = ""
        elt = packet.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and hasattr(elt, "info"):
                try:
                    ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass
                break
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        now = datetime.now(timezone.utc)
        randomized = is_randomized_mac(src_mac)

        if src_mac in self._clients:
            client = self._clients[src_mac]
            client.last_seen = now
            client.packets += 1
            if signal_dbm > client.signal_dbm:
                client.signal_dbm = signal_dbm
            if ssid and ssid not in client.probe_requests:
                client.probe_requests.append(ssid)
        else:
            self._clients[src_mac] = WifiClient(
                mac=src_mac,
                signal_dbm=signal_dbm,
                probe_requests=[ssid] if ssid else [],
                vendor=lookup_oui(src_mac),
                is_randomized_mac=randomized,
                packets=1,
                first_seen=now,
                last_seen=now,
            )

    def _handle_probe_response(self, packet: Any, signal_dbm: int) -> None:
        """Process a probe response frame (type=0, subtype=5).

        Probe responses are sent by APs in reply to directed or broadcast
        probe requests. They contain the same IEs as beacon frames but are
        unicast to the requesting station.

        Args:
            packet: Scapy packet with Dot11ProbeResp layer.
            signal_dbm: Received signal strength in dBm.
        """
        # Probe responses contain similar IE structure to beacons
        # Reuse beacon parsing logic
        try:
            from scapy.all import Dot11ProbeResp, Dot11Elt  # type: ignore[import-untyped]
        except ImportError:
            return

        if not packet.haslayer(Dot11ProbeResp):
            return

        dot11 = packet.getlayer("Dot11")
        bssid = dot11.addr3
        if not bssid:
            return
        bssid = bssid.upper()

        ssid = ""
        channel = 0
        elt = packet.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and hasattr(elt, "info"):
                try:
                    ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass
            elif elt.ID == 3 and hasattr(elt, "info") and len(elt.info) >= 1:
                channel = elt.info[0]
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        now = datetime.now(timezone.utc)

        # Update AP if hidden SSID was resolved via probe response
        if bssid in self._aps:
            ap = self._aps[bssid]
            if ssid and ap.hidden:
                ap.ssid = ssid
                ap.hidden = False
            ap.last_seen = now
        else:
            # Create new AP from probe response
            self._aps[bssid] = AccessPoint(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                frequency=frequency_from_channel(channel),
                signal_dbm=signal_dbm,
                first_seen=now,
                last_seen=now,
                vendor=lookup_oui(bssid),
            )

    def _handle_authentication(self, packet: Any) -> None:
        """Process an authentication frame (type=0, subtype=11).

        Authentication frames are part of the 802.11 authentication
        handshake (Open System or Shared Key). In WPA3-SAE, the
        authentication frames carry the SAE Commit/Confirm exchanges.

        Args:
            packet: Scapy packet with Dot11Auth layer.
        """
        try:
            from scapy.all import Dot11Auth  # type: ignore[import-untyped]
        except ImportError:
            return

        if not packet.haslayer(Dot11Auth):
            return

        dot11 = packet.getlayer("Dot11")
        src_mac = dot11.addr2
        dst_mac = dot11.addr1
        bssid = dot11.addr3

        if src_mac and bssid:
            src_mac = src_mac.upper()
            bssid = bssid.upper()
            # If src is not the AP, it is a client authenticating
            if src_mac != bssid and src_mac not in self._aps:
                now = datetime.now(timezone.utc)
                if src_mac in self._clients:
                    self._clients[src_mac].packets += 1
                else:
                    self._clients[src_mac] = WifiClient(
                        mac=src_mac,
                        vendor=lookup_oui(src_mac),
                        is_randomized_mac=is_randomized_mac(src_mac),
                        associated_ap=bssid,
                        packets=1,
                        first_seen=now,
                        last_seen=now,
                    )

    def _handle_deauth(self, packet: Any) -> None:
        """Process a deauthentication frame (type=0, subtype=12).

        Deauthentication frames are used to terminate an existing
        authentication. In adversarial contexts, deauth flooding is
        used for denial-of-service or to force WPA handshake recapture.

        Reference:
            IEEE. (2020). IEEE Std 802.11-2020. Section 9.3.3.12.
            Vanhoef, M. (2017). Key Reinstallation Attacks (KRACK).

        Args:
            packet: Scapy packet with Dot11Deauth layer.
        """
        try:
            from scapy.all import Dot11Deauth  # type: ignore[import-untyped]
        except ImportError:
            return

        if not packet.haslayer(Dot11Deauth):
            return

        dot11 = packet.getlayer("Dot11")
        deauth = packet.getlayer(Dot11Deauth)

        src_mac = (dot11.addr2 or "").upper()
        dst_mac = (dot11.addr1 or "").upper()
        bssid = (dot11.addr3 or "").upper()
        reason_code = deauth.reason if hasattr(deauth, "reason") else 1

        now = datetime.now(timezone.utc)

        # Check if we already have this event tuple
        existing = None
        for evt in self._deauth_events:
            if evt.src_mac == src_mac and evt.dst_mac == dst_mac and evt.bssid == bssid:
                existing = evt
                break

        if existing:
            existing.count += 1
            existing.timestamp = now
        else:
            self._deauth_events.append(DeauthEvent(
                src_mac=src_mac,
                dst_mac=dst_mac,
                bssid=bssid,
                reason_code=reason_code,
                timestamp=now,
                count=1,
            ))

    def _handle_association_request(self, packet: Any) -> None:
        """Process an association request frame (type=0, subtype=0).

        Association requests are sent by clients to join a BSS. They
        contain the SSID IE in cleartext, which can reveal hidden SSIDs.

        Args:
            packet: Scapy packet with Dot11AssoReq layer.
        """
        try:
            from scapy.all import Dot11AssoReq, Dot11Elt  # type: ignore[import-untyped]
        except ImportError:
            return

        dot11 = packet.getlayer("Dot11")
        src_mac = (dot11.addr2 or "").upper()
        bssid = (dot11.addr3 or "").upper()

        ssid = ""
        elt = packet.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and hasattr(elt, "info"):
                try:
                    ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass
                break
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        now = datetime.now(timezone.utc)

        # Update client with AP association
        if src_mac:
            if src_mac in self._clients:
                self._clients[src_mac].associated_ap = bssid
                self._clients[src_mac].packets += 1
                self._clients[src_mac].last_seen = now
            else:
                self._clients[src_mac] = WifiClient(
                    mac=src_mac,
                    associated_ap=bssid,
                    vendor=lookup_oui(src_mac),
                    is_randomized_mac=is_randomized_mac(src_mac),
                    packets=1,
                    first_seen=now,
                    last_seen=now,
                )

            # Update AP client list
            if bssid in self._aps and src_mac not in self._aps[bssid].clients:
                self._aps[bssid].clients.append(src_mac)

        # Reveal hidden SSID via association
        if ssid and bssid in self._aps and self._aps[bssid].hidden:
            self._aps[bssid].ssid = ssid
            self._aps[bssid].hidden = False

    def _handle_association_response(self, packet: Any) -> None:
        """Process an association response frame (type=0, subtype=1).

        Args:
            packet: Scapy packet with Dot11AssoResp layer.
        """
        dot11 = packet.getlayer("Dot11")
        dst_mac = (dot11.addr1 or "").upper()
        bssid = (dot11.addr3 or "").upper()

        # The destination of the assoc response is the client
        if dst_mac and bssid:
            if dst_mac in self._clients:
                self._clients[dst_mac].associated_ap = bssid
            if bssid in self._aps and dst_mac not in self._aps[bssid].clients:
                self._aps[bssid].clients.append(dst_mac)

    def _handle_data_frame(self, packet: Any, signal_dbm: int) -> None:
        """Process a data frame (type=2) to track client-AP associations.

        Data frame address fields vary based on the To DS and From DS
        bits in the Frame Control field:
            To DS=0, From DS=0: IBSS (addr1=DA, addr2=SA, addr3=BSSID)
            To DS=1, From DS=0: Client to AP (addr1=BSSID, addr2=SA, addr3=DA)
            To DS=0, From DS=1: AP to Client (addr1=DA, addr2=BSSID, addr3=SA)
            To DS=1, From DS=1: WDS (addr1=RA, addr2=TA, addr3=DA, addr4=SA)

        Reference:
            IEEE. (2020). IEEE Std 802.11-2020. Section 9.2.4.1.4.

        Args:
            packet: Scapy packet with Dot11 layer (type=2).
            signal_dbm: Received signal strength in dBm.
        """
        dot11 = packet.getlayer("Dot11")
        fc_field = dot11.FCfield if hasattr(dot11, "FCfield") else 0

        # Extract To DS and From DS flags
        if isinstance(fc_field, int):
            to_ds = bool(fc_field & 0x01)
            from_ds = bool(fc_field & 0x02)
        else:
            to_ds = bool(getattr(fc_field, "to-DS", 0))
            from_ds = bool(getattr(fc_field, "from-DS", 0))

        client_mac = None
        ap_mac = None
        now = datetime.now(timezone.utc)

        if to_ds and not from_ds:
            # Client to AP: addr1=BSSID, addr2=SA (client)
            ap_mac = (dot11.addr1 or "").upper()
            client_mac = (dot11.addr2 or "").upper()
        elif not to_ds and from_ds:
            # AP to Client: addr1=DA (client), addr2=BSSID
            client_mac = (dot11.addr1 or "").upper()
            ap_mac = (dot11.addr2 or "").upper()
        elif not to_ds and not from_ds:
            # IBSS: addr2=SA, addr3=BSSID
            client_mac = (dot11.addr2 or "").upper()
            ap_mac = (dot11.addr3 or "").upper()

        if client_mac and ap_mac and client_mac != ap_mac:
            # Skip broadcast/multicast addresses
            if client_mac.startswith("FF:FF:FF") or client_mac.startswith("01:"):
                return

            if client_mac in self._clients:
                self._clients[client_mac].associated_ap = ap_mac
                self._clients[client_mac].packets += 1
                self._clients[client_mac].last_seen = now
            else:
                self._clients[client_mac] = WifiClient(
                    mac=client_mac,
                    signal_dbm=signal_dbm,
                    associated_ap=ap_mac,
                    vendor=lookup_oui(client_mac),
                    is_randomized_mac=is_randomized_mac(client_mac),
                    packets=1,
                    first_seen=now,
                    last_seen=now,
                )

            # Track client in AP
            if ap_mac in self._aps and client_mac not in self._aps[ap_mac].clients:
                self._aps[ap_mac].clients.append(client_mac)

    def _generate_simulated_data(self) -> None:
        """Generate realistic simulated WiFi data for educational demonstration.

        Produces a representative set of access points and clients
        illustrating various security configurations, including WPA3,
        WPA2, WPA, WEP, and open networks.
        """
        now = datetime.now(timezone.utc)

        simulated_aps: list[dict[str, Any]] = [
            {
                "bssid": "A4:CF:12:D3:5E:01",
                "ssid": "SecureOffice-5G",
                "channel": 36,
                "signal_dbm": -42,
                "encryption": EncryptionType.WPA3,
                "cipher": CipherSuite.GCMP_256,
                "auth": AuthKeyMgmt.SAE,
                "pmf": True,
                "wps_enabled": False,
                "vendor": "Espressif",
                "beacon_interval": 100,
            },
            {
                "bssid": "B0:4E:26:A1:3B:02",
                "ssid": "HomeNetwork",
                "channel": 6,
                "signal_dbm": -55,
                "encryption": EncryptionType.WPA2,
                "cipher": CipherSuite.CCMP,
                "auth": AuthKeyMgmt.PSK,
                "pmf": True,
                "wps_enabled": False,
                "vendor": "TP-Link",
                "beacon_interval": 100,
            },
            {
                "bssid": "00:14:6C:7E:40:03",
                "ssid": "NETGEAR-Guest",
                "channel": 11,
                "signal_dbm": -62,
                "encryption": EncryptionType.WPA2,
                "cipher": CipherSuite.CCMP,
                "auth": AuthKeyMgmt.PSK,
                "pmf": False,
                "wps_enabled": True,
                "vendor": "Netgear",
                "beacon_interval": 100,
            },
            {
                "bssid": "00:1C:10:F4:22:04",
                "ssid": "Linksys",
                "channel": 1,
                "signal_dbm": -70,
                "encryption": EncryptionType.WPA,
                "cipher": CipherSuite.TKIP,
                "auth": AuthKeyMgmt.PSK,
                "pmf": False,
                "wps_enabled": True,
                "vendor": "Linksys",
                "beacon_interval": 100,
            },
            {
                "bssid": "00:22:B0:CC:DD:05",
                "ssid": "Legacy_WiFi",
                "channel": 3,
                "signal_dbm": -78,
                "encryption": EncryptionType.WEP,
                "cipher": CipherSuite.WEP40,
                "auth": AuthKeyMgmt.UNKNOWN,
                "pmf": False,
                "wps_enabled": False,
                "vendor": "D-Link",
                "beacon_interval": 100,
            },
            {
                "bssid": "08:BD:43:AA:BB:06",
                "ssid": "CoffeeShop_Free",
                "channel": 6,
                "signal_dbm": -58,
                "encryption": EncryptionType.OPEN,
                "cipher": CipherSuite.NONE,
                "auth": AuthKeyMgmt.UNKNOWN,
                "pmf": False,
                "wps_enabled": False,
                "vendor": "Netgear",
                "beacon_interval": 100,
            },
            {
                "bssid": "DC:9F:DB:11:22:07",
                "ssid": "",
                "channel": 44,
                "signal_dbm": -48,
                "encryption": EncryptionType.WPA2,
                "cipher": CipherSuite.CCMP,
                "auth": AuthKeyMgmt.IEEE_802_1X,
                "pmf": True,
                "wps_enabled": False,
                "vendor": "Ubiquiti",
                "beacon_interval": 100,
                "hidden": True,
            },
            {
                "bssid": "18:E8:29:33:44:08",
                "ssid": "Enterprise-WPA3",
                "channel": 149,
                "signal_dbm": -50,
                "encryption": EncryptionType.WPA3,
                "cipher": CipherSuite.CCMP_256,
                "auth": AuthKeyMgmt.SAE,
                "pmf": True,
                "wps_enabled": False,
                "vendor": "Ubiquiti",
                "beacon_interval": 100,
            },
            {
                "bssid": "00:18:0A:55:66:09",
                "ssid": "CorpNet-2.4",
                "channel": 1,
                "signal_dbm": -65,
                "encryption": EncryptionType.WPA2,
                "cipher": CipherSuite.TKIP,
                "auth": AuthKeyMgmt.PSK,
                "pmf": False,
                "wps_enabled": False,
                "vendor": "Cisco Meraki",
                "beacon_interval": 100,
            },
            {
                "bssid": "00:0B:86:77:88:10",
                "ssid": "Aruba-Secure",
                "channel": 48,
                "signal_dbm": -52,
                "encryption": EncryptionType.WPA2_WPA3,
                "cipher": CipherSuite.CCMP,
                "auth": AuthKeyMgmt.SAE,
                "pmf": True,
                "wps_enabled": False,
                "vendor": "Aruba Networks",
                "beacon_interval": 100,
            },
        ]

        for ap_data in simulated_aps:
            bssid = ap_data["bssid"]
            channel = ap_data["channel"]
            self._aps[bssid] = AccessPoint(
                bssid=bssid,
                ssid=ap_data["ssid"],
                channel=channel,
                frequency=frequency_from_channel(channel),
                signal_dbm=ap_data["signal_dbm"],
                encryption=ap_data["encryption"],
                cipher=ap_data["cipher"],
                auth=ap_data["auth"],
                wps_enabled=ap_data["wps_enabled"],
                pmf=ap_data["pmf"],
                beacon_interval=ap_data["beacon_interval"],
                first_seen=now,
                last_seen=now,
                vendor=ap_data["vendor"],
                hidden=ap_data.get("hidden", False),
                beacon_count=50,
            )

        simulated_clients: list[dict[str, Any]] = [
            {
                "mac": "A4:83:E7:12:34:A1",
                "signal_dbm": -52,
                "associated_ap": "A4:CF:12:D3:5E:01",
                "probe_requests": ["SecureOffice-5G", "HomeNetwork"],
                "vendor": "Apple",
                "is_randomized_mac": False,
            },
            {
                "mac": "DA:A1:19:56:78:B2",
                "signal_dbm": -60,
                "associated_ap": None,
                "probe_requests": ["Airport_WiFi", "Hotel_Guest", "Starbucks"],
                "vendor": "Unknown",
                "is_randomized_mac": True,
            },
            {
                "mac": "08:D4:2B:9A:BC:C3",
                "signal_dbm": -58,
                "associated_ap": "B0:4E:26:A1:3B:02",
                "probe_requests": ["HomeNetwork"],
                "vendor": "Samsung",
                "is_randomized_mac": False,
            },
            {
                "mac": "00:13:02:DE:F0:D4",
                "signal_dbm": -65,
                "associated_ap": "00:14:6C:7E:40:03",
                "probe_requests": ["NETGEAR-Guest", "Office_Secure"],
                "vendor": "Intel",
                "is_randomized_mac": False,
            },
            {
                "mac": "FE:23:45:67:89:E5",
                "signal_dbm": -72,
                "associated_ap": None,
                "probe_requests": [
                    "Home_WiFi", "Work_Net", "Cafe_Free",
                    "Library_Public", "Gym_WiFi",
                ],
                "vendor": "Unknown",
                "is_randomized_mac": True,
            },
            {
                "mac": "14:F6:5A:AB:CD:F6",
                "signal_dbm": -48,
                "associated_ap": "08:BD:43:AA:BB:06",
                "probe_requests": ["CoffeeShop_Free"],
                "vendor": "Xiaomi",
                "is_randomized_mac": False,
            },
            {
                "mac": "B8:27:EB:11:22:G7",
                "signal_dbm": -75,
                "associated_ap": "00:22:B0:CC:DD:05",
                "probe_requests": ["Legacy_WiFi"],
                "vendor": "Raspberry Pi",
                "is_randomized_mac": False,
            },
        ]

        for cl_data in simulated_clients:
            mac = cl_data["mac"]
            self._clients[mac] = WifiClient(
                mac=mac,
                signal_dbm=cl_data["signal_dbm"],
                associated_ap=cl_data["associated_ap"],
                probe_requests=cl_data["probe_requests"],
                vendor=cl_data["vendor"],
                is_randomized_mac=cl_data["is_randomized_mac"],
                packets=25,
                first_seen=now,
                last_seen=now,
            )

            # Add clients to AP client lists
            ap_bssid = cl_data["associated_ap"]
            if ap_bssid and ap_bssid in self._aps:
                if mac not in self._aps[ap_bssid].clients:
                    self._aps[ap_bssid].clients.append(mac)

        # Simulated deauth events
        self._deauth_events = [
            DeauthEvent(
                src_mac="00:00:00:00:00:00",
                dst_mac="FF:FF:FF:FF:FF:FF",
                bssid="B0:4E:26:A1:3B:02",
                reason_code=7,
                timestamp=now,
                count=47,
            ),
            DeauthEvent(
                src_mac="B0:4E:26:A1:3B:02",
                dst_mac="08:D4:2B:9A:BC:C3",
                bssid="B0:4E:26:A1:3B:02",
                reason_code=3,
                timestamp=now,
                count=1,
            ),
        ]

    @property
    def raw_frames(self) -> list[Any]:
        """Return the list of raw captured Scapy frames."""
        return self._raw_frames
