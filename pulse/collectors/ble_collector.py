"""
Pulse BLE Collector
====================

Bluetooth Low Energy (BLE) device scanner and advertisement parser.
Captures BLE advertising packets on channels 37, 38, and 39 to
enumerate nearby BLE devices, extract service UUIDs, manufacturer
data, and device names.

Uses the Bleak library as the primary scanning backend with Scapy BLE
as an alternative. Provides a simulated fallback for educational
demonstration when hardware or libraries are unavailable.

References:
    - Bluetooth SIG. (2023). Bluetooth Core Specification v5.4.
      Vol 3, Part C: Generic Access Profile.
    - Bluetooth SIG. (2023). Assigned Numbers Document.
      https://www.bluetooth.com/specifications/assigned-numbers/
    - Ryan, M. (2013). Bluetooth: With Low Energy comes Low Security.
      USENIX WOOT '13.
    - Celosia, G., & Cunche, M. (2020). Discontinued Privacy: Personal
      Data Leaks in Apple Bluetooth-Low-Energy Continuity Protocols.
      PoPETs 2020(1).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from shared.logger import PhantomLogger

from pulse.core.models import (
    BLEAddressType,
    BLEDevice,
    BLE_COMPANY_IDS,
    BLE_SERVICE_UUIDS,
)

logger = PhantomLogger("pulse.collectors.ble")


# ---------------------------------------------------------------------------
# BLE company lookup
# ---------------------------------------------------------------------------


def lookup_company(manufacturer_data: bytes) -> tuple[str, str]:
    """Extract the Bluetooth SIG company identifier from manufacturer data.

    The first two bytes of manufacturer-specific advertising data contain
    the Company Identifier Code in little-endian format, assigned by the
    Bluetooth SIG.

    Reference:
        Bluetooth SIG. (2023). Assigned Numbers. Section 7.1: Company
        Identifiers.

    Args:
        manufacturer_data: Raw manufacturer-specific data bytes.

    Returns:
        Tuple of (company name, hex representation of remaining data).
    """
    if len(manufacturer_data) < 2:
        return ("Unknown", manufacturer_data.hex())

    company_id = int.from_bytes(manufacturer_data[:2], byteorder="little")
    company_name = BLE_COMPANY_IDS.get(company_id, f"Unknown (0x{company_id:04X})")
    remaining = manufacturer_data[2:].hex() if len(manufacturer_data) > 2 else ""
    return (company_name, remaining)


def resolve_service_uuid(uuid_str: str) -> str:
    """Resolve a 16-bit or 128-bit BLE service UUID to a human-readable name.

    16-bit UUIDs are defined in the Bluetooth SIG Assigned Numbers
    document. Full 128-bit UUIDs with the Bluetooth Base UUID
    (0000xxxx-0000-1000-8000-00805F9B34FB) are also resolved.

    Args:
        uuid_str: UUID string in any standard format.

    Returns:
        Human-readable service name, or the original UUID if unknown.
    """
    # Try direct 16-bit lookup
    try:
        uuid_int = int(uuid_str, 16)
        if uuid_int in BLE_SERVICE_UUIDS:
            return BLE_SERVICE_UUIDS[uuid_int]
    except (ValueError, TypeError):
        pass

    # Try extracting 16-bit UUID from 128-bit Bluetooth Base UUID
    uuid_upper = uuid_str.upper().replace("-", "")
    if len(uuid_upper) == 32:
        # Check if it matches Bluetooth Base UUID pattern
        if uuid_upper[8:] == "00001000800000805F9B34FB":
            try:
                short_uuid = int(uuid_upper[:8], 16)
                if short_uuid in BLE_SERVICE_UUIDS:
                    return BLE_SERVICE_UUIDS[short_uuid]
            except ValueError:
                pass

    return uuid_str


def classify_ble_address(address: str, address_type_hint: Optional[str] = None) -> BLEAddressType:
    """Classify a BLE address into its address type.

    BLE defines four address types:
        - Public: globally unique, assigned by IEEE
        - Random Static: randomly generated, fixed per boot cycle
        - Random Private Resolvable: uses IRK for privacy
        - Random Private Non-Resolvable: fully random, temporary

    The two MSBs of a random address indicate the sub-type:
        - 11: Static
        - 01: Non-resolvable private
        - 00: Resolvable private

    Reference:
        Bluetooth SIG. (2023). Core Specification v5.4. Vol 6, Part B,
        Section 1.3.

    Args:
        address: BLE device address in colon-separated hex format.
        address_type_hint: Optional hint from scanner ('public' or 'random').

    Returns:
        Classified BLE address type.
    """
    if address_type_hint and address_type_hint.lower() == "public":
        return BLEAddressType.PUBLIC

    if not address or len(address) < 2:
        return BLEAddressType.UNKNOWN

    try:
        first_octet = int(address.split(":")[0], 16)
    except (ValueError, IndexError):
        return BLEAddressType.UNKNOWN

    # Check two most significant bits of the first octet
    msb_two = (first_octet >> 6) & 0x03

    if address_type_hint and address_type_hint.lower() == "random":
        if msb_two == 3:  # 0b11 = Static
            return BLEAddressType.RANDOM_STATIC
        elif msb_two == 0:  # 0b00 = Resolvable private
            return BLEAddressType.RANDOM_PRIVATE_RESOLVABLE
        else:  # 0b01 = Non-resolvable private
            return BLEAddressType.RANDOM_PRIVATE_NON_RESOLVABLE

    # Without type hint, guess based on locally-administered bit
    if first_octet & 0x02:  # Locally administered
        if msb_two == 3:
            return BLEAddressType.RANDOM_STATIC
        elif msb_two == 0:
            return BLEAddressType.RANDOM_PRIVATE_RESOLVABLE
        else:
            return BLEAddressType.RANDOM_PRIVATE_NON_RESOLVABLE

    return BLEAddressType.PUBLIC


# ---------------------------------------------------------------------------
# BLE Collector
# ---------------------------------------------------------------------------


class BLECollector:
    """Bluetooth Low Energy device scanner and advertisement parser.

    Scans BLE advertising channels to discover nearby devices, extracting
    device names, service UUIDs, manufacturer data, and RSSI values.

    Primary backend: Bleak (cross-platform BLE library)
    Fallback: Simulated scan for educational demonstration

    Reference:
        Bluetooth SIG. (2023). Core Specification v5.4. Vol 3, Part C,
        Section 9: Advertising and Scan Response Data Format.

    Usage::

        collector = BLECollector()
        devices = await collector.scan(duration=10)
    """

    def __init__(self) -> None:
        self._devices: dict[str, BLEDevice] = {}

    async def scan(self, duration: int = 10) -> list[BLEDevice]:
        """Scan for BLE devices.

        Attempts to use the Bleak library for real BLE scanning.
        Falls back to simulated data if Bleak is unavailable or
        if Bluetooth hardware is not accessible.

        Args:
            duration: Scan duration in seconds.

        Returns:
            List of discovered BLE devices.
        """
        self._devices.clear()

        try:
            success = await self._scan_bleak(duration)
            if not success:
                self._generate_simulated_data()
        except Exception as exc:
            logger.warning(
                f"BLE scan error: {exc}. "
                "Using simulated data."
            )
            self._generate_simulated_data()

        logger.info(
            f"BLE scan complete. "
            f"Devices found: {len(self._devices)}"
        )

        return list(self._devices.values())

    async def _scan_bleak(self, duration: int) -> bool:
        """Scan using the Bleak BLE library.

        Bleak provides a cross-platform (Linux, macOS, Windows) BLE
        scanning API using platform-specific backends (BlueZ on Linux,
        CoreBluetooth on macOS, WinRT on Windows).

        Reference:
            Bleak Documentation. https://bleak.readthedocs.io/

        Args:
            duration: Scan duration in seconds.

        Returns:
            True if scan succeeded, False otherwise.
        """
        try:
            from bleak import BleakScanner  # type: ignore[import-untyped]
        except ImportError:
            logger.warning(
                "Bleak not found. "
                "Install with: pip install bleak"
            )
            return False

        logger.info(
            f"Starting BLE scan for {duration}s "
            "using Bleak backend"
        )

        try:
            scanner = BleakScanner(
                detection_callback=self._bleak_detection_callback,
            )
            await scanner.start()

            import asyncio
            await asyncio.sleep(duration)

            await scanner.stop()
            return True

        except Exception as exc:
            logger.error(
                f"Bleak scan error: {exc}"
            )
            return False

    def _bleak_detection_callback(self, device: Any, advertisement_data: Any) -> None:
        """Callback for Bleak scanner detection events.

        Called for each BLE advertisement received during scanning.

        Args:
            device: Bleak BLEDevice object.
            advertisement_data: Bleak AdvertisementData object.
        """
        now = datetime.now(timezone.utc)
        address = device.address.upper()

        # Determine address type
        addr_type_hint = None
        if hasattr(device, "details"):
            details = device.details
            if isinstance(details, dict) and "props" in details:
                props = details["props"]
                if isinstance(props, dict) and "AddressType" in props:
                    addr_type_hint = props["AddressType"]

        address_type = classify_ble_address(address, addr_type_hint)

        # Extract service UUIDs
        services: list[str] = []
        if hasattr(advertisement_data, "service_uuids"):
            for uuid_str in advertisement_data.service_uuids:
                resolved = resolve_service_uuid(uuid_str)
                services.append(resolved)

        # Extract manufacturer data
        company = ""
        manufacturer_hex = ""
        if hasattr(advertisement_data, "manufacturer_data"):
            for company_id, mfr_data in advertisement_data.manufacturer_data.items():
                company = BLE_COMPANY_IDS.get(company_id, f"Unknown (0x{company_id:04X})")
                manufacturer_hex = mfr_data.hex()
                break  # Use first manufacturer data entry

        # Extract TX power
        tx_power = None
        if hasattr(advertisement_data, "tx_power"):
            tx_power = advertisement_data.tx_power

        # Extract device name
        name = ""
        if hasattr(advertisement_data, "local_name") and advertisement_data.local_name:
            name = advertisement_data.local_name
        elif device.name:
            name = device.name

        rssi = advertisement_data.rssi if hasattr(advertisement_data, "rssi") else -100

        if address in self._devices:
            existing = self._devices[address]
            existing.last_seen = now
            existing.rssi = rssi
            if name and not existing.name:
                existing.name = name
            for svc in services:
                if svc not in existing.services:
                    existing.services.append(svc)
        else:
            self._devices[address] = BLEDevice(
                address=address,
                name=name,
                rssi=rssi,
                address_type=address_type,
                services=services,
                manufacturer_data=manufacturer_hex,
                company=company,
                connectable=getattr(device, "connectable", False) or False,
                tx_power=tx_power,
                first_seen=now,
                last_seen=now,
            )

    def _generate_simulated_data(self) -> None:
        """Generate simulated BLE device data for educational demonstration.

        Produces a realistic set of BLE devices spanning common device
        categories: smartphones, fitness trackers, smart home devices,
        and IoT sensors.
        """
        now = datetime.now(timezone.utc)

        simulated_devices: list[dict[str, Any]] = [
            {
                "address": "5A:3B:C1:D2:E3:F4",
                "name": "iPhone 15 Pro",
                "rssi": -45,
                "address_type": BLEAddressType.RANDOM_PRIVATE_RESOLVABLE,
                "services": ["Nearby", "Generic Access"],
                "manufacturer_data": "4c001005",
                "company": "Apple",
                "connectable": True,
                "tx_power": 7,
            },
            {
                "address": "C8:28:32:A1:B2:C3",
                "name": "Galaxy S24",
                "rssi": -52,
                "address_type": BLEAddressType.RANDOM_STATIC,
                "services": ["Generic Access", "Generic Attribute"],
                "manufacturer_data": "75000142",
                "company": "Samsung Electronics",
                "connectable": True,
                "tx_power": 8,
            },
            {
                "address": "D4:22:CD:00:76:EC",
                "name": "Fitbit Charge 6",
                "rssi": -62,
                "address_type": BLEAddressType.PUBLIC,
                "services": ["Heart Rate", "Battery Service", "Device Information"],
                "manufacturer_data": "",
                "company": "Google",
                "connectable": True,
                "tx_power": 4,
            },
            {
                "address": "A4:C1:38:E5:D6:47",
                "name": "Garmin Venu 3",
                "rssi": -58,
                "address_type": BLEAddressType.PUBLIC,
                "services": [
                    "Heart Rate",
                    "Running Speed and Cadence",
                    "Device Information",
                    "Battery Service",
                ],
                "manufacturer_data": "87001a03",
                "company": "Garmin International",
                "connectable": True,
                "tx_power": 4,
            },
            {
                "address": "E8:B4:C8:11:22:33",
                "name": "Echo Dot",
                "rssi": -40,
                "address_type": BLEAddressType.PUBLIC,
                "services": ["Generic Access", "Custom Service (0xFFF0)"],
                "manufacturer_data": "71010201",
                "company": "Amazon.com Services",
                "connectable": True,
                "tx_power": 9,
            },
            {
                "address": "F0:18:98:44:55:66",
                "name": "Tile Mate",
                "rssi": -65,
                "address_type": BLEAddressType.PUBLIC,
                "services": ["Generic Access"],
                "manufacturer_data": "1003feed",
                "company": "Tile",
                "connectable": True,
                "tx_power": 0,
            },
            {
                "address": "7A:BC:DE:F0:12:34",
                "name": "",
                "rssi": -78,
                "address_type": BLEAddressType.RANDOM_PRIVATE_NON_RESOLVABLE,
                "services": ["COVID Exposure Notification"],
                "manufacturer_data": "",
                "company": "Unknown",
                "connectable": False,
                "tx_power": -10,
            },
            {
                "address": "DC:A6:32:AB:CD:EF",
                "name": "RuuviTag #B3F4",
                "rssi": -55,
                "address_type": BLEAddressType.PUBLIC,
                "services": ["Environmental Sensing"],
                "manufacturer_data": "990405",
                "company": "Ruuvi Innovations",
                "connectable": False,
                "tx_power": 4,
            },
            {
                "address": "20:C3:8F:77:88:99",
                "name": "Bose QC Ultra",
                "rssi": -48,
                "address_type": BLEAddressType.RANDOM_STATIC,
                "services": [
                    "Generic Access",
                    "Generic Attribute",
                    "Human Interface Device (HID)",
                    "Battery Service",
                ],
                "manufacturer_data": "8f030103",
                "company": "Bose Corporation",
                "connectable": True,
                "tx_power": 6,
            },
            {
                "address": "38:A1:B2:C3:D4:E5",
                "name": "Sonos Roam",
                "rssi": -42,
                "address_type": BLEAddressType.PUBLIC,
                "services": ["Generic Access"],
                "manufacturer_data": "ff020a01",
                "company": "Sonos",
                "connectable": True,
                "tx_power": 8,
            },
            {
                "address": "0E:5F:A0:B1:C2:D3",
                "name": "",
                "rssi": -85,
                "address_type": BLEAddressType.RANDOM_PRIVATE_NON_RESOLVABLE,
                "services": [],
                "manufacturer_data": "4c0012",
                "company": "Apple",
                "connectable": False,
                "tx_power": -16,
            },
            {
                "address": "F4:5C:89:DE:F0:12",
                "name": "Mi Band 8",
                "rssi": -70,
                "address_type": BLEAddressType.PUBLIC,
                "services": [
                    "Heart Rate",
                    "Battery Service",
                    "Device Information",
                ],
                "manufacturer_data": "0f010201",
                "company": "Xiaomi",
                "connectable": True,
                "tx_power": 3,
            },
        ]

        for dev_data in simulated_devices:
            address = dev_data["address"]
            self._devices[address] = BLEDevice(
                address=address,
                name=dev_data["name"],
                rssi=dev_data["rssi"],
                address_type=dev_data["address_type"],
                services=dev_data["services"],
                manufacturer_data=dev_data["manufacturer_data"],
                company=dev_data["company"],
                connectable=dev_data["connectable"],
                tx_power=dev_data.get("tx_power"),
                first_seen=now,
                last_seen=now,
            )
