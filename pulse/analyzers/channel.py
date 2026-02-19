"""
Pulse Channel Analyzer
========================

Analyses WiFi channel utilization and interference to recommend
optimal channel assignments. Covers both 2.4 GHz (channels 1-14)
and 5 GHz (channels 36-165) bands with overlap and congestion
modelling.

In the 2.4 GHz band, each 20 MHz channel overlaps with adjacent
channels. Only channels 1, 6, and 11 (in the Americas regulatory
domain) are non-overlapping with 25 MHz spacing. Co-channel and
adjacent-channel interference degrade throughput and increase
retransmissions.

References:
    - IEEE. (2020). IEEE Std 802.11-2020. Annex E: Country Information
      and Operating Classes.
    - Cisco. (2023). 2.4 GHz Band Channel Assignment. Wireless LAN
      Design Guide.
    - Gast, M. S. (2013). 802.11ac: A Survival Guide. O'Reilly Media.
      Chapter 2: Radio Propagation.
    - Geier, J. (2010). Designing and Deploying 802.11n Wireless Networks.
      Cisco Press. Chapter 4: RF Analysis.
"""

from __future__ import annotations

import math
from typing import Optional

from shared.logger import PhantomLogger

from pulse.core.models import (
    AccessPoint,
    ChannelInfo,
    CHANNEL_FREQ_MAP_24GHZ,
    CHANNEL_FREQ_MAP_5GHZ,
    DFS_CHANNELS,
    NON_OVERLAPPING_24GHZ,
)

logger = PhantomLogger("pulse.analyzers.channel")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 2.4 GHz channel overlap: channels within +/-4 overlap due to 22 MHz channel width
_24GHZ_OVERLAP_RANGE = 4

# Maximum practical capacity (networks) per 2.4 GHz channel before
# significant degradation. Based on empirical studies.
_24GHZ_MAX_CAPACITY = 8

# Maximum practical capacity per 5 GHz channel (wider bandwidth, more channels)
_5GHZ_MAX_CAPACITY = 15


# ---------------------------------------------------------------------------
# Channel Analyzer
# ---------------------------------------------------------------------------


class ChannelAnalyzer:
    """Analyses WiFi channel utilization and interference.

    Evaluates the distribution of access points across 2.4 GHz and
    5 GHz channels, computes overlap-weighted interference scores,
    and recommends the least congested channels for deployment.

    The interference model accounts for:
        - Co-channel interference (same channel)
        - Adjacent channel interference (channels within +/-4 in 2.4 GHz)
        - Signal-strength-weighted congestion
        - DFS channel availability in 5 GHz

    Reference:
        Geier, J. (2010). Designing and Deploying 802.11n Wireless
        Networks. Chapter 4: RF Analysis.

    Usage::

        analyzer = ChannelAnalyzer()
        channels = analyzer.analyze(access_points)
    """

    def analyze(
        self, aps: dict[str, AccessPoint]
    ) -> list[ChannelInfo]:
        """Analyze channel utilization across all detected access points.

        Args:
            aps: Dictionary of access points keyed by BSSID.

        Returns:
            List of ChannelInfo objects for all active channels,
            sorted by interference score (worst first).
        """
        if not aps:
            return []

        # Count networks per channel and collect signal strengths
        channel_aps: dict[int, list[AccessPoint]] = {}
        for ap in aps.values():
            ch = ap.channel
            if ch <= 0:
                continue
            if ch not in channel_aps:
                channel_aps[ch] = []
            channel_aps[ch].append(ap)

        # Separate 2.4 GHz and 5 GHz analysis
        channels_24: list[ChannelInfo] = self._analyze_24ghz(channel_aps)
        channels_5: list[ChannelInfo] = self._analyze_5ghz(channel_aps)

        all_channels = channels_24 + channels_5

        # Sort by interference score descending (worst first)
        all_channels.sort(key=lambda c: c.interference_score, reverse=True)

        logger.info(
            f"Channel analysis complete. "
            f"2.4GHz channels: {len(channels_24)}, "
            f"5GHz channels: {len(channels_5)}"
        )

        return all_channels

    def _analyze_24ghz(
        self, channel_aps: dict[int, list[AccessPoint]]
    ) -> list[ChannelInfo]:
        """Analyze 2.4 GHz band channels (1-14).

        The 2.4 GHz band has 14 channels (region-dependent), each 22 MHz
        wide with 5 MHz spacing between centre frequencies. This means
        channels overlap significantly. Only channels 1, 6, and 11 are
        non-overlapping in the standard 20 MHz mode.

        Adjacent channel interference (ACI) degrades performance even
        when not on the exact same channel. The overlap factor decreases
        with channel distance:
            - Same channel: 1.0 (full co-channel interference)
            - +/-1 channel: 0.75
            - +/-2 channels: 0.50
            - +/-3 channels: 0.25
            - +/-4 channels: 0.10
            - >4 channels: 0.0 (no overlap)

        Reference:
            Cisco. (2023). 2.4 GHz Band Channel Assignment.

        Args:
            channel_aps: Mapping of channel number to list of APs.

        Returns:
            List of ChannelInfo for 2.4 GHz channels with networks.
        """
        results: list[ChannelInfo] = []

        # Overlap attenuation factors based on channel separation
        overlap_factor: dict[int, float] = {
            0: 1.0,   # Same channel (co-channel)
            1: 0.75,  # Adjacent
            2: 0.50,
            3: 0.25,
            4: 0.10,
        }

        # Analyse each 2.4 GHz channel (only those with networks + non-overlapping)
        channels_to_analyze: set[int] = set()
        for ch in range(1, 15):
            if ch in channel_aps:
                channels_to_analyze.add(ch)
        # Always include non-overlapping channels for comparison
        channels_to_analyze.update(NON_OVERLAPPING_24GHZ)

        for channel in sorted(channels_to_analyze):
            if channel not in CHANNEL_FREQ_MAP_24GHZ:
                continue

            frequency = CHANNEL_FREQ_MAP_24GHZ[channel]
            direct_count = len(channel_aps.get(channel, []))

            # Calculate overlap-weighted interference score
            interference = 0.0
            total_signal_weight = 0.0

            for other_ch, other_aps in channel_aps.items():
                if other_ch not in CHANNEL_FREQ_MAP_24GHZ:
                    continue

                ch_distance = abs(channel - other_ch)
                if ch_distance > _24GHZ_OVERLAP_RANGE:
                    continue

                factor = overlap_factor.get(ch_distance, 0.0)
                if factor <= 0:
                    continue

                for ap in other_aps:
                    # Weight by signal strength (stronger signals cause more interference)
                    # Convert dBm to linear scale for weighting
                    signal_linear = 10 ** (ap.signal_dbm / 10.0)
                    weighted = factor * signal_linear
                    interference += weighted
                    total_signal_weight += signal_linear

            # Normalize interference to [0, 1]
            if total_signal_weight > 0:
                # Congestion index: ratio of interference to maximum expected
                max_interference = _24GHZ_MAX_CAPACITY * 1.0  # All on same channel at max signal
                congestion = min(1.0, interference / (max_interference * 10 ** (-40 / 10.0)))
            else:
                congestion = 0.0

            # Channel utilization estimate (proportion of capacity used)
            utilization = min(1.0, direct_count / _24GHZ_MAX_CAPACITY)

            # Generate recommendation
            recommendation = self._recommend_24ghz(
                channel, direct_count, congestion
            )

            results.append(ChannelInfo(
                channel=channel,
                frequency=frequency,
                utilization=round(utilization, 3),
                networks_count=direct_count,
                interference_score=round(congestion, 3),
                recommendation=recommendation,
                is_dfs=False,
                band="2.4GHz",
            ))

        return results

    def _analyze_5ghz(
        self, channel_aps: dict[int, list[AccessPoint]]
    ) -> list[ChannelInfo]:
        """Analyze 5 GHz band channels (36-165).

        The 5 GHz band offers significantly more spectrum with 20 MHz
        non-overlapping channels. Interference is primarily co-channel
        (same channel) rather than adjacent-channel, as each channel is
        fully separated.

        DFS (Dynamic Frequency Selection) channels (52-144) require
        radar detection capability and may not be available in all
        regulatory domains.

        Reference:
            Gast, M. S. (2013). 802.11ac: A Survival Guide. Chapter 2.

        Args:
            channel_aps: Mapping of channel number to list of APs.

        Returns:
            List of ChannelInfo for 5 GHz channels with networks.
        """
        results: list[ChannelInfo] = []

        # Include all 5 GHz channels that have networks
        channels_to_analyze: set[int] = set()
        for ch in channel_aps:
            if ch in CHANNEL_FREQ_MAP_5GHZ:
                channels_to_analyze.add(ch)

        # Also include a few standard UNII-1 channels for comparison
        for ch in (36, 40, 44, 48):
            channels_to_analyze.add(ch)

        for channel in sorted(channels_to_analyze):
            if channel not in CHANNEL_FREQ_MAP_5GHZ:
                continue

            frequency = CHANNEL_FREQ_MAP_5GHZ[channel]
            aps_on_channel = channel_aps.get(channel, [])
            direct_count = len(aps_on_channel)
            is_dfs = channel in DFS_CHANNELS

            # 5 GHz interference is mostly co-channel (no adjacent overlap)
            interference = 0.0
            for ap in aps_on_channel:
                signal_linear = 10 ** (ap.signal_dbm / 10.0)
                interference += signal_linear

            # Normalize
            if direct_count > 0:
                max_expected = _5GHZ_MAX_CAPACITY * 10 ** (-40 / 10.0)
                congestion = min(1.0, interference / max_expected)
            else:
                congestion = 0.0

            utilization = min(1.0, direct_count / _5GHZ_MAX_CAPACITY)

            recommendation = self._recommend_5ghz(
                channel, direct_count, congestion, is_dfs
            )

            results.append(ChannelInfo(
                channel=channel,
                frequency=frequency,
                utilization=round(utilization, 3),
                networks_count=direct_count,
                interference_score=round(congestion, 3),
                recommendation=recommendation,
                is_dfs=is_dfs,
                band="5GHz",
            ))

        return results

    def suggest_best_channel(
        self,
        aps: dict[str, AccessPoint],
        band: str = "2.4GHz",
    ) -> Optional[int]:
        """Suggest the best channel for a new network deployment.

        For 2.4 GHz, only non-overlapping channels (1, 6, 11) are
        considered. For 5 GHz, non-DFS channels are preferred.

        Args:
            aps: Dictionary of access points.
            band: Frequency band ("2.4GHz" or "5GHz").

        Returns:
            Recommended channel number, or None if analysis fails.
        """
        channels = self.analyze(aps)

        if band == "2.4GHz":
            candidates = [
                c for c in channels
                if c.band == "2.4GHz" and c.channel in NON_OVERLAPPING_24GHZ
            ]
        else:
            # Prefer non-DFS 5 GHz channels
            candidates = [
                c for c in channels
                if c.band == "5GHz" and not c.is_dfs
            ]
            if not candidates:
                candidates = [
                    c for c in channels if c.band == "5GHz"
                ]

        if not candidates:
            return None

        # Sort by interference score ascending (best first)
        candidates.sort(key=lambda c: (c.interference_score, c.networks_count))
        return candidates[0].channel

    @staticmethod
    def _recommend_24ghz(
        channel: int, network_count: int, congestion: float
    ) -> str:
        """Generate a recommendation string for a 2.4 GHz channel.

        Args:
            channel: Channel number.
            network_count: Number of networks on this channel.
            congestion: Congestion index [0, 1].

        Returns:
            Human-readable recommendation string.
        """
        is_non_overlapping = channel in NON_OVERLAPPING_24GHZ

        if network_count == 0 and is_non_overlapping:
            return (
                f"Channel {channel}: EXCELLENT - No networks detected on this "
                f"non-overlapping channel. Recommended for deployment."
            )
        elif network_count == 0:
            return (
                f"Channel {channel}: Not recommended despite being empty. "
                f"Use non-overlapping channels (1, 6, 11) to avoid adjacent "
                f"channel interference."
            )
        elif congestion < 0.3:
            quality = "Good" if is_non_overlapping else "Acceptable"
            note = "" if is_non_overlapping else " Prefer channels 1, 6, or 11."
            return (
                f"Channel {channel}: {quality} - {network_count} network(s), "
                f"low congestion ({congestion:.0%}).{note}"
            )
        elif congestion < 0.6:
            return (
                f"Channel {channel}: Moderate - {network_count} network(s), "
                f"moderate congestion ({congestion:.0%}). Consider alternative "
                f"non-overlapping channel."
            )
        else:
            return (
                f"Channel {channel}: Congested - {network_count} network(s), "
                f"high interference ({congestion:.0%}). Avoid this channel; "
                f"switch to 5 GHz if possible."
            )

    @staticmethod
    def _recommend_5ghz(
        channel: int,
        network_count: int,
        congestion: float,
        is_dfs: bool,
    ) -> str:
        """Generate a recommendation string for a 5 GHz channel.

        Args:
            channel: Channel number.
            network_count: Number of networks on this channel.
            congestion: Congestion index [0, 1].
            is_dfs: Whether the channel requires DFS.

        Returns:
            Human-readable recommendation string.
        """
        dfs_note = " (DFS - requires radar detection)" if is_dfs else ""

        if network_count == 0:
            if is_dfs:
                return (
                    f"Channel {channel}{dfs_note}: Available but requires "
                    f"DFS capability. Good option if AP supports DFS."
                )
            return (
                f"Channel {channel}: EXCELLENT - No networks detected. "
                f"Recommended for deployment."
            )
        elif congestion < 0.3:
            return (
                f"Channel {channel}{dfs_note}: Good - {network_count} "
                f"network(s), low congestion ({congestion:.0%})."
            )
        elif congestion < 0.6:
            return (
                f"Channel {channel}{dfs_note}: Moderate - {network_count} "
                f"network(s), moderate congestion ({congestion:.0%})."
            )
        else:
            return (
                f"Channel {channel}{dfs_note}: Congested - {network_count} "
                f"network(s), high interference ({congestion:.0%}). "
                f"Consider a different 5 GHz channel."
            )
