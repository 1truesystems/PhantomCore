"""
Spectra Beacon Detector
========================

Detects Command-and-Control (C2) beacon communication patterns by
analysing the timing regularity of flows between host pairs. Beacons
are characterised by periodic "heartbeat" traffic with low timing
entropy and high autocorrelation at the beacon interval.

Detection Pipeline:
    1. Group flows by (source, destination) pair.
    2. For pairs with sufficient samples (>10 flows), compute
       inter-arrival times.
    3. Compute timing statistics: mean, std, coefficient of variation.
    4. Compute timing entropy (Shannon) -- low entropy = regular.
    5. Compute autocorrelation -- peaks indicate periodicity.
    6. Classify as beacon if CV < threshold or entropy < threshold.

References:
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
      Bell System Technical Journal, 27(3), 379-423.
    - Box, G. E. P. & Jenkins, G. M. (1976). Time Series Analysis:
      Forecasting and Control. Holden-Day.
    - Bilge, L., Balzarotti, D., Robertson, W., Kirda, E., & Kruegel, C.
      (2012). Disclosure: Detecting Botnet Command and Control Servers
      Through Large-Scale NetFlow Analysis. ACSAC.
    - Sommer, R. & Paxson, V. (2010). Outside the Closed World: On
      Using Machine Learning for Network Intrusion Detection. IEEE
      Symposium on Security and Privacy.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np

from shared.logger import PhantomLogger
from shared.math_utils import (
    timing_entropy,
    autocorrelation,
)

from spectra.core.models import BeaconResult, NetworkFlow

logger = PhantomLogger("spectra.beacon")


class BeaconDetector:
    """Detects C2 beacon patterns in network flow timing data.

    A beacon is a periodic communication pattern where a compromised
    host contacts a C2 server at regular intervals. Detection relies
    on statistical analysis of inter-arrival times between flows
    for each (source, destination) pair.

    Classification criteria (configurable):
    - Coefficient of variation (CV = std/mean):
        - CV < 0.1: very likely beacon (highly regular)
        - CV < 0.3: possible beacon (somewhat regular)
    - Timing entropy:
        - Entropy < 2.0: suspicious regularity
    - Autocorrelation:
        - Peak > 0.7 at non-zero lag: periodic signal detected

    Usage::

        detector = BeaconDetector(min_flows=10)
        beacons = detector.detect(flows)
    """

    def __init__(
        self,
        min_flows: int = 10,
        cv_strong_threshold: float = 0.1,
        cv_weak_threshold: float = 0.3,
        entropy_threshold: float = 2.0,
        autocorrelation_threshold: float = 0.7,
        max_autocorrelation_lag: int = 30,
    ) -> None:
        """Initialise the beacon detector.

        Args:
            min_flows: Minimum number of flows between a pair to
                analyse for beaconing. Default 10.
            cv_strong_threshold: Coefficient of variation below this
                value strongly indicates beaconing. Default 0.1.
            cv_weak_threshold: Coefficient of variation below this
                value weakly indicates beaconing. Default 0.3.
            entropy_threshold: Timing entropy below this value
                indicates suspicious regularity. Default 2.0.
            autocorrelation_threshold: Autocorrelation peak above this
                value indicates periodicity. Default 0.7.
            max_autocorrelation_lag: Maximum lag for autocorrelation
                computation. Default 30.
        """
        self.min_flows: int = min_flows
        self.cv_strong: float = cv_strong_threshold
        self.cv_weak: float = cv_weak_threshold
        self.entropy_threshold: float = entropy_threshold
        self.acf_threshold: float = autocorrelation_threshold
        self.max_acf_lag: int = max_autocorrelation_lag

    def detect(self, flows: list[NetworkFlow]) -> list[BeaconResult]:
        """Detect beacon patterns across all flow pairs.

        Groups flows by (src_ip, dst_ip) pair, then analyses the
        timing regularity of each pair with sufficient samples.

        Args:
            flows: List of network flows with timestamp information.

        Returns:
            List of BeaconResult objects for each pair analysed,
            sorted by confidence descending. Only pairs classified
            as beacons (is_beacon=True) or near-beacons are included.
        """
        results: list[BeaconResult] = []

        # Group flows by (src, dst) pair
        pair_flows: dict[tuple[str, str], list[NetworkFlow]] = defaultdict(list)

        for flow in flows:
            pair_flows[(flow.src_ip, flow.dst_ip)].append(flow)

        for (src, dst), pair_flow_list in pair_flows.items():
            if len(pair_flow_list) < self.min_flows:
                continue

            result = self._analyze_pair(src, dst, pair_flow_list)
            if result is not None:
                results.append(result)

        # Sort by confidence descending
        results.sort(key=lambda r: r.confidence, reverse=True)

        beacon_count = sum(1 for r in results if r.is_beacon)
        logger.info(
            f"Beacon detection: "
            f"{len(results)} pairs analysed, "
            f"{beacon_count} beacons detected"
        )

        return results

    # ------------------------------------------------------------------ #
    #  Per-pair Analysis
    # ------------------------------------------------------------------ #

    def _analyze_pair(
        self,
        src: str,
        dst: str,
        pair_flows: list[NetworkFlow],
    ) -> BeaconResult | None:
        """Analyse a single (src, dst) pair for beacon behaviour.

        Computes inter-arrival times from flow timestamps, then
        applies statistical tests:
        1. Mean and standard deviation of intervals.
        2. Coefficient of variation (CV = std/mean).
        3. Timing entropy via histogram binning.
        4. Autocorrelation function for periodicity detection.

        Args:
            src: Source IP address.
            dst: Destination IP address.
            pair_flows: Flows from src to dst.

        Returns:
            BeaconResult if analysis is meaningful, None otherwise.
        """
        # Extract and sort timestamps
        timestamps: list[float] = []
        for flow in pair_flows:
            if flow.timestamps:
                timestamps.extend(flow.timestamps)
            elif flow.start_time:
                timestamps.append(flow.start_time.timestamp())

        timestamps.sort()

        if len(timestamps) < self.min_flows:
            return None

        # Compute inter-arrival times
        intervals: list[float] = []
        for i in range(1, len(timestamps)):
            delta = timestamps[i] - timestamps[i - 1]
            if delta > 0:  # Filter zero-delta duplicates
                intervals.append(delta)

        if len(intervals) < self.min_flows - 1:
            return None

        # -- Statistical Measures --

        intervals_arr = np.array(intervals, dtype=np.float64)

        # Mean and standard deviation
        mean_interval = float(np.mean(intervals_arr))
        std_interval = float(np.std(intervals_arr, ddof=1)) if len(intervals_arr) > 1 else 0.0

        # Coefficient of variation (jitter metric)
        cv = std_interval / mean_interval if mean_interval > 0 else float('inf')

        # -- Timing Entropy --
        # Uses Shannon entropy on binned intervals from shared.math_utils
        t_entropy = timing_entropy(intervals)

        # -- Autocorrelation --
        acf_peak = 0.0
        if len(intervals_arr) > 3:
            max_lag = min(self.max_acf_lag, len(intervals_arr) - 2)
            if max_lag >= 1:
                try:
                    acf_values = autocorrelation(intervals_arr, max_lag=max_lag)
                    # Find highest autocorrelation at non-zero lag
                    if len(acf_values) > 1:
                        non_zero_acf = acf_values[1:]  # Exclude lag-0 (always 1.0)
                        acf_peak = float(np.max(np.abs(non_zero_acf)))
                except (ValueError, RuntimeWarning):
                    acf_peak = 0.0

        # -- Classification --
        is_beacon, confidence = self._classify(
            cv, t_entropy, acf_peak, len(intervals)
        )

        return BeaconResult(
            src=src,
            dst=dst,
            interval_mean=round(mean_interval, 4),
            interval_std=round(std_interval, 4),
            entropy=round(t_entropy, 4),
            confidence=round(confidence, 4),
            is_beacon=is_beacon,
            flow_count=len(pair_flows),
            coefficient_of_variation=round(cv, 6),
            autocorrelation_peak=round(acf_peak, 4),
        )

    # ------------------------------------------------------------------ #
    #  Classification
    # ------------------------------------------------------------------ #

    def _classify(
        self,
        cv: float,
        entropy: float,
        acf_peak: float,
        sample_size: int,
    ) -> tuple[bool, float]:
        """Classify whether the timing pattern is a beacon.

        Uses a weighted scoring approach combining multiple indicators:
        - CV score: low CV = regular timing.
        - Entropy score: low entropy = regular distribution.
        - ACF score: high autocorrelation peak = periodic.
        - Sample size: more samples = higher confidence.

        Classification thresholds:
        - CV < 0.1: very likely beacon (+0.35 confidence)
        - CV < 0.3: possible beacon (+0.20 confidence)
        - Entropy < 2.0: suspicious regularity (+0.25 confidence)
        - ACF peak > 0.7: periodic signal (+0.25 confidence)

        Reference:
            Bilge, L. et al. (2012). Disclosure: Detecting Botnet C&C
            Servers Through Large-Scale NetFlow Analysis. ACSAC.

        Args:
            cv: Coefficient of variation.
            entropy: Timing entropy in bits.
            acf_peak: Maximum autocorrelation at non-zero lag.
            sample_size: Number of inter-arrival intervals analysed.

        Returns:
            Tuple of (is_beacon, confidence_score).
        """
        confidence = 0.0

        # CV scoring
        if cv < self.cv_strong:
            confidence += 0.35
        elif cv < self.cv_weak:
            confidence += 0.20
        elif cv < 0.5:
            confidence += 0.05

        # Entropy scoring
        if entropy < 1.0:
            confidence += 0.25
        elif entropy < self.entropy_threshold:
            confidence += 0.15
        elif entropy < 3.0:
            confidence += 0.05

        # Autocorrelation scoring
        if acf_peak > self.acf_threshold:
            confidence += 0.25
        elif acf_peak > 0.5:
            confidence += 0.10

        # Sample size adjustment
        # More samples give higher confidence in the classification
        if sample_size >= 100:
            confidence *= 1.1
        elif sample_size >= 50:
            confidence *= 1.05
        elif sample_size < 20:
            confidence *= 0.8

        # Cap confidence
        confidence = min(confidence, 0.99)

        # Beacon classification: confidence >= 0.5 is considered a beacon
        is_beacon = confidence >= 0.5

        return is_beacon, confidence
