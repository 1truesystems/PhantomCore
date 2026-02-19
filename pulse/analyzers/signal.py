"""
Pulse Signal Analyzer
======================

Analyses wireless signal propagation using established RF propagation
models. Provides distance estimation from RSSI, signal quality
classification, path loss modelling, and position estimation via
trilateration (weighted least squares).

Implements the following propagation models:
    - Free Space Path Loss (FSPL): Friis Transmission Equation
    - Log-Distance Path Loss: empirical indoor/outdoor model
    - RSSI-to-Distance conversion using path loss exponent
    - Weighted Least Squares trilateration for position estimation

References:
    - Friis, H. T. (1946). A Note on a Simple Transmission Formula.
      Proceedings of the IRE, 34(5), 254-256.
    - Rappaport, T. S. (2002). Wireless Communications: Principles
      and Practice (2nd ed.). Prentice Hall. Chapters 3-4.
    - Goldsmith, A. (2005). Wireless Communications. Cambridge
      University Press. Chapter 2: Path Loss and Shadowing.
    - Bahl, P., & Padmanabhan, V. N. (2000). RADAR: An In-Building
      RF-based User Location and Tracking System. IEEE INFOCOM 2000.
    - Liu, H., Darabi, H., Banerjee, P., & Liu, J. (2007). Survey of
      Wireless Indoor Positioning Techniques and Systems. IEEE
      Transactions on Systems, Man, and Cybernetics, Part C, 37(6).
"""

from __future__ import annotations

import math
from typing import Any, Optional

from shared.logger import PhantomLogger

from pulse.core.models import (
    SignalMeasurement,
    SignalQuality,
)

logger = PhantomLogger("pulse.analyzers.signal")


# ---------------------------------------------------------------------------
# Path Loss Exponents for different environments
# ---------------------------------------------------------------------------

PATH_LOSS_EXPONENTS: dict[str, float] = {
    "free_space": 2.0,
    "urban_los": 2.7,
    "urban_nlos": 3.5,
    "suburban": 3.0,
    "indoor_open": 2.2,
    "indoor_office": 3.0,
    "indoor_dense": 4.0,
    "indoor_multi_floor": 5.0,
    "indoor_residential": 2.8,
    "corridor": 1.8,
    "factory": 3.3,
}

# Shadow fading standard deviation (dB) for different environments
SHADOW_FADING_SIGMA: dict[str, float] = {
    "free_space": 0.0,
    "urban_los": 3.0,
    "urban_nlos": 6.0,
    "indoor_open": 3.0,
    "indoor_office": 5.0,
    "indoor_dense": 7.0,
    "indoor_residential": 4.0,
}


# ---------------------------------------------------------------------------
# Signal Quality Classifier
# ---------------------------------------------------------------------------


def classify_signal_quality(rssi_dbm: int) -> SignalQuality:
    """Classify WiFi signal strength into quality categories.

    Based on industry-standard thresholds used by wireless site
    survey tools and Cisco's signal strength recommendations.

    Classification:
        Excellent:  > -50 dBm  (strong, reliable for all applications)
        Good:       -50 to -60 dBm  (reliable for most applications)
        Fair:       -60 to -70 dBm  (adequate for web/email)
        Weak:       -70 to -80 dBm  (minimum for basic connectivity)
        Very Weak:  < -80 dBm  (unreliable, frequent disconnections)

    Reference:
        Cisco. (2024). Wireless LAN Design Guide. Table 2-1:
        Signal Strength Recommendations.

    Args:
        rssi_dbm: Received signal strength in dBm.

    Returns:
        Signal quality classification.
    """
    if rssi_dbm > -50:
        return SignalQuality.EXCELLENT
    elif rssi_dbm > -60:
        return SignalQuality.GOOD
    elif rssi_dbm > -70:
        return SignalQuality.FAIR
    elif rssi_dbm > -80:
        return SignalQuality.WEAK
    else:
        return SignalQuality.VERY_WEAK


def signal_quality_to_percentage(rssi_dbm: int) -> int:
    """Convert RSSI in dBm to an approximate signal percentage.

    Uses a linear mapping from the usable RSSI range:
        -30 dBm -> 100%
        -90 dBm -> 0%

    This is an approximation used by many WiFi tools for user-facing
    display. The actual relationship between RSSI and throughput is
    non-linear.

    Args:
        rssi_dbm: Signal strength in dBm.

    Returns:
        Signal strength as percentage [0, 100].
    """
    # Clamp to reasonable range
    clamped = max(-90, min(-30, rssi_dbm))
    return int(((clamped + 90) / 60.0) * 100)


# ---------------------------------------------------------------------------
# Free Space Path Loss
# ---------------------------------------------------------------------------


def free_space_path_loss(
    distance_m: float,
    frequency_mhz: float,
) -> float:
    """Calculate Free Space Path Loss (FSPL) in decibels.

    The FSPL equation derives from the Friis transmission formula
    and represents signal attenuation in unobstructed free space:

        FSPL(dB) = 20 * log10(d) + 20 * log10(f) + 32.44

    where:
        d = distance in meters
        f = frequency in MHz

    The constant 32.44 incorporates the speed of light and unit
    conversions: 32.44 = 20*log10(4*pi/(c)) adjusted for MHz and meters.

    Reference:
        Friis, H. T. (1946). A Note on a Simple Transmission Formula.
        Proceedings of the IRE, 34(5), 254-256.

    Args:
        distance_m: Distance in meters (must be > 0).
        frequency_mhz: Frequency in MHz (must be > 0).

    Returns:
        Path loss in dB.

    Raises:
        ValueError: If distance or frequency is <= 0.
    """
    if distance_m <= 0:
        raise ValueError(f"Distance must be > 0, got {distance_m}")
    if frequency_mhz <= 0:
        raise ValueError(f"Frequency must be > 0, got {frequency_mhz}")

    return (
        20.0 * math.log10(distance_m)
        + 20.0 * math.log10(frequency_mhz)
        + 32.44
    )


# ---------------------------------------------------------------------------
# Log-Distance Path Loss Model
# ---------------------------------------------------------------------------


def log_distance_path_loss(
    distance_m: float,
    reference_distance_m: float = 1.0,
    reference_loss_db: float = 40.0,
    path_loss_exponent: float = 3.0,
    shadow_fading_db: float = 0.0,
) -> float:
    """Calculate path loss using the log-distance model.

    The log-distance path loss model is a generalization of FSPL that
    accounts for environmental effects through the path loss exponent:

        PL(d) = PL(d0) + 10 * n * log10(d / d0) + X_sigma

    where:
        PL(d0) = reference path loss at distance d0 (typically 1m)
        n = path loss exponent (environment-dependent)
        d0 = reference distance (typically 1m)
        X_sigma = zero-mean Gaussian shadow fading (N(0, sigma))

    Path loss exponent values:
        n = 2.0: Free space
        n = 2.7-3.5: Urban cellular
        n = 3.0-5.0: Indoor (varies by environment)
        n = 1.6-1.8: Corridors (waveguide effect)

    Reference:
        Rappaport, T. S. (2002). Wireless Communications: Principles
        and Practice (2nd ed.). Equation 4.68.

    Args:
        distance_m: Distance in meters (must be > 0).
        reference_distance_m: Reference distance d0 in meters.
        reference_loss_db: Path loss at reference distance PL(d0) in dB.
        path_loss_exponent: Path loss exponent n.
        shadow_fading_db: Shadow fading component X_sigma in dB.

    Returns:
        Estimated path loss in dB.
    """
    if distance_m <= 0:
        raise ValueError(f"Distance must be > 0, got {distance_m}")
    if reference_distance_m <= 0:
        raise ValueError(
            f"Reference distance must be > 0, got {reference_distance_m}"
        )

    if distance_m < reference_distance_m:
        # Below reference distance, use FSPL approximation
        return reference_loss_db * (distance_m / reference_distance_m)

    path_loss = (
        reference_loss_db
        + 10.0 * path_loss_exponent * math.log10(distance_m / reference_distance_m)
        + shadow_fading_db
    )

    return path_loss


# ---------------------------------------------------------------------------
# RSSI-based Distance Estimation
# ---------------------------------------------------------------------------


def estimate_distance(
    rssi_dbm: float,
    tx_power_dbm: float = 20.0,
    path_loss_exponent: float = 3.0,
    reference_distance_m: float = 1.0,
    reference_loss_db: Optional[float] = None,
) -> float:
    """Estimate distance from RSSI using the log-distance path loss model.

    Solves the log-distance equation for distance d:

        d = d0 * 10^((TxPower - RSSI - PL(d0)) / (10 * n))

    Or simplified when PL(d0) is absorbed into TxPower:

        d = 10^((TxPower - RSSI) / (10 * n))

    Note: RSSI-based distance estimation has significant uncertainty
    (typically +/- 50% or more) due to multipath, shadowing, and
    environmental variability.

    Reference:
        Bahl, P., & Padmanabhan, V. N. (2000). RADAR: An In-Building
        RF-based User Location and Tracking System. Section 3.

    Args:
        rssi_dbm: Measured RSSI in dBm.
        tx_power_dbm: Transmit power in dBm (at 1 meter distance).
        path_loss_exponent: Path loss exponent n.
        reference_distance_m: Reference distance d0.
        reference_loss_db: Path loss at d0. If None, uses
            free-space default.

    Returns:
        Estimated distance in meters (always >= 0.1).
    """
    if reference_loss_db is None:
        # Default: free-space path loss at 1m for 2.4 GHz
        reference_loss_db = 40.0  # Approximately FSPL at 1m, 2437 MHz

    # PL_measured = TxPower - RSSI
    measured_loss = tx_power_dbm - rssi_dbm

    # Solve for d: PL = PL(d0) + 10*n*log10(d/d0)
    # => d/d0 = 10^((PL - PL(d0)) / (10*n))
    # => d = d0 * 10^(...)
    exponent = (measured_loss - reference_loss_db) / (10.0 * path_loss_exponent)
    distance = reference_distance_m * (10.0 ** exponent)

    return max(0.1, distance)


# ---------------------------------------------------------------------------
# Signal Analyzer Class
# ---------------------------------------------------------------------------


class SignalAnalyzer:
    """Analyses wireless signal propagation and estimates positions.

    Provides signal quality assessment, distance estimation, and
    position triangulation from multiple RSSI measurements.

    Reference:
        Liu, H., et al. (2007). Survey of Wireless Indoor Positioning
        Techniques and Systems.

    Usage::

        analyzer = SignalAnalyzer()
        results = analyzer.analyze_propagation(measurements)
    """

    def __init__(
        self,
        environment: str = "indoor_office",
    ) -> None:
        """Initialize the signal analyzer.

        Args:
            environment: Environment type for path loss model.
                Options: free_space, urban_los, urban_nlos, indoor_open,
                indoor_office, indoor_dense, indoor_residential, corridor.
        """
        self._environment = environment
        self._path_loss_exponent = PATH_LOSS_EXPONENTS.get(
            environment, 3.0
        )
        self._shadow_sigma = SHADOW_FADING_SIGMA.get(environment, 5.0)

    def analyze_propagation(
        self,
        measurements: list[SignalMeasurement],
    ) -> dict[str, Any]:
        """Analyze signal propagation from multiple measurements.

        Args:
            measurements: List of RSSI measurements.

        Returns:
            Dictionary with analysis results including:
                - per_ap: Per-AP signal statistics
                - distances: Estimated distances per BSSID
                - quality_distribution: Count per quality class
                - position_estimate: Triangulated position if >= 3 measurements
                - propagation_model: Model parameters used
        """
        if not measurements:
            return {
                "per_ap": {},
                "distances": {},
                "quality_distribution": {},
                "position_estimate": None,
                "propagation_model": {
                    "environment": self._environment,
                    "path_loss_exponent": self._path_loss_exponent,
                    "shadow_fading_sigma": self._shadow_sigma,
                },
            }

        # Group measurements by BSSID
        by_bssid: dict[str, list[SignalMeasurement]] = {}
        for m in measurements:
            if m.bssid not in by_bssid:
                by_bssid[m.bssid] = []
            by_bssid[m.bssid].append(m)

        # Per-AP analysis
        per_ap: dict[str, dict[str, Any]] = {}
        distances: dict[str, float] = {}
        quality_counts: dict[str, int] = {
            q.value: 0 for q in SignalQuality
        }

        for bssid, ap_measurements in by_bssid.items():
            rssi_values = [m.rssi_dbm for m in ap_measurements]
            avg_rssi = sum(rssi_values) / len(rssi_values)
            min_rssi = min(rssi_values)
            max_rssi = max(rssi_values)

            # Signal quality
            quality = classify_signal_quality(int(avg_rssi))
            quality_counts[quality.value] = quality_counts.get(quality.value, 0) + 1

            # Distance estimation
            tx_power = ap_measurements[0].tx_power_dbm
            freq = ap_measurements[0].frequency_mhz
            dist = estimate_distance(
                rssi_dbm=avg_rssi,
                tx_power_dbm=float(tx_power),
                path_loss_exponent=self._path_loss_exponent,
            )
            distances[bssid] = round(dist, 2)

            # Signal variance (indicator of multipath/fading)
            if len(rssi_values) > 1:
                mean = avg_rssi
                variance = sum((r - mean) ** 2 for r in rssi_values) / (len(rssi_values) - 1)
                std_dev = math.sqrt(variance)
            else:
                variance = 0.0
                std_dev = 0.0

            per_ap[bssid] = {
                "measurement_count": len(ap_measurements),
                "avg_rssi_dbm": round(avg_rssi, 1),
                "min_rssi_dbm": min_rssi,
                "max_rssi_dbm": max_rssi,
                "rssi_std_dev": round(std_dev, 2),
                "signal_quality": quality.value,
                "signal_percentage": signal_quality_to_percentage(int(avg_rssi)),
                "estimated_distance_m": distances[bssid],
                "tx_power_dbm": tx_power,
                "frequency_mhz": freq,
            }

        # Attempt position estimation via trilateration
        position_estimate = self._trilaterate(measurements, distances)

        return {
            "per_ap": per_ap,
            "distances": distances,
            "quality_distribution": quality_counts,
            "position_estimate": position_estimate,
            "propagation_model": {
                "environment": self._environment,
                "path_loss_exponent": self._path_loss_exponent,
                "shadow_fading_sigma": self._shadow_sigma,
            },
        }

    def _trilaterate(
        self,
        measurements: list[SignalMeasurement],
        distances: dict[str, float],
    ) -> Optional[dict[str, Any]]:
        """Estimate position using weighted least squares trilateration.

        Given >= 3 reference points with known positions and estimated
        distances, solve for the receiver position that minimizes:

            Sum_i w_i * (d_measured_i - d_estimated_i)^2

        The system is linearized by subtracting the last equation from
        all others, yielding a standard least squares problem Ax = b.

        Reference:
            Bahl, P., & Padmanabhan, V. N. (2000). RADAR: An In-Building
            RF-based User Location and Tracking System. Section 3.3.

        Args:
            measurements: Signal measurements (need location_estimate set).
            distances: Estimated distances per BSSID.

        Returns:
            Position estimate dict with x, y, confidence, or None.
        """
        # Collect reference points with known positions
        ref_points: list[tuple[float, float, float]] = []  # (x, y, distance)

        for m in measurements:
            if m.location_estimate is not None and m.bssid in distances:
                x, y = m.location_estimate
                d = distances[m.bssid]
                ref_points.append((x, y, d))

        # Need at least 3 reference points for 2D trilateration
        if len(ref_points) < 3:
            return None

        # Weighted Least Squares Trilateration
        # Linearize: subtract last equation from all others
        n = len(ref_points)
        x_n, y_n, d_n = ref_points[-1]

        # Build the system: A * [x, y]^T = b
        # For each i (0..n-2):
        # 2*(x_n - x_i)*x + 2*(y_n - y_i)*y = d_i^2 - d_n^2 - x_i^2 + x_n^2 - y_i^2 + y_n^2
        a_rows: list[list[float]] = []
        b_vals: list[float] = []
        weights: list[float] = []

        for i in range(n - 1):
            x_i, y_i, d_i = ref_points[i]

            a_row = [
                2.0 * (x_n - x_i),
                2.0 * (y_n - y_i),
            ]
            b_val = (
                d_i ** 2 - d_n ** 2
                - x_i ** 2 + x_n ** 2
                - y_i ** 2 + y_n ** 2
            )

            # Weight by inverse distance (closer APs get more weight)
            w = 1.0 / max(d_i, 0.1)

            a_rows.append(a_row)
            b_vals.append(b_val)
            weights.append(w)

        # Solve Weighted Least Squares: (A^T W A) x = A^T W b
        # For 2x2 system, we can solve directly
        if len(a_rows) < 2:
            return None

        # Build weighted normal equations
        ata = [[0.0, 0.0], [0.0, 0.0]]
        atb = [0.0, 0.0]

        for i in range(len(a_rows)):
            w = weights[i]
            for j in range(2):
                for k in range(2):
                    ata[j][k] += w * a_rows[i][j] * a_rows[i][k]
                atb[j] += w * a_rows[i][j] * b_vals[i]

        # Solve 2x2 system using Cramer's rule
        det = ata[0][0] * ata[1][1] - ata[0][1] * ata[1][0]
        if abs(det) < 1e-10:
            return None

        est_x = (atb[0] * ata[1][1] - atb[1] * ata[0][1]) / det
        est_y = (ata[0][0] * atb[1] - ata[1][0] * atb[0]) / det

        # Calculate residual error as confidence indicator
        total_residual = 0.0
        for i in range(n):
            x_i, y_i, d_i = ref_points[i]
            est_dist = math.sqrt((est_x - x_i) ** 2 + (est_y - y_i) ** 2)
            total_residual += (est_dist - d_i) ** 2

        rmse = math.sqrt(total_residual / n)

        # Confidence: inverse relationship with RMSE
        # RMSE < 1m -> high confidence; RMSE > 10m -> low confidence
        confidence = max(0.1, min(1.0, 1.0 / (1.0 + rmse / 5.0)))

        return {
            "x": round(est_x, 2),
            "y": round(est_y, 2),
            "rmse_m": round(rmse, 2),
            "confidence": round(confidence, 3),
            "reference_points_used": n,
            "method": "weighted_least_squares_trilateration",
        }

    def compute_link_budget(
        self,
        tx_power_dbm: float = 20.0,
        tx_antenna_gain_dbi: float = 2.0,
        rx_antenna_gain_dbi: float = 0.0,
        distance_m: float = 10.0,
        frequency_mhz: float = 2437.0,
        cable_loss_db: float = 1.0,
    ) -> dict[str, float]:
        """Compute a wireless link budget.

        The link budget calculates expected received power:

            P_rx = P_tx + G_tx - L_cable - PL(d) + G_rx

        where:
            P_tx = transmit power (dBm)
            G_tx = transmit antenna gain (dBi)
            L_cable = cable/connector losses (dB)
            PL(d) = path loss at distance d (dB)
            G_rx = receive antenna gain (dBi)

        Reference:
            Rappaport, T. S. (2002). Wireless Communications.
            Equation 4.3: Link Budget.

        Args:
            tx_power_dbm: Transmit power in dBm.
            tx_antenna_gain_dbi: Transmit antenna gain in dBi.
            rx_antenna_gain_dbi: Receive antenna gain in dBi.
            distance_m: Distance in meters.
            frequency_mhz: Operating frequency in MHz.
            cable_loss_db: Cable and connector losses in dB.

        Returns:
            Dictionary with link budget components and margins.
        """
        # Calculate path loss using log-distance model
        pl = log_distance_path_loss(
            distance_m=distance_m,
            path_loss_exponent=self._path_loss_exponent,
        )

        # Received power
        eirp = tx_power_dbm + tx_antenna_gain_dbi - cable_loss_db
        rx_power = eirp - pl + rx_antenna_gain_dbi

        # Signal quality at receiver
        quality = classify_signal_quality(int(rx_power))

        # Typical receiver sensitivity thresholds (dBm)
        sensitivity_thresholds = {
            "802.11b (11 Mbps)": -85,
            "802.11g (54 Mbps)": -76,
            "802.11n (MCS7)": -70,
            "802.11ac (MCS9)": -62,
            "802.11ax (MCS11)": -55,
        }

        margins = {}
        for standard, sensitivity in sensitivity_thresholds.items():
            margins[standard] = round(rx_power - sensitivity, 1)

        return {
            "tx_power_dbm": tx_power_dbm,
            "tx_antenna_gain_dbi": tx_antenna_gain_dbi,
            "eirp_dbm": round(eirp, 1),
            "path_loss_db": round(pl, 1),
            "rx_antenna_gain_dbi": rx_antenna_gain_dbi,
            "cable_loss_db": cable_loss_db,
            "rx_power_dbm": round(rx_power, 1),
            "signal_quality": quality.value,
            "signal_percentage": signal_quality_to_percentage(int(rx_power)),
            "distance_m": distance_m,
            "frequency_mhz": frequency_mhz,
            "environment": self._environment,
            "path_loss_exponent": self._path_loss_exponent,
            "link_margins": margins,
        }
