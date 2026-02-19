"""
Frequency Analyzer
===================

Performs byte-level frequency analysis on binary data, computing
frequency distributions, chi-squared goodness-of-fit statistics,
Index of Coincidence (IC), and Kasiski examination for polyalphabetic
cipher detection.

The frequency analysis pipeline:
1. Compute byte frequency distribution (256-bin histogram)
2. Chi-squared test against uniform distribution
3. Index of Coincidence computation
4. Kasiski examination (repeated trigram distance GCD)
5. Cipher type classification from IC and chi-squared

Cipher type classification based on IC:
    - IC ~ 0.0667 (1/15)  : Monoalphabetic substitution (English IC)
    - IC ~ 0.038 - 0.050  : Polyalphabetic substitution
    - IC ~ 0.031 (1/32)   : Random / modern cipher
    - IC > 0.065           : Plaintext (natural language)

References:
    - Friedman, W. F. (1922). The Index of Coincidence and Its
      Applications in Cryptanalysis. Riverbank Publication No. 22.
    - Kasiski, F. W. (1863). Die Geheimschriften und die Dechiffrirkunst.
    - Pearson, K. (1900). On the criterion that a given system of
      deviations. Philosophical Magazine, 50(302), 157-175.
    - Sinkov, A. (1966). Elementary Cryptanalysis: A Mathematical
      Approach. Mathematical Association of America.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Sequence

from shared.math_utils import (
    frequency_distribution,
    chi_squared_test,
)
from cipher.core.models import CipherType, FrequencyResult


class FrequencyAnalyzer:
    """Performs frequency analysis on binary data.

    Computes byte frequency distributions, statistical tests, and
    cipher type classifications to characterise the data.

    Usage::

        analyzer = FrequencyAnalyzer()
        result = analyzer.analyze(data)
        print(f"IC: {result.ic:.6f}")
        print(f"Cipher type: {result.likely_cipher_type.value}")
    """

    # Index of Coincidence for English text (26-letter alphabet)
    # IC = sum(f_i * (f_i - 1)) / (N * (N - 1))
    # For English: approximately 0.0667 (1.73 / 26)
    IC_ENGLISH: float = 0.0667

    # IC for random / uniform distribution over 26 letters
    IC_RANDOM_26: float = 1.0 / 26.0  # ~0.0385

    # IC for uniform distribution over 256 byte values
    IC_RANDOM_256: float = 1.0 / 256.0  # ~0.0039

    def analyze(self, data: bytes) -> FrequencyResult:
        """Perform complete frequency analysis on the data.

        Args:
            data: Raw bytes to analyse.

        Returns:
            FrequencyResult with distribution, statistics, and classification.
        """
        if not data:
            return FrequencyResult(
                distribution={i: 0.0 for i in range(256)},
                chi_squared=0.0,
                chi_squared_p_value=1.0,
                ic=0.0,
                likely_cipher_type=CipherType.PLAINTEXT,
                most_common_bytes=[],
                least_common_bytes=[],
                kasiski_key_lengths=[],
                byte_count=0,
            )

        byte_count = len(data)

        # Step 1: Byte frequency distribution
        distribution = frequency_distribution(data)

        # Step 2: Chi-squared test against uniform distribution
        observed = [distribution[i] * byte_count for i in range(256)]
        chi2, p_value = chi_squared_test(observed)

        # Step 3: Index of Coincidence
        ic = self._index_of_coincidence(data)

        # Step 4: Kasiski examination
        kasiski_lengths = self._kasiski_examination(data)

        # Step 5: Classify cipher type
        cipher_type = self._classify_cipher_type(ic, chi2, p_value, byte_count)

        # Most and least common bytes
        sorted_dist = sorted(distribution.items(), key=lambda x: x[1], reverse=True)
        most_common = [(byte_val, freq) for byte_val, freq in sorted_dist[:10]]
        least_common = [
            (byte_val, freq)
            for byte_val, freq in sorted_dist[-10:]
            if freq > 0
        ]

        return FrequencyResult(
            distribution=distribution,
            chi_squared=chi2,
            chi_squared_p_value=p_value,
            ic=ic,
            likely_cipher_type=cipher_type,
            most_common_bytes=most_common,
            least_common_bytes=least_common,
            kasiski_key_lengths=kasiski_lengths,
            byte_count=byte_count,
        )

    @staticmethod
    def _index_of_coincidence(data: bytes) -> float:
        """Compute the Index of Coincidence (IC) for byte data.

        The IC measures the probability that two randomly chosen bytes
        from the data are the same:

            IC = sum_{i=0}^{255} f_i * (f_i - 1) / (N * (N - 1))

        where f_i is the count of byte value i and N is the total count.

        For English text (letters only):
            IC ~ 0.0667 (monoalphabetic preserves this)
        For random data over 256 values:
            IC ~ 0.0039 (1/256)
        For random data over 26 letters:
            IC ~ 0.0385 (1/26)

        Reference:
            Friedman, W. F. (1922). The Index of Coincidence and Its
            Applications in Cryptanalysis. Riverbank Publication No. 22.

        Args:
            data: Byte sequence to analyse.

        Returns:
            Index of Coincidence value.
        """
        n = len(data)
        if n < 2:
            return 0.0

        counts = Counter(data)
        numerator = sum(f * (f - 1) for f in counts.values())
        denominator = n * (n - 1)

        if denominator == 0:
            return 0.0

        return numerator / denominator

    @staticmethod
    def _kasiski_examination(
        data: bytes, min_trigram_len: int = 3, max_distances: int = 50
    ) -> list[int]:
        """Perform Kasiski examination to find likely key lengths.

        Finds repeated trigrams (or longer n-grams) in the data, computes
        the distances between their occurrences, and finds the GCD of
        these distances. The GCD values suggest likely key lengths for
        polyalphabetic ciphers.

        Reference:
            Kasiski, F. W. (1863). Die Geheimschriften und die
            Dechiffrirkunst. Berlin: E. S. Mittler und Sohn.

        Args:
            data: Byte sequence to examine.
            min_trigram_len: Minimum n-gram length to search for.
            max_distances: Maximum number of distances to process.

        Returns:
            List of likely key lengths, sorted by frequency of occurrence.
        """
        if len(data) < min_trigram_len * 2:
            return []

        # Find repeated trigrams and their positions
        trigram_positions: dict[bytes, list[int]] = {}
        for i in range(len(data) - min_trigram_len + 1):
            trigram = data[i : i + min_trigram_len]
            if trigram in trigram_positions:
                trigram_positions[trigram].append(i)
            else:
                trigram_positions[trigram] = [i]

        # Compute distances between repeated trigrams
        distances: list[int] = []
        for positions in trigram_positions.values():
            if len(positions) < 2:
                continue
            for i in range(len(positions)):
                for j in range(i + 1, min(i + 5, len(positions))):
                    dist = positions[j] - positions[i]
                    if dist > 0:
                        distances.append(dist)
            if len(distances) >= max_distances:
                break

        if not distances:
            return []

        # Find factors of each distance
        factor_counts: Counter[int] = Counter()
        for dist in distances:
            factors = _find_factors(dist)
            for f in factors:
                if 2 <= f <= 30:  # Practical key length range
                    factor_counts[f] += 1

        if not factor_counts:
            return []

        # Sort by frequency (most common factor = most likely key length)
        sorted_factors = factor_counts.most_common(10)
        return [f for f, _ in sorted_factors]

    def _classify_cipher_type(
        self,
        ic: float,
        chi2: float,
        p_value: float,
        byte_count: int,
    ) -> CipherType:
        """Classify the likely cipher type based on IC and chi-squared.

        Classification thresholds:
        - IC > 0.060: Text or monoalphabetic substitution
        - IC in [0.040, 0.060]: Transposition or weak polyalphabetic
        - IC in [0.030, 0.040]: Polyalphabetic substitution
        - IC < 0.030: Random or modern cipher (byte-level)

        Note: These thresholds are calibrated for byte-level analysis.
        For letter-only analysis, different thresholds apply.

        Reference:
            Sinkov, A. (1966). Elementary Cryptanalysis.

        Args:
            ic: Index of Coincidence value.
            chi2: Chi-squared statistic.
            p_value: Chi-squared p-value.
            byte_count: Total number of bytes.

        Returns:
            CipherType classification.
        """
        # For very short data, classification is unreliable
        if byte_count < 20:
            return CipherType.PLAINTEXT

        # Byte-level IC thresholds
        # Note: For byte-level (256 symbols), IC values are much lower
        # than for letter-only (26 symbols) analysis.
        #
        # We need to distinguish between:
        # - Text data where some byte values dominate (printable ASCII)
        # - Cipher data where bytes are more uniformly distributed

        # Check if data is primarily text (printable ASCII)
        is_text_like = ic > 0.01  # Text has much higher IC at byte level

        if ic > 0.06:
            # Very high IC -- likely plaintext (letter-only IC range)
            return CipherType.PLAINTEXT
        elif ic > 0.04:
            # High IC -- monoalphabetic or plaintext
            return CipherType.MONOALPHABETIC
        elif ic > 0.02:
            # Medium IC -- possibly transposition (preserves letter frequencies)
            # or weak polyalphabetic
            if p_value < 0.05:
                return CipherType.TRANSPOSITION
            return CipherType.POLYALPHABETIC
        elif ic > 0.005:
            # Low-ish IC -- polyalphabetic
            return CipherType.POLYALPHABETIC
        else:
            # Very low IC -- random or modern cipher
            return CipherType.RANDOM_OR_MODERN


def _gcd(a: int, b: int) -> int:
    """Compute the Greatest Common Divisor using Euclid's algorithm."""
    while b:
        a, b = b, a % b
    return a


def _find_factors(n: int) -> list[int]:
    """Find all factors of a positive integer.

    Args:
        n: Positive integer.

    Returns:
        Sorted list of factors.
    """
    if n <= 0:
        return []

    factors: set[int] = set()
    for i in range(1, int(math.isqrt(n)) + 1):
        if n % i == 0:
            factors.add(i)
            factors.add(n // i)

    return sorted(factors)
