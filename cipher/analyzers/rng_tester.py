"""
Random Number Generator Statistical Tester
=============================================

Implements a subset of the NIST SP 800-22 statistical test suite for
evaluating the randomness quality of binary data. The suite includes
seven tests that assess different statistical properties of the input.

Implemented tests:
    1. Frequency (Monobit) Test -- proportion of ones
    2. Block Frequency Test -- frequency within M-bit blocks
    3. Runs Test -- count of uninterrupted sequences of identical bits
    4. Longest Run of Ones Test -- within 8-bit blocks
    5. Serial Test -- frequency of 2-bit overlapping patterns
    6. Approximate Entropy Test -- comparing m-bit and (m+1)-bit block frequencies
    7. Cumulative Sums Test -- maximum excursion of a random walk

Each test returns a p-value; the null hypothesis (data is random) is
rejected if p-value < 0.01 (significance level alpha = 0.01).

References:
    - NIST SP 800-22 Rev. 1a (2010). A Statistical Test Suite for
      Random and Pseudorandom Number Generators for Cryptographic
      Applications.
    - Rukhin, A., Soto, J., Nechvatal, J., Smid, M., Barker, E.,
      Leigh, S., ... & Banks, D. (2010). Statistical test suite for
      random and pseudorandom number generators for cryptographic
      applications. NIST Special Publication 800-22, Revision 1a.
    - Knuth, D. E. (1997). The Art of Computer Programming, Volume 2:
      Seminumerical Algorithms (3rd ed.). Addison-Wesley.
"""

from __future__ import annotations

import math
from typing import Sequence

from cipher.core.models import RNGTestResult, RNGSuiteResult


# ===================================================================== #
#  Mathematical Helper Functions
# ===================================================================== #


def _erfc(x: float) -> float:
    """Complementary error function erfc(x) = 1 - erf(x).

    Uses the rational approximation from Abramowitz & Stegun (1964),
    formula 7.1.26, which provides accuracy to ~1.5e-7.

    Reference:
        Abramowitz, M., & Stegun, I. A. (1964). Handbook of
        Mathematical Functions. Dover Publications, formula 7.1.26.

    Args:
        x: Input value.

    Returns:
        erfc(x) value.
    """
    # Handle negative values using erfc(-x) = 2 - erfc(x)
    if x < 0:
        return 2.0 - _erfc(-x)

    # Coefficients for the rational approximation
    p = 0.3275911
    a1 = 0.254829592
    a2 = -0.284496736
    a3 = 1.421413741
    a4 = -1.453152027
    a5 = 1.061405429

    t = 1.0 / (1.0 + p * x)
    t2 = t * t
    t3 = t2 * t
    t4 = t3 * t
    t5 = t4 * t

    return (a1 * t + a2 * t2 + a3 * t3 + a4 * t4 + a5 * t5) * math.exp(-x * x)


def _igamc(a: float, x: float) -> float:
    """Regularized upper incomplete gamma function Q(a, x) = 1 - P(a, x).

    Used for computing p-values from chi-squared statistics.

    Reference:
        Press, W. H. et al. (2007). Numerical Recipes, 3rd ed.
        Cambridge University Press, Section 6.2.

    Args:
        a: Shape parameter (> 0).
        x: Integration limit (>= 0).

    Returns:
        Q(a, x) value in [0, 1].
    """
    if x <= 0.0:
        return 1.0
    if a <= 0.0:
        return 0.0

    if x < a + 1.0:
        # Series representation for P(a, x), then Q = 1 - P
        return 1.0 - _gammainc_series(a, x)
    else:
        # Continued fraction representation for Q(a, x)
        return _gammainc_cf(a, x)


def _gammainc_series(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a, x) via series expansion."""
    if x == 0.0:
        return 0.0

    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(300):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-14:
            break

    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gammainc_cf(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) via continued fraction."""
    b = x + 1.0 - a
    c = 1.0 / 1e-30
    d = 1.0 / b
    h = d

    for i in range(1, 300):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < 1e-30:
            d = 1e-30
        c = b + an / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break

    return h * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert a byte sequence to a list of individual bits (0/1).

    Args:
        data: Input bytes.

    Returns:
        List of integers, each 0 or 1, MSB first per byte.
    """
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


# ===================================================================== #
#  NIST SP 800-22 Statistical Tests
# ===================================================================== #


class RNGTester:
    """Implements NIST SP 800-22 statistical tests for randomness.

    Runs a suite of seven tests on binary data and produces p-values
    for each test. Data is considered random if all tests pass at
    the 0.01 significance level.

    Usage::

        tester = RNGTester()
        result = tester.run_suite(data)
        print(f"Overall: {'PASS' if result.overall_pass else 'FAIL'}")
        for test in result.tests:
            print(f"  {test.test_name}: p={test.p_value:.6f} {'PASS' if test.passed else 'FAIL'}")
    """

    # Significance level (alpha) for the hypothesis test
    ALPHA: float = 0.01

    # Minimum recommended data size (in bits) for reliable results
    MIN_BITS: int = 100

    def run_suite(self, data: bytes) -> RNGSuiteResult:
        """Run the complete NIST SP 800-22 test suite.

        Args:
            data: Binary data to test.

        Returns:
            RNGSuiteResult with all test outcomes.
        """
        bits = _bytes_to_bits(data)
        n = len(bits)

        tests: list[RNGTestResult] = []

        if n < self.MIN_BITS:
            return RNGSuiteResult(
                tests=[],
                total_tests=0,
                tests_passed=0,
                tests_failed=0,
                overall_pass=False,
                data_size_bits=n,
                assessment=(
                    f"Insufficient data ({n} bits). Minimum {self.MIN_BITS} bits "
                    f"required for reliable statistical testing."
                ),
            )

        # Test 1: Frequency (Monobit) Test
        tests.append(self._frequency_test(bits, n))

        # Test 2: Block Frequency Test
        tests.append(self._block_frequency_test(bits, n))

        # Test 3: Runs Test
        tests.append(self._runs_test(bits, n))

        # Test 4: Longest Run of Ones Test
        tests.append(self._longest_run_test(bits, n))

        # Test 5: Serial Test
        tests.append(self._serial_test(bits, n))

        # Test 6: Approximate Entropy Test
        tests.append(self._approximate_entropy_test(bits, n))

        # Test 7: Cumulative Sums Test
        tests.append(self._cumulative_sums_test(bits, n))

        # Aggregate results
        passed = sum(1 for t in tests if t.passed)
        failed = len(tests) - passed

        assessment = (
            f"All {len(tests)} tests passed. Data appears random."
            if failed == 0
            else f"{failed} of {len(tests)} tests failed. Data may not be random."
        )

        return RNGSuiteResult(
            tests=tests,
            total_tests=len(tests),
            tests_passed=passed,
            tests_failed=failed,
            overall_pass=(failed == 0),
            data_size_bits=n,
            assessment=assessment,
        )

    # ------------------------------------------------------------------ #
    #  Test 1: Frequency (Monobit) Test
    # ------------------------------------------------------------------ #

    def _frequency_test(self, bits: list[int], n: int) -> RNGTestResult:
        """NIST SP 800-22 Section 2.1: Frequency (Monobit) Test.

        Tests whether the proportion of ones in the sequence is
        approximately 0.5, as expected for a random sequence.

        The test statistic is:
            S_n = |sum_{i=1}^{n} (2*bit_i - 1)| / sqrt(n)
            p-value = erfc(S_n / sqrt(2))

        Reference:
            NIST SP 800-22 Rev. 1a, Section 2.1.

        Args:
            bits: List of bits (0/1).
            n: Number of bits.

        Returns:
            RNGTestResult with p-value and pass/fail.
        """
        # Convert 0/1 to -1/+1 and sum
        s_n = sum(2 * b - 1 for b in bits)
        s_obs = abs(s_n) / math.sqrt(n)

        p_value = _erfc(s_obs / math.sqrt(2.0))

        return RNGTestResult(
            test_name="Frequency (Monobit)",
            p_value=p_value,
            passed=p_value >= self.ALPHA,
            description=(
                "Tests whether the proportion of ones is approximately 1/2. "
                f"Sum S_n = {s_n}, S_obs = {s_obs:.4f}."
            ),
            statistic=s_obs,
        )

    # ------------------------------------------------------------------ #
    #  Test 2: Block Frequency Test
    # ------------------------------------------------------------------ #

    def _block_frequency_test(
        self, bits: list[int], n: int, block_size: int = 128
    ) -> RNGTestResult:
        """NIST SP 800-22 Section 2.2: Frequency Test within a Block.

        Divides the sequence into non-overlapping blocks of M bits and
        tests whether the proportion of ones in each block is approximately
        M/2.

        The test statistic is:
            chi^2 = 4*M * sum_{j=1}^{N} (pi_j - 0.5)^2
        where pi_j is the proportion of ones in block j, N = floor(n/M).

        p-value = igamc(N/2, chi^2/2)

        Reference:
            NIST SP 800-22 Rev. 1a, Section 2.2.

        Args:
            bits: List of bits.
            n: Total number of bits.
            block_size: Block size M in bits.

        Returns:
            RNGTestResult.
        """
        M = min(block_size, n // 10)  # Ensure at least 10 blocks
        if M < 2:
            M = 2
        N = n // M  # Number of complete blocks

        if N < 1:
            return RNGTestResult(
                test_name="Block Frequency",
                p_value=0.0,
                passed=False,
                description="Insufficient data for block frequency test.",
                statistic=0.0,
            )

        chi_sq = 0.0
        for j in range(N):
            block = bits[j * M : (j + 1) * M]
            pi_j = sum(block) / M
            chi_sq += (pi_j - 0.5) ** 2

        chi_sq *= 4.0 * M

        p_value = _igamc(N / 2.0, chi_sq / 2.0)

        return RNGTestResult(
            test_name="Block Frequency",
            p_value=p_value,
            passed=p_value >= self.ALPHA,
            description=(
                f"Tests frequency within {M}-bit blocks ({N} blocks). "
                f"Chi-squared = {chi_sq:.4f}."
            ),
            statistic=chi_sq,
        )

    # ------------------------------------------------------------------ #
    #  Test 3: Runs Test
    # ------------------------------------------------------------------ #

    def _runs_test(self, bits: list[int], n: int) -> RNGTestResult:
        """NIST SP 800-22 Section 2.3: Runs Test.

        Tests the total number of runs (uninterrupted sequences of
        identical bits). An excess or deficit of runs indicates
        non-randomness.

        The test statistic:
            V_n = 1 + sum_{k=1}^{n-1} r(k), where r(k)=1 if bit_k != bit_{k+1}
            p-value = erfc(|V_n - 2*n*pi*(1-pi)| / (2*sqrt(2*n)*pi*(1-pi)))

        where pi = proportion of ones.

        Pre-condition: The monobit test should pass first (pi not too far
        from 0.5). If |pi - 0.5| >= 2/sqrt(n), the test is not applicable.

        Reference:
            NIST SP 800-22 Rev. 1a, Section 2.3.

        Args:
            bits: List of bits.
            n: Total number of bits.

        Returns:
            RNGTestResult.
        """
        pi = sum(bits) / n
        tau = 2.0 / math.sqrt(n)

        if abs(pi - 0.5) >= tau:
            return RNGTestResult(
                test_name="Runs",
                p_value=0.0,
                passed=False,
                description=(
                    f"Pre-test failed: pi = {pi:.4f}, |pi - 0.5| = {abs(pi-0.5):.4f} "
                    f">= tau = {tau:.4f}. Monobit test prerequisite not met."
                ),
                statistic=0.0,
            )

        # Count runs (number of transitions + 1)
        v_obs = 1
        for k in range(n - 1):
            if bits[k] != bits[k + 1]:
                v_obs += 1

        # Expected number of runs and p-value
        numerator = abs(v_obs - 2.0 * n * pi * (1.0 - pi))
        denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)

        if denominator == 0:
            p_value = 0.0
        else:
            p_value = _erfc(numerator / denominator)

        return RNGTestResult(
            test_name="Runs",
            p_value=p_value,
            passed=p_value >= self.ALPHA,
            description=(
                f"Tests total number of runs (transitions). "
                f"V_obs = {v_obs}, pi = {pi:.4f}."
            ),
            statistic=float(v_obs),
        )

    # ------------------------------------------------------------------ #
    #  Test 4: Longest Run of Ones Test
    # ------------------------------------------------------------------ #

    def _longest_run_test(self, bits: list[int], n: int) -> RNGTestResult:
        """NIST SP 800-22 Section 2.4: Longest Run of Ones in a Block.

        Tests whether the longest run of ones within 8-bit blocks is
        consistent with what would be expected in a random sequence.

        For M=8 blocks:
        - K=3 categories: longest run <= 1, ==2, ==3, >= 4
        - Expected probabilities: [0.2148, 0.3672, 0.2305, 0.1875]

        Reference:
            NIST SP 800-22 Rev. 1a, Section 2.4.

        Args:
            bits: List of bits.
            n: Total number of bits.

        Returns:
            RNGTestResult.
        """
        M = 8  # Block size
        N = n // M  # Number of blocks

        if N < 1:
            return RNGTestResult(
                test_name="Longest Run of Ones",
                p_value=0.0,
                passed=False,
                description="Insufficient data for longest run test.",
                statistic=0.0,
            )

        # K=3 categories for M=8
        # v[0]: longest run <= 1
        # v[1]: longest run == 2
        # v[2]: longest run == 3
        # v[3]: longest run >= 4
        K = 3
        v = [0] * (K + 1)

        # Theoretical probabilities for M=8
        pi_values = [0.2148, 0.3672, 0.2305, 0.1875]

        for j in range(N):
            block = bits[j * M : (j + 1) * M]
            # Find longest run of ones in this block
            max_run = 0
            current_run = 0
            for bit in block:
                if bit == 1:
                    current_run += 1
                    max_run = max(max_run, current_run)
                else:
                    current_run = 0

            # Categorize
            if max_run <= 1:
                v[0] += 1
            elif max_run == 2:
                v[1] += 1
            elif max_run == 3:
                v[2] += 1
            else:  # max_run >= 4
                v[3] += 1

        # Chi-squared statistic
        chi_sq = 0.0
        for i in range(K + 1):
            expected = N * pi_values[i]
            if expected > 0:
                chi_sq += (v[i] - expected) ** 2 / expected

        p_value = _igamc(K / 2.0, chi_sq / 2.0)

        return RNGTestResult(
            test_name="Longest Run of Ones",
            p_value=p_value,
            passed=p_value >= self.ALPHA,
            description=(
                f"Tests longest run of ones in {M}-bit blocks ({N} blocks). "
                f"Categories: {v}. Chi-squared = {chi_sq:.4f}."
            ),
            statistic=chi_sq,
        )

    # ------------------------------------------------------------------ #
    #  Test 5: Serial Test
    # ------------------------------------------------------------------ #

    def _serial_test(
        self, bits: list[int], n: int, m: int = 2
    ) -> RNGTestResult:
        """NIST SP 800-22 Section 2.11: Serial Test.

        Tests whether the frequency of all 2^m overlapping m-bit
        patterns is approximately the same, as expected for random data.

        Computes psi-squared statistics for m, m-1, and m-2 bit patterns,
        then:
            del_psi_m = psi^2_m - psi^2_{m-1}
            del2_psi_m = psi^2_m - 2*psi^2_{m-1} + psi^2_{m-2}
            P1 = igamc(2^{m-2}, del_psi_m / 2)
            P2 = igamc(2^{m-3}, del2_psi_m / 2)

        Reference:
            NIST SP 800-22 Rev. 1a, Section 2.11.

        Args:
            bits: List of bits.
            n: Total number of bits.
            m: Pattern length (default 2).

        Returns:
            RNGTestResult (uses P1, the first p-value).
        """
        if n < 2 * m:
            return RNGTestResult(
                test_name="Serial",
                p_value=0.0,
                passed=False,
                description="Insufficient data for serial test.",
                statistic=0.0,
            )

        def _psi_sq(pattern_len: int) -> float:
            """Compute psi-squared for patterns of given length."""
            if pattern_len <= 0:
                return 0.0

            # Augment the sequence (circular)
            augmented = bits + bits[:pattern_len - 1]
            num_patterns = 2 ** pattern_len
            counts = [0] * num_patterns

            for i in range(n):
                pattern_val = 0
                for j in range(pattern_len):
                    pattern_val = (pattern_val << 1) | augmented[i + j]
                counts[pattern_val] += 1

            psi2 = sum(c * c for c in counts) * (num_patterns / n) - n
            return psi2

        psi_m = _psi_sq(m)
        psi_m1 = _psi_sq(m - 1)
        psi_m2 = _psi_sq(m - 2)

        del_psi = psi_m - psi_m1
        del2_psi = psi_m - 2.0 * psi_m1 + psi_m2

        # P-value 1
        df1 = 2 ** (m - 2)
        p1 = _igamc(df1, del_psi / 2.0) if df1 > 0 and del_psi > 0 else 1.0

        return RNGTestResult(
            test_name="Serial",
            p_value=p1,
            passed=p1 >= self.ALPHA,
            description=(
                f"Tests frequency of {m}-bit overlapping patterns. "
                f"Psi^2_m = {psi_m:.4f}, del_Psi = {del_psi:.4f}, "
                f"del2_Psi = {del2_psi:.4f}."
            ),
            statistic=del_psi,
        )

    # ------------------------------------------------------------------ #
    #  Test 6: Approximate Entropy Test
    # ------------------------------------------------------------------ #

    def _approximate_entropy_test(
        self, bits: list[int], n: int, m: int = 2
    ) -> RNGTestResult:
        """NIST SP 800-22 Section 2.12: Approximate Entropy Test.

        Compares the frequency of overlapping blocks of length m and m+1.
        For truly random sequences, the approximate entropy should be
        close to log(2).

        ApEn = phi_m - phi_{m+1}
        chi^2 = 2*n*(log(2) - ApEn)
        p-value = igamc(2^{m-1}, chi^2 / 2)

        Reference:
            NIST SP 800-22 Rev. 1a, Section 2.12.
            Pincus, S. M. (1991). Approximate entropy as a measure of
            system complexity. PNAS, 88(6), 2297-2301.

        Args:
            bits: List of bits.
            n: Total number of bits.
            m: Block length.

        Returns:
            RNGTestResult.
        """
        def _phi(block_len: int) -> float:
            """Compute phi for the given block length."""
            if block_len <= 0:
                return 0.0

            # Augment sequence (circular)
            augmented = bits + bits[:block_len - 1]
            num_patterns = 2 ** block_len
            counts = [0] * num_patterns

            for i in range(n):
                pattern_val = 0
                for j in range(block_len):
                    pattern_val = (pattern_val << 1) | augmented[i + j]
                counts[pattern_val] += 1

            # Compute phi
            phi = 0.0
            for c in counts:
                if c > 0:
                    pi_i = c / n
                    phi += pi_i * math.log(pi_i)

            return phi

        phi_m = _phi(m)
        phi_m1 = _phi(m + 1)

        apen = phi_m - phi_m1
        chi_sq = 2.0 * n * (math.log(2) - apen)

        df = 2 ** (m - 1)
        if df > 0 and chi_sq > 0:
            p_value = _igamc(df, chi_sq / 2.0)
        else:
            p_value = 1.0

        return RNGTestResult(
            test_name="Approximate Entropy",
            p_value=p_value,
            passed=p_value >= self.ALPHA,
            description=(
                f"Tests approximate entropy with m={m}. "
                f"phi_m = {phi_m:.6f}, phi_(m+1) = {phi_m1:.6f}, "
                f"ApEn = {apen:.6f}, chi^2 = {chi_sq:.4f}."
            ),
            statistic=chi_sq,
        )

    # ------------------------------------------------------------------ #
    #  Test 7: Cumulative Sums Test
    # ------------------------------------------------------------------ #

    def _cumulative_sums_test(self, bits: list[int], n: int) -> RNGTestResult:
        """NIST SP 800-22 Section 2.13: Cumulative Sums (Cusum) Test.

        Tests the maximum excursion of a random walk defined by the
        partial sums of the +1/-1 mapped sequence. For random data,
        the walk should not deviate too far from zero.

        z = max_{1<=k<=n} |S_k| where S_k = sum_{i=1}^{k} (2*bit_i - 1)

        The p-value is computed using the distribution of the maximum
        of a standard Brownian bridge.

        Reference:
            NIST SP 800-22 Rev. 1a, Section 2.13.

        Args:
            bits: List of bits.
            n: Total number of bits.

        Returns:
            RNGTestResult.
        """
        # Forward cumulative sum
        cumsum = 0
        z = 0
        for bit in bits:
            cumsum += 2 * bit - 1
            z = max(z, abs(cumsum))

        # Compute p-value using the formula from NIST SP 800-22
        # p-value = 1 - sum_{k=floor((-n/z+1)/4)}^{floor((n/z-1)/4)}
        #   [Phi((4k+1)*z/sqrt(n)) - Phi((4k-1)*z/sqrt(n))]
        # + sum_{k=floor((-n/z-3)/4)}^{floor((n/z-1)/4)}
        #   [Phi((4k+3)*z/sqrt(n)) - Phi((4k+1)*z/sqrt(n))]

        if z == 0:
            p_value = 1.0
        else:
            sqrt_n = math.sqrt(n)

            sum1 = 0.0
            start1 = int(math.floor((-n / z + 1) / 4))
            end1 = int(math.floor((n / z - 1) / 4))
            for k in range(start1, end1 + 1):
                term1 = _normal_cdf((4 * k + 1) * z / sqrt_n)
                term2 = _normal_cdf((4 * k - 1) * z / sqrt_n)
                sum1 += term1 - term2

            sum2 = 0.0
            start2 = int(math.floor((-n / z - 3) / 4))
            end2 = int(math.floor((n / z - 1) / 4))
            for k in range(start2, end2 + 1):
                term1 = _normal_cdf((4 * k + 3) * z / sqrt_n)
                term2 = _normal_cdf((4 * k + 1) * z / sqrt_n)
                sum2 += term1 - term2

            p_value = 1.0 - sum1 + sum2
            p_value = max(0.0, min(1.0, p_value))

        return RNGTestResult(
            test_name="Cumulative Sums",
            p_value=p_value,
            passed=p_value >= self.ALPHA,
            description=(
                f"Tests maximum excursion of random walk. "
                f"z = {z}, n = {n}."
            ),
            statistic=float(z),
        )


def _normal_cdf(x: float) -> float:
    """Cumulative distribution function of the standard normal distribution.

    Phi(x) = 0.5 * (1 + erf(x / sqrt(2)))
           = 0.5 * erfc(-x / sqrt(2))

    Args:
        x: Input value.

    Returns:
        Phi(x) value in [0, 1].
    """
    return 0.5 * _erfc(-x / math.sqrt(2.0))
