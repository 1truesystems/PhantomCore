"""
PhantomCore Mathematical Utilities
====================================

Central mathematics library providing entropy estimators, statistical tests,
outlier detection, Markov-chain analysis, Bayesian inference, PageRank,
and signal-processing primitives used across every PhantomCore module.

Every function includes a full implementation backed by NumPy, a detailed
docstring, and an academic citation.

References (master list):
    [1] Shannon, C. E. (1948). A Mathematical Theory of Communication.
        Bell System Technical Journal, 27(3), 379-423.
    [2] NIST SP 800-90B (2018). Recommendation for the Entropy Sources
        Used for Random Bit Generation.
    [3] Renyi, A. (1961). On Measures of Entropy and Information.
        Proceedings of the 4th Berkeley Symposium, 1, 547-561.
    [4] Kullback, S. & Leibler, R. A. (1951). On Information and
        Sufficiency. Annals of Mathematical Statistics, 22(1), 79-86.
    [5] Pearson, K. (1900). On the Criterion that a Given System of
        Deviations ... Philosophical Magazine, 50(302), 157-175.
    [6] Grubbs, F. E. (1969). Procedures for Detecting Outlying
        Observations in Samples. Technometrics, 11(1), 1-21.
    [7] Tukey, J. W. (1977). Exploratory Data Analysis. Addison-Wesley.
    [8] Norris, J. R. (1997). Markov Chains. Cambridge University Press.
    [9] Bayes, T. (1763). An Essay towards Solving a Problem in the
        Doctrine of Chances. Philosophical Transactions, 53, 370-418.
    [10] Page, L., Brin, S., Motwani, R. & Winograd, T. (1999).
         The PageRank Citation Ranking. Stanford InfoLab.
    [11] Box, G. E. P. & Jenkins, G. M. (1976). Time Series Analysis:
         Forecasting and Control. Holden-Day.
    [12] Bilge, L. et al. (2012). Disclosure: Detecting Botnet C&C
         Servers Through Large-Scale NetFlow Analysis. ACSAC.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Sequence

import numpy as np
from numpy.typing import NDArray


# ---------------------------------------------------------------------------
#  Type aliases for readability
# ---------------------------------------------------------------------------
FloatArray = NDArray[np.floating]
BoolArray = NDArray[np.bool_]


# ========================== Entropy Measures ===============================


def shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of a byte sequence.

    Shannon entropy quantifies the average information content per symbol:

    .. math::

        H = -\\sum_{i=0}^{255} p_i \\, \\log_2(p_i)

    where :math:`p_i` is the relative frequency of byte value *i*.
    The result is in **bits per byte** and ranges from 0.0 (constant
    stream) to 8.0 (perfectly uniform distribution over 256 symbols).

    Reference:
        Shannon, C. E. (1948). A Mathematical Theory of Communication.
        Bell System Technical Journal, 27(3), 379-423.

    Args:
        data: Raw byte sequence to analyse.

    Returns:
        Shannon entropy in bits per byte. Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0.0:
            entropy -= p * math.log2(p)
    return entropy


def min_entropy(data: bytes) -> float:
    """Compute the min-entropy of a byte sequence.

    Min-entropy is the most conservative entropy estimator:

    .. math::

        H_{\\min} = -\\log_2\\bigl(\\max_i\\, p_i\\bigr)

    It represents the probability of the most likely outcome and is
    the metric recommended by NIST SP 800-90B for evaluating hardware
    and software entropy sources.

    Reference:
        NIST SP 800-90B (2018). Recommendation for the Entropy Sources
        Used for Random Bit Generation. Section 6.3.

    Args:
        data: Raw byte sequence.

    Returns:
        Min-entropy in bits per byte. Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    max_prob = max(counts.values()) / length
    if max_prob <= 0.0:
        return 0.0
    return -math.log2(max_prob)


def renyi_entropy(data: bytes, alpha: float) -> float:
    """Compute the Renyi entropy of order *alpha* for a byte sequence.

    The Renyi entropy generalises Shannon entropy via a single parameter:

    .. math::

        H_\\alpha = \\frac{1}{1 - \\alpha}
                    \\log_2\\!\\Bigl(\\sum_{i=0}^{255} p_i^\\alpha\\Bigr)

    Special cases:
      - alpha -> 1  : Shannon entropy (via L'Hopital's rule).
      - alpha = 0   : Hartley entropy (log2 of support size).
      - alpha -> inf : min-entropy.

    Reference:
        Renyi, A. (1961). On Measures of Entropy and Information.
        Proceedings of the 4th Berkeley Symposium on Mathematical
        Statistics and Probability, 1, 547-561.

    Args:
        data:  Raw byte sequence.
        alpha: Order parameter (>= 0, != 1 for the general formula).

    Returns:
        Renyi entropy in bits per byte. Returns 0.0 for empty input.

    Raises:
        ValueError: If *alpha* is negative.
    """
    if alpha < 0.0:
        raise ValueError(
            f"alpha must be >= 0, got {alpha}"
        )
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    probabilities = np.array(
        [c / length for c in counts.values()], dtype=np.float64
    )

    # Special case: alpha == 1 -> Shannon entropy (limit)
    if math.isclose(alpha, 1.0, rel_tol=1e-9):
        return shannon_entropy(data)

    # Special case: alpha == 0 -> Hartley entropy
    if math.isclose(alpha, 0.0, rel_tol=1e-9):
        return math.log2(len(counts))

    # Special case: alpha -> infinity -> min-entropy
    if math.isinf(alpha):
        return min_entropy(data)

    sum_p_alpha = float(np.sum(probabilities ** alpha))
    if sum_p_alpha <= 0.0:
        return 0.0
    return (1.0 / (1.0 - alpha)) * math.log2(sum_p_alpha)


# ======================== Divergence Measures ==============================


def kl_divergence(p: FloatArray, q: FloatArray) -> float:
    """Compute the Kullback-Leibler divergence D_KL(P || Q).

    .. math::

        D_{KL}(P \\| Q) = \\sum_i p_i \\, \\ln\\!\\left(\\frac{p_i}{q_i}\\right)

    The result is in **nats** (natural logarithm base). Both *p* and *q*
    must be valid probability distributions (non-negative, summing to ~1).
    Zero entries in *q* where *p* is positive yield +inf (per convention).

    Reference:
        Kullback, S. & Leibler, R. A. (1951). On Information and
        Sufficiency. Annals of Mathematical Statistics, 22(1), 79-86.

    Args:
        p: Probability distribution P (1-D NumPy array).
        q: Probability distribution Q (1-D NumPy array, same shape as *p*).

    Returns:
        KL divergence in nats (>= 0). Returns +inf if *q* has zeros
        where *p* is positive.

    Raises:
        ValueError: If array shapes differ or contain negative values.
    """
    p = np.asarray(p, dtype=np.float64)
    q = np.asarray(q, dtype=np.float64)

    if p.shape != q.shape:
        raise ValueError(
            f"Array shapes differ: "
            f"p={p.shape}, q={q.shape}"
        )
    if np.any(p < 0) or np.any(q < 0):
        raise ValueError(
            "Probabilities must be non-negative"
        )

    mask = p > 0
    if not np.any(mask):
        return 0.0

    # Where p > 0 but q == 0, divergence is infinite
    if np.any(q[mask] == 0):
        return float("inf")

    divergence = float(np.sum(p[mask] * np.log(p[mask] / q[mask])))
    return divergence


# ======================== Statistical Tests ================================


def chi_squared_test(
    observed: FloatArray, expected: FloatArray
) -> tuple[float, float]:
    """Perform Pearson's chi-squared goodness-of-fit test.

    The test statistic is:

    .. math::

        \\chi^2 = \\sum_i \\frac{(O_i - E_i)^2}{E_i}

    The p-value is computed using the regularised upper incomplete
    gamma function, matching ``scipy.stats.chi2.sf`` without requiring
    SciPy as a hard dependency.

    Reference:
        Pearson, K. (1900). On the Criterion that a Given System of
        Deviations from the Probable in the Case of a Correlated System
        of Variables is Such that it Can Be Reasonably Supposed to Have
        Arisen from Random Sampling. Philosophical Magazine, 50(302),
        157-175.

    Args:
        observed: Observed frequency counts (1-D array of length *k*).
        expected: Expected frequency counts (1-D array of length *k*).

    Returns:
        Tuple of ``(chi2_statistic, p_value)``.

    Raises:
        ValueError: If arrays differ in length or expected contains zeros.
    """
    observed = np.asarray(observed, dtype=np.float64)
    expected = np.asarray(expected, dtype=np.float64)

    if observed.shape != expected.shape:
        raise ValueError(
            "Array shapes must match"
        )
    if np.any(expected <= 0):
        raise ValueError(
            "Expected values must be > 0"
        )

    chi2 = float(np.sum((observed - expected) ** 2 / expected))
    dof = len(observed) - 1

    if dof <= 0:
        return chi2, 1.0

    # p-value via regularised upper incomplete gamma: Q(dof/2, chi2/2)
    p_value = _upper_inc_gamma_reg(dof / 2.0, chi2 / 2.0)
    return chi2, p_value


# --------------- Incomplete gamma helpers (Numerical Recipes, Ch. 6) ------


def _upper_inc_gamma_reg(a: float, x: float) -> float:
    """Regularised upper incomplete gamma Q(a, x) = 1 - P(a, x).

    Uses series expansion for small *x* and the Lentz continued-fraction
    algorithm for large *x*.

    Reference:
        Press, W. H. et al. (2007). Numerical Recipes (3rd ed.).
        Cambridge University Press, Section 6.2.
    """
    if x < 0.0 or a <= 0.0:
        return 1.0
    if x == 0.0:
        return 1.0

    if x < a + 1.0:
        return 1.0 - _gamma_p_series(a, x)
    else:
        return _gamma_q_cf(a, x)


def _gamma_p_series(a: float, x: float) -> float:
    """Lower regularised incomplete gamma P(a, x) by series expansion."""
    if x == 0.0:
        return 0.0
    ap = a
    delta = 1.0 / a
    total = delta
    for _ in range(300):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-15:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_q_cf(a: float, x: float) -> float:
    """Upper regularised incomplete gamma Q(a, x) by Lentz continued fraction."""
    tiny = 1e-30
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    f = d
    for i in range(1, 300):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        f *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return f * math.exp(-x + a * math.log(x) - math.lgamma(a))


# ======================== Outlier Detection =================================


def z_score_outliers(data: FloatArray, threshold: float = 3.0) -> BoolArray:
    """Detect outliers using the Z-score method.

    An observation is flagged when its absolute Z-score exceeds *threshold*:

    .. math::

        z_i = \\frac{x_i - \\bar{x}}{s}

    The conventional threshold of 3.0 corresponds to approximately
    0.27 % of observations under a normal distribution.

    Reference:
        Grubbs, F. E. (1969). Procedures for Detecting Outlying
        Observations in Samples. Technometrics, 11(1), 1-21.

    Args:
        data:      1-D numeric array.
        threshold: Z-score cutoff (default 3.0).

    Returns:
        Boolean mask of same shape as *data*; ``True`` marks an outlier.
    """
    data = np.asarray(data, dtype=np.float64)
    if data.size < 2:
        return np.zeros(data.shape, dtype=np.bool_)

    mean = np.mean(data)
    std = np.std(data, ddof=1)
    if std == 0.0:
        return np.zeros(data.shape, dtype=np.bool_)

    z_scores = np.abs((data - mean) / std)
    return z_scores > threshold  # type: ignore[return-value]


def iqr_outliers(data: FloatArray, k: float = 1.5) -> BoolArray:
    """Detect outliers using Tukey's Interquartile Range (IQR) method.

    A value is an outlier if it falls below ``Q1 - k*IQR`` or above
    ``Q3 + k*IQR``.  Use *k* = 1.5 for "mild" outliers and *k* = 3.0
    for "extreme" outliers.

    Reference:
        Tukey, J. W. (1977). Exploratory Data Analysis.
        Addison-Wesley, Reading, MA. pp. 43-44.

    Args:
        data: 1-D numeric array.
        k:    IQR multiplier (default 1.5).

    Returns:
        Boolean mask; ``True`` marks an outlier.
    """
    data = np.asarray(data, dtype=np.float64)
    if data.size < 4:
        return np.zeros(data.shape, dtype=np.bool_)

    q1 = float(np.percentile(data, 25))
    q3 = float(np.percentile(data, 75))
    iqr = q3 - q1

    lower = q1 - k * iqr
    upper = q3 + k * iqr
    return (data < lower) | (data > upper)  # type: ignore[return-value]


# ======================== Markov Chains ====================================


def markov_transition_matrix(
    sequence: list[int] | Sequence[int], n_states: int
) -> FloatArray:
    """Estimate a row-stochastic Markov transition matrix from observations.

    For each consecutive pair (s_t, s_{t+1}):

    .. math::

        P_{ij} = \\frac{\\text{count}(i \\to j)}{\\sum_k \\text{count}(i \\to k)}

    Rows with zero total transitions are set to a uniform distribution
    (1 / n_states) to ensure the matrix remains stochastic.

    Reference:
        Norris, J. R. (1997). Markov Chains. Cambridge Texts in
        Statistical Science. Cambridge University Press. Chapter 1.

    Args:
        sequence: Observed state sequence (integer labels in [0, n_states)).
        n_states: Total number of discrete states.

    Returns:
        ``(n_states, n_states)`` row-stochastic NumPy transition matrix.

    Raises:
        ValueError: If any element is outside ``[0, n_states)``.
    """
    seq = list(sequence)
    if not seq:
        return np.full(
            (n_states, n_states), 1.0 / n_states, dtype=np.float64
        )

    arr = np.array(seq, dtype=np.int64)
    if np.any(arr < 0) or np.any(arr >= n_states):
        raise ValueError(
            f"State values must be in [0, {n_states})"
        )

    matrix = np.zeros((n_states, n_states), dtype=np.float64)
    for i in range(len(arr) - 1):
        matrix[arr[i], arr[i + 1]] += 1.0

    row_sums = matrix.sum(axis=1, keepdims=True)
    zero_rows = (row_sums == 0).flatten()
    row_sums[row_sums == 0] = 1.0  # prevent division by zero
    matrix = matrix / row_sums
    matrix[zero_rows] = 1.0 / n_states

    return matrix


# ======================== Bayesian Inference ===============================


def bayesian_update(
    prior: float,
    likelihood: float | list[float],
    evidence: float | None = None,
) -> float:
    """Apply Bayes' theorem to compute the posterior probability.

    Supports two calling conventions:

    1. Classic: ``bayesian_update(prior, likelihood, evidence)``
       Computes P(H|E) = P(E|H) * P(H) / P(E).

    2. Sequential likelihood ratios: ``bayesian_update(prior, [r1, r2, ...])``
       Applies each likelihood ratio via the odds form of Bayes' theorem:
       odds = prior / (1 - prior); odds *= product(ratios);
       posterior = odds / (1 + odds).

    Reference:
        Bayes, T. (1763). An Essay towards Solving a Problem in the
        Doctrine of Chances. Philosophical Transactions of the Royal
        Society of London, 53, 370-418.

    Args:
        prior:      P(H)   -- Prior probability of the hypothesis [0, 1].
        likelihood: P(E|H) scalar or list of likelihood ratios.
        evidence:   P(E)   -- Marginal probability (required for classic form).

    Returns:
        Posterior probability P(H|E), clamped to [0, 1].

    Raises:
        ValueError: If *evidence* is zero or any probability is outside [0, 1].
    """
    if not (0.0 <= prior <= 1.0):
        raise ValueError(
            f"Probability 'prior' must be in [0, 1], got {prior}"
        )

    # Sequential likelihood-ratio form
    if isinstance(likelihood, list):
        if prior <= 0.0:
            return 0.0
        if prior >= 1.0:
            return 1.0
        odds = prior / (1.0 - prior)
        for ratio in likelihood:
            odds *= ratio
        posterior = odds / (1.0 + odds)
        return max(0.0, min(1.0, posterior))

    # Classic Bayes' theorem form
    if evidence is None:
        raise ValueError(
            "evidence is required for classic Bayes' theorem form"
        )
    for name, val in [("likelihood", likelihood), ("evidence", evidence)]:
        if not (0.0 <= val <= 1.0):
            raise ValueError(
                f"Probability '{name}' must be in [0, 1], got {val}"
            )
    if evidence == 0.0:
        raise ValueError(
            "Evidence probability must not be zero"
        )
    return (likelihood * prior) / evidence


# ======================== PageRank =========================================


def pagerank(
    adjacency: FloatArray,
    damping: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-8,
) -> FloatArray:
    """Compute PageRank scores via power iteration.

    .. math::

        \\mathbf{r}^{(t+1)} = d \\cdot M^T \\, \\mathbf{r}^{(t)}
        + \\frac{1-d}{N} \\, \\mathbf{1}

    where *M* is the row-stochastic transition matrix derived from the
    adjacency matrix and *d* is the damping factor.  Dangling nodes (rows
    with no outgoing edges) redistribute their rank uniformly.

    Reference:
        Page, L., Brin, S., Motwani, R. & Winograd, T. (1999).
        The PageRank Citation Ranking: Bringing Order to the Web.
        Stanford InfoLab Technical Report 1999-66.

    Args:
        adjacency: ``(N, N)`` adjacency matrix where ``adjacency[i][j] > 0``
                   means node *i* links to node *j*.
        damping:   Damping factor *d* in (0, 1). Default 0.85.
        max_iter:  Maximum number of power-iteration steps.
        tol:       Convergence tolerance on the L1 norm of rank change.

    Returns:
        1-D NumPy array of PageRank scores summing to ~1.0.

    Raises:
        ValueError: If the adjacency matrix is not square.
    """
    adj = np.asarray(adjacency, dtype=np.float64)
    if adj.ndim != 2 or adj.shape[0] != adj.shape[1]:
        raise ValueError(
            "Adjacency matrix must be square"
        )

    n = adj.shape[0]
    if n == 0:
        return np.array([], dtype=np.float64)

    # Build row-stochastic transition matrix
    out_degree = adj.sum(axis=1)
    dangling = out_degree == 0

    M = adj.copy()
    for i in range(n):
        if out_degree[i] > 0:
            M[i] /= out_degree[i]

    Mt = M.T

    # Initialise rank vector uniformly
    rank = np.full(n, 1.0 / n, dtype=np.float64)
    teleport = (1.0 - damping) / n

    for _ in range(max_iter):
        new_rank = damping * Mt.dot(rank)

        # Redistribute dangling-node rank uniformly
        dangling_sum = float(rank[dangling].sum())
        new_rank += damping * dangling_sum / n

        # Teleportation component
        new_rank += teleport

        # Check convergence (L1 norm)
        diff = float(np.abs(new_rank - rank).sum())
        rank = new_rank
        if diff < tol:
            break

    # Normalise for numerical safety
    total = rank.sum()
    if total > 0:
        rank /= total

    return rank


# ======================== Signal Analysis ==================================


def timing_entropy(intervals: list[float] | Sequence[float]) -> float:
    """Compute Shannon entropy of timing intervals.

    Timing intervals are discretised into bins via Sturges' rule, and
    Shannon entropy is computed over the bin counts.  Low entropy
    indicates periodic / beacon-like behaviour characteristic of C2
    communication channels.

    References:
        Shannon, C. E. (1948). A Mathematical Theory of Communication.
        Bell System Technical Journal, 27(3), 379-423.

        Bilge, L., Balzarotti, D., Robertson, W., Kirda, E. & Kruegel, C.
        (2012). Disclosure: Detecting Botnet Command and Control Servers
        Through Large-Scale NetFlow Analysis. ACSAC.

    Args:
        intervals: List of timing intervals (seconds) between events.

    Returns:
        Shannon entropy of the interval distribution in bits.
        Returns 0.0 for fewer than 2 observations.
    """
    if len(intervals) < 2:
        return 0.0

    arr = np.array(intervals, dtype=np.float64)

    # Sturges' rule: k = ceil(1 + log2(n))
    n_bins = max(2, int(math.ceil(1.0 + math.log2(len(arr)))))

    counts, _ = np.histogram(arr, bins=n_bins)
    total = counts.sum()
    if total == 0:
        return 0.0

    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)

    return entropy


def frequency_distribution(data: bytes) -> FloatArray:
    """Compute a 256-bin byte-value frequency histogram.

    Returns the raw count of each byte value (0-255) as a NumPy array.
    Divide by ``len(data)`` to obtain relative frequencies suitable for
    entropy calculations and chi-squared tests.

    Reference:
        Shannon, C. E. (1948). A Mathematical Theory of Communication.
        Bell System Technical Journal, 27(3), 379-423.

    Args:
        data: Raw byte sequence.

    Returns:
        1-D float64 array of length 256 containing occurrence counts.
    """
    hist = np.zeros(256, dtype=np.float64)
    if not data:
        return hist

    byte_arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(byte_arr, minlength=256)
    hist[:] = counts.astype(np.float64)
    return hist


def autocorrelation(data: FloatArray, max_lag: int) -> FloatArray:
    """Compute the normalised autocorrelation of a signal up to *max_lag*.

    .. math::

        R(\\tau) = \\frac{1}{(N - \\tau) \\, \\sigma^2}
                   \\sum_{t=0}^{N-\\tau-1}
                   (x_t - \\bar{x})(x_{t+\\tau} - \\bar{x})

    Autocorrelation is essential for detecting periodicity in network
    traffic -- a hallmark of C2 beacon communication.

    Reference:
        Box, G. E. P. & Jenkins, G. M. (1976). Time Series Analysis:
        Forecasting and Control. Holden-Day, San Francisco.

    Args:
        data:    1-D numeric signal.
        max_lag: Maximum lag to compute (must be < len(data)).

    Returns:
        1-D array of length ``max_lag + 1`` with autocorrelation
        coefficients R(0), R(1), ..., R(max_lag). R(0) is always 1.0.

    Raises:
        ValueError: If *max_lag* >= len(data).
    """
    data = np.asarray(data, dtype=np.float64)
    n = data.size
    if max_lag >= n:
        raise ValueError(
            f"max_lag ({max_lag}) must be < len(data) ({n})"
        )
    if n < 2:
        return np.ones(max_lag + 1, dtype=np.float64)

    mean = np.mean(data)
    var = np.var(data)
    if var == 0.0:
        # Constant signal: autocorrelation is trivially 1 at all lags
        return np.ones(max_lag + 1, dtype=np.float64)

    centered = data - mean
    result = np.empty(max_lag + 1, dtype=np.float64)
    for lag in range(max_lag + 1):
        if lag == 0:
            result[lag] = 1.0
        else:
            cov = np.sum(centered[: n - lag] * centered[lag:]) / (n - lag)
            result[lag] = cov / var

    return result
