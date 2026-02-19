"""
Spectra Markov Chain Analyzer
==============================

Markov chain analysis of network communication patterns. Builds
transition probability matrices from observed IP-to-IP flow sequences,
computes stationary distributions, and detects anomalous transitions
that deviate from expected communication patterns.

The Markov model captures the conditional probability of host B
communicating after host A, enabling prediction of likely future
communication partners and identification of unusual state transitions.

References:
    - Norris, J. R. (1997). Markov Chains. Cambridge Texts in Statistical
      Science. Cambridge University Press. Chapters 1-3.
    - Kullback, S., & Leibler, R. A. (1951). On Information and Sufficiency.
      The Annals of Mathematical Statistics, 22(1), 79-86.
    - Stewart, W. J. (1994). Introduction to the Numerical Solution of
      Markov Chains. Princeton University Press.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np

from shared.logger import PhantomLogger
from shared.math_utils import (
    kl_divergence,
    markov_transition_matrix,
)

from spectra.core.models import NetworkFlow

logger = PhantomLogger("spectra.markov")


class MarkovAnalyzer:
    """Markov chain analyzer for network communication patterns.

    Models the network as a discrete-time Markov chain where states
    are IP addresses and transitions are observed communication events.
    Analyses include:

    1. Transition matrix estimation (maximum-likelihood).
    2. Stationary distribution computation (dominant eigenvector).
    3. KL divergence from uniform distribution (anomaly metric).
    4. Low-probability transition detection.
    5. Next-hop prediction.

    Usage::

        analyzer = MarkovAnalyzer()
        results = analyzer.analyze(flows)
    """

    def __init__(
        self,
        anomaly_threshold: float = 0.01,
        min_transitions: int = 5,
    ) -> None:
        """Initialise the Markov analyzer.

        Args:
            anomaly_threshold: Transition probability below this value
                is considered anomalous (unlikely transition).
            min_transitions: Minimum number of observed transitions
                before analysis is meaningful.
        """
        self.anomaly_threshold: float = anomaly_threshold
        self.min_transitions: int = min_transitions

    def analyze(self, flows: list[NetworkFlow]) -> dict[str, Any]:
        """Perform Markov chain analysis on network flows.

        Constructs a first-order Markov chain from observed IP-to-IP
        transitions, then computes:
        - Transition probability matrix
        - Stationary distribution
        - KL divergence from uniform
        - Anomalous (low-probability) transitions
        - Predicted next-hop targets

        Args:
            flows: List of network flows (sorted by time preferred).

        Returns:
            Dictionary containing:
            - ``states``: list of IP addresses (state labels)
            - ``transition_matrix``: NxN probability matrix as list-of-lists
            - ``stationary_distribution``: dict of IP -> steady-state prob
            - ``kl_from_uniform``: KL divergence of stationary dist from uniform
            - ``anomalous_transitions``: list of (src, dst, prob) for rare transitions
            - ``predictions``: dict of IP -> [(target_ip, prob), ...] top-3 predictions
            - ``total_transitions``: total transitions observed
            - ``unique_states``: number of unique states
        """
        if not flows:
            return self._empty_result()

        # -- Step 1: Build IP transition sequences --
        # Sort flows by start_time to get temporal ordering
        sorted_flows = sorted(
            flows,
            key=lambda f: f.start_time.timestamp() if f.start_time else 0.0
        )

        # Extract transition sequence: for each flow, we observe
        # a transition from src_ip to dst_ip
        all_ips: set[str] = set()
        transitions: list[tuple[str, str]] = []

        for flow in sorted_flows:
            all_ips.add(flow.src_ip)
            all_ips.add(flow.dst_ip)
            transitions.append((flow.src_ip, flow.dst_ip))

        if len(transitions) < self.min_transitions:
            return self._empty_result()

        # -- Step 2: Map IPs to integer states --
        state_list = sorted(all_ips)
        n_states = len(state_list)
        state_to_idx: dict[str, int] = {ip: i for i, ip in enumerate(state_list)}

        # Build integer sequence: for each (src, dst) transition, the
        # Markov chain moves from state src to state dst
        int_sequence: list[int] = []
        for src, dst in transitions:
            int_sequence.append(state_to_idx[src])
            int_sequence.append(state_to_idx[dst])

        # -- Step 3: Compute transition matrix --
        # markov_transition_matrix expects integer sequence and n_states
        trans_matrix = markov_transition_matrix(int_sequence, n_states)
        # trans_matrix is an (n_states, n_states) numpy float64 array

        # -- Step 4: Compute stationary distribution --
        stationary = self._compute_stationary_distribution(trans_matrix, n_states)

        # -- Step 5: KL divergence from uniform distribution --
        uniform = np.full(n_states, 1.0 / n_states, dtype=np.float64)
        stationary_arr = np.array(
            [stationary.get(ip, 1.0 / n_states) for ip in state_list],
            dtype=np.float64,
        )
        # Ensure valid distributions (no zeros for KL computation)
        eps = 1e-10
        stationary_safe = np.maximum(stationary_arr, eps)
        stationary_safe = stationary_safe / stationary_safe.sum()
        uniform_safe = np.maximum(uniform, eps)

        try:
            kl_div = kl_divergence(stationary_safe, uniform_safe)
        except (ValueError, RuntimeWarning):
            kl_div = 0.0

        # -- Step 6: Detect anomalous transitions --
        anomalous = self._detect_anomalous_transitions(
            trans_matrix, state_list, transitions
        )

        # -- Step 7: Predict next-hop targets --
        predictions = self._predict_next_targets(trans_matrix, state_list)

        # Convert transition matrix to list-of-lists for serialisation
        matrix_as_lists = trans_matrix.tolist()

        result = {
            "states": state_list,
            "transition_matrix": matrix_as_lists,
            "stationary_distribution": stationary,
            "kl_from_uniform": float(kl_div),
            "anomalous_transitions": anomalous,
            "predictions": predictions,
            "total_transitions": len(transitions),
            "unique_states": n_states,
        }

        logger.info(
            f"Markov analysis: {n_states} states, "
            f"{len(transitions)} transitions, "
            f"KL divergence: {kl_div:.4f}"
        )

        return result

    # ------------------------------------------------------------------ #
    #  Stationary Distribution
    # ------------------------------------------------------------------ #

    def _compute_stationary_distribution(
        self,
        trans_matrix: np.ndarray,
        n_states: int,
    ) -> dict[str, float]:
        """Compute the stationary distribution of the Markov chain.

        The stationary distribution pi satisfies pi = pi * P, where P is
        the transition matrix. It is the left eigenvector corresponding
        to eigenvalue 1 of the transition matrix.

        For irreducible, aperiodic chains this is the unique long-run
        proportion of time spent in each state (ergodic theorem).

        Uses the power iteration method: repeatedly multiply an initial
        uniform vector by the transpose of the transition matrix until
        convergence.

        Reference:
            Stewart, W. J. (1994). Introduction to the Numerical Solution
            of Markov Chains. Princeton University Press. Chapter 2.

        Args:
            trans_matrix: Row-stochastic (n_states x n_states) matrix.
            n_states: Number of states.

        Returns:
            Dictionary mapping state index to steady-state probability.
        """
        if n_states == 0:
            return {}

        if n_states == 1:
            return {"0": 1.0}

        # Power iteration: pi^{t+1} = pi^t * P
        pi = np.full(n_states, 1.0 / n_states, dtype=np.float64)

        for _ in range(1000):
            pi_new = pi @ trans_matrix  # pi * P
            # Normalise to ensure it sums to 1
            total = pi_new.sum()
            if total > 0:
                pi_new /= total

            # Check convergence
            diff = float(np.abs(pi_new - pi).sum())
            pi = pi_new
            if diff < 1e-10:
                break

        return {str(i): float(pi[i]) for i in range(n_states)}

    # ------------------------------------------------------------------ #
    #  Anomalous Transition Detection
    # ------------------------------------------------------------------ #

    def _detect_anomalous_transitions(
        self,
        trans_matrix: np.ndarray,
        state_list: list[str],
        transitions: list[tuple[str, str]],
    ) -> list[dict[str, Any]]:
        """Detect transitions with unusually low probability.

        An observed transition (i -> j) is anomalous if P(j|i) is below
        the anomaly threshold, indicating it is a rare or unexpected
        communication pattern.

        Args:
            trans_matrix: Row-stochastic transition matrix.
            state_list: List of state labels (IP addresses).
            transitions: List of observed (src, dst) transitions.

        Returns:
            List of dicts with keys: src, dst, probability, description.
        """
        anomalous: list[dict[str, Any]] = []
        state_idx = {ip: i for i, ip in enumerate(state_list)}

        # Track unique anomalous pairs to avoid duplicates
        seen_pairs: set[tuple[str, str]] = set()

        for src, dst in transitions:
            if (src, dst) in seen_pairs:
                continue

            i = state_idx.get(src)
            j = state_idx.get(dst)
            if i is None or j is None:
                continue

            prob = float(trans_matrix[i, j])
            if 0 < prob < self.anomaly_threshold:
                seen_pairs.add((src, dst))
                anomalous.append({
                    "src": src,
                    "dst": dst,
                    "probability": prob,
                    "description": (
                        f"Rare transition {src} -> {dst} "
                        f"(P={prob:.6f}, threshold={self.anomaly_threshold}). "
                        f"This communication pattern is unusual given "
                        f"the observed Markov chain."
                    ),
                })

        # Sort by probability ascending (rarest first)
        anomalous.sort(key=lambda x: x["probability"])

        return anomalous

    # ------------------------------------------------------------------ #
    #  Next-hop Prediction
    # ------------------------------------------------------------------ #

    def _predict_next_targets(
        self,
        trans_matrix: np.ndarray,
        state_list: list[str],
        top_k: int = 3,
    ) -> dict[str, list[tuple[str, float]]]:
        """Predict the most likely next communication targets for each host.

        For each state i, returns the top-K states j ranked by P(j|i),
        representing the most probable next communication partners.

        Args:
            trans_matrix: Row-stochastic transition matrix.
            state_list: List of state labels (IP addresses).
            top_k: Number of top predictions per state.

        Returns:
            Dictionary mapping IP -> list of (target_ip, probability) tuples
            sorted by probability descending.
        """
        predictions: dict[str, list[tuple[str, float]]] = {}

        for i, ip in enumerate(state_list):
            row = trans_matrix[i]
            # Get indices sorted by probability descending
            sorted_indices = np.argsort(row)[::-1]

            top_targets: list[tuple[str, float]] = []
            for j in sorted_indices[:top_k]:
                prob = float(row[j])
                if prob > 0:
                    top_targets.append((state_list[j], prob))

            if top_targets:
                predictions[ip] = top_targets

        return predictions

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _empty_result(self) -> dict[str, Any]:
        """Return an empty analysis result."""
        return {
            "states": [],
            "transition_matrix": [],
            "stationary_distribution": {},
            "kl_from_uniform": 0.0,
            "anomalous_transitions": [],
            "predictions": {},
            "total_transitions": 0,
            "unique_states": 0,
        }
