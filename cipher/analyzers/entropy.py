"""
Entropy Analyzer
=================

Performs comprehensive entropy analysis on binary data, computing
Shannon entropy, min-entropy, Renyi entropy (order 2), and per-block
entropy measurements. Classifies data type based on empirical entropy
ranges derived from analysis of common file formats.

Entropy ranges for data type classification:
    - [0, 1)   : Empty or uniform data (single repeated value)
    - [1, 3)   : Plain text (natural language, source code)
    - [3, 5)   : Structured data (XML, JSON, protocol buffers)
    - [5, 6)   : Compressed text (gzip'd text, tokenised data)
    - [6, 7)   : Encoded data (Base64, hex-encoded binaries)
    - [7, 7.5) : Compressed data (zlib, bzip2, zstd archives)
    - [7.5, 8] : Encrypted or truly random data (AES-CBC, /dev/urandom)

References:
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
      Bell System Technical Journal, 27(3), 379-423.
    - Renyi, A. (1961). On Measures of Entropy and Information.
    - Cachin, C. (1997). Entropy Measures and Unconditional Security.
    - Lyda, R., & Hamrock, J. (2007). Using Entropy Analysis to Find
      Encrypted and Packed Malware. IEEE Security & Privacy, 5(2).
"""

from __future__ import annotations

from collections import Counter
from typing import Sequence

from shared.math_utils import (
    shannon_entropy,
    min_entropy,
    renyi_entropy,
)
from cipher.core.models import BlockEntropy, DataType, EntropyResult


class EntropyAnalyzer:
    """Analyses the entropy characteristics of binary data.

    Computes multiple entropy measures and provides block-level analysis
    for visualisation of entropy distribution across the data.

    Attributes:
        block_sizes: List of block sizes (in bytes) for block analysis.
        max_sample_size: Maximum number of bytes to analyse.
        default_block_size: Default block size for the entropy map.
    """

    # Default block size for the entropy map (256 bytes)
    DEFAULT_BLOCK_SIZE: int = 256

    def __init__(
        self,
        block_sizes: list[int] | None = None,
        max_sample_size: int = 1_048_576,
    ) -> None:
        """Initialise the entropy analyzer.

        Args:
            block_sizes: Block sizes for per-block entropy analysis.
                Defaults to [8, 16, 32, 64].
            max_sample_size: Maximum bytes to read for analysis.
        """
        self.block_sizes: list[int] = block_sizes or [8, 16, 32, 64]
        self.max_sample_size: int = max_sample_size
        self.default_block_size: int = self.DEFAULT_BLOCK_SIZE

    def analyze(self, data: bytes) -> EntropyResult:
        """Perform full entropy analysis on the given data.

        Computes Shannon entropy, min-entropy, Renyi entropy (alpha=2),
        per-block entropy for each configured block size, and classifies
        the data type based on the overall Shannon entropy.

        Args:
            data: Raw bytes to analyse.

        Returns:
            EntropyResult with all computed metrics.
        """
        if not data:
            return EntropyResult(
                shannon=0.0,
                min_entropy=0.0,
                renyi=0.0,
                block_entropies=[],
                data_type=DataType.EMPTY_UNIFORM,
                data_size=0,
                unique_bytes=0,
                entropy_map=[],
            )

        # Truncate to max sample size
        sample = data[: self.max_sample_size]

        # Compute global entropy measures
        h_shannon = shannon_entropy(sample)
        h_min = min_entropy(sample)
        h_renyi = renyi_entropy(sample, alpha=2.0)

        # Count unique byte values
        unique = len(set(sample))

        # Block entropy analysis using the default block size
        block_entropies = self._compute_block_entropies(
            sample, self.default_block_size
        )

        # Entropy map for visualisation (per-block Shannon entropy)
        entropy_map = [b.entropy for b in block_entropies]

        # Classify data type
        data_type = self._classify_data_type(h_shannon)

        return EntropyResult(
            shannon=h_shannon,
            min_entropy=h_min,
            renyi=h_renyi,
            block_entropies=block_entropies,
            data_type=data_type,
            data_size=len(sample),
            unique_bytes=unique,
            entropy_map=entropy_map,
        )

    def analyze_blocks(
        self, data: bytes, block_size: int
    ) -> list[BlockEntropy]:
        """Compute per-block entropy for a specific block size.

        Args:
            data: Raw bytes to analyse.
            block_size: Size of each block in bytes.

        Returns:
            List of BlockEntropy measurements.
        """
        return self._compute_block_entropies(data, block_size)

    def _compute_block_entropies(
        self, data: bytes, block_size: int
    ) -> list[BlockEntropy]:
        """Split data into blocks and compute Shannon entropy per block.

        Args:
            data: Raw bytes.
            block_size: Block size in bytes.

        Returns:
            List of BlockEntropy objects ordered by offset.
        """
        if block_size <= 0 or not data:
            return []

        results: list[BlockEntropy] = []
        data_len = len(data)

        for offset in range(0, data_len, block_size):
            block = data[offset : offset + block_size]
            if len(block) < 2:
                # Too small to be meaningful
                continue
            h = shannon_entropy(block)
            results.append(
                BlockEntropy(offset=offset, size=len(block), entropy=h)
            )

        return results

    @staticmethod
    def _classify_data_type(entropy: float) -> DataType:
        """Classify data type based on Shannon entropy value.

        The thresholds are empirically derived from analysis of common
        file formats. See module docstring for ranges.

        Reference:
            Lyda, R., & Hamrock, J. (2007). Using Entropy Analysis to
            Find Encrypted and Packed Malware. IEEE S&P, 5(2), 40-45.

        Args:
            entropy: Shannon entropy in bits per byte [0, 8].

        Returns:
            DataType classification.
        """
        if entropy < 1.0:
            return DataType.EMPTY_UNIFORM
        elif entropy < 3.0:
            return DataType.PLAIN_TEXT
        elif entropy < 5.0:
            return DataType.STRUCTURED_DATA
        elif entropy < 6.0:
            return DataType.COMPRESSED_TEXT
        elif entropy < 7.0:
            return DataType.ENCODED_DATA
        elif entropy < 7.5:
            return DataType.COMPRESSED
        else:
            return DataType.ENCRYPTED_RANDOM
