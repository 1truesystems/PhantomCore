"""
Entropy Map Analyzer
=====================

Computes Shannon entropy across binary sections and sliding windows
to detect packed, encrypted, or compressed regions.

Shannon entropy H(X) measures information density:
    H(X) = -sum_{i=0}^{255} p(x_i) * log2(p(x_i))

For a uniform distribution over 256 byte values, H = 8.0 bits (maximum).
High-entropy regions (H > 7.0) typically indicate encryption, compression,
or random data, while code and structured data occupy the range 4.0-6.5.

The analyzer also detects common packer signatures (UPX, ASPack, PECompact,
Themida, etc.) by examining section names and byte patterns.

References:
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
      Bell System Technical Journal, 27(3), 379-423.
    - Lyda, R., & Hamrock, J. (2007). Using Entropy Analysis to Find
      Encrypted and Packed Malware. IEEE Security & Privacy, 5(2), 40-45.
"""

from __future__ import annotations

from shared.math_utils import shannon_entropy

from morph.core.models import SectionInfo


# ---------------------------------------------------------------------------
# Entropy classification thresholds
# ---------------------------------------------------------------------------

ENTROPY_NULL: float = 1.0
ENTROPY_CODE_LOW: float = 1.0
ENTROPY_CODE_HIGH: float = 4.5
ENTROPY_STRUCTURED_HIGH: float = 6.5
ENTROPY_COMPRESSED_HIGH: float = 7.0
ENTROPY_PACKED_HIGH: float = 7.5
ENTROPY_ENCRYPTED_THRESHOLD: float = 7.5


def _classify_entropy(entropy: float) -> str:
    """Classify an entropy value into a human-readable category.

    Args:
        entropy: Shannon entropy in [0.0, 8.0].

    Returns:
        Classification string.
    """
    if entropy < ENTROPY_NULL:
        return "null/empty"
    elif entropy < ENTROPY_CODE_HIGH:
        return "code/data"
    elif entropy < ENTROPY_STRUCTURED_HIGH:
        return "structured data"
    elif entropy < ENTROPY_COMPRESSED_HIGH:
        return "compressed or high-entropy code"
    elif entropy < ENTROPY_PACKED_HIGH:
        return "likely packed"
    else:
        return "encrypted/compressed"


# ---------------------------------------------------------------------------
# Packer signature patterns
# ---------------------------------------------------------------------------

_PACKER_SECTION_NAMES: dict[str, str] = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    "upx!": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".pec1": "PECompact",
    ".pec2": "PECompact",
    "pecompact2": "PECompact",
    ".petite": "Petite",
    ".yp": "Y0da Protector",
    ".themida": "Themida",
    "winlicen": "Themida",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    ".nsp2": "NsPack",
    ".mew": "MEW",
    ".fsg": "FSG",
    ".packed": "Generic packer",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    "bero": "BeRoEXEPacker",
    "mpress1": "Mpress",
    "mpress2": "Mpress",
    ".perplex": "Perplex PE Protector",
    ".seau": "SeauSFX",
    ".rlpack": "RLPack",
    "rpcc": "RPCC",
    ".svkp": "SVK Protector",
    ".tsustub": "TSULoader",
    ".wwpack": "WWPack32",
}

_PACKER_BYTE_SIGNATURES: list[tuple[bytes, str]] = [
    (b"UPX!", "UPX"),
    (b"UPX0", "UPX"),
    (b"UPX1", "UPX"),
    (b"\x60\xbe", "UPX (entry stub)"),
    (b"ASPack", "ASPack"),
    (b"PEC2", "PECompact"),
    (b"PETITE", "Petite"),
    (b"FSG!", "FSG"),
    (b"NsPack", "NsPack"),
    (b"MEW", "MEW"),
    (b"Themida", "Themida"),
    (b"VMProtect", "VMProtect"),
    (b".vmp0", "VMProtect"),
    (b"Enigma protector", "Enigma Protector"),
    (b"MPRESS", "Mpress"),
]


# ---------------------------------------------------------------------------
# EntropyMapAnalyzer
# ---------------------------------------------------------------------------

class EntropyMapAnalyzer:
    """Analyze entropy distribution across binary sections and windows.

    Provides per-section entropy calculation, full-binary sliding-window
    entropy mapping, and packer/cryptor detection heuristics.

    Reference:
        Shannon, C. E. (1948). A Mathematical Theory of Communication.
        Lyda, R., & Hamrock, J. (2007). Using Entropy Analysis to Find
        Encrypted and Packed Malware.

    Usage::

        analyzer = EntropyMapAnalyzer()
        sections = analyzer.analyze(data, sections)
        entropy_map = analyzer.sliding_window_entropy(data)
        packer = analyzer.detect_packer(data, sections)
    """

    def __init__(self, window_size: int = 256) -> None:
        """Initialise the analyzer.

        Args:
            window_size: Size of the sliding window in bytes for the
                         full-binary entropy scan.  Default is 256.
        """
        self._window_size: int = window_size

    def analyze(
        self,
        data: bytes,
        sections: list[SectionInfo],
    ) -> list[SectionInfo]:
        """Compute entropy for each section and fill the entropy field.

        For each section, extracts the corresponding byte range from the
        raw binary data and calculates Shannon entropy.  The ``entropy``
        and ``type_guess`` fields are updated in-place.

        Args:
            data: Complete binary file bytes.
            sections: List of SectionInfo models to update.

        Returns:
            The same list with ``entropy`` and ``type_guess`` fields populated.
        """
        for section in sections:
            start = section.offset
            end = start + section.size
            if start >= len(data) or section.size == 0:
                section.entropy = 0.0
                if not section.type_guess:
                    section.type_guess = "null/empty"
                continue

            end = min(end, len(data))
            section_data = data[start:end]
            section.entropy = shannon_entropy(section_data)

            # Update type_guess with entropy classification if not already set
            # to something specific from the parser
            entropy_class = _classify_entropy(section.entropy)
            if section.type_guess in ("", "PROGBITS", "Unknown"):
                section.type_guess = entropy_class

        return sections

    def sliding_window_entropy(
        self,
        data: bytes,
        window_size: int | None = None,
        step: int | None = None,
    ) -> list[tuple[int, float]]:
        """Compute a sliding-window entropy map across the entire binary.

        Slides a fixed-size window across the binary data and calculates
        Shannon entropy for each window position.  The result is a list
        of ``(offset, entropy)`` tuples that can be visualised as an
        entropy graph.

        Args:
            data: Complete binary file bytes.
            window_size: Override window size (default: instance default).
            step: Step size between windows.  Default is ``window_size``
                  (non-overlapping windows).

        Returns:
            List of (offset, entropy) tuples.
        """
        ws = window_size or self._window_size
        step_size = step or ws

        if not data or ws <= 0:
            return []

        entropy_map: list[tuple[int, float]] = []
        data_len = len(data)

        offset = 0
        while offset + ws <= data_len:
            window = data[offset : offset + ws]
            ent = shannon_entropy(window)
            entropy_map.append((offset, ent))
            offset += step_size

        # Handle the last partial window if there's remaining data
        if offset < data_len and data_len - offset >= ws // 4:
            window = data[offset:]
            ent = shannon_entropy(window)
            entropy_map.append((offset, ent))

        return entropy_map

    def overall_entropy(self, data: bytes) -> float:
        """Calculate the overall Shannon entropy of the entire binary.

        Args:
            data: Complete binary file bytes.

        Returns:
            Entropy value in [0.0, 8.0].
        """
        return shannon_entropy(data)

    def detect_packer(
        self,
        data: bytes,
        sections: list[SectionInfo],
    ) -> str:
        """Detect if the binary is packed using known packer signatures.

        Detection is performed using two complementary strategies:

        1. **Section name matching**: Many packers create uniquely named
           sections (e.g. ``UPX0``, ``.aspack``, ``.vmp0``).

        2. **Byte pattern matching**: Searching the first portion of the
           binary for known packer signature strings.

        3. **Entropy heuristic**: If overall entropy exceeds 7.0 and the
           executable section has entropy > 7.0, the binary is flagged as
           likely packed even without a specific signature match.

        Args:
            data: Complete binary file bytes.
            sections: Parsed section information.

        Returns:
            Packer name string, or empty string if no packer is detected.
        """
        # Strategy 1: Check section names
        for section in sections:
            name_lower = section.name.lower().strip(".")
            full_lower = section.name.lower()
            if full_lower in _PACKER_SECTION_NAMES:
                return _PACKER_SECTION_NAMES[full_lower]
            if name_lower in _PACKER_SECTION_NAMES:
                return _PACKER_SECTION_NAMES[name_lower]

        # Strategy 2: Search for byte patterns in the first 4 KiB
        search_region = data[:4096]
        for pattern, packer_name in _PACKER_BYTE_SIGNATURES:
            if pattern in search_region:
                return packer_name

        # Also check the entire overlay / end region
        if len(data) > 4096:
            tail_region = data[-4096:]
            for pattern, packer_name in _PACKER_BYTE_SIGNATURES:
                if pattern in tail_region:
                    return packer_name

        # Strategy 3: Entropy-based heuristic
        overall = self.overall_entropy(data)
        if overall > 7.0:
            # Check if code sections also have high entropy
            code_sections = [
                s for s in sections
                if "X" in s.flags or s.name in (".text", ".code", ".CODE")
            ]
            high_entropy_code = any(s.entropy > 7.0 for s in code_sections)
            if high_entropy_code:
                return "Unknown (high entropy)"

        return ""

    def get_entropy_summary(
        self,
        sections: list[SectionInfo],
    ) -> dict[str, int]:
        """Summarise the number of sections in each entropy classification.

        Args:
            sections: Sections with entropy values populated.

        Returns:
            Dictionary mapping classification labels to section counts.
        """
        summary: dict[str, int] = {
            "null/empty": 0,
            "code/data": 0,
            "structured data": 0,
            "compressed or high-entropy code": 0,
            "likely packed": 0,
            "encrypted/compressed": 0,
        }

        for section in sections:
            if section.size == 0:
                continue
            classification = _classify_entropy(section.entropy)
            if classification in summary:
                summary[classification] += 1

        return summary
