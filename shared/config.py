"""
PhantomCore Configuration Management
=====================================

Centralized configuration for all PhantomCore toolkit modules using
Python dataclasses and TOML-based persistence.

Architecture follows the Twelve-Factor App methodology for configuration
management (Wiggins, 2011), separating config from code.

References:
    - Wiggins, A. (2011). The Twelve-Factor App. https://12factor.net/
    - PEP 681 -- Data Class Transforms (2022).
    - TOML v1.0.0 Specification. https://toml.io/en/v1.0.0
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]


# ---------------------------------------------------------------------------
# Default configuration file path relative to the PhantomCore root
# ---------------------------------------------------------------------------
_DEFAULT_CONFIG_PATH: Path = Path(__file__).resolve().parent.parent / "config.toml"


# ========================== Tool-Specific Configs ==========================


@dataclass(frozen=False, slots=True)
class SpectraConfig:
    """Configuration for Spectra -- Network Spectrum Analyzer.

    Controls packet capture parameters, protocol dissection depth,
    and anomaly detection thresholds used by the Spectra module.
    """

    # Network analysis parameters
    interface: str = "eth0"
    capture_timeout: int = 60
    max_packets: int = 10_000
    bpf_filter: str = ""
    promiscuous: bool = False
    snap_length: int = 65535
    anomaly_threshold: float = 2.5
    protocol_depth: int = 7
    enable_dns_resolution: bool = False
    output_format: str = "json"


@dataclass(frozen=False, slots=True)
class CipherConfig:
    """Configuration for Cipher -- Cryptographic Analysis Engine.

    Parameters governing entropy analysis, cipher identification,
    and key-strength estimation routines.

    Reference:
        Shannon, C. E. (1948). A Mathematical Theory of Communication.
        Bell System Technical Journal, 27(3), 379-423.
    """

    # Cryptographic analysis parameters
    min_entropy_threshold: float = 7.5
    block_sizes: list[int] = field(default_factory=lambda: [8, 16, 32, 64])
    known_ciphers_db: str = "ciphers.json"
    frequency_analysis: bool = True
    chi_squared_significance: float = 0.05
    max_sample_size: int = 1_048_576  # 1 MiB
    detect_ecb_patterns: bool = True
    avalanche_test: bool = True
    output_format: str = "json"


@dataclass(frozen=False, slots=True)
class MorphConfig:
    """Configuration for Morph -- Malware Mutation Analyzer.

    Controls behavioral analysis parameters, sandbox settings,
    and polymorphic code detection heuristics.

    Reference:
        Szor, P. (2005). The Art of Computer Virus Research and Defense.
        Addison-Wesley Professional.
    """

    # Malware analysis parameters
    sandbox_timeout: int = 120
    max_file_size: int = 52_428_800  # 50 MiB
    yara_rules_path: str = "rules/"
    pe_analysis: bool = True
    elf_analysis: bool = True
    behavior_monitoring: bool = True
    mutation_depth: int = 5
    similarity_threshold: float = 0.75
    api_call_logging: bool = True
    output_format: str = "json"


@dataclass(frozen=False, slots=True)
class NexusConfig:
    """Configuration for Nexus -- Network Topology & Threat Intelligence.

    Governs OSINT collection parameters, graph-analysis depth,
    and threat-feed integration settings.

    Reference:
        Page, L., Brin, S., Motwani, R., & Winograd, T. (1999).
        The PageRank Citation Ranking: Bringing Order to the Web.
        Stanford InfoLab.
    """

    # Threat intelligence parameters
    max_depth: int = 3
    max_nodes: int = 1000
    request_timeout: int = 30
    rate_limit_rps: float = 5.0
    enable_whois: bool = True
    enable_dns_enum: bool = True
    enable_cert_transparency: bool = True
    threat_feeds: list[str] = field(default_factory=list)
    pagerank_damping: float = 0.85
    pagerank_iterations: int = 100
    output_format: str = "json"


@dataclass(frozen=False, slots=True)
class PulseConfig:
    """Configuration for Pulse -- C2 Beacon & Heartbeat Detector.

    Parameters for timing analysis, beacon detection, and
    command-and-control communication pattern identification.

    Reference:
        Bilge, L., Balzarotti, D., Robertson, W., Kirda, E., & Kruegel, C.
        (2012). Disclosure: Detecting Botnet Command and Control Servers
        Through Large-Scale NetFlow Analysis. ACSAC.
    """

    # C2 beacon detection parameters
    capture_duration: int = 300
    min_beacon_count: int = 10
    jitter_tolerance: float = 0.15
    timing_entropy_threshold: float = 2.0
    frequency_bands: list[float] = field(
        default_factory=lambda: [0.1, 0.5, 1.0, 5.0, 10.0, 60.0]
    )
    autocorrelation_lags: int = 50
    min_confidence: float = 0.7
    whitelisted_domains: list[str] = field(default_factory=list)
    output_format: str = "json"


# =========================== Global Settings ===============================


@dataclass(frozen=False, slots=True)
class GlobalConfig:
    """Global settings shared across all PhantomCore modules.

    Controls logging verbosity, output directories, language preferences,
    and general operational parameters.
    """

    # Global parameters
    language: str = "ka"  # Georgian as default
    log_level: str = "INFO"
    log_file: str = "phantomcore.log"
    log_json: bool = False
    output_dir: str = "output"
    report_format: str = "html"
    color_theme: str = "dark"
    max_workers: int = 4
    debug: bool = False
    version: str = "1.0.0"


# =========================== Master Config =================================


@dataclass(frozen=False, slots=True)
class PhantomConfig:
    """Master configuration aggregating all tool-specific and global settings.

    Usage:
        >>> config = PhantomConfig.load()                  # from default path
        >>> config = PhantomConfig.load("custom.toml")     # from custom path
        >>> print(config.spectra.interface)
        'eth0'
        >>> print(config.global_settings.language)
        'ka'
    """

    global_settings: GlobalConfig = field(default_factory=GlobalConfig)
    spectra: SpectraConfig = field(default_factory=SpectraConfig)
    cipher: CipherConfig = field(default_factory=CipherConfig)
    morph: MorphConfig = field(default_factory=MorphConfig)
    nexus: NexusConfig = field(default_factory=NexusConfig)
    pulse: PulseConfig = field(default_factory=PulseConfig)

    # ------------------------------------------------------------------ #
    #  TOML Loading
    # ------------------------------------------------------------------ #

    @classmethod
    def load(cls, path: str | Path | None = None) -> PhantomConfig:
        """Load configuration from a TOML file.

        If *path* is ``None`` the loader looks for ``config.toml`` in the
        PhantomCore project root.  Missing keys gracefully fall back to
        dataclass defaults -- no ``KeyError`` is raised.

        Args:
            path: Filesystem path to a TOML configuration file.
                  Defaults to ``<project_root>/config.toml``.

        Returns:
            A fully-populated :class:`PhantomConfig` instance.

        Raises:
            FileNotFoundError: If the specified path does not exist
                *and* was explicitly provided by the caller.
        """
        config_path = Path(path) if path is not None else _DEFAULT_CONFIG_PATH

        if not config_path.exists():
            if path is not None:
                raise FileNotFoundError(
                    f"Configuration file not found: {config_path}"
                )
            # Fall back to pure defaults when the default file is absent.
            return cls()

        with open(config_path, "rb") as fh:
            raw: dict[str, Any] = tomllib.load(fh)

        return cls(
            global_settings=cls._build_section(GlobalConfig, raw.get("global", {})),
            spectra=cls._build_section(SpectraConfig, raw.get("spectra", {})),
            cipher=cls._build_section(CipherConfig, raw.get("cipher", {})),
            morph=cls._build_section(MorphConfig, raw.get("morph", {})),
            nexus=cls._build_section(NexusConfig, raw.get("nexus", {})),
            pulse=cls._build_section(PulseConfig, raw.get("pulse", {})),
        )

    # ------------------------------------------------------------------ #
    #  Serialisation helpers
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Serialise the entire configuration tree to a plain dictionary."""
        return asdict(self)

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_section(cls: type, data: dict[str, Any]) -> Any:
        """Instantiate a dataclass *cls* using only the keys it declares.

        Unknown keys in the TOML source are silently ignored so that
        forward-compatible config files do not break older code.
        """
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


# ========================= Module-level convenience ========================

def get_config(path: str | Path | None = None) -> PhantomConfig:
    """Module-level convenience wrapper around :meth:`PhantomConfig.load`.

    Caches the result so that repeated imports share one instance.
    """
    if not hasattr(get_config, "_cached") or path is not None:
        get_config._cached = PhantomConfig.load(path)  # type: ignore[attr-defined]
    return get_config._cached  # type: ignore[attr-defined]
