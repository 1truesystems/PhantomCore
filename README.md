# PhantomCore

**Cybersecurity Educational Toolkit** — 5 professional tools for security research, analysis, and education.

> **Disclaimer:** For authorized security research and educational purposes only. See [Legal](#legal-disclaimer) section.

---

## Tools

| Tool | Purpose | Key Algorithms |
|------|---------|---------------|
| **CIPHER** | Cryptographic analysis | Shannon/Renyi entropy, Chi-squared, NIST SP 800-22 RNG tests, CVSS cipher grading |
| **MORPH** | Binary analysis | ELF/PE/DEX parsing, Capstone disassembly, CFG construction, McCabe complexity |
| **NEXUS** | Threat intelligence | CVSS v3.1 calculator, Bayesian exploit probability, MITRE ATT&CK mapping, IoC extraction |
| **SPECTRA** | Network intelligence | PageRank, Louvain community detection, Markov chains, Z-score anomaly detection |
| **PULSE** | Wireless analysis | RSSI triangulation (Friis/FSPL), Deauth flood detection (EMA), AP security grading |

## Quick Start

```bash
# Setup
git clone https://github.com/1truesystems/PhantomCore.git
cd PhantomCore
bash phantomcore.sh setup

# Health check
./pc.sh doctor

# Examples
./pc.sh cipher entropy /usr/bin/ls
./pc.sh cipher hash-id "5d41402abc4b2a76b9719d911017c592"
./pc.sh cipher tls example.com
./pc.sh cipher password "MyP@ssw0rd"
./pc.sh morph /usr/bin/ls
./pc.sh nexus cve CVE-2021-44228
./pc.sh nexus ioc threat_report.txt
./pc.sh nexus mitre T1190
./pc.sh spectra -i capture.pcap
./pc.sh pulse scan --interface wlan0mon
```

## Architecture

```
PhantomCore/
├── pc.sh                  # Quick launcher (computer + phone)
├── phantomcore.sh         # Main launcher (setup, doctor, test, pipeline)
├── config.toml            # Configuration
├── requirements.txt       # Dependencies
├── shared/                # Shared infrastructure
│   ├── config.py          # TOML config loader
│   ├── console.py         # Rich console UI
│   ├── models.py          # Pydantic models (Finding, Risk, ScanResult)
│   ├── math_utils.py      # Math library (entropy, Bayesian, PageRank, Markov)
│   ├── network.py         # Async HTTP (retry, cache, circuit breaker)
│   ├── logger.py          # Structured logging
│   └── templates/         # HTML report template (Jinja2)
├── cipher/                # Cryptanalysis Framework
│   ├── analyzers/         # entropy, hash_id, cipher_suite, password, frequency, rng, key_strength
│   └── parsers/           # hash_parser, tls_parser
├── morph/                 # Binary Analysis Framework
│   ├── analyzers/         # entropy_map, strings, shellcode, cfg_builder, imports
│   └── parsers/           # elf_parser, pe_parser, dex_parser, magic
├── nexus/                 # Threat Intelligence Correlator
│   ├── analyzers/         # cvss, exploit_prob, attack_surface, risk_scorer, mitre
│   ├── collectors/        # cve_search, ioc_extractor
│   └── data/              # mitre_attack.json
├── spectra/               # Network Intelligence Engine
│   ├── analyzers/         # anomaly, graph, markov, fingerprint, lateral, beacon
│   └── collectors/        # packet_collector
└── pulse/                 # Wireless Protocol Analyzer
    ├── analyzers/         # probe, beacon, channel, deauth, signal, hidden_ssid
    └── collectors/        # wifi_collector, ble_collector, pcap_reader
```

## CIPHER — Cryptanalysis Framework

```bash
pc cipher entropy <file>              # Shannon/Min/Renyi entropy analysis
pc cipher hash-id <hash>              # Identify hash type (50+ algorithms)
pc cipher tls <domain>                # TLS/SSL cipher suite grading (A+ to F)
pc cipher password <password>         # Password strength (Markov entropy, NIST SP 800-63)
pc cipher frequency <file>            # Frequency analysis (Chi-squared, Index of Coincidence)
pc cipher key-strength --algorithm RSA --key-size 2048  # Key strength + quantum resistance
pc cipher rng <file>                  # NIST SP 800-22 randomness tests (7 tests)
```

## MORPH — Binary Analysis Framework

```bash
pc morph <binary>                     # Auto-detect format (ELF/PE/DEX)
pc morph <binary> --format pe         # Force format
pc morph <binary> --strings-only      # Extract strings (ASCII, UTF-16, Base64)
pc morph <binary> --entropy-only      # Section entropy map
```

Detects: process injection, keylogging, anti-debug, privilege escalation, shellcode patterns, packed/encrypted sections.

## NEXUS — Threat Intelligence Correlator

```bash
pc nexus cve <CVE-ID>                 # CVE lookup + CVSS v3.1 + exploit probability
pc nexus ioc <file>                   # Extract IoCs (IP, domain, URL, hash, email, CVE)
pc nexus mitre <technique-id>         # MITRE ATT&CK technique lookup
pc nexus search <query>               # Full-text CVE search (SQLite FTS5)
pc nexus assess <config.json>         # Multi-factor risk assessment
```

## SPECTRA — Network Intelligence Engine

```bash
pc spectra -i <pcap>                  # PCAP file analysis
pc spectra --live -d 60               # Live capture (60 seconds)
pc spectra --live --interface eth0    # Specific interface
```

Analyzes: anomalies (Z-score/IQR), C2 beacons (timing entropy), lateral movement, network topology (PageRank, Betweenness), communication communities (Louvain).

## PULSE — Wireless Protocol Analyzer

```bash
pc pulse scan -i wlan0mon             # WiFi scanning + security grading (A-F)
pc pulse ble                          # BLE device scanning
pc pulse ids -i wlan0mon -d 300       # Wireless IDS (deauth detection, rogue AP)
pc pulse analyze <pcap>               # WiFi PCAP analysis
```

## Requirements

- Python 3.11+
- ARM64 / x86_64
- Root access (for wireless capture and live network capture)

## Phone Deployment (NetHunter)

```bash
# Compress and push
tar cf /tmp/phantomcore.tar --exclude='__pycache__' --exclude='.venv' .
adb push /tmp/phantomcore.tar /data/local/tmp/

# Extract in chroot
adb shell "su -c 'chroot /data/local/nhsystem/kali-arm64 /usr/bin/bash -c \
  \"mkdir -p /null3xxx-toolkit/PhantomCore && \
  tar xf /tmp/phantomcore.tar -C /null3xxx-toolkit/PhantomCore\"'"

# Setup
adb shell "su -c 'chroot /data/local/nhsystem/kali-arm64 /usr/bin/bash -c \
  \"cd /null3xxx-toolkit/PhantomCore && bash phantomcore.sh setup\"'"
```

## Legal Disclaimer

This software is intended for **educational and authorized security research** purposes only. The author(s) assume no liability for unauthorized or illegal use. The user is solely responsible for ensuring compliance with all applicable laws.

**Unauthorized access to computer systems is illegal.** Always obtain proper written authorization before testing any system you do not own.

## License

Educational use only. Part of the null3xxx-toolkit.
