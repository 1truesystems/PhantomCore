# PhantomCore - Complete Usage Guide

## What is PhantomCore?

PhantomCore is a collection of **5 professional cybersecurity tools**. Think of yourself as a doctor - a doctor needs a stethoscope, blood pressure monitor, X-ray machine, and blood analyzer. PhantomCore is exactly that kind of "medical" toolkit, but for computer systems.

**5 Tools:**

| # | Name | What it does | Analogy |
|---|------|-------------|---------|
| 1 | **CIPHER** | Cipher and password analysis | "Laboratory" - checks how strong encryption is |
| 2 | **MORPH** | Looking inside programs | "X-Ray" - sees what's inside a binary |
| 3 | **NEXUS** | Threat intelligence | "Detective" - searches for known vulnerabilities |
| 4 | **SPECTRA** | Network traffic analysis | "Surveillance camera" - sees who's talking to whom on the network |
| 5 | **PULSE** | WiFi/Bluetooth analysis | "Radar" - scans wireless signals |

---

## How to Run

### On Computer
```bash
# From the PhantomCore directory:
./pc.sh <tool> <command> <arguments>

# Examples:
./pc.sh cipher entropy /usr/bin/ls
./pc.sh morph /usr/bin/ls
```

### On Phone (NetHunter chroot)
```bash
# From Termux:
./pc.sh cipher entropy /usr/bin/ls
./pc.sh morph /usr/bin/ls
```

### Health Check
```bash
./pc.sh doctor    # checks that everything is working
./pc.sh test      # runs tests
```

---

## 1. CIPHER - Cryptographic Analysis

CIPHER is your "laboratory" that checks **how secure** ciphers, passwords, and cryptographic systems are.

### 1.1 Entropy Analysis (`entropy`)

**What it does:** Measures the "randomness" (chaos) of data in a file. High entropy = encrypted or compressed. Low = plain text.

**Why you need it:** If malware encrypts its code, its entropy will be high. This helps you detect hidden malicious code.

```bash
# Check file entropy
pc cipher entropy /usr/bin/ls
pc cipher entropy suspicious_file.exe
pc cipher entropy /path/to/any/file

# What the results mean:
# 0.0-3.0  = text, empty data
# 3.0-6.0  = structured (code, HTML, JSON)
# 6.0-7.5  = compressed (ZIP, GZIP)
# 7.5-8.0  = encrypted or packed malware!
```

**Practical Example:**
```bash
# Check a suspicious file
pc cipher entropy unknown_file.bin
# If entropy > 7.5 and it's an EXE -> likely packed malware
# If entropy < 5.0 -> normal file
```

### 1.2 Hash Identification (`hash-id`)

**What it does:** You provide a hash (e.g., `5d41402abc4b2a76b9719d911017c592`) and it tells you what type of hash algorithm was used.

**Why you need it:** In CTFs, forensics, and pentesting, you often find unknown hashes. You need to know if it's MD5, SHA256, or bcrypt to crack or verify it.

```bash
# MD5 hash identification
pc cipher hash-id "5d41402abc4b2a76b9719d911017c592"

# SHA256 hash identification
pc cipher hash-id "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

# Any hash - provide it and get the type
pc cipher hash-id "<paste_hash_here>"
```

### 1.3 TLS/SSL Assessment (`tls`)

**What it does:** Connects to a website and checks its HTTPS security: what ciphers it uses, whether the certificate is valid, whether it has outdated protocols.

**Why you need it:** When auditing a website or server, the first thing to check is the TLS configuration. Bad TLS = data is not protected.

```bash
# Website TLS check
pc cipher tls google.com
pc cipher tls example.com
pc cipher tls mysite.com

# On a specific port
pc cipher tls mail.example.com --port 587

# Rating scale:
# A+ = Excellent
# A  = Very good
# B  = Good
# C  = Weak, needs improvement
# D  = Dangerous
# F  = Failed, critically weak
```

### 1.4 Password Strength Analysis (`password`)

**What it does:** Analyzes a password - how strong it is, how long a computer would take to crack it, what patterns it has.

**Why you need it:** In pentesting you often need to evaluate the strength of found passwords, or check your own passwords.

```bash
# Password check
pc cipher password "MyP@ssw0rd!"
pc cipher password "123456"
pc cipher password "correct-horse-battery-staple"

# Reports:
# - Entropy in bits (higher is better)
# - Estimated crack time
# - Found patterns (word+numbers, dates...)
# - NIST SP 800-63 compliance
```

### 1.5 Frequency Analysis (`frequency`)

**What it does:** Counts the frequency of each byte in a file. Uses Chi-squared test and Index of Coincidence.

**Why you need it:** Classic cryptanalysis - if a file is encrypted with Caesar/Vigenere, frequency analysis can break it.

```bash
pc cipher frequency encrypted_message.txt
pc cipher frequency /path/to/file
```

### 1.6 Key Strength (`key-strength`)

**What it does:** Checks cryptographic key strength against NIST standards. Also evaluates quantum resistance.

**Why you need it:** During audits you need to know whether RSA 1024-bit keys are sufficient, or whether AES-128 is still secure today.

```bash
# RSA 2048-bit key assessment
pc cipher key-strength --algorithm RSA --key-size 2048

# AES 256-bit
pc cipher key-strength --algorithm AES --key-size 256

# ECDSA
pc cipher key-strength --algorithm ECDSA --key-size 256
```

### 1.7 Randomness Testing (`rng`)

**What it does:** Tests data with 7 statistical tests to check if it's truly random (NIST SP 800-22).

**Why you need it:** Cryptographic systems rely on random numbers. If the RNG is weak, the entire system is weak.

```bash
# Random data test
pc cipher rng /dev/urandom     # system RNG
pc cipher rng random_data.bin  # any file
```

---

## 2. MORPH - Binary Analysis ("X-Ray")

MORPH is your "X-ray" - it sees what's happening inside a program: what functions it uses, whether there's malicious code, how suspicious it is.

### 2.1 Full Analysis

**What it does:** Analyzes ELF (Linux), PE (Windows), DEX (Android) files. Examines: structure, imports, strings, entropy, shellcode, suspicious APIs.

```bash
# Linux binary analysis (ELF detected automatically)
pc morph /usr/bin/ls
pc morph /usr/bin/ssh
pc morph /usr/bin/nmap

# Windows EXE analysis
pc morph suspicious.exe --format pe
pc morph malware_sample.exe -f pe

# Android APK/DEX analysis
pc morph classes.dex --format dex
```

### 2.2 Risk Assessment

MORPH scores every file on a **0-100** scale:

| Score | Level | What it means |
|-------|-------|---------------|
| 0-25 | LOW | Legitimate program |
| 26-50 | MEDIUM | Some suspicious signs (may be normal) |
| 51-75 | HIGH | Suspicious, requires attention |
| 76-100 | CRITICAL | Almost certainly malware |

### 2.3 What Suspicious Signs it Looks For

- **Process Injection** - program tries to inject code into other processes
- **Keylogging** - keyboard monitoring (GetAsyncKeyState, SetWindowsHookEx)
- **Anti-Debug** - malware tries to avoid analysis
- **Privilege Escalation** - attempts to gain elevated privileges
- **Network Activity** - network communication (C2 server connection)
- **Shellcode Patterns** - malicious code patterns (XOR decoder, NOP sled, API hashing)
- **Packed/Encrypted** - packed or encrypted sections

### 2.4 Specialized Modes

```bash
# Strings extraction only
pc morph suspicious.exe --strings-only
# Shows: URLs, IPs, file paths, registry keys

# Entropy only
pc morph packed_malware.exe --entropy-only
# Shows: each section's entropy, whether it's packed

# JSON output (for integration with other tools)
pc morph sample.exe --json

# HTML report
pc morph sample.exe --output report.html
```

### 2.5 Practical Scenario: "Someone sent me a suspicious file"

```bash
# Step 1: General analysis
pc morph suspicious_file.exe -f pe

# Step 2: If Risk > 50, check strings
pc morph suspicious_file.exe --strings-only

# Step 3: If entropy > 7.5, it's likely packed
pc cipher entropy suspicious_file.exe

# Conclusion: If Risk > 75, don't open it!
```

---

## 3. NEXUS - Threat Intelligence ("Detective")

NEXUS is your "detective" - it searches for known vulnerabilities (CVEs), identifies Indicators of Compromise (IoCs), and maps to the MITRE ATT&CK framework.

### 3.1 CVE Lookup (`cve`)

**What it does:** Searches for a specific CVE (Common Vulnerabilities and Exposures) and provides full information: what the vulnerability is, how dangerous it is, likelihood of exploitation.

**Why you need it:** You're a pentester or Blue Team member and found a vulnerability - you need to know how serious it is.

```bash
# Log4Shell - one of the most famous vulnerabilities
pc nexus cve CVE-2021-44228

# Any CVE
pc nexus cve CVE-2023-0001
pc nexus cve CVE-2024-3400

# Reports:
# - Description (what the vulnerability is)
# - CVSS score (0-10, severity)
# - Exploitation Probability (likelihood of exploitation)
# - MITRE ATT&CK technique (how it's exploited)
```

### 3.2 IoC Extraction (`ioc`)

**What it does:** Scans a file and extracts **Indicators of Compromise** - IP addresses, domains, URLs, hashes, emails, CVEs.

**Why you need it:** You have a malware analysis report, or a suspicious log - NEXUS automatically extracts all IoCs.

```bash
# Extract IoCs from a threat report
pc nexus ioc threat_report.txt
pc nexus ioc malware_analysis.txt
pc nexus ioc /var/log/syslog

# Extracts:
# - IP addresses (192.168.1.1, 10.0.0.1)
# - Domains (evil.com, c2-server.net)
# - URLs
# - Hashes (MD5, SHA1, SHA256)
# - Email addresses
# - CVE IDs
```

### 3.3 MITRE ATT&CK Technique (`mitre`)

**What it does:** Looks up a MITRE ATT&CK technique by ID. MITRE ATT&CK is a universal catalog of attacker tactics and techniques.

**Why you need it:** During incident investigation or Red Team reporting, you need to reference specific techniques.

```bash
# Look up a specific technique
pc nexus mitre T1190    # Exploit Public-Facing Application
pc nexus mitre T1059    # Command and Scripting Interpreter
pc nexus mitre T1059.001  # PowerShell (sub-technique)
pc nexus mitre T1071    # Application Layer Protocol

# Reports:
# - Technique description
# - What tactic it belongs to
# - What platforms it works on
# - How to detect it (Detection)
```

### 3.4 CVE Database Search (`search`)

```bash
# Free-text search in CVE database
pc nexus search "remote code execution"
pc nexus search "Apache Log4j"
pc nexus search "buffer overflow Linux kernel"
pc nexus search "SQL injection WordPress"
```

### 3.5 Risk Assessment (`assess`)

```bash
# Full assessment with JSON config
pc nexus assess assessment_config.json
```

Configuration file format:
```json
{
  "cve_ids": ["CVE-2021-44228", "CVE-2023-0001"],
  "ioc_text": "Text with suspicious IPs and domains",
  "ioc_files": ["/path/to/threat_report.txt"],
  "asset_criticality": 75.0
}
```

---

## 4. SPECTRA - Network Analysis ("Surveillance Camera")

SPECTRA is your "surveillance camera" for the network - it analyzes network traffic, finds anomalies, and builds communication graphs.

### 4.1 PCAP File Analysis

**What it does:** Reads a PCAP file (network traffic recording) and analyzes: who communicated with whom, on which ports, whether there are anomalies, whether there are C2 beacons.

```bash
# PCAP file analysis
pc spectra -i capture.pcap
pc spectra -i /path/to/network_dump.pcap

# With HTML report
pc spectra -i capture.pcap --output report.html

# JSON format
pc spectra -i capture.pcap --format json

# Anomaly sensitivity adjustment
pc spectra -i capture.pcap --anomaly-threshold 2.0   # more sensitive
pc spectra -i capture.pcap --anomaly-threshold 4.0   # less sensitive
```

### 4.2 Live Traffic Capture

```bash
# 60-second live capture (requires root)
pc spectra --live --duration 60

# On a specific interface
pc spectra --live --interface eth0 --duration 120

# On WiFi interface
pc spectra --live --interface wlan0mon --duration 60
```

### 4.3 What SPECTRA Looks For

- **Anomalies** - unexpected traffic spikes/drops (Z-score, IQR)
- **C2 Beacons** - malware's periodic "pings" to C2 server (timing entropy)
- **Lateral Movement** - hacker moving through the network from one machine to another
- **Network Topology** - who is connected to whom (graph theory)
- **Key Nodes** - most active/important IPs (PageRank, Betweenness)
- **Communication Groups** - IP clusters (Louvain community detection)

### 4.4 Practical Scenario: "I suspect malware is on the network"

```bash
# Step 1: Record traffic (with tcpdump or Wireshark)
sudo tcpdump -i eth0 -w capture.pcap -c 10000

# Step 2: Analyze with SPECTRA
pc spectra -i capture.pcap

# Step 3: Look at:
# - Beacon Detection: Is there C2 communication?
# - Anomalies: Is anything unusual happening?
# - Top Talkers: Who is sending the most data?
# - Lateral Movement: Is anyone "crawling" through the network?
```

---

## 5. PULSE - Wireless Analysis ("Radar")

PULSE is your "radar" - it scans WiFi networks, Bluetooth devices, and finds security problems.

### 5.1 WiFi Scanning (`scan`)

**What it does:** Scans WiFi networks, rates their security (A-F), finds weak networks.

**Why you need it:** The first step in wireless penetration testing - surveying the environment.

```bash
# WiFi scan (requires monitor mode)
pc pulse scan --interface wlan0mon
pc pulse scan -i wlan0mon --duration 60

# Specific channel
pc pulse scan -i wlan0mon --channel 6

# With report
pc pulse scan -i wlan0mon --output wifi_audit.html

# Enable monitor mode (before scanning):
sudo airmon-ng start wlan0
```

### 5.2 Security Rating

| Grade | Encryption | Status |
|-------|-----------|--------|
| A | WPA3 + PMF | Excellent |
| B | WPA2-AES + PMF | Good |
| C | WPA2-AES (without PMF) | Acceptable |
| D | WPA/TKIP | Weak, needs upgrade |
| F | WEP or Open | Critically weak! |

### 5.3 BLE (Bluetooth Low Energy) Scanning (`ble`)

```bash
# BLE device scanning
pc pulse ble
pc pulse ble --duration 30

# Shows:
# - Device name
# - MAC address (randomized or not)
# - Services (UUID)
# - Signal strength
# - Tracking risk
```

### 5.4 Wireless IDS (`ids`)

**What it does:** Continuous monitoring - watches the wireless environment and detects attacks in real time.

```bash
# 5-minute monitoring
pc pulse ids --interface wlan0mon --duration 300

# Specific channel
pc pulse ids -i wlan0mon --channel 6 --duration 600

# What it detects:
# - Deauth attacks (WiFi connection disconnection)
# - Rogue AP (fake access point)
# - WEP/Open networks
# - Suspicious clients
```

### 5.5 PCAP Analysis (`analyze`)

```bash
# WiFi PCAP file analysis (recorded with Wireshark or airodump)
pc pulse analyze wifi_capture.pcap
pc pulse analyze wifi_capture.pcap --output report.html
```

---

## Practical Scenarios

### Scenario 1: CTF (Capture The Flag) Competition

```bash
# 1. Found a hash - what type is it?
pc cipher hash-id "e99a18c428cb38d5f260853678922e03"

# 2. Suspicious binary - what is it?
pc morph challenge_binary

# 3. Encrypted file - what cipher is it?
pc cipher frequency encrypted_file.txt
pc cipher entropy encrypted_file.txt

# 4. Network PCAP - what's happening?
pc spectra -i challenge.pcap
```

### Scenario 2: Penetration Testing

```bash
# 1. WiFi environment scanning
pc pulse scan -i wlan0mon -d 120

# 2. Server TLS check
pc cipher tls target-server.com

# 3. Research found CVEs
pc nexus cve CVE-2024-XXXX
pc nexus mitre T1190

# 4. Network traffic analysis
pc spectra -i pentest_capture.pcap

# 5. Check found binaries
pc morph suspicious_service -f elf
```

### Scenario 3: Incident Response

```bash
# 1. Extract IoCs from logs
pc nexus ioc /var/log/syslog
pc nexus ioc suspicious_email.txt

# 2. Analyze found malware
pc morph malware_sample.exe -f pe
pc cipher entropy malware_sample.exe

# 3. Network traffic analysis (search for C2 beacons)
pc spectra -i incident_capture.pcap

# 4. Research found CVEs
pc nexus cve CVE-2021-44228

# 5. Wireless IDS (if wireless attack suspected)
pc pulse ids -i wlan0mon -d 600
```

### Scenario 4: Security Audit

```bash
# 1. Check all servers' TLS
pc cipher tls server1.company.com
pc cipher tls server2.company.com
pc cipher tls mail.company.com --port 587

# 2. Check cryptographic configuration
pc cipher key-strength --algorithm RSA --key-size 2048
pc cipher key-strength --algorithm AES --key-size 128

# 3. WiFi infrastructure audit
pc pulse scan -i wlan0mon -d 120
pc pulse ids -i wlan0mon -d 300

# 4. Network traffic normality check
pc spectra --live -d 300 --interface eth0
```

---

## Key Concepts

### Entropy
A measure of information "randomness" (0-8 bits/byte). Text = low, encrypted = high. Created by Shannon in 1948.

### CVSS (Common Vulnerability Scoring System)
Standard for vulnerability severity scoring (0-10). 9.0+ = critical.

### MITRE ATT&CK
A universal catalog of attacker tactics and techniques. T1190 = Exploit Public Application, T1059 = Scripting, T1071 = C2 Communication.

### IoC (Indicators of Compromise)
IP addresses, domains, hashes, URLs associated with malicious activity.

### C2 (Command and Control)
The malware's "command center" - the server from which a hacker controls infected computers. SPECTRA can detect beacons.

### Shellcode
Small malicious code that executes directly in memory. MORPH looks for such patterns in binaries.

---

## Global Options

All tools support:

```bash
--output, -o    # Output format or file path
--verbose, -v   # Verbose output (for debugging)
--quiet, -q     # Quiet mode
--config, -c    # Configuration file path
```

---

## Tips

1. **Always start with `pc doctor`** - make sure everything is working
2. **Don't rely on a single tool** - use several together
3. **MORPH + CIPHER together** - binary analysis + entropy = full picture
4. **NEXUS + SPECTRA together** - CVE + network analysis = threat correlation
5. **JSON output** - for automation and integration with other tools
6. **HTML reports** - beautiful reports for clients or management

---

## Legal Disclaimer

PhantomCore is designed **for educational and authorized security research only**. Use only:
- On your own systems
- With written authorization
- In educational environments (CTF, laboratory)
- Within professional pentesting engagements (under contract)

Use on unauthorized systems is **illegal** and may result in criminal liability.
