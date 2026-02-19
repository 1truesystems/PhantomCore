#!/usr/bin/env bash
# ============================================================
# PhantomCore Quick Launcher (Computer + Phone)
# ============================================================
# Usage:
#   pc doctor                           # health check
#   pc test                             # tests
#   pc cipher entropy /usr/bin/ls       # entropy
#   pc cipher hash-id <hash>            # hash ID
#   pc cipher tls example.com           # TLS assessment
#   pc cipher password "MyP@ss"         # password strength
#   pc morph /usr/bin/ls                # binary analysis
#   pc nexus cve CVE-2021-44228         # CVE lookup
#   pc nexus ioc report.txt             # IoC extraction
#   pc nexus mitre T1190                # MITRE ATT&CK
#   pc spectra -i capture.pcap          # PCAP analysis
#   pc pulse scan --interface wlan0mon  # WiFi scanning
# ============================================================

set -euo pipefail

# Where are we?
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHROOT="/data/local/nhsystem/kali-arm64"

# Phone or computer?
if [ -d "$CHROOT" ]; then
    # ===== Phone (chroot) =====
    PC_DIR="/null3xxx-toolkit/PhantomCore"
    SETUP="export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin && cd ${PC_DIR} && source .venv/bin/activate"

    if [ $# -eq 0 ]; then
        echo "[*] PhantomCore interactive shell (phone)"
        echo "[*] To exit: exit"
        su -c "chroot ${CHROOT} /usr/bin/bash -c '${SETUP} && bash --norc'"
        exit 0
    fi

    CMD="$1"; shift
    case "$CMD" in
        doctor|test|setup)
            su -c "chroot ${CHROOT} /usr/bin/bash -c '${SETUP} && bash phantomcore.sh ${CMD} $*'" ;;
        cipher|morph|spectra|nexus|pulse)
            su -c "chroot ${CHROOT} /usr/bin/bash -c '${SETUP} && python -m ${CMD}.cli $*'" ;;
        *)
            su -c "chroot ${CHROOT} /usr/bin/bash -c '${SETUP} && $CMD $*'" ;;
    esac
else
    # ===== Computer (direct) =====
    cd "$SCRIPT_DIR"

    # venv activation
    if [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    fi

    if [ $# -eq 0 ]; then
        echo "[*] PhantomCore interactive shell (computer)"
        echo "[*] Usage: pc cipher entropy /usr/bin/ls"
        echo "[*]            pc morph /usr/bin/ls"
        echo "[*]            pc nexus cve CVE-2021-44228"
        echo "[*]            pc doctor"
        exit 0
    fi

    CMD="$1"; shift
    case "$CMD" in
        doctor|test|setup)
            bash phantomcore.sh "$CMD" "$@" ;;
        cipher|morph|spectra|nexus|pulse)
            python -m "${CMD}.cli" "$@" ;;
        *)
            eval "$CMD $*" ;;
    esac
fi
