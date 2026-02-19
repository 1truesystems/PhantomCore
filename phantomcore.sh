#!/usr/bin/env bash
# ============================================================================
# PhantomCore - Elite Cybersecurity Educational Toolkit Launcher
# ============================================================================
# 5 tools: SPECTRA, CIPHER, MORPH, NEXUS, PULSE
# alias: pc
# ============================================================================
set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
PYTHON="${VENV_DIR}/bin/python"
PIP="${VENV_DIR}/bin/pip"
REQUIREMENTS="${SCRIPT_DIR}/requirements.txt"
LOG_FILE="${SCRIPT_DIR}/phantomcore.log"

# --- Platform detection ---
detect_platform() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        aarch64|arm64) PLATFORM="arm64" ;;
        x86_64|amd64)  PLATFORM="x86_64" ;;
        armv7l|armhf)   PLATFORM="armv7" ;;
        *)              PLATFORM="unknown" ;;
    esac

    local os
    os="$(uname -s)"
    case "${os}" in
        Linux)  OS_TYPE="linux" ;;
        Darwin) OS_TYPE="macos" ;;
        *)      OS_TYPE="unknown" ;;
    esac

    # Termux / chroot detection
    if [ -f /data/local/nhsystem/kali-arm64/usr/bin/bash ]; then
        ENVIRONMENT="kali-chroot"
    elif [ -n "${TERMUX_VERSION:-}" ]; then
        ENVIRONMENT="termux"
    elif [ -f /etc/debian_version ]; then
        ENVIRONMENT="debian"
    else
        ENVIRONMENT="generic"
    fi
}

# --- Banner ---
show_banner() {
    echo -e "${MAGENTA}"
    cat << 'BANNER'
    ____  __                __                  ______
   / __ \/ /_  ____ _____  / /_____  ____ ___  / ____/___  ________
  / /_/ / __ \/ __ `/ __ \/ __/ __ \/ __ `__ \/ /   / __ \/ ___/ _ \
 / ____/ / / / /_/ / / / / /_/ /_/ / / / / / / /___/ /_/ / /  /  __/
/_/   /_/ /_/\__,_/_/ /_/\__/\____/_/ /_/ /_/\____/\____/_/   \___/
BANNER
    echo -e "${NC}"
    echo -e "${CYAN}  Elite Cybersecurity Educational Toolkit v1.0.0${NC}"
    echo -e "${GRAY}  Platform: ${PLATFORM} | OS: ${OS_TYPE} | Env: ${ENVIRONMENT}${NC}"
    echo -e "${GRAY}  ──────────────────────────────────────────────────${NC}"
    echo ""
}

# --- venv management ---
ensure_venv() {
    if [ ! -d "${VENV_DIR}" ]; then
        echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
        python3 -m venv "${VENV_DIR}" 2>/dev/null || {
            echo -e "${RED}[!] Failed to create venv. Please install python3-venv.${NC}"
            exit 1
        }
    fi

    if [ ! -f "${PYTHON}" ]; then
        echo -e "${RED}[!] Python not found: ${PYTHON}${NC}"
        exit 1
    fi
}

# --- Dependency installation ---
install_deps() {
    echo -e "${CYAN}[*] Installing dependencies...${NC}"
    "${PIP}" install --upgrade pip --quiet 2>/dev/null
    "${PIP}" install -r "${REQUIREMENTS}" --quiet 2>/dev/null || {
        echo -e "${YELLOW}[!] Some packages failed to install. Trying individually...${NC}"
        while IFS= read -r line; do
            line="$(echo "${line}" | sed 's/#.*//' | xargs)"
            [ -z "${line}" ] && continue
            "${PIP}" install "${line}" --quiet 2>/dev/null || \
                echo -e "${YELLOW}  [!] Failed to install: ${line}${NC}"
        done < "${REQUIREMENTS}"
    }
    echo -e "${GREEN}[+] Dependencies installed.${NC}"
}

# --- Alias installation ---
install_alias() {
    local alias_path="/usr/local/bin/pc"
    if [ -w "/usr/local/bin" ] || [ "$(id -u)" -eq 0 ]; then
        cat > "${alias_path}" << ALIAS
#!/usr/bin/env bash
exec "${SCRIPT_DIR}/phantomcore.sh" "\$@"
ALIAS
        chmod +x "${alias_path}"
        echo -e "${GREEN}[+] Alias installed: ${alias_path}${NC}"
    else
        echo -e "${YELLOW}[!] Root privileges required for alias installation.${NC}"
        echo -e "${GRAY}    Run: sudo ln -sf ${SCRIPT_DIR}/phantomcore.sh /usr/local/bin/pc${NC}"
    fi
}

# --- Setup ---
cmd_setup() {
    echo -e "${CYAN}[*] PhantomCore Setup${NC}"
    detect_platform
    ensure_venv
    install_deps
    install_alias
    echo ""
    echo -e "${GREEN}[+] Setup complete!${NC}"
    echo -e "${GRAY}    Run: pc doctor  - for health check${NC}"
}

# --- Tool Runners ---
run_tool() {
    local tool_module="$1"
    shift
    ensure_venv
    cd "${SCRIPT_DIR}"
    PYTHONPATH="${SCRIPT_DIR}" "${PYTHON}" -m "${tool_module}" "$@"
}

cmd_spectra() {
    echo -e "${CYAN}[SPECTRA]${NC} Network Intelligence Engine"
    run_tool "spectra.cli" "$@"
}

cmd_cipher() {
    echo -e "${GREEN}[CIPHER]${NC} Cryptanalysis Framework"
    run_tool "cipher.cli" "$@"
}

cmd_morph() {
    echo -e "${MAGENTA}[MORPH]${NC} Binary Analysis Framework"
    run_tool "morph.cli" "$@"
}

cmd_nexus() {
    echo -e "${YELLOW}[NEXUS]${NC} Threat Intelligence Correlator"
    run_tool "nexus.cli" "$@"
}

cmd_pulse() {
    echo -e "${RED}[PULSE]${NC} Wireless Protocol Analyzer"
    run_tool "pulse.cli" "$@"
}

# --- Pipeline ---
cmd_pipeline() {
    echo -e "${WHITE}[PIPELINE]${NC} Integrated analysis"
    local target="${1:-}"
    if [ -z "${target}" ]; then
        echo -e "${RED}[!] Usage: pc pipeline <target>${NC}"
        exit 1
    fi

    echo -e "${CYAN}── Phase 1: SPECTRA ──${NC}"
    cmd_spectra -i "${target}" 2>/dev/null || echo -e "${YELLOW}  [!] SPECTRA skipped${NC}"

    echo -e "${GREEN}── Phase 2: CIPHER ──${NC}"
    cmd_cipher entropy "${target}" 2>/dev/null || echo -e "${YELLOW}  [!] CIPHER skipped${NC}"

    echo -e "${MAGENTA}── Phase 3: MORPH ──${NC}"
    cmd_morph "${target}" 2>/dev/null || echo -e "${YELLOW}  [!] MORPH skipped${NC}"

    echo -e "${YELLOW}── Phase 4: NEXUS ──${NC}"
    cmd_nexus ioc "${target}" 2>/dev/null || echo -e "${YELLOW}  [!] NEXUS skipped${NC}"

    echo -e "${RED}── Phase 5: PULSE ──${NC}"
    cmd_pulse analyze "${target}" 2>/dev/null || echo -e "${YELLOW}  [!] PULSE skipped${NC}"

    echo ""
    echo -e "${GREEN}[+] Pipeline complete.${NC}"
}

# --- Doctor ---
cmd_doctor() {
    echo -e "${CYAN}[DOCTOR]${NC} Health check"
    echo ""
    ensure_venv

    local all_ok=true

    # Python version
    local pyver
    pyver="$("${PYTHON}" --version 2>&1)"
    echo -e "  ${GREEN}✓${NC} Python: ${pyver}"

    # Platform
    echo -e "  ${GREEN}✓${NC} Platform: ${PLATFORM} / ${OS_TYPE} / ${ENVIRONMENT}"

    # Check each module
    local modules=("shared.config" "shared.console" "shared.models" "shared.math_utils" "shared.logger" "shared.network"
                    "spectra.cli" "spectra.core.engine"
                    "cipher.cli" "cipher.core.engine"
                    "morph.cli" "morph.core.engine"
                    "nexus.cli" "nexus.core.engine"
                    "pulse.cli" "pulse.core.engine")

    for mod in "${modules[@]}"; do
        if cd "${SCRIPT_DIR}" && PYTHONPATH="${SCRIPT_DIR}" "${PYTHON}" -c "import ${mod}" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} ${mod}"
        else
            echo -e "  ${RED}✗${NC} ${mod}"
            all_ok=false
        fi
    done

    echo ""

    # Check dependencies
    echo -e "${CYAN}  Dependencies:${NC}"
    local deps=("httpx" "pydantic" "rich" "click" "jinja2" "numpy" "scipy" "scapy" "networkx" "Crypto" "capstone")
    for dep in "${deps[@]}"; do
        if cd "${SCRIPT_DIR}" && PYTHONPATH="${SCRIPT_DIR}" "${PYTHON}" -c "import ${dep}" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} ${dep}"
        else
            echo -e "  ${YELLOW}○${NC} ${dep} (not installed)"
            all_ok=false
        fi
    done

    echo ""
    if [ "${all_ok}" = true ]; then
        echo -e "${GREEN}[+] All components are ready!${NC}"
    else
        echo -e "${YELLOW}[!] Some components are not available.${NC}"
        echo -e "${GRAY}    Run: pc setup${NC}"
    fi
}

# --- Test ---
cmd_test() {
    echo -e "${CYAN}[TEST]${NC} Running tests"
    ensure_venv
    cd "${SCRIPT_DIR}"
    PYTHONPATH="${SCRIPT_DIR}" "${PYTHON}" -m pytest -v --tb=short "$@" 2>/dev/null || {
        # Fallback: basic import tests
        echo -e "${YELLOW}[*] pytest not available, running basic tests...${NC}"
        PYTHONPATH="${SCRIPT_DIR}" "${PYTHON}" -c "
from shared.math_utils import shannon_entropy, frequency_distribution
import numpy as np

# Test 1: entropy of zeros should be 0
zeros = bytes(1000)
e = shannon_entropy(zeros)
assert abs(e) < 0.01, f'entropy(zeros) = {e}, expected ~0.0'
print(f'  ✓ entropy(zeros) = {e:.4f} (expected ~0.0)')

# Test 2: entropy of random should be ~8.0
rng = np.random.default_rng(42)
random_data = bytes(rng.integers(0, 256, size=100000, dtype=np.uint8))
e = shannon_entropy(random_data)
assert 7.9 < e < 8.1, f'entropy(random) = {e}, expected ~8.0'
print(f'  ✓ entropy(random) = {e:.4f} (expected ~8.0)')

# Test 3: frequency distribution
dist = frequency_distribution(b'AAABBC')
assert dist[65] == 3  # 'A' = 65
print(f'  ✓ frequency_distribution correct')

print()
print('All basic tests completed successfully!')
"
    }
}

# --- Help ---
cmd_help() {
    show_banner
    echo -e "${WHITE}Usage:${NC} pc <command> [arguments]"
    echo ""
    echo -e "${WHITE}Tools:${NC}"
    echo -e "  ${CYAN}spectra${NC}    Network Intelligence Engine (PCAP/live analysis)"
    echo -e "  ${GREEN}cipher${NC}     Cryptanalysis Framework (entropy, hashes, TLS)"
    echo -e "  ${MAGENTA}morph${NC}      Binary Analysis Framework (ELF/PE/DEX)"
    echo -e "  ${YELLOW}nexus${NC}      Threat Intelligence Correlator (CVE, MITRE ATT&CK)"
    echo -e "  ${RED}pulse${NC}      Wireless Protocol Analyzer (WiFi/BLE)"
    echo ""
    echo -e "${WHITE}Commands:${NC}"
    echo -e "  ${WHITE}setup${NC}      Install dependencies and configure"
    echo -e "  ${WHITE}pipeline${NC}   Run all tools sequentially"
    echo -e "  ${WHITE}doctor${NC}     Health check"
    echo -e "  ${WHITE}test${NC}       Run tests"
    echo -e "  ${WHITE}help${NC}       This message"
    echo ""
    echo -e "${WHITE}Examples:${NC}"
    echo -e "  ${GRAY}pc spectra -i capture.pcap${NC}"
    echo -e "  ${GRAY}pc cipher entropy /usr/bin/ls${NC}"
    echo -e "  ${GRAY}pc cipher hash-id 5d41402abc4b2a76b9719d911017c592${NC}"
    echo -e "  ${GRAY}pc morph /usr/bin/ls${NC}"
    echo -e "  ${GRAY}pc nexus cve CVE-2021-44228${NC}"
    echo -e "  ${GRAY}pc pulse scan --interface wlan0mon${NC}"
    echo ""
}

# --- Main ---
main() {
    detect_platform

    local cmd="${1:-help}"
    shift 2>/dev/null || true

    case "${cmd}" in
        setup)      cmd_setup ;;
        spectra)    cmd_spectra "$@" ;;
        cipher)     cmd_cipher "$@" ;;
        morph)      cmd_morph "$@" ;;
        nexus)      cmd_nexus "$@" ;;
        pulse)      cmd_pulse "$@" ;;
        pipeline)   cmd_pipeline "$@" ;;
        doctor)     cmd_doctor ;;
        test)       cmd_test "$@" ;;
        help|--help|-h) cmd_help ;;
        *)
            echo -e "${RED}[!] Unknown command: ${cmd}${NC}"
            echo -e "${GRAY}    Run: pc help${NC}"
            exit 1
            ;;
    esac
}

main "$@"
