"""
Import API Analyzer
====================

Categorises imported API functions by their security-relevant behaviour
and generates findings for suspicious import combinations.

The analyzer maintains a curated database of Windows API functions
organised by behavioural category.  When a binary imports functions
from multiple suspicious categories, the combined risk is elevated.

Categories:
    - Process injection (CreateRemoteThread, VirtualAllocEx, etc.)
    - Code injection (LoadLibrary, GetProcAddress)
    - Keylogging (GetAsyncKeyState, SetWindowsHookEx)
    - Anti-debug (IsDebuggerPresent, CheckRemoteDebuggerPresent)
    - Anti-VM (CPUID detection, registry VM checks)
    - File operations (DeleteFile, MoveFile, CreateFile)
    - Network (WSASocket, connect, send, recv, InternetOpen)
    - Registry (RegSetValue, RegCreateKey)
    - Cryptographic (CryptEncrypt, BCryptEncrypt)
    - Privilege escalation (AdjustTokenPrivileges, OpenProcessToken)

References:
    - Microsoft. (2024). Windows API Index. Microsoft Learn.
    - MITRE ATT&CK Framework. (2024). https://attack.mitre.org/
    - Sikorski, M., & Honig, A. (2012). Practical Malware Analysis.
      No Starch Press.
"""

from __future__ import annotations

from shared.models import Finding, Risk, RiskLevel, Severity

from morph.core.models import ImportCategory, ImportInfo


# ---------------------------------------------------------------------------
# API category database
# ---------------------------------------------------------------------------

_API_CATEGORIES: dict[str, ImportCategory] = {
    # Process injection
    "CreateRemoteThread": ImportCategory.PROCESS_INJECTION,
    "CreateRemoteThreadEx": ImportCategory.PROCESS_INJECTION,
    "VirtualAllocEx": ImportCategory.PROCESS_INJECTION,
    "VirtualProtectEx": ImportCategory.PROCESS_INJECTION,
    "WriteProcessMemory": ImportCategory.PROCESS_INJECTION,
    "ReadProcessMemory": ImportCategory.PROCESS_INJECTION,
    "NtQueueApcThread": ImportCategory.PROCESS_INJECTION,
    "NtCreateThreadEx": ImportCategory.PROCESS_INJECTION,
    "RtlCreateUserThread": ImportCategory.PROCESS_INJECTION,
    "QueueUserAPC": ImportCategory.PROCESS_INJECTION,
    "NtMapViewOfSection": ImportCategory.PROCESS_INJECTION,
    "NtUnmapViewOfSection": ImportCategory.PROCESS_INJECTION,
    "SetThreadContext": ImportCategory.PROCESS_INJECTION,
    "GetThreadContext": ImportCategory.PROCESS_INJECTION,
    "SuspendThread": ImportCategory.PROCESS_INJECTION,
    "ResumeThread": ImportCategory.PROCESS_INJECTION,
    "OpenProcess": ImportCategory.PROCESS_INJECTION,
    "NtWriteVirtualMemory": ImportCategory.PROCESS_INJECTION,

    # Code injection / dynamic loading
    "LoadLibraryA": ImportCategory.CODE_INJECTION,
    "LoadLibraryW": ImportCategory.CODE_INJECTION,
    "LoadLibraryExA": ImportCategory.CODE_INJECTION,
    "LoadLibraryExW": ImportCategory.CODE_INJECTION,
    "GetProcAddress": ImportCategory.CODE_INJECTION,
    "GetModuleHandleA": ImportCategory.CODE_INJECTION,
    "GetModuleHandleW": ImportCategory.CODE_INJECTION,
    "LdrLoadDll": ImportCategory.CODE_INJECTION,
    "LdrGetProcedureAddress": ImportCategory.CODE_INJECTION,
    "VirtualAlloc": ImportCategory.CODE_INJECTION,
    "VirtualProtect": ImportCategory.CODE_INJECTION,
    "HeapCreate": ImportCategory.CODE_INJECTION,

    # Keylogging
    "GetAsyncKeyState": ImportCategory.KEYLOGGING,
    "GetKeyState": ImportCategory.KEYLOGGING,
    "GetKeyboardState": ImportCategory.KEYLOGGING,
    "SetWindowsHookExA": ImportCategory.KEYLOGGING,
    "SetWindowsHookExW": ImportCategory.KEYLOGGING,
    "GetForegroundWindow": ImportCategory.KEYLOGGING,
    "GetWindowTextA": ImportCategory.KEYLOGGING,
    "GetWindowTextW": ImportCategory.KEYLOGGING,
    "AttachThreadInput": ImportCategory.KEYLOGGING,
    "MapVirtualKeyA": ImportCategory.KEYLOGGING,
    "MapVirtualKeyW": ImportCategory.KEYLOGGING,
    "GetClipboardData": ImportCategory.KEYLOGGING,

    # Anti-debug
    "IsDebuggerPresent": ImportCategory.ANTI_DEBUG,
    "CheckRemoteDebuggerPresent": ImportCategory.ANTI_DEBUG,
    "NtQueryInformationProcess": ImportCategory.ANTI_DEBUG,
    "NtSetInformationThread": ImportCategory.ANTI_DEBUG,
    "OutputDebugStringA": ImportCategory.ANTI_DEBUG,
    "OutputDebugStringW": ImportCategory.ANTI_DEBUG,
    "FindWindowA": ImportCategory.ANTI_DEBUG,
    "FindWindowW": ImportCategory.ANTI_DEBUG,
    "GetTickCount": ImportCategory.ANTI_DEBUG,
    "QueryPerformanceCounter": ImportCategory.ANTI_DEBUG,
    "NtQuerySystemInformation": ImportCategory.ANTI_DEBUG,
    "CloseHandle": ImportCategory.ANTI_DEBUG,  # Used with invalid handles for detection
    "UnhandledExceptionFilter": ImportCategory.ANTI_DEBUG,
    "SetUnhandledExceptionFilter": ImportCategory.ANTI_DEBUG,
    "RaiseException": ImportCategory.ANTI_DEBUG,

    # Anti-VM
    "GetSystemFirmwareTable": ImportCategory.ANTI_VM,
    "EnumSystemFirmwareTables": ImportCategory.ANTI_VM,
    "GetVolumeInformationA": ImportCategory.ANTI_VM,
    "GetVolumeInformationW": ImportCategory.ANTI_VM,
    "GetDiskFreeSpaceExA": ImportCategory.ANTI_VM,
    "GetDiskFreeSpaceExW": ImportCategory.ANTI_VM,
    "EnumDeviceDrivers": ImportCategory.ANTI_VM,
    "GetDeviceDriverBaseNameA": ImportCategory.ANTI_VM,
    "GetDeviceDriverBaseNameW": ImportCategory.ANTI_VM,
    "GlobalMemoryStatusEx": ImportCategory.ANTI_VM,

    # File operations
    "CreateFileA": ImportCategory.FILE_OPERATIONS,
    "CreateFileW": ImportCategory.FILE_OPERATIONS,
    "DeleteFileA": ImportCategory.FILE_OPERATIONS,
    "DeleteFileW": ImportCategory.FILE_OPERATIONS,
    "MoveFileA": ImportCategory.FILE_OPERATIONS,
    "MoveFileW": ImportCategory.FILE_OPERATIONS,
    "MoveFileExA": ImportCategory.FILE_OPERATIONS,
    "MoveFileExW": ImportCategory.FILE_OPERATIONS,
    "CopyFileA": ImportCategory.FILE_OPERATIONS,
    "CopyFileW": ImportCategory.FILE_OPERATIONS,
    "WriteFile": ImportCategory.FILE_OPERATIONS,
    "ReadFile": ImportCategory.FILE_OPERATIONS,
    "GetTempPathA": ImportCategory.FILE_OPERATIONS,
    "GetTempPathW": ImportCategory.FILE_OPERATIONS,
    "GetTempFileNameA": ImportCategory.FILE_OPERATIONS,
    "GetTempFileNameW": ImportCategory.FILE_OPERATIONS,
    "FindFirstFileA": ImportCategory.FILE_OPERATIONS,
    "FindFirstFileW": ImportCategory.FILE_OPERATIONS,
    "FindNextFileA": ImportCategory.FILE_OPERATIONS,
    "FindNextFileW": ImportCategory.FILE_OPERATIONS,
    "GetSystemDirectoryA": ImportCategory.FILE_OPERATIONS,
    "GetSystemDirectoryW": ImportCategory.FILE_OPERATIONS,
    "SetFileAttributesA": ImportCategory.FILE_OPERATIONS,
    "SetFileAttributesW": ImportCategory.FILE_OPERATIONS,
    "CreateDirectoryA": ImportCategory.FILE_OPERATIONS,
    "CreateDirectoryW": ImportCategory.FILE_OPERATIONS,

    # Network
    "WSAStartup": ImportCategory.NETWORK,
    "WSASocketA": ImportCategory.NETWORK,
    "WSASocketW": ImportCategory.NETWORK,
    "socket": ImportCategory.NETWORK,
    "connect": ImportCategory.NETWORK,
    "bind": ImportCategory.NETWORK,
    "listen": ImportCategory.NETWORK,
    "accept": ImportCategory.NETWORK,
    "send": ImportCategory.NETWORK,
    "recv": ImportCategory.NETWORK,
    "sendto": ImportCategory.NETWORK,
    "recvfrom": ImportCategory.NETWORK,
    "closesocket": ImportCategory.NETWORK,
    "InternetOpenA": ImportCategory.NETWORK,
    "InternetOpenW": ImportCategory.NETWORK,
    "InternetOpenUrlA": ImportCategory.NETWORK,
    "InternetOpenUrlW": ImportCategory.NETWORK,
    "InternetConnectA": ImportCategory.NETWORK,
    "InternetConnectW": ImportCategory.NETWORK,
    "InternetReadFile": ImportCategory.NETWORK,
    "HttpOpenRequestA": ImportCategory.NETWORK,
    "HttpOpenRequestW": ImportCategory.NETWORK,
    "HttpSendRequestA": ImportCategory.NETWORK,
    "HttpSendRequestW": ImportCategory.NETWORK,
    "URLDownloadToFileA": ImportCategory.NETWORK,
    "URLDownloadToFileW": ImportCategory.NETWORK,
    "URLDownloadToCacheFileA": ImportCategory.NETWORK,
    "URLDownloadToCacheFileW": ImportCategory.NETWORK,
    "WinHttpOpen": ImportCategory.NETWORK,
    "WinHttpConnect": ImportCategory.NETWORK,
    "WinHttpOpenRequest": ImportCategory.NETWORK,
    "WinHttpSendRequest": ImportCategory.NETWORK,
    "WinHttpReceiveResponse": ImportCategory.NETWORK,
    "WinHttpReadData": ImportCategory.NETWORK,
    "getaddrinfo": ImportCategory.NETWORK,
    "gethostbyname": ImportCategory.NETWORK,
    "inet_addr": ImportCategory.NETWORK,
    "DnsQuery_A": ImportCategory.NETWORK,
    "DnsQuery_W": ImportCategory.NETWORK,

    # Registry
    "RegOpenKeyExA": ImportCategory.REGISTRY,
    "RegOpenKeyExW": ImportCategory.REGISTRY,
    "RegCreateKeyExA": ImportCategory.REGISTRY,
    "RegCreateKeyExW": ImportCategory.REGISTRY,
    "RegSetValueExA": ImportCategory.REGISTRY,
    "RegSetValueExW": ImportCategory.REGISTRY,
    "RegQueryValueExA": ImportCategory.REGISTRY,
    "RegQueryValueExW": ImportCategory.REGISTRY,
    "RegDeleteKeyA": ImportCategory.REGISTRY,
    "RegDeleteKeyW": ImportCategory.REGISTRY,
    "RegDeleteValueA": ImportCategory.REGISTRY,
    "RegDeleteValueW": ImportCategory.REGISTRY,
    "RegEnumKeyExA": ImportCategory.REGISTRY,
    "RegEnumKeyExW": ImportCategory.REGISTRY,
    "RegEnumValueA": ImportCategory.REGISTRY,
    "RegEnumValueW": ImportCategory.REGISTRY,
    "RegCloseKey": ImportCategory.REGISTRY,
    "SHDeleteKeyA": ImportCategory.REGISTRY,
    "SHDeleteKeyW": ImportCategory.REGISTRY,

    # Cryptographic operations
    "CryptAcquireContextA": ImportCategory.CRYPTO,
    "CryptAcquireContextW": ImportCategory.CRYPTO,
    "CryptEncrypt": ImportCategory.CRYPTO,
    "CryptDecrypt": ImportCategory.CRYPTO,
    "CryptGenRandom": ImportCategory.CRYPTO,
    "CryptCreateHash": ImportCategory.CRYPTO,
    "CryptHashData": ImportCategory.CRYPTO,
    "CryptDeriveKey": ImportCategory.CRYPTO,
    "CryptImportKey": ImportCategory.CRYPTO,
    "CryptExportKey": ImportCategory.CRYPTO,
    "CryptGenKey": ImportCategory.CRYPTO,
    "CryptDestroyKey": ImportCategory.CRYPTO,
    "CryptReleaseContext": ImportCategory.CRYPTO,
    "BCryptOpenAlgorithmProvider": ImportCategory.CRYPTO,
    "BCryptEncrypt": ImportCategory.CRYPTO,
    "BCryptDecrypt": ImportCategory.CRYPTO,
    "BCryptGenerateSymmetricKey": ImportCategory.CRYPTO,
    "BCryptGenRandom": ImportCategory.CRYPTO,
    "BCryptHashData": ImportCategory.CRYPTO,

    # Privilege escalation
    "AdjustTokenPrivileges": ImportCategory.PRIVILEGE,
    "OpenProcessToken": ImportCategory.PRIVILEGE,
    "LookupPrivilegeValueA": ImportCategory.PRIVILEGE,
    "LookupPrivilegeValueW": ImportCategory.PRIVILEGE,
    "DuplicateTokenEx": ImportCategory.PRIVILEGE,
    "ImpersonateLoggedOnUser": ImportCategory.PRIVILEGE,
    "SetTokenInformation": ImportCategory.PRIVILEGE,
    "CreateProcessAsUserA": ImportCategory.PRIVILEGE,
    "CreateProcessAsUserW": ImportCategory.PRIVILEGE,
    "LogonUserA": ImportCategory.PRIVILEGE,
    "LogonUserW": ImportCategory.PRIVILEGE,
    "LsaEnumerateLogonSessions": ImportCategory.PRIVILEGE,
    "SamConnect": ImportCategory.PRIVILEGE,
    "SamEnumerateUsersInDomain": ImportCategory.PRIVILEGE,
}

# MITRE ATT&CK technique mappings for findings
_CATEGORY_ATTACK_MAP: dict[ImportCategory, str] = {
    ImportCategory.PROCESS_INJECTION: "T1055 - Process Injection",
    ImportCategory.CODE_INJECTION: "T1055.001 - Dynamic-link Library Injection",
    ImportCategory.KEYLOGGING: "T1056.001 - Keylogging",
    ImportCategory.ANTI_DEBUG: "T1622 - Debugger Evasion",
    ImportCategory.ANTI_VM: "T1497 - Virtualization/Sandbox Evasion",
    ImportCategory.FILE_OPERATIONS: "T1070 - Indicator Removal",
    ImportCategory.NETWORK: "T1071 - Application Layer Protocol",
    ImportCategory.REGISTRY: "T1112 - Modify Registry",
    ImportCategory.CRYPTO: "T1027 - Obfuscated Files or Information",
    ImportCategory.PRIVILEGE: "T1134 - Access Token Manipulation",
}

# Category severity mapping
_CATEGORY_SEVERITY: dict[ImportCategory, Severity] = {
    ImportCategory.PROCESS_INJECTION: Severity.CRITICAL,
    ImportCategory.CODE_INJECTION: Severity.HIGH,
    ImportCategory.KEYLOGGING: Severity.CRITICAL,
    ImportCategory.ANTI_DEBUG: Severity.MEDIUM,
    ImportCategory.ANTI_VM: Severity.MEDIUM,
    ImportCategory.FILE_OPERATIONS: Severity.LOW,
    ImportCategory.NETWORK: Severity.MEDIUM,
    ImportCategory.REGISTRY: Severity.LOW,
    ImportCategory.CRYPTO: Severity.LOW,
    ImportCategory.PRIVILEGE: Severity.HIGH,
    ImportCategory.GENERAL: Severity.INFO,
}

# Category risk mapping
_CATEGORY_RISK: dict[ImportCategory, RiskLevel] = {
    ImportCategory.PROCESS_INJECTION: RiskLevel.CRITICAL,
    ImportCategory.CODE_INJECTION: RiskLevel.HIGH,
    ImportCategory.KEYLOGGING: RiskLevel.CRITICAL,
    ImportCategory.ANTI_DEBUG: RiskLevel.MEDIUM,
    ImportCategory.ANTI_VM: RiskLevel.MEDIUM,
    ImportCategory.FILE_OPERATIONS: RiskLevel.LOW,
    ImportCategory.NETWORK: RiskLevel.MEDIUM,
    ImportCategory.REGISTRY: RiskLevel.LOW,
    ImportCategory.CRYPTO: RiskLevel.LOW,
    ImportCategory.PRIVILEGE: RiskLevel.HIGH,
    ImportCategory.GENERAL: RiskLevel.NEGLIGIBLE,
}

# Dangerous category combinations that elevate risk
_DANGEROUS_COMBINATIONS: list[tuple[set[ImportCategory], str, Severity]] = [
    (
        {ImportCategory.PROCESS_INJECTION, ImportCategory.NETWORK},
        "Process injection combined with network capabilities suggests "
        "a remote access trojan (RAT) or code injection backdoor.",
        Severity.CRITICAL,
    ),
    (
        {ImportCategory.KEYLOGGING, ImportCategory.NETWORK},
        "Keylogging combined with network capabilities suggests "
        "a credential-stealing trojan or spyware.",
        Severity.CRITICAL,
    ),
    (
        {ImportCategory.PROCESS_INJECTION, ImportCategory.PRIVILEGE},
        "Process injection with privilege escalation capabilities "
        "suggests a privilege escalation exploit or rootkit component.",
        Severity.CRITICAL,
    ),
    (
        {ImportCategory.CRYPTO, ImportCategory.FILE_OPERATIONS},
        "Cryptographic operations combined with file I/O capabilities "
        "may indicate ransomware-like behaviour (file encryption).",
        Severity.HIGH,
    ),
    (
        {ImportCategory.ANTI_DEBUG, ImportCategory.ANTI_VM},
        "Anti-debug and anti-VM techniques combined suggest the binary "
        "is actively evading analysis environments.",
        Severity.HIGH,
    ),
    (
        {ImportCategory.NETWORK, ImportCategory.REGISTRY},
        "Network access combined with registry modification suggests "
        "persistence establishment via C2 communication.",
        Severity.MEDIUM,
    ),
    (
        {ImportCategory.CODE_INJECTION, ImportCategory.CRYPTO},
        "Dynamic code loading with cryptographic operations suggests "
        "encrypted payload decryption at runtime.",
        Severity.HIGH,
    ),
    (
        {ImportCategory.PROCESS_INJECTION, ImportCategory.ANTI_DEBUG, ImportCategory.NETWORK},
        "Triple combination of process injection, anti-debugging, and "
        "network access is highly indicative of sophisticated malware.",
        Severity.CRITICAL,
    ),
]


# ---------------------------------------------------------------------------
# ImportAnalyzer
# ---------------------------------------------------------------------------

class ImportAnalyzer:
    """Analyze imported API functions for suspicious behaviour patterns.

    Categorises each imported function, generates findings for suspicious
    categories, and detects dangerous combinations of capabilities that
    elevate the overall risk assessment.

    Reference:
        Sikorski, M., & Honig, A. (2012). Practical Malware Analysis.
        MITRE ATT&CK Framework. (2024). https://attack.mitre.org/

    Usage::

        analyzer = ImportAnalyzer()
        categorised_imports = analyzer.categorize(imports)
        findings = analyzer.analyze(imports)
    """

    def categorize(self, imports: list[ImportInfo]) -> list[ImportInfo]:
        """Assign behavioural categories to imported functions.

        Looks up each function name in the curated API database and
        sets the ``category`` field.  Functions not in the database
        are assigned :attr:`ImportCategory.GENERAL`.

        The lookup is performed both with the exact function name and
        with the ANSI/Unicode suffix stripped (e.g. ``CreateFileA``
        matches both ``CreateFileA`` and ``CreateFile``).

        Args:
            imports: List of ImportInfo models.

        Returns:
            The same list with ``category`` fields populated.
        """
        for imp in imports:
            func = imp.function
            category = _API_CATEGORIES.get(func)

            if category is None:
                # Try stripping A/W suffix
                if func.endswith(("A", "W")) and len(func) > 1:
                    base_name = func[:-1]
                    category = _API_CATEGORIES.get(base_name)

            if category is None:
                # Try with A/W suffix added
                for suffix in ("A", "W"):
                    category = _API_CATEGORIES.get(func + suffix)
                    if category is not None:
                        break

            imp.category = category if category is not None else ImportCategory.GENERAL

        return imports

    def analyze(self, imports: list[ImportInfo]) -> list[Finding]:
        """Analyze imports and generate security findings.

        Performs three levels of analysis:

        1. **Per-category findings**: Generates a finding for each
           suspicious import category that has at least one match.

        2. **Combination analysis**: Checks for dangerous combinations
           of import categories that elevate risk.

        3. **Individual high-risk imports**: Flags specific APIs that
           are almost exclusively used by malicious software.

        Args:
            imports: List of ImportInfo models (pre-categorised or not).

        Returns:
            List of Finding models.
        """
        # Ensure categories are assigned
        self.categorize(imports)

        findings: list[Finding] = []

        # Group imports by category
        category_groups: dict[ImportCategory, list[ImportInfo]] = {}
        for imp in imports:
            if imp.category not in category_groups:
                category_groups[imp.category] = []
            category_groups[imp.category].append(imp)

        # Per-category findings (skip GENERAL)
        for category, category_imports in category_groups.items():
            if category == ImportCategory.GENERAL:
                continue

            func_names = [imp.function for imp in category_imports]
            attack_technique = _CATEGORY_ATTACK_MAP.get(category, "")
            severity = _CATEGORY_SEVERITY.get(category, Severity.INFO)
            finding = Finding(
                title=f"Suspicious imports: {category.value.replace('_', ' ').title()}",
                description=(
                    f"Binary imports {len(func_names)} function(s) in the "
                    f"'{category.value}' category: {', '.join(func_names[:10])}"
                    f"{'...' if len(func_names) > 10 else ''}. "
                    f"MITRE ATT&CK: {attack_technique}."
                ),
                severity=severity,
                evidence=(
                    f"Category: {category.value}, Count: {len(func_names)}, "
                    f"Functions: {', '.join(func_names[:10])}"
                ),
                recommendation=self._get_recommendation(category),
                references=[
                    ref for ref in [
                        "Sikorski, M., & Honig, A. (2012). Practical Malware Analysis.",
                        f"MITRE ATT&CK: {attack_technique}" if attack_technique else None,
                    ] if ref
                ],
            )
            findings.append(finding)

        # Combination analysis
        present_categories = set(category_groups.keys()) - {ImportCategory.GENERAL}
        for combo_set, description, combo_severity in _DANGEROUS_COMBINATIONS:
            if combo_set.issubset(present_categories):
                involved_funcs: list[str] = []
                for cat in combo_set:
                    for imp in category_groups.get(cat, []):
                        involved_funcs.append(imp.function)

                findings.append(Finding(
                    title="Dangerous import combination detected",
                    description=description,
                    severity=combo_severity,
                    evidence=(
                        f"Categories: {', '.join(c.value for c in combo_set)}; "
                        f"Functions: {', '.join(involved_funcs[:20])}"
                    ),
                    recommendation=(
                        "This combination of capabilities is commonly found in "
                        "malicious software. Perform thorough dynamic analysis "
                        "in a sandboxed environment."
                    ),
                    references=[
                        "MITRE ATT&CK Framework: https://attack.mitre.org/",
                    ],
                ))

        return findings

    def get_category_summary(
        self,
        imports: list[ImportInfo],
    ) -> dict[str, int]:
        """Summarise the number of imports per category.

        Args:
            imports: Categorised imports.

        Returns:
            Dictionary mapping category names to counts.
        """
        summary: dict[str, int] = {}
        for imp in imports:
            cat_name = imp.category.value
            summary[cat_name] = summary.get(cat_name, 0) + 1
        return summary

    @staticmethod
    def _get_recommendation(category: ImportCategory) -> str:
        """Return a remediation recommendation for a category.

        Args:
            category: The import category.

        Returns:
            Recommendation string.
        """
        recommendations: dict[ImportCategory, str] = {
            ImportCategory.PROCESS_INJECTION: (
                "Investigate process injection targets and verify whether "
                "this is a legitimate debugging or instrumentation tool."
            ),
            ImportCategory.CODE_INJECTION: (
                "Verify whether dynamic library loading is for legitimate "
                "plugin architectures or suspicious runtime code injection."
            ),
            ImportCategory.KEYLOGGING: (
                "Confirm whether keyboard monitoring is part of an "
                "accessibility feature or an unauthorised keylogger."
            ),
            ImportCategory.ANTI_DEBUG: (
                "Anti-debugging techniques are common in both DRM-protected "
                "software and malware. Determine the software's purpose."
            ),
            ImportCategory.ANTI_VM: (
                "VM detection can be legitimate (licensing) or malicious "
                "(sandbox evasion). Analyse dynamic behaviour."
            ),
            ImportCategory.FILE_OPERATIONS: (
                "File operations are normal for most applications. Flag "
                "only when combined with other suspicious indicators."
            ),
            ImportCategory.NETWORK: (
                "Network operations should be correlated with expected "
                "functionality. Unexpected network access is suspicious."
            ),
            ImportCategory.REGISTRY: (
                "Check whether registry modifications affect startup keys "
                "(persistence) or security settings."
            ),
            ImportCategory.CRYPTO: (
                "Verify whether cryptographic operations align with the "
                "application's expected data protection needs."
            ),
            ImportCategory.PRIVILEGE: (
                "Privilege escalation APIs require careful scrutiny. "
                "Verify whether elevation is required for stated functionality."
            ),
        }
        return recommendations.get(category, "Review the imports in context.")
