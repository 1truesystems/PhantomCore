"""
PE/COFF Binary Format Parser
===============================

Manual struct-based parser for the Portable Executable (PE) format used
by Microsoft Windows for executables (.exe), dynamic link libraries (.dll),
and other binary images.

All parsing is performed using :mod:`struct` without external libraries
such as ``pefile`` or ``lief``.  Both PE32 (32-bit) and PE32+ (64-bit)
optional headers are supported.

The parser extracts:
    - DOS header (MZ stub)
    - PE signature verification
    - COFF file header (machine, section count, timestamp, characteristics)
    - Optional header (entry point, image base, subsystem, data directories)
    - Section table (name, virtual size/address, raw size/offset, characteristics)
    - Import directory table (imported DLLs and their functions)
    - Export directory (exported functions)

References:
    - Microsoft. (2024). PE Format. Microsoft Learn.
      https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    - Pietrek, M. (1994). Peering Inside the PE: A Tour of the Win32
      Portable Executable File Format. Microsoft Systems Journal.
"""

from __future__ import annotations

import struct
import time
from datetime import datetime, timezone
from typing import Optional

from morph.core.models import (
    BinaryInfo,
    BinaryFormat,
    ImportInfo,
    SectionInfo,
    SymbolInfo,
)


# ---------------------------------------------------------------------------
# PE Constants
# ---------------------------------------------------------------------------

# Magic numbers
MZ_MAGIC: bytes = b"MZ"
PE_MAGIC: bytes = b"PE\x00\x00"

# Optional header magic
PE32_MAGIC: int = 0x10B      # PE32 (32-bit)
PE32PLUS_MAGIC: int = 0x20B  # PE32+ (64-bit)
ROM_MAGIC: int = 0x107       # ROM image

# Machine types
IMAGE_FILE_MACHINE_UNKNOWN: int = 0x0
IMAGE_FILE_MACHINE_I386: int = 0x14C
IMAGE_FILE_MACHINE_R3000: int = 0x162
IMAGE_FILE_MACHINE_R4000: int = 0x166
IMAGE_FILE_MACHINE_MIPS16: int = 0x266
IMAGE_FILE_MACHINE_ARM: int = 0x1C0
IMAGE_FILE_MACHINE_ARMNT: int = 0x1C4
IMAGE_FILE_MACHINE_AMD64: int = 0x8664
IMAGE_FILE_MACHINE_ARM64: int = 0xAA64
IMAGE_FILE_MACHINE_IA64: int = 0x200
IMAGE_FILE_MACHINE_RISCV32: int = 0x5032
IMAGE_FILE_MACHINE_RISCV64: int = 0x5064

_MACHINE_NAMES: dict[int, str] = {
    IMAGE_FILE_MACHINE_UNKNOWN: "Unknown",
    IMAGE_FILE_MACHINE_I386: "x86",
    IMAGE_FILE_MACHINE_R3000: "MIPS R3000",
    IMAGE_FILE_MACHINE_R4000: "MIPS R4000",
    IMAGE_FILE_MACHINE_MIPS16: "MIPS16",
    IMAGE_FILE_MACHINE_ARM: "ARM",
    IMAGE_FILE_MACHINE_ARMNT: "ARM Thumb-2",
    IMAGE_FILE_MACHINE_AMD64: "x86_64",
    IMAGE_FILE_MACHINE_ARM64: "AArch64",
    IMAGE_FILE_MACHINE_IA64: "IA-64",
    IMAGE_FILE_MACHINE_RISCV32: "RISC-V 32",
    IMAGE_FILE_MACHINE_RISCV64: "RISC-V 64",
}

# Characteristics flags (COFF header)
IMAGE_FILE_RELOCS_STRIPPED: int = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE: int = 0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED: int = 0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED: int = 0x0008
IMAGE_FILE_LARGE_ADDRESS_AWARE: int = 0x0020
IMAGE_FILE_32BIT_MACHINE: int = 0x0100
IMAGE_FILE_DEBUG_STRIPPED: int = 0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: int = 0x0400
IMAGE_FILE_NET_RUN_FROM_SWAP: int = 0x0800
IMAGE_FILE_SYSTEM: int = 0x1000
IMAGE_FILE_DLL: int = 0x2000
IMAGE_FILE_UP_SYSTEM_ONLY: int = 0x4000

# Subsystem values
IMAGE_SUBSYSTEM_UNKNOWN: int = 0
IMAGE_SUBSYSTEM_NATIVE: int = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI: int = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI: int = 3
IMAGE_SUBSYSTEM_POSIX_CUI: int = 7
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: int = 9
IMAGE_SUBSYSTEM_EFI_APPLICATION: int = 10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: int = 11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: int = 12
IMAGE_SUBSYSTEM_EFI_ROM: int = 13
IMAGE_SUBSYSTEM_XBOX: int = 14

_SUBSYSTEM_NAMES: dict[int, str] = {
    IMAGE_SUBSYSTEM_UNKNOWN: "Unknown",
    IMAGE_SUBSYSTEM_NATIVE: "Native",
    IMAGE_SUBSYSTEM_WINDOWS_GUI: "Windows GUI",
    IMAGE_SUBSYSTEM_WINDOWS_CUI: "Windows Console",
    IMAGE_SUBSYSTEM_POSIX_CUI: "POSIX Console",
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: "Windows CE GUI",
    IMAGE_SUBSYSTEM_EFI_APPLICATION: "EFI Application",
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: "EFI Boot Service Driver",
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: "EFI Runtime Driver",
    IMAGE_SUBSYSTEM_EFI_ROM: "EFI ROM",
    IMAGE_SUBSYSTEM_XBOX: "Xbox",
}

# Section characteristics
IMAGE_SCN_CNT_CODE: int = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA: int = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA: int = 0x00000080
IMAGE_SCN_MEM_DISCARDABLE: int = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED: int = 0x04000000
IMAGE_SCN_MEM_NOT_PAGED: int = 0x08000000
IMAGE_SCN_MEM_SHARED: int = 0x10000000
IMAGE_SCN_MEM_EXECUTE: int = 0x20000000
IMAGE_SCN_MEM_READ: int = 0x40000000
IMAGE_SCN_MEM_WRITE: int = 0x80000000

# Data directory indices
IMAGE_DIRECTORY_ENTRY_EXPORT: int = 0
IMAGE_DIRECTORY_ENTRY_IMPORT: int = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE: int = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION: int = 3
IMAGE_DIRECTORY_ENTRY_SECURITY: int = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC: int = 5
IMAGE_DIRECTORY_ENTRY_DEBUG: int = 6
IMAGE_DIRECTORY_ENTRY_TLS: int = 9
IMAGE_DIRECTORY_ENTRY_IAT: int = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: int = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: int = 14


# ---------------------------------------------------------------------------
# Internal parsed structures
# ---------------------------------------------------------------------------

class _DOSHeader:
    """Parsed DOS MZ header."""
    __slots__ = ("e_magic", "e_lfanew")

    def __init__(self) -> None:
        self.e_magic: int = 0
        self.e_lfanew: int = 0


class _COFFHeader:
    """Parsed COFF file header."""
    __slots__ = (
        "machine", "number_of_sections", "time_date_stamp",
        "pointer_to_symbol_table", "number_of_symbols",
        "size_of_optional_header", "characteristics",
    )

    def __init__(self) -> None:
        self.machine: int = 0
        self.number_of_sections: int = 0
        self.time_date_stamp: int = 0
        self.pointer_to_symbol_table: int = 0
        self.number_of_symbols: int = 0
        self.size_of_optional_header: int = 0
        self.characteristics: int = 0


class _OptionalHeader:
    """Parsed PE optional header (PE32 or PE32+)."""
    __slots__ = (
        "magic", "major_linker_version", "minor_linker_version",
        "size_of_code", "size_of_initialized_data",
        "size_of_uninitialized_data", "address_of_entry_point",
        "base_of_code", "base_of_data", "image_base",
        "section_alignment", "file_alignment",
        "major_os_version", "minor_os_version",
        "major_image_version", "minor_image_version",
        "major_subsystem_version", "minor_subsystem_version",
        "win32_version_value", "size_of_image", "size_of_headers",
        "checksum", "subsystem", "dll_characteristics",
        "size_of_stack_reserve", "size_of_stack_commit",
        "size_of_heap_reserve", "size_of_heap_commit",
        "loader_flags", "number_of_rva_and_sizes",
        "data_directories",
    )

    def __init__(self) -> None:
        self.magic: int = 0
        self.major_linker_version: int = 0
        self.minor_linker_version: int = 0
        self.size_of_code: int = 0
        self.size_of_initialized_data: int = 0
        self.size_of_uninitialized_data: int = 0
        self.address_of_entry_point: int = 0
        self.base_of_code: int = 0
        self.base_of_data: int = 0
        self.image_base: int = 0
        self.section_alignment: int = 0
        self.file_alignment: int = 0
        self.major_os_version: int = 0
        self.minor_os_version: int = 0
        self.major_image_version: int = 0
        self.minor_image_version: int = 0
        self.major_subsystem_version: int = 0
        self.minor_subsystem_version: int = 0
        self.win32_version_value: int = 0
        self.size_of_image: int = 0
        self.size_of_headers: int = 0
        self.checksum: int = 0
        self.subsystem: int = 0
        self.dll_characteristics: int = 0
        self.size_of_stack_reserve: int = 0
        self.size_of_stack_commit: int = 0
        self.size_of_heap_reserve: int = 0
        self.size_of_heap_commit: int = 0
        self.loader_flags: int = 0
        self.number_of_rva_and_sizes: int = 0
        self.data_directories: list[tuple[int, int]] = []  # (rva, size) pairs


class _PESection:
    """Parsed PE section header."""
    __slots__ = (
        "name", "virtual_size", "virtual_address",
        "size_of_raw_data", "pointer_to_raw_data",
        "pointer_to_relocations", "pointer_to_linenumbers",
        "number_of_relocations", "number_of_linenumbers",
        "characteristics",
    )

    def __init__(self) -> None:
        self.name: str = ""
        self.virtual_size: int = 0
        self.virtual_address: int = 0
        self.size_of_raw_data: int = 0
        self.pointer_to_raw_data: int = 0
        self.pointer_to_relocations: int = 0
        self.pointer_to_linenumbers: int = 0
        self.number_of_relocations: int = 0
        self.number_of_linenumbers: int = 0
        self.characteristics: int = 0


class _ImportEntry:
    """A single imported function from a DLL."""
    __slots__ = ("dll_name", "function_name", "ordinal", "hint", "rva")

    def __init__(self) -> None:
        self.dll_name: str = ""
        self.function_name: str = ""
        self.ordinal: int = 0
        self.hint: int = 0
        self.rva: int = 0


class _ExportEntry:
    """A single exported function."""
    __slots__ = ("name", "ordinal", "rva")

    def __init__(self) -> None:
        self.name: str = ""
        self.ordinal: int = 0
        self.rva: int = 0


# ---------------------------------------------------------------------------
# PE Parser
# ---------------------------------------------------------------------------

class PEParser:
    """Manual struct-based PE/COFF binary parser.

    Parses PE32 and PE32+ (64-bit) Windows executables using only the
    Python standard library :mod:`struct` module.

    Reference:
        Microsoft. (2024). PE Format. Microsoft Learn.
        Pietrek, M. (1994). Peering Inside the PE.

    Usage::

        parser = PEParser(raw_bytes)
        if parser.parse():
            info = parser.get_binary_info()
            sections = parser.get_sections()
            imports = parser.get_imports()
    """

    def __init__(self, data: bytes) -> None:
        """Initialise the parser with raw binary data.

        Args:
            data: Complete PE file contents as bytes.
        """
        self._data: bytes = data
        self._dos_header: _DOSHeader = _DOSHeader()
        self._coff_header: _COFFHeader = _COFFHeader()
        self._optional_header: _OptionalHeader = _OptionalHeader()
        self._sections: list[_PESection] = []
        self._imports: list[_ImportEntry] = []
        self._exports: list[_ExportEntry] = []
        self._is_pe32plus: bool = False
        self._parsed: bool = False

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #

    def parse(self) -> bool:
        """Parse the PE binary.

        Returns:
            ``True`` if parsing succeeded, ``False`` on invalid data.
        """
        if len(self._data) < 64:
            return False
        if self._data[:2] != MZ_MAGIC:
            return False

        try:
            self._parse_dos_header()
            if not self._verify_pe_signature():
                return False
            self._parse_coff_header()
            self._parse_optional_header()
            self._parse_section_table()
            self._parse_import_directory()
            self._parse_export_directory()
            self._parsed = True
            return True
        except (struct.error, IndexError, ValueError):
            return False

    def get_binary_info(self) -> BinaryInfo:
        """Build a :class:`BinaryInfo` from parsed PE headers.

        Returns:
            Populated BinaryInfo model.
        """
        machine = self._coff_header.machine
        arch = _MACHINE_NAMES.get(machine, f"unknown(0x{machine:x})")
        bits = 64 if self._is_pe32plus else 32

        return BinaryInfo(
            format=BinaryFormat.PE,
            arch=arch,
            bits=bits,
            endian="little",
            entry_point=self._optional_header.address_of_entry_point,
        )

    def get_sections(self) -> list[SectionInfo]:
        """Return parsed section information.

        Returns:
            List of SectionInfo models.
        """
        result: list[SectionInfo] = []
        for sec in self._sections:
            flags_str = self._section_characteristics_str(sec.characteristics)
            type_guess = self._guess_section_type(sec)
            result.append(SectionInfo(
                name=sec.name,
                offset=sec.pointer_to_raw_data,
                size=sec.size_of_raw_data,
                vaddr=sec.virtual_address,
                flags=flags_str,
                type_guess=type_guess,
            ))
        return result

    def get_imports(self) -> list[ImportInfo]:
        """Return parsed import table entries.

        Returns:
            List of ImportInfo models with DLL and function names.
        """
        result: list[ImportInfo] = []
        for imp in self._imports:
            result.append(ImportInfo(
                library=imp.dll_name,
                function=imp.function_name,
                address=imp.rva,
            ))
        return result

    def get_exports(self) -> list[SymbolInfo]:
        """Return parsed export table entries.

        Returns:
            List of SymbolInfo models.
        """
        result: list[SymbolInfo] = []
        for exp in self._exports:
            result.append(SymbolInfo(
                name=exp.name,
                value=exp.rva,
                type="FUNC",
                bind="GLOBAL",
                section="export",
            ))
        return result

    def get_timestamp(self) -> Optional[datetime]:
        """Return the compilation timestamp from the COFF header.

        Returns:
            UTC datetime of compilation, or ``None`` if timestamp is zero.
        """
        ts = self._coff_header.time_date_stamp
        if ts == 0:
            return None
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None

    def get_subsystem(self) -> str:
        """Return the subsystem name string.

        Returns:
            Subsystem description string.
        """
        return _SUBSYSTEM_NAMES.get(
            self._optional_header.subsystem,
            f"Unknown(0x{self._optional_header.subsystem:x})",
        )

    def is_dll(self) -> bool:
        """Check if the binary has the DLL characteristics flag set."""
        return bool(self._coff_header.characteristics & IMAGE_FILE_DLL)

    def get_executable_data(self) -> bytes:
        """Return concatenated bytes of all executable sections.

        Returns:
            Bytes from sections with IMAGE_SCN_MEM_EXECUTE flag.
        """
        parts: list[bytes] = []
        for sec in self._sections:
            if sec.characteristics & IMAGE_SCN_MEM_EXECUTE:
                start = sec.pointer_to_raw_data
                end = start + sec.size_of_raw_data
                if end <= len(self._data):
                    parts.append(self._data[start:end])
        return b"".join(parts)

    def get_executable_sections_info(self) -> list[tuple[int, int, bytes]]:
        """Return (vaddr, offset, data) for all executable sections.

        Returns:
            List of (virtual_address, file_offset, section_bytes) tuples.
        """
        result: list[tuple[int, int, bytes]] = []
        for sec in self._sections:
            if sec.characteristics & IMAGE_SCN_MEM_EXECUTE:
                start = sec.pointer_to_raw_data
                end = start + sec.size_of_raw_data
                if end <= len(self._data):
                    result.append((sec.virtual_address, start, self._data[start:end]))
        return result

    # ------------------------------------------------------------------ #
    #  DOS header
    # ------------------------------------------------------------------ #

    def _parse_dos_header(self) -> None:
        """Parse the DOS MZ header.

        The DOS header is a 64-byte structure at offset 0.
        We only need e_magic (offset 0, 2 bytes) and e_lfanew (offset 60, 4 bytes).
        """
        self._dos_header.e_magic = struct.unpack_from("<H", self._data, 0)[0]
        self._dos_header.e_lfanew = struct.unpack_from("<I", self._data, 60)[0]

    def _verify_pe_signature(self) -> bool:
        """Verify the PE signature at offset e_lfanew.

        Returns:
            ``True`` if ``PE\\0\\0`` signature is present.
        """
        pe_offset = self._dos_header.e_lfanew
        if pe_offset + 4 > len(self._data):
            return False
        return self._data[pe_offset:pe_offset + 4] == PE_MAGIC

    # ------------------------------------------------------------------ #
    #  COFF header
    # ------------------------------------------------------------------ #

    def _parse_coff_header(self) -> None:
        """Parse the COFF file header (20 bytes after PE signature)."""
        offset = self._dos_header.e_lfanew + 4  # Skip PE signature
        fmt = "<HHIIIHH"
        if offset + struct.calcsize(fmt) > len(self._data):
            return

        fields = struct.unpack_from(fmt, self._data, offset)
        coff = self._coff_header
        (
            coff.machine,
            coff.number_of_sections,
            coff.time_date_stamp,
            coff.pointer_to_symbol_table,
            coff.number_of_symbols,
            coff.size_of_optional_header,
            coff.characteristics,
        ) = fields

    # ------------------------------------------------------------------ #
    #  Optional header
    # ------------------------------------------------------------------ #

    def _parse_optional_header(self) -> None:
        """Parse the PE optional header (PE32 or PE32+)."""
        if self._coff_header.size_of_optional_header == 0:
            return

        offset = self._dos_header.e_lfanew + 4 + 20  # PE sig + COFF header
        oh = self._optional_header

        # Read magic to determine PE32 vs PE32+
        oh.magic = struct.unpack_from("<H", self._data, offset)[0]
        self._is_pe32plus = oh.magic == PE32PLUS_MAGIC

        if self._is_pe32plus:
            self._parse_optional_header_pe32plus(offset)
        else:
            self._parse_optional_header_pe32(offset)

    def _parse_optional_header_pe32(self, offset: int) -> None:
        """Parse PE32 (32-bit) optional header."""
        oh = self._optional_header

        # Standard fields (28 bytes)
        fmt_std = "<HBBIIIIII"
        if offset + struct.calcsize(fmt_std) > len(self._data):
            return
        fields = struct.unpack_from(fmt_std, self._data, offset)
        (
            oh.magic, oh.major_linker_version, oh.minor_linker_version,
            oh.size_of_code, oh.size_of_initialized_data,
            oh.size_of_uninitialized_data, oh.address_of_entry_point,
            oh.base_of_code, oh.base_of_data,
        ) = fields

        # Windows-specific fields (PE32: 68 bytes starting at offset+28)
        win_offset = offset + 28
        fmt_win = "<IIIHHHHHHIIIIHHIIIIII"
        if win_offset + struct.calcsize(fmt_win) > len(self._data):
            return
        fields = struct.unpack_from(fmt_win, self._data, win_offset)
        (
            oh.image_base, oh.section_alignment, oh.file_alignment,
            oh.major_os_version, oh.minor_os_version,
            oh.major_image_version, oh.minor_image_version,
            oh.major_subsystem_version, oh.minor_subsystem_version,
            oh.win32_version_value, oh.size_of_image, oh.size_of_headers,
            oh.checksum, oh.subsystem, oh.dll_characteristics,
            oh.size_of_stack_reserve, oh.size_of_stack_commit,
            oh.size_of_heap_reserve, oh.size_of_heap_commit,
            oh.loader_flags, oh.number_of_rva_and_sizes,
        ) = fields

        # Data directories (8 bytes each: RVA + Size)
        dd_offset = win_offset + struct.calcsize(fmt_win)
        self._parse_data_directories(dd_offset, oh.number_of_rva_and_sizes)

    def _parse_optional_header_pe32plus(self, offset: int) -> None:
        """Parse PE32+ (64-bit) optional header."""
        oh = self._optional_header

        # Standard fields (24 bytes -- no base_of_data in PE32+)
        fmt_std = "<HBBIIIII"
        if offset + struct.calcsize(fmt_std) > len(self._data):
            return
        fields = struct.unpack_from(fmt_std, self._data, offset)
        (
            oh.magic, oh.major_linker_version, oh.minor_linker_version,
            oh.size_of_code, oh.size_of_initialized_data,
            oh.size_of_uninitialized_data, oh.address_of_entry_point,
            oh.base_of_code,
        ) = fields
        oh.base_of_data = 0  # Not present in PE32+

        # Windows-specific fields (PE32+: 88 bytes starting at offset+24)
        win_offset = offset + 24
        fmt_win = "<QIIHHHHHHIIIIHHQQQQII"
        if win_offset + struct.calcsize(fmt_win) > len(self._data):
            return
        fields = struct.unpack_from(fmt_win, self._data, win_offset)
        (
            oh.image_base, oh.section_alignment, oh.file_alignment,
            oh.major_os_version, oh.minor_os_version,
            oh.major_image_version, oh.minor_image_version,
            oh.major_subsystem_version, oh.minor_subsystem_version,
            oh.win32_version_value, oh.size_of_image, oh.size_of_headers,
            oh.checksum, oh.subsystem, oh.dll_characteristics,
            oh.size_of_stack_reserve, oh.size_of_stack_commit,
            oh.size_of_heap_reserve, oh.size_of_heap_commit,
            oh.loader_flags, oh.number_of_rva_and_sizes,
        ) = fields

        # Data directories
        dd_offset = win_offset + struct.calcsize(fmt_win)
        self._parse_data_directories(dd_offset, oh.number_of_rva_and_sizes)

    def _parse_data_directories(self, offset: int, count: int) -> None:
        """Parse the data directory array.

        Args:
            offset: File offset of the first data directory entry.
            count: Number of data directory entries.
        """
        oh = self._optional_header
        oh.data_directories = []
        # Cap at 16 to prevent malformed binaries from causing issues
        count = min(count, 16)

        for i in range(count):
            dd_offset = offset + i * 8
            if dd_offset + 8 > len(self._data):
                oh.data_directories.append((0, 0))
                continue
            rva, size = struct.unpack_from("<II", self._data, dd_offset)
            oh.data_directories.append((rva, size))

    # ------------------------------------------------------------------ #
    #  Section table
    # ------------------------------------------------------------------ #

    def _parse_section_table(self) -> None:
        """Parse the section table immediately following the optional header."""
        offset = (
            self._dos_header.e_lfanew
            + 4  # PE signature
            + 20  # COFF header
            + self._coff_header.size_of_optional_header
        )

        section_header_size = 40  # IMAGE_SECTION_HEADER is always 40 bytes

        for i in range(self._coff_header.number_of_sections):
            sec_offset = offset + i * section_header_size
            if sec_offset + section_header_size > len(self._data):
                break

            sec = _PESection()

            # Name: 8 bytes (null-padded ASCII)
            raw_name = self._data[sec_offset:sec_offset + 8]
            sec.name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")

            # Remaining fields: 32 bytes
            fmt = "<IIIIIIHHI"
            fields = struct.unpack_from(fmt, self._data, sec_offset + 8)
            (
                sec.virtual_size,
                sec.virtual_address,
                sec.size_of_raw_data,
                sec.pointer_to_raw_data,
                sec.pointer_to_relocations,
                sec.pointer_to_linenumbers,
                sec.number_of_relocations,
                sec.number_of_linenumbers,
                sec.characteristics,
            ) = fields

            self._sections.append(sec)

    # ------------------------------------------------------------------ #
    #  Import directory
    # ------------------------------------------------------------------ #

    def _parse_import_directory(self) -> None:
        """Parse the import directory table to extract DLL imports."""
        oh = self._optional_header
        if len(oh.data_directories) <= IMAGE_DIRECTORY_ENTRY_IMPORT:
            return

        import_rva, import_size = oh.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT]
        if import_rva == 0 or import_size == 0:
            return

        import_offset = self._rva_to_offset(import_rva)
        if import_offset is None:
            return

        # Each import directory entry (IMAGE_IMPORT_DESCRIPTOR) is 20 bytes
        entry_size = 20
        idx = 0

        while True:
            entry_offset = import_offset + idx * entry_size
            if entry_offset + entry_size > len(self._data):
                break

            fields = struct.unpack_from("<IIIII", self._data, entry_offset)
            original_first_thunk_rva = fields[0]  # OriginalFirstThunk (ILT RVA)
            # fields[1] = TimeDateStamp
            # fields[2] = ForwarderChain
            name_rva = fields[3]  # DLL name RVA
            first_thunk_rva = fields[4]  # FirstThunk (IAT RVA)

            # Null terminator entry
            if name_rva == 0 and original_first_thunk_rva == 0:
                break

            # Read DLL name
            dll_name = self._read_rva_string(name_rva)
            if not dll_name:
                idx += 1
                continue

            # Parse the Import Lookup Table (ILT) or IAT
            ilt_rva = original_first_thunk_rva if original_first_thunk_rva != 0 else first_thunk_rva
            if ilt_rva != 0:
                self._parse_ilt(dll_name, ilt_rva)

            idx += 1
            # Safety: limit to 1000 DLLs
            if idx > 1000:
                break

    def _parse_ilt(self, dll_name: str, ilt_rva: int) -> None:
        """Parse the Import Lookup Table for a single DLL.

        Args:
            dll_name: Name of the importing DLL.
            ilt_rva: RVA of the ILT.
        """
        ilt_offset = self._rva_to_offset(ilt_rva)
        if ilt_offset is None:
            return

        thunk_size = 8 if self._is_pe32plus else 4
        ordinal_flag = 1 << 63 if self._is_pe32plus else 1 << 31
        fmt = "<Q" if self._is_pe32plus else "<I"

        entry_idx = 0
        while True:
            thunk_offset = ilt_offset + entry_idx * thunk_size
            if thunk_offset + thunk_size > len(self._data):
                break

            thunk_value = struct.unpack_from(fmt, self._data, thunk_offset)[0]
            if thunk_value == 0:
                break

            imp = _ImportEntry()
            imp.dll_name = dll_name
            imp.rva = ilt_rva + entry_idx * thunk_size

            if thunk_value & ordinal_flag:
                # Import by ordinal
                imp.ordinal = thunk_value & 0xFFFF
                imp.function_name = f"Ordinal_{imp.ordinal}"
            else:
                # Import by name: thunk_value is RVA to IMAGE_IMPORT_BY_NAME
                # which is: 2-byte Hint, then null-terminated name
                hint_rva = thunk_value & 0x7FFFFFFF
                hint_offset = self._rva_to_offset(hint_rva)
                if hint_offset is not None and hint_offset + 2 < len(self._data):
                    imp.hint = struct.unpack_from("<H", self._data, hint_offset)[0]
                    imp.function_name = self._read_offset_string(hint_offset + 2)

            self._imports.append(imp)
            entry_idx += 1
            # Safety limit
            if entry_idx > 10000:
                break

    # ------------------------------------------------------------------ #
    #  Export directory
    # ------------------------------------------------------------------ #

    def _parse_export_directory(self) -> None:
        """Parse the export directory table."""
        oh = self._optional_header
        if len(oh.data_directories) <= IMAGE_DIRECTORY_ENTRY_EXPORT:
            return

        export_rva, export_size = oh.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT]
        if export_rva == 0 or export_size == 0:
            return

        export_offset = self._rva_to_offset(export_rva)
        if export_offset is None:
            return

        # IMAGE_EXPORT_DIRECTORY is 40 bytes
        if export_offset + 40 > len(self._data):
            return

        fields = struct.unpack_from("<IIHHIIIIIII", self._data, export_offset)
        # fields[0] = Characteristics
        # fields[1] = TimeDateStamp
        # fields[2] = MajorVersion
        # fields[3] = MinorVersion
        # fields[4] = Name (RVA)
        ordinal_base = fields[5]  # Base
        number_of_functions = fields[6]
        number_of_names = fields[7]
        functions_rva = fields[8]  # AddressOfFunctions
        names_rva = fields[9]     # AddressOfNames
        ordinals_rva = fields[10]  # AddressOfNameOrdinals

        functions_offset = self._rva_to_offset(functions_rva)
        names_offset = self._rva_to_offset(names_rva)
        ordinals_offset = self._rva_to_offset(ordinals_rva)

        if functions_offset is None:
            return

        # Safety limits
        number_of_names = min(number_of_names, 10000)
        number_of_functions = min(number_of_functions, 10000)

        # Read function RVAs
        func_rvas: list[int] = []
        for i in range(number_of_functions):
            off = functions_offset + i * 4
            if off + 4 > len(self._data):
                break
            func_rvas.append(struct.unpack_from("<I", self._data, off)[0])

        # Read names and ordinals
        if names_offset is not None and ordinals_offset is not None:
            for i in range(number_of_names):
                name_ptr_off = names_offset + i * 4
                ordinal_off = ordinals_offset + i * 2
                if name_ptr_off + 4 > len(self._data):
                    break
                if ordinal_off + 2 > len(self._data):
                    break

                name_rva_val = struct.unpack_from("<I", self._data, name_ptr_off)[0]
                ordinal_idx = struct.unpack_from("<H", self._data, ordinal_off)[0]

                exp = _ExportEntry()
                exp.name = self._read_rva_string(name_rva_val)
                exp.ordinal = ordinal_idx + ordinal_base
                if ordinal_idx < len(func_rvas):
                    exp.rva = func_rvas[ordinal_idx]

                self._exports.append(exp)

    # ------------------------------------------------------------------ #
    #  Utility methods
    # ------------------------------------------------------------------ #

    def _rva_to_offset(self, rva: int) -> Optional[int]:
        """Convert a Relative Virtual Address to a file offset.

        Uses the section table to map an RVA to its corresponding position
        in the file on disk.

        Args:
            rva: Relative Virtual Address.

        Returns:
            File offset, or ``None`` if the RVA is not in any section.
        """
        for sec in self._sections:
            sec_start = sec.virtual_address
            sec_end = sec_start + max(sec.virtual_size, sec.size_of_raw_data)
            if sec_start <= rva < sec_end:
                offset = sec.pointer_to_raw_data + (rva - sec_start)
                if offset < len(self._data):
                    return offset
        # For addresses within the headers
        if rva < (self._sections[0].virtual_address if self._sections else 0x1000):
            return rva if rva < len(self._data) else None
        return None

    def _read_rva_string(self, rva: int) -> str:
        """Read a null-terminated ASCII string at the given RVA.

        Args:
            rva: Relative Virtual Address of the string.

        Returns:
            Decoded string, or empty string on failure.
        """
        offset = self._rva_to_offset(rva)
        if offset is None:
            return ""
        return self._read_offset_string(offset)

    def _read_offset_string(self, offset: int) -> str:
        """Read a null-terminated ASCII string at the given file offset.

        Args:
            offset: File offset.

        Returns:
            Decoded string, or empty string on failure.
        """
        if offset < 0 or offset >= len(self._data):
            return ""
        end = self._data.find(b"\x00", offset)
        if end == -1:
            end = min(offset + 256, len(self._data))
        return self._data[offset:end].decode("ascii", errors="replace")

    @staticmethod
    def _section_characteristics_str(characteristics: int) -> str:
        """Convert section characteristics bitmask to a readable string.

        Args:
            characteristics: Section characteristics flags.

        Returns:
            Flags string like ``"RWX"`` or ``"R--"``.
        """
        parts: list[str] = []
        if characteristics & IMAGE_SCN_MEM_READ:
            parts.append("R")
        if characteristics & IMAGE_SCN_MEM_WRITE:
            parts.append("W")
        if characteristics & IMAGE_SCN_MEM_EXECUTE:
            parts.append("X")
        if characteristics & IMAGE_SCN_CNT_CODE:
            parts.append("CODE")
        if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
            parts.append("IDATA")
        if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
            parts.append("UDATA")
        return " ".join(parts) if parts else "-"

    @staticmethod
    def _guess_section_type(sec: _PESection) -> str:
        """Heuristically classify a section by its name and characteristics.

        Args:
            sec: Parsed section entry.

        Returns:
            Type description string.
        """
        name_lower = sec.name.lower()
        known_sections: dict[str, str] = {
            ".text": "Code",
            ".code": "Code",
            ".rdata": "Read-only data",
            ".data": "Initialized data",
            ".bss": "Uninitialized data",
            ".idata": "Import data",
            ".edata": "Export data",
            ".rsrc": "Resources",
            ".reloc": "Relocations",
            ".tls": "Thread-local storage",
            ".debug": "Debug information",
            ".pdata": "Exception handling",
            ".xdata": "Exception unwind data",
            ".crt": "C runtime data",
        }

        if name_lower in known_sections:
            return known_sections[name_lower]

        if sec.characteristics & IMAGE_SCN_CNT_CODE:
            return "Code"
        if sec.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
            return "Initialized data"
        if sec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
            return "Uninitialized data"

        return "Unknown"
