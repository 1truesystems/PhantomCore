"""
ELF Binary Format Parser
==========================

Manual struct-based parser for the Executable and Linkable Format (ELF),
the standard binary format for Unix-like operating systems including Linux,
FreeBSD, and Solaris.

All parsing is performed using :mod:`struct` without any external libraries
such as ``pyelftools``.  Both 32-bit (ELF32) and 64-bit (ELF64) variants
are fully supported.

The parser extracts:
    - ELF header (magic, class, endianness, type, machine, entry point)
    - Section headers (name, type, flags, address, offset, size)
    - Program headers / segments (type, flags, offset, vaddr, sizes)
    - Symbol tables (.symtab and .dynsym)
    - Dynamic section (.dynamic) entries
    - String tables (.strtab, .dynstr)

References:
    - TIS Committee. (1995). Tool Interface Standard (TIS) Executable and
      Linkable Format (ELF) Specification, Version 1.2.
    - System V Application Binary Interface, Edition 4.1.
    - Linux man page: elf(5).
"""

from __future__ import annotations

import struct
from typing import Optional

from morph.core.models import (
    BinaryInfo,
    BinaryFormat,
    ImportInfo,
    SectionInfo,
    SymbolInfo,
)


# ---------------------------------------------------------------------------
# ELF Constants
# ---------------------------------------------------------------------------

# Magic number
ELF_MAGIC: bytes = b"\x7fELF"

# ELF Class (32-bit vs 64-bit)
ELFCLASSNONE: int = 0
ELFCLASS32: int = 1
ELFCLASS64: int = 2

# Data encoding (endianness)
ELFDATANONE: int = 0
ELFDATA2LSB: int = 1  # Little-endian
ELFDATA2MSB: int = 2  # Big-endian

# ELF type
ET_NONE: int = 0
ET_REL: int = 1   # Relocatable
ET_EXEC: int = 2  # Executable
ET_DYN: int = 3   # Shared object / PIE
ET_CORE: int = 4  # Core dump

_ET_NAMES: dict[int, str] = {
    ET_NONE: "NONE",
    ET_REL: "REL (Relocatable)",
    ET_EXEC: "EXEC (Executable)",
    ET_DYN: "DYN (Shared object)",
    ET_CORE: "CORE (Core dump)",
}

# Machine architectures
EM_NONE: int = 0
EM_SPARC: int = 2
EM_386: int = 3
EM_MIPS: int = 8
EM_PPC: int = 20
EM_PPC64: int = 21
EM_ARM: int = 40
EM_X86_64: int = 62
EM_AARCH64: int = 183
EM_RISCV: int = 243

_EM_NAMES: dict[int, str] = {
    EM_NONE: "None",
    EM_SPARC: "SPARC",
    EM_386: "x86",
    EM_MIPS: "MIPS",
    EM_PPC: "PowerPC",
    EM_PPC64: "PowerPC64",
    EM_ARM: "ARM",
    EM_X86_64: "x86_64",
    EM_AARCH64: "AArch64",
    EM_RISCV: "RISC-V",
}

# Section header types
SHT_NULL: int = 0
SHT_PROGBITS: int = 1
SHT_SYMTAB: int = 2
SHT_STRTAB: int = 3
SHT_RELA: int = 4
SHT_HASH: int = 5
SHT_DYNAMIC: int = 6
SHT_NOTE: int = 7
SHT_NOBITS: int = 8
SHT_REL: int = 9
SHT_DYNSYM: int = 11
SHT_INIT_ARRAY: int = 14
SHT_FINI_ARRAY: int = 15
SHT_GNU_HASH: int = 0x6FFFFFF6
SHT_GNU_VERSYM: int = 0x6FFFFFFF
SHT_GNU_VERNEED: int = 0x6FFFFFFE
SHT_GNU_VERDEF: int = 0x6FFFFFFD

_SHT_NAMES: dict[int, str] = {
    SHT_NULL: "NULL",
    SHT_PROGBITS: "PROGBITS",
    SHT_SYMTAB: "SYMTAB",
    SHT_STRTAB: "STRTAB",
    SHT_RELA: "RELA",
    SHT_HASH: "HASH",
    SHT_DYNAMIC: "DYNAMIC",
    SHT_NOTE: "NOTE",
    SHT_NOBITS: "NOBITS",
    SHT_REL: "REL",
    SHT_DYNSYM: "DYNSYM",
    SHT_INIT_ARRAY: "INIT_ARRAY",
    SHT_FINI_ARRAY: "FINI_ARRAY",
    SHT_GNU_HASH: "GNU_HASH",
    SHT_GNU_VERSYM: "GNU_VERSYM",
    SHT_GNU_VERNEED: "GNU_VERNEED",
    SHT_GNU_VERDEF: "GNU_VERDEF",
}

# Section header flags
SHF_WRITE: int = 0x1
SHF_ALLOC: int = 0x2
SHF_EXECINSTR: int = 0x4

# Program header types
PT_NULL: int = 0
PT_LOAD: int = 1
PT_DYNAMIC: int = 2
PT_INTERP: int = 3
PT_NOTE: int = 4
PT_SHLIB: int = 5
PT_PHDR: int = 6
PT_TLS: int = 7
PT_GNU_EH_FRAME: int = 0x6474E550
PT_GNU_STACK: int = 0x6474E551
PT_GNU_RELRO: int = 0x6474E552

_PT_NAMES: dict[int, str] = {
    PT_NULL: "NULL",
    PT_LOAD: "LOAD",
    PT_DYNAMIC: "DYNAMIC",
    PT_INTERP: "INTERP",
    PT_NOTE: "NOTE",
    PT_SHLIB: "SHLIB",
    PT_PHDR: "PHDR",
    PT_TLS: "TLS",
    PT_GNU_EH_FRAME: "GNU_EH_FRAME",
    PT_GNU_STACK: "GNU_STACK",
    PT_GNU_RELRO: "GNU_RELRO",
}

# Program header flags
PF_X: int = 0x1  # Execute
PF_W: int = 0x2  # Write
PF_R: int = 0x4  # Read

# Symbol binding
STB_LOCAL: int = 0
STB_GLOBAL: int = 1
STB_WEAK: int = 2

_STB_NAMES: dict[int, str] = {
    STB_LOCAL: "LOCAL",
    STB_GLOBAL: "GLOBAL",
    STB_WEAK: "WEAK",
}

# Symbol types
STT_NOTYPE: int = 0
STT_OBJECT: int = 1
STT_FUNC: int = 2
STT_SECTION: int = 3
STT_FILE: int = 4

_STT_NAMES: dict[int, str] = {
    STT_NOTYPE: "NOTYPE",
    STT_OBJECT: "OBJECT",
    STT_FUNC: "FUNC",
    STT_SECTION: "SECTION",
    STT_FILE: "FILE",
}

# Dynamic tags
DT_NULL: int = 0
DT_NEEDED: int = 1
DT_PLTRELSZ: int = 2
DT_PLTGOT: int = 3
DT_HASH: int = 4
DT_STRTAB: int = 5
DT_SYMTAB: int = 6
DT_RELA: int = 7
DT_RELASZ: int = 8
DT_STRSZ: int = 10
DT_INIT: int = 12
DT_FINI: int = 13
DT_SONAME: int = 14
DT_RPATH: int = 15
DT_RUNPATH: int = 29

_DT_NAMES: dict[int, str] = {
    DT_NULL: "NULL",
    DT_NEEDED: "NEEDED",
    DT_PLTRELSZ: "PLTRELSZ",
    DT_PLTGOT: "PLTGOT",
    DT_HASH: "HASH",
    DT_STRTAB: "STRTAB",
    DT_SYMTAB: "SYMTAB",
    DT_RELA: "RELA",
    DT_RELASZ: "RELASZ",
    DT_STRSZ: "STRSZ",
    DT_INIT: "INIT",
    DT_FINI: "FINI",
    DT_SONAME: "SONAME",
    DT_RPATH: "RPATH",
    DT_RUNPATH: "RUNPATH",
}

# Special section indices
SHN_UNDEF: int = 0
SHN_ABS: int = 0xFFF1
SHN_COMMON: int = 0xFFF2


# ---------------------------------------------------------------------------
# Internal parsed structures
# ---------------------------------------------------------------------------

class _ELFHeader:
    """Parsed ELF header fields."""
    __slots__ = (
        "ei_class", "ei_data", "ei_version", "ei_osabi",
        "e_type", "e_machine", "e_version", "e_entry",
        "e_phoff", "e_shoff", "e_flags", "e_ehsize",
        "e_phentsize", "e_phnum", "e_shentsize", "e_shnum",
        "e_shstrndx",
    )

    def __init__(self) -> None:
        self.ei_class: int = 0
        self.ei_data: int = 0
        self.ei_version: int = 0
        self.ei_osabi: int = 0
        self.e_type: int = 0
        self.e_machine: int = 0
        self.e_version: int = 0
        self.e_entry: int = 0
        self.e_phoff: int = 0
        self.e_shoff: int = 0
        self.e_flags: int = 0
        self.e_ehsize: int = 0
        self.e_phentsize: int = 0
        self.e_phnum: int = 0
        self.e_shentsize: int = 0
        self.e_shnum: int = 0
        self.e_shstrndx: int = 0


class _SectionHeader:
    """Parsed section header entry."""
    __slots__ = (
        "sh_name", "sh_type", "sh_flags", "sh_addr",
        "sh_offset", "sh_size", "sh_link", "sh_info",
        "sh_addralign", "sh_entsize", "name",
    )

    def __init__(self) -> None:
        self.sh_name: int = 0
        self.sh_type: int = 0
        self.sh_flags: int = 0
        self.sh_addr: int = 0
        self.sh_offset: int = 0
        self.sh_size: int = 0
        self.sh_link: int = 0
        self.sh_info: int = 0
        self.sh_addralign: int = 0
        self.sh_entsize: int = 0
        self.name: str = ""


class _ProgramHeader:
    """Parsed program header (segment) entry."""
    __slots__ = (
        "p_type", "p_flags", "p_offset", "p_vaddr",
        "p_paddr", "p_filesz", "p_memsz", "p_align",
    )

    def __init__(self) -> None:
        self.p_type: int = 0
        self.p_flags: int = 0
        self.p_offset: int = 0
        self.p_vaddr: int = 0
        self.p_paddr: int = 0
        self.p_filesz: int = 0
        self.p_memsz: int = 0
        self.p_align: int = 0


class _DynamicEntry:
    """Parsed dynamic section entry."""
    __slots__ = ("d_tag", "d_val")

    def __init__(self, d_tag: int = 0, d_val: int = 0) -> None:
        self.d_tag = d_tag
        self.d_val = d_val


class _Symbol:
    """Parsed symbol table entry."""
    __slots__ = (
        "st_name", "st_value", "st_size", "st_info",
        "st_other", "st_shndx", "name",
    )

    def __init__(self) -> None:
        self.st_name: int = 0
        self.st_value: int = 0
        self.st_size: int = 0
        self.st_info: int = 0
        self.st_other: int = 0
        self.st_shndx: int = 0
        self.name: str = ""


# ---------------------------------------------------------------------------
# ELF Parser
# ---------------------------------------------------------------------------

class ELFParser:
    """Manual struct-based ELF binary parser.

    Parses both ELF32 and ELF64 binaries using only the Python standard
    library :mod:`struct` module.  No external dependencies such as
    ``pyelftools`` or ``lief`` are used.

    Reference:
        TIS Committee. (1995). Tool Interface Standard (TIS) Executable and
        Linkable Format (ELF) Specification, Version 1.2.

    Usage::

        parser = ELFParser(raw_bytes)
        if parser.parse():
            info = parser.get_binary_info()
            sections = parser.get_sections()
            symbols = parser.get_symbols()
            imports = parser.get_imports()
    """

    def __init__(self, data: bytes) -> None:
        """Initialise the parser with raw binary data.

        Args:
            data: Complete ELF file contents as bytes.
        """
        self._data: bytes = data
        self._header: _ELFHeader = _ELFHeader()
        self._sections: list[_SectionHeader] = []
        self._program_headers: list[_ProgramHeader] = []
        self._symbols: list[_Symbol] = []
        self._dynamic_symbols: list[_Symbol] = []
        self._dynamic_entries: list[_DynamicEntry] = []
        self._needed_libs: list[str] = []
        self._rpath: str = ""
        self._runpath: str = ""
        self._soname: str = ""
        self._endian: str = "<"  # Little-endian by default
        self._is_64bit: bool = False
        self._parsed: bool = False

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #

    def parse(self) -> bool:
        """Parse the ELF binary.

        Returns:
            ``True`` if parsing succeeded, ``False`` on invalid data.
        """
        if len(self._data) < 16:
            return False
        if self._data[:4] != ELF_MAGIC:
            return False

        try:
            self._parse_elf_header()
            self._parse_section_headers()
            self._resolve_section_names()
            self._parse_program_headers()
            self._parse_symbol_tables()
            self._parse_dynamic_section()
            self._parsed = True
            return True
        except (struct.error, IndexError, ValueError):
            return False

    def get_binary_info(self) -> BinaryInfo:
        """Build a :class:`BinaryInfo` from the parsed ELF header.

        Returns:
            Populated BinaryInfo model.
        """
        h = self._header
        return BinaryInfo(
            format=BinaryFormat.ELF,
            arch=_EM_NAMES.get(h.e_machine, f"unknown({h.e_machine})"),
            bits=64 if self._is_64bit else 32,
            endian="little" if self._endian == "<" else "big",
            entry_point=h.e_entry,
        )

    def get_sections(self) -> list[SectionInfo]:
        """Return parsed section information.

        Returns:
            List of SectionInfo models (one per section header).
        """
        result: list[SectionInfo] = []
        for sh in self._sections:
            flags_str = self._section_flags_str(sh.sh_flags)
            type_name = _SHT_NAMES.get(sh.sh_type, f"0x{sh.sh_type:x}")
            result.append(SectionInfo(
                name=sh.name,
                offset=sh.sh_offset,
                size=sh.sh_size,
                vaddr=sh.sh_addr,
                flags=flags_str,
                type_guess=type_name,
            ))
        return result

    def get_program_headers(self) -> list[dict[str, object]]:
        """Return parsed program (segment) headers.

        Returns:
            List of dictionaries with segment details.
        """
        result: list[dict[str, object]] = []
        for ph in self._program_headers:
            flags_str = self._segment_flags_str(ph.p_flags)
            result.append({
                "type": _PT_NAMES.get(ph.p_type, f"0x{ph.p_type:x}"),
                "offset": ph.p_offset,
                "vaddr": ph.p_vaddr,
                "paddr": ph.p_paddr,
                "filesz": ph.p_filesz,
                "memsz": ph.p_memsz,
                "flags": flags_str,
                "align": ph.p_align,
            })
        return result

    def get_symbols(self) -> list[SymbolInfo]:
        """Return all symbols from .symtab and .dynsym.

        Returns:
            List of SymbolInfo models.
        """
        all_syms = self._symbols + self._dynamic_symbols
        result: list[SymbolInfo] = []
        for sym in all_syms:
            st_bind = (sym.st_info >> 4) & 0xF
            st_type = sym.st_info & 0xF
            bind_name = _STB_NAMES.get(st_bind, f"UNKNOWN({st_bind})")
            type_name = _STT_NAMES.get(st_type, f"UNKNOWN({st_type})")

            section_name: str
            if sym.st_shndx == SHN_UNDEF:
                section_name = "UND"
            elif sym.st_shndx == SHN_ABS:
                section_name = "ABS"
            elif sym.st_shndx == SHN_COMMON:
                section_name = "COM"
            elif sym.st_shndx < len(self._sections):
                section_name = self._sections[sym.st_shndx].name
            else:
                section_name = str(sym.st_shndx)

            result.append(SymbolInfo(
                name=sym.name,
                value=sym.st_value,
                size=sym.st_size,
                type=type_name,
                bind=bind_name,
                section=section_name,
            ))
        return result

    def get_imports(self) -> list[ImportInfo]:
        """Extract imported symbols (undefined dynamic symbols).

        Imports are identified as symbols in ``.dynsym`` with:
        - ``st_shndx == SHN_UNDEF`` (undefined -- resolved at runtime)
        - Non-empty names

        Returns:
            List of ImportInfo models.
        """
        result: list[ImportInfo] = []
        for sym in self._dynamic_symbols:
            if sym.st_shndx != SHN_UNDEF:
                continue
            if not sym.name:
                continue
            # Determine which library provides this symbol by scanning
            # the NEEDED entries.  For ELF, precise mapping requires
            # version information; we associate with "libc" heuristically
            # or leave the library field populated from NEEDED list.
            lib = self._guess_library_for_symbol(sym.name)
            result.append(ImportInfo(
                library=lib,
                function=sym.name,
                address=sym.st_value,
            ))
        return result

    def get_needed_libraries(self) -> list[str]:
        """Return the list of DT_NEEDED shared library names.

        Returns:
            List of library name strings (e.g. ``["libc.so.6", "libm.so.6"]``).
        """
        return list(self._needed_libs)

    def get_rpath(self) -> str:
        """Return the DT_RPATH value, if present."""
        return self._rpath

    def get_runpath(self) -> str:
        """Return the DT_RUNPATH value, if present."""
        return self._runpath

    def get_interp(self) -> str:
        """Return the PT_INTERP string (dynamic linker path).

        Returns:
            Interpreter path string, or empty string if not found.
        """
        for ph in self._program_headers:
            if ph.p_type == PT_INTERP:
                start = ph.p_offset
                end = start + ph.p_filesz
                if end <= len(self._data):
                    raw = self._data[start:end]
                    return raw.rstrip(b"\x00").decode("ascii", errors="replace")
        return ""

    def get_executable_data(self) -> bytes:
        """Return concatenated bytes of all executable sections.

        Useful for disassembly and shellcode analysis.

        Returns:
            Bytes from all sections with SHF_EXECINSTR flag.
        """
        parts: list[bytes] = []
        for sh in self._sections:
            if sh.sh_flags & SHF_EXECINSTR:
                start = sh.sh_offset
                end = start + sh.sh_size
                if end <= len(self._data):
                    parts.append(self._data[start:end])
        return b"".join(parts)

    def get_executable_sections_info(self) -> list[tuple[int, int, bytes]]:
        """Return (vaddr, offset, data) for all executable sections.

        Returns:
            List of (virtual_address, file_offset, section_bytes) tuples.
        """
        result: list[tuple[int, int, bytes]] = []
        for sh in self._sections:
            if sh.sh_flags & SHF_EXECINSTR:
                start = sh.sh_offset
                end = start + sh.sh_size
                if end <= len(self._data):
                    result.append((sh.sh_addr, sh.sh_offset, self._data[start:end]))
        return result

    # ------------------------------------------------------------------ #
    #  ELF header parsing
    # ------------------------------------------------------------------ #

    def _parse_elf_header(self) -> None:
        """Parse the ELF identification and file header."""
        h = self._header
        # e_ident fields
        h.ei_class = self._data[4]
        h.ei_data = self._data[5]
        h.ei_version = self._data[6]
        h.ei_osabi = self._data[7]

        self._is_64bit = h.ei_class == ELFCLASS64
        self._endian = "<" if h.ei_data == ELFDATA2LSB else ">"

        if self._is_64bit:
            # ELF64 header: offsets 16..63
            fmt = f"{self._endian}HHIQQQIHHHHHH"
            fields = struct.unpack_from(fmt, self._data, 16)
            (
                h.e_type, h.e_machine, h.e_version, h.e_entry,
                h.e_phoff, h.e_shoff, h.e_flags, h.e_ehsize,
                h.e_phentsize, h.e_phnum, h.e_shentsize, h.e_shnum,
                h.e_shstrndx,
            ) = fields
        else:
            # ELF32 header: offsets 16..51
            fmt = f"{self._endian}HHIIIIIHHHHHH"
            fields = struct.unpack_from(fmt, self._data, 16)
            (
                h.e_type, h.e_machine, h.e_version, h.e_entry,
                h.e_phoff, h.e_shoff, h.e_flags, h.e_ehsize,
                h.e_phentsize, h.e_phnum, h.e_shentsize, h.e_shnum,
                h.e_shstrndx,
            ) = fields

    # ------------------------------------------------------------------ #
    #  Section header parsing
    # ------------------------------------------------------------------ #

    def _parse_section_headers(self) -> None:
        """Parse all section headers from the section header table."""
        h = self._header
        if h.e_shoff == 0 or h.e_shnum == 0:
            return

        for i in range(h.e_shnum):
            offset = h.e_shoff + i * h.e_shentsize
            sh = _SectionHeader()

            if self._is_64bit:
                # Elf64_Shdr: 64 bytes
                fmt = f"{self._endian}IIQQQQIIQQ"
                if offset + struct.calcsize(fmt) > len(self._data):
                    break
                fields = struct.unpack_from(fmt, self._data, offset)
                (
                    sh.sh_name, sh.sh_type, sh.sh_flags, sh.sh_addr,
                    sh.sh_offset, sh.sh_size, sh.sh_link, sh.sh_info,
                    sh.sh_addralign, sh.sh_entsize,
                ) = fields
            else:
                # Elf32_Shdr: 40 bytes
                fmt = f"{self._endian}IIIIIIIIII"
                if offset + struct.calcsize(fmt) > len(self._data):
                    break
                fields = struct.unpack_from(fmt, self._data, offset)
                (
                    sh.sh_name, sh.sh_type, sh.sh_flags, sh.sh_addr,
                    sh.sh_offset, sh.sh_size, sh.sh_link, sh.sh_info,
                    sh.sh_addralign, sh.sh_entsize,
                ) = fields

            self._sections.append(sh)

    def _resolve_section_names(self) -> None:
        """Resolve section names from the section header string table."""
        h = self._header
        if h.e_shstrndx == 0 or h.e_shstrndx >= len(self._sections):
            return

        strtab_sh = self._sections[h.e_shstrndx]
        strtab_start = strtab_sh.sh_offset
        strtab_end = strtab_start + strtab_sh.sh_size

        if strtab_end > len(self._data):
            return

        strtab_data = self._data[strtab_start:strtab_end]

        for sh in self._sections:
            sh.name = self._read_cstring(strtab_data, sh.sh_name)

    # ------------------------------------------------------------------ #
    #  Program header parsing
    # ------------------------------------------------------------------ #

    def _parse_program_headers(self) -> None:
        """Parse all program headers (segments)."""
        h = self._header
        if h.e_phoff == 0 or h.e_phnum == 0:
            return

        for i in range(h.e_phnum):
            offset = h.e_phoff + i * h.e_phentsize
            ph = _ProgramHeader()

            if self._is_64bit:
                # Elf64_Phdr: 56 bytes
                fmt = f"{self._endian}IIQQQQQQ"
                if offset + struct.calcsize(fmt) > len(self._data):
                    break
                fields = struct.unpack_from(fmt, self._data, offset)
                (
                    ph.p_type, ph.p_flags, ph.p_offset, ph.p_vaddr,
                    ph.p_paddr, ph.p_filesz, ph.p_memsz, ph.p_align,
                ) = fields
            else:
                # Elf32_Phdr: 32 bytes
                fmt = f"{self._endian}IIIIIIII"
                if offset + struct.calcsize(fmt) > len(self._data):
                    break
                fields = struct.unpack_from(fmt, self._data, offset)
                (
                    ph.p_type, ph.p_offset, ph.p_vaddr, ph.p_paddr,
                    ph.p_filesz, ph.p_memsz, ph.p_flags, ph.p_align,
                ) = fields

            self._program_headers.append(ph)

    # ------------------------------------------------------------------ #
    #  Symbol table parsing
    # ------------------------------------------------------------------ #

    def _parse_symbol_tables(self) -> None:
        """Parse both .symtab and .dynsym symbol tables."""
        for sh in self._sections:
            if sh.sh_type == SHT_SYMTAB:
                symbols = self._parse_symbol_table(sh)
                self._symbols.extend(symbols)
            elif sh.sh_type == SHT_DYNSYM:
                symbols = self._parse_symbol_table(sh)
                self._dynamic_symbols.extend(symbols)

    def _parse_symbol_table(self, sh: _SectionHeader) -> list[_Symbol]:
        """Parse a single symbol table section.

        Args:
            sh: The section header for the symbol table.

        Returns:
            List of parsed symbol entries.
        """
        if sh.sh_entsize == 0:
            return []

        # Find the associated string table
        strtab_data = b""
        if sh.sh_link < len(self._sections):
            strtab_sh = self._sections[sh.sh_link]
            st_start = strtab_sh.sh_offset
            st_end = st_start + strtab_sh.sh_size
            if st_end <= len(self._data):
                strtab_data = self._data[st_start:st_end]

        symbols: list[_Symbol] = []
        num_entries = sh.sh_size // sh.sh_entsize

        for i in range(num_entries):
            offset = sh.sh_offset + i * sh.sh_entsize
            sym = _Symbol()

            if self._is_64bit:
                # Elf64_Sym: 24 bytes
                fmt = f"{self._endian}IBBHQQ"
                if offset + struct.calcsize(fmt) > len(self._data):
                    break
                fields = struct.unpack_from(fmt, self._data, offset)
                (
                    sym.st_name, sym.st_info, sym.st_other,
                    sym.st_shndx, sym.st_value, sym.st_size,
                ) = fields
            else:
                # Elf32_Sym: 16 bytes
                fmt = f"{self._endian}IIIBBH"
                if offset + struct.calcsize(fmt) > len(self._data):
                    break
                fields = struct.unpack_from(fmt, self._data, offset)
                (
                    sym.st_name, sym.st_value, sym.st_size,
                    sym.st_info, sym.st_other, sym.st_shndx,
                ) = fields

            if strtab_data:
                sym.name = self._read_cstring(strtab_data, sym.st_name)

            symbols.append(sym)

        return symbols

    # ------------------------------------------------------------------ #
    #  Dynamic section parsing
    # ------------------------------------------------------------------ #

    def _parse_dynamic_section(self) -> None:
        """Parse the .dynamic section for DT_NEEDED, DT_RPATH, etc."""
        dynamic_sh: Optional[_SectionHeader] = None
        for sh in self._sections:
            if sh.sh_type == SHT_DYNAMIC:
                dynamic_sh = sh
                break

        if dynamic_sh is None:
            return

        # Find the dynamic string table (.dynstr)
        dynstr_data = b""
        for sh in self._sections:
            if sh.name == ".dynstr" and sh.sh_type == SHT_STRTAB:
                st_start = sh.sh_offset
                st_end = st_start + sh.sh_size
                if st_end <= len(self._data):
                    dynstr_data = self._data[st_start:st_end]
                break

        # If not found by name, try the sh_link of the dynamic section
        if not dynstr_data and dynamic_sh.sh_link < len(self._sections):
            link_sh = self._sections[dynamic_sh.sh_link]
            st_start = link_sh.sh_offset
            st_end = st_start + link_sh.sh_size
            if st_end <= len(self._data):
                dynstr_data = self._data[st_start:st_end]

        # Parse dynamic entries
        if self._is_64bit:
            entry_size = 16  # Elf64_Dyn: d_tag (int64) + d_val (uint64)
            fmt = f"{self._endian}qQ"
        else:
            entry_size = 8   # Elf32_Dyn: d_tag (int32) + d_val (uint32)
            fmt = f"{self._endian}iI"

        offset = dynamic_sh.sh_offset
        end = offset + dynamic_sh.sh_size

        while offset + entry_size <= end and offset + entry_size <= len(self._data):
            d_tag, d_val = struct.unpack_from(fmt, self._data, offset)
            self._dynamic_entries.append(_DynamicEntry(d_tag, d_val))

            if d_tag == DT_NULL:
                break

            if d_tag == DT_NEEDED and dynstr_data:
                lib_name = self._read_cstring(dynstr_data, d_val)
                self._needed_libs.append(lib_name)
            elif d_tag == DT_RPATH and dynstr_data:
                self._rpath = self._read_cstring(dynstr_data, d_val)
            elif d_tag == DT_RUNPATH and dynstr_data:
                self._runpath = self._read_cstring(dynstr_data, d_val)
            elif d_tag == DT_SONAME and dynstr_data:
                self._soname = self._read_cstring(dynstr_data, d_val)

            offset += entry_size

    # ------------------------------------------------------------------ #
    #  Utility methods
    # ------------------------------------------------------------------ #

    @staticmethod
    def _read_cstring(data: bytes, offset: int) -> str:
        """Read a null-terminated C string from a byte buffer.

        Args:
            data: Source byte buffer.
            offset: Starting offset within data.

        Returns:
            Decoded string (ASCII with error replacement).
        """
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\x00", offset)
        if end == -1:
            end = len(data)
        return data[offset:end].decode("ascii", errors="replace")

    @staticmethod
    def _section_flags_str(flags: int) -> str:
        """Convert section flags bitmask to a readable string.

        Args:
            flags: Section header flags value (sh_flags).

        Returns:
            String like ``"WAX"`` for Write+Alloc+Exec.
        """
        parts: list[str] = []
        if flags & SHF_WRITE:
            parts.append("W")
        if flags & SHF_ALLOC:
            parts.append("A")
        if flags & SHF_EXECINSTR:
            parts.append("X")
        return "".join(parts) if parts else "-"

    @staticmethod
    def _segment_flags_str(flags: int) -> str:
        """Convert program header flags to a readable string.

        Args:
            flags: Program header flags value (p_flags).

        Returns:
            String like ``"RWX"`` for Read+Write+Execute.
        """
        parts: list[str] = []
        if flags & PF_R:
            parts.append("R")
        if flags & PF_W:
            parts.append("W")
        if flags & PF_X:
            parts.append("X")
        return "".join(parts) if parts else "-"

    def _guess_library_for_symbol(self, symbol_name: str) -> str:
        """Heuristically guess which library provides a symbol.

        This is a best-effort mapping; precise resolution would require
        loading the actual shared libraries.

        Args:
            symbol_name: The imported symbol name.

        Returns:
            Guessed library name, or the first NEEDED library, or ``"unknown"``.
        """
        # Common libc functions
        libc_funcs = {
            "printf", "puts", "scanf", "malloc", "free", "calloc", "realloc",
            "memcpy", "memset", "memmove", "strlen", "strcpy", "strcmp",
            "strncpy", "strncmp", "strcat", "strncat", "strstr", "strchr",
            "open", "close", "read", "write", "lseek", "stat", "fstat",
            "mmap", "munmap", "mprotect", "brk", "sbrk",
            "fork", "exec", "execve", "execvp", "waitpid", "exit", "_exit",
            "socket", "bind", "listen", "accept", "connect", "send", "recv",
            "getenv", "setenv", "system", "popen", "pclose",
            "fopen", "fclose", "fread", "fwrite", "fprintf", "fscanf",
            "signal", "sigaction", "raise", "abort",
            "__libc_start_main", "__cxa_atexit", "__stack_chk_fail",
        }
        libpthread_funcs = {
            "pthread_create", "pthread_join", "pthread_exit", "pthread_mutex_lock",
            "pthread_mutex_unlock", "pthread_cond_wait", "pthread_cond_signal",
        }
        libdl_funcs = {"dlopen", "dlclose", "dlsym", "dlerror"}
        libm_funcs = {
            "sin", "cos", "tan", "sqrt", "pow", "log", "log10", "exp",
            "floor", "ceil", "fabs", "fmod",
        }

        name_lower = symbol_name.lstrip("_")
        if name_lower in libc_funcs or symbol_name in libc_funcs:
            return "libc.so.6"
        if name_lower in libpthread_funcs or symbol_name in libpthread_funcs:
            return "libpthread.so.0"
        if name_lower in libdl_funcs or symbol_name in libdl_funcs:
            return "libdl.so.2"
        if name_lower in libm_funcs or symbol_name in libm_funcs:
            return "libm.so.6"

        # Fall back to first NEEDED library
        if self._needed_libs:
            return self._needed_libs[0]

        return "unknown"
