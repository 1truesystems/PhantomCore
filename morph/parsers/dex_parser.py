"""
Android DEX Format Parser
===========================

Manual struct-based parser for the Dalvik Executable (DEX) format used
by the Android Runtime (ART) and its predecessor, the Dalvik Virtual Machine.

All parsing is performed using :mod:`struct` without external libraries.
The parser supports DEX versions 035 through 039.

The parser extracts:
    - DEX header (magic, checksum, signature, file size, endianness)
    - String IDs table
    - Type IDs table
    - Proto IDs table (method prototypes)
    - Field IDs table
    - Method IDs table
    - Class definitions table (class names, superclass, access flags)

References:
    - Google. (2024). DEX Format. Android Open Source Project.
      https://source.android.com/docs/core/runtime/dex-format
    - Enck, W., Octeau, D., McDaniel, P., & Chaudhuri, S. (2011).
      A Study of Android Application Security. USENIX Security.
"""

from __future__ import annotations

import hashlib
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
# DEX Constants
# ---------------------------------------------------------------------------

DEX_MAGIC_PREFIX: bytes = b"dex\n"
DEX_SUPPORTED_VERSIONS: set[bytes] = {
    b"035\x00",
    b"036\x00",
    b"037\x00",
    b"038\x00",
    b"039\x00",
}

# Endianness tags
ENDIAN_CONSTANT: int = 0x12345678
REVERSE_ENDIAN_CONSTANT: int = 0x78563412

# Access flags for classes, fields, and methods
ACC_PUBLIC: int = 0x0001
ACC_PRIVATE: int = 0x0002
ACC_PROTECTED: int = 0x0004
ACC_STATIC: int = 0x0008
ACC_FINAL: int = 0x0010
ACC_SYNCHRONIZED: int = 0x0020
ACC_VOLATILE: int = 0x0040  # field
ACC_BRIDGE: int = 0x0040    # method
ACC_TRANSIENT: int = 0x0080  # field
ACC_VARARGS: int = 0x0080    # method
ACC_NATIVE: int = 0x0100
ACC_INTERFACE: int = 0x0200
ACC_ABSTRACT: int = 0x0400
ACC_STRICT: int = 0x0800
ACC_SYNTHETIC: int = 0x1000
ACC_ANNOTATION: int = 0x2000
ACC_ENUM: int = 0x4000
ACC_CONSTRUCTOR: int = 0x10000
ACC_DECLARED_SYNCHRONIZED: int = 0x20000

# No-index sentinel
NO_INDEX: int = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Internal parsed structures
# ---------------------------------------------------------------------------

class _DEXHeader:
    """Parsed DEX file header (112 bytes)."""
    __slots__ = (
        "magic", "version", "checksum", "signature",
        "file_size", "header_size", "endian_tag",
        "link_size", "link_off",
        "map_off",
        "string_ids_size", "string_ids_off",
        "type_ids_size", "type_ids_off",
        "proto_ids_size", "proto_ids_off",
        "field_ids_size", "field_ids_off",
        "method_ids_size", "method_ids_off",
        "class_defs_size", "class_defs_off",
        "data_size", "data_off",
    )

    def __init__(self) -> None:
        self.magic: bytes = b""
        self.version: str = ""
        self.checksum: int = 0
        self.signature: bytes = b""
        self.file_size: int = 0
        self.header_size: int = 0
        self.endian_tag: int = 0
        self.link_size: int = 0
        self.link_off: int = 0
        self.map_off: int = 0
        self.string_ids_size: int = 0
        self.string_ids_off: int = 0
        self.type_ids_size: int = 0
        self.type_ids_off: int = 0
        self.proto_ids_size: int = 0
        self.proto_ids_off: int = 0
        self.field_ids_size: int = 0
        self.field_ids_off: int = 0
        self.method_ids_size: int = 0
        self.method_ids_off: int = 0
        self.class_defs_size: int = 0
        self.class_defs_off: int = 0
        self.data_size: int = 0
        self.data_off: int = 0


class _ClassDef:
    """Parsed class definition entry."""
    __slots__ = (
        "class_idx", "access_flags", "superclass_idx",
        "interfaces_off", "source_file_idx",
        "annotations_off", "class_data_off", "static_values_off",
    )

    def __init__(self) -> None:
        self.class_idx: int = 0
        self.access_flags: int = 0
        self.superclass_idx: int = 0
        self.interfaces_off: int = 0
        self.source_file_idx: int = 0
        self.annotations_off: int = 0
        self.class_data_off: int = 0
        self.static_values_off: int = 0


class _MethodId:
    """Parsed method_id_item."""
    __slots__ = ("class_idx", "proto_idx", "name_idx")

    def __init__(self) -> None:
        self.class_idx: int = 0
        self.proto_idx: int = 0
        self.name_idx: int = 0


class _FieldId:
    """Parsed field_id_item."""
    __slots__ = ("class_idx", "type_idx", "name_idx")

    def __init__(self) -> None:
        self.class_idx: int = 0
        self.type_idx: int = 0
        self.name_idx: int = 0


class _ProtoId:
    """Parsed proto_id_item (method prototype)."""
    __slots__ = ("shorty_idx", "return_type_idx", "parameters_off")

    def __init__(self) -> None:
        self.shorty_idx: int = 0
        self.return_type_idx: int = 0
        self.parameters_off: int = 0


# ---------------------------------------------------------------------------
# DEX Parser
# ---------------------------------------------------------------------------

class DEXParser:
    """Manual struct-based Android DEX format parser.

    Parses DEX files (versions 035-039) using only the Python standard
    library :mod:`struct` module.  Extracts class definitions, method
    references, field references, and string constants.

    Reference:
        Google. (2024). DEX Format. Android Open Source Project.
        https://source.android.com/docs/core/runtime/dex-format

    Usage::

        parser = DEXParser(raw_bytes)
        if parser.parse():
            info = parser.get_binary_info()
            classes = parser.get_class_names()
            methods = parser.get_method_names()
    """

    def __init__(self, data: bytes) -> None:
        """Initialise the parser with raw DEX data.

        Args:
            data: Complete DEX file contents as bytes.
        """
        self._data: bytes = data
        self._header: _DEXHeader = _DEXHeader()
        self._strings: list[str] = []
        self._type_ids: list[int] = []         # Each is a string_id index
        self._proto_ids: list[_ProtoId] = []
        self._field_ids: list[_FieldId] = []
        self._method_ids: list[_MethodId] = []
        self._class_defs: list[_ClassDef] = []
        self._endian: str = "<"  # DEX is almost always little-endian
        self._parsed: bool = False

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #

    def parse(self) -> bool:
        """Parse the DEX binary.

        Returns:
            ``True`` if parsing succeeded, ``False`` on invalid data.
        """
        if len(self._data) < 112:
            return False

        # Verify magic
        if self._data[:4] != DEX_MAGIC_PREFIX:
            return False
        version_bytes = self._data[4:8]
        if version_bytes not in DEX_SUPPORTED_VERSIONS:
            return False

        try:
            self._parse_header()
            self._parse_string_ids()
            self._parse_type_ids()
            self._parse_proto_ids()
            self._parse_field_ids()
            self._parse_method_ids()
            self._parse_class_defs()
            self._parsed = True
            return True
        except (struct.error, IndexError, ValueError):
            return False

    def get_binary_info(self) -> BinaryInfo:
        """Build a :class:`BinaryInfo` from the parsed DEX header.

        Returns:
            Populated BinaryInfo model.
        """
        return BinaryInfo(
            format=BinaryFormat.DEX,
            arch="dalvik",
            bits=32,
            endian="little" if self._endian == "<" else "big",
            entry_point=0,
        )

    def get_sections(self) -> list[SectionInfo]:
        """Return pseudo-sections representing the major DEX data areas.

        DEX files do not have traditional sections like ELF/PE, so we
        synthesize section entries for the major data areas to provide
        a uniform interface for entropy analysis.

        Returns:
            List of SectionInfo models.
        """
        h = self._header
        sections: list[SectionInfo] = []

        if h.string_ids_size > 0:
            sections.append(SectionInfo(
                name="string_ids",
                offset=h.string_ids_off,
                size=h.string_ids_size * 4,
                vaddr=h.string_ids_off,
                flags="R",
                type_guess="String ID table",
            ))

        if h.type_ids_size > 0:
            sections.append(SectionInfo(
                name="type_ids",
                offset=h.type_ids_off,
                size=h.type_ids_size * 4,
                vaddr=h.type_ids_off,
                flags="R",
                type_guess="Type ID table",
            ))

        if h.proto_ids_size > 0:
            sections.append(SectionInfo(
                name="proto_ids",
                offset=h.proto_ids_off,
                size=h.proto_ids_size * 12,
                vaddr=h.proto_ids_off,
                flags="R",
                type_guess="Proto ID table",
            ))

        if h.field_ids_size > 0:
            sections.append(SectionInfo(
                name="field_ids",
                offset=h.field_ids_off,
                size=h.field_ids_size * 8,
                vaddr=h.field_ids_off,
                flags="R",
                type_guess="Field ID table",
            ))

        if h.method_ids_size > 0:
            sections.append(SectionInfo(
                name="method_ids",
                offset=h.method_ids_off,
                size=h.method_ids_size * 8,
                vaddr=h.method_ids_off,
                flags="R",
                type_guess="Method ID table",
            ))

        if h.class_defs_size > 0:
            sections.append(SectionInfo(
                name="class_defs",
                offset=h.class_defs_off,
                size=h.class_defs_size * 32,
                vaddr=h.class_defs_off,
                flags="R",
                type_guess="Class definitions",
            ))

        if h.data_size > 0:
            sections.append(SectionInfo(
                name="data",
                offset=h.data_off,
                size=h.data_size,
                vaddr=h.data_off,
                flags="R",
                type_guess="Data section",
            ))

        return sections

    def get_strings(self) -> list[str]:
        """Return all strings from the DEX string table.

        Returns:
            List of decoded string values.
        """
        return list(self._strings)

    def get_class_names(self) -> list[str]:
        """Return all class names defined in the DEX file.

        DEX class names use the internal format ``Lpackage/Class;``.
        This method returns both raw and human-readable forms.

        Returns:
            List of class name strings.
        """
        names: list[str] = []
        for cdef in self._class_defs:
            type_name = self._get_type_name(cdef.class_idx)
            if type_name:
                names.append(type_name)
        return names

    def get_method_names(self) -> list[str]:
        """Return all method references as ``ClassName.methodName`` strings.

        Returns:
            List of fully qualified method name strings.
        """
        results: list[str] = []
        for mid in self._method_ids:
            class_name = self._get_type_name(mid.class_idx)
            method_name = self._get_string(mid.name_idx)
            if class_name and method_name:
                # Convert Lcom/example/Class; to com.example.Class
                readable = self._type_to_readable(class_name)
                results.append(f"{readable}.{method_name}")
            elif method_name:
                results.append(method_name)
        return results

    def get_field_names(self) -> list[str]:
        """Return all field references as ``ClassName.fieldName`` strings.

        Returns:
            List of fully qualified field name strings.
        """
        results: list[str] = []
        for fid in self._field_ids:
            class_name = self._get_type_name(fid.class_idx)
            field_name = self._get_string(fid.name_idx)
            if class_name and field_name:
                readable = self._type_to_readable(class_name)
                results.append(f"{readable}.{field_name}")
            elif field_name:
                results.append(field_name)
        return results

    def get_symbols(self) -> list[SymbolInfo]:
        """Return method and field references as SymbolInfo entries.

        Returns:
            List of SymbolInfo models.
        """
        symbols: list[SymbolInfo] = []

        # Methods
        for i, mid in enumerate(self._method_ids):
            class_name = self._get_type_name(mid.class_idx)
            method_name = self._get_string(mid.name_idx)
            readable = self._type_to_readable(class_name) if class_name else ""
            full_name = f"{readable}.{method_name}" if readable else method_name
            symbols.append(SymbolInfo(
                name=full_name,
                value=i,
                type="METHOD",
                bind="GLOBAL",
                section="methods",
            ))

        # Fields
        for i, fid in enumerate(self._field_ids):
            class_name = self._get_type_name(fid.class_idx)
            field_name = self._get_string(fid.name_idx)
            readable = self._type_to_readable(class_name) if class_name else ""
            full_name = f"{readable}.{field_name}" if readable else field_name
            symbols.append(SymbolInfo(
                name=full_name,
                value=i,
                type="FIELD",
                bind="GLOBAL",
                section="fields",
            ))

        return symbols

    def get_imports(self) -> list[ImportInfo]:
        """Extract method references that appear to be API imports.

        In DEX, all method references to Android framework or Java standard
        library classes are effectively imports.

        Returns:
            List of ImportInfo models.
        """
        framework_prefixes = (
            "Landroid/", "Ldalvik/", "Ljava/", "Ljavax/",
            "Lorg/apache/", "Lcom/google/android/",
        )

        imports: list[ImportInfo] = []
        for mid in self._method_ids:
            class_name = self._get_type_name(mid.class_idx)
            if not class_name:
                continue

            is_framework = any(class_name.startswith(prefix) for prefix in framework_prefixes)
            if not is_framework:
                continue

            method_name = self._get_string(mid.name_idx)
            readable = self._type_to_readable(class_name)
            imports.append(ImportInfo(
                library=readable,
                function=method_name,
                address=0,
            ))

        return imports

    # ------------------------------------------------------------------ #
    #  Header parsing
    # ------------------------------------------------------------------ #

    def _parse_header(self) -> None:
        """Parse the 112-byte DEX file header."""
        h = self._header
        h.magic = self._data[:4]
        h.version = self._data[4:7].decode("ascii", errors="replace")

        # Determine endianness from the endian_tag at offset 40
        endian_tag = struct.unpack_from("<I", self._data, 40)[0]
        if endian_tag == ENDIAN_CONSTANT:
            self._endian = "<"
        elif endian_tag == REVERSE_ENDIAN_CONSTANT:
            self._endian = ">"
        else:
            self._endian = "<"

        e = self._endian

        h.checksum = struct.unpack_from(f"{e}I", self._data, 8)[0]
        h.signature = self._data[12:32]  # 20 bytes SHA-1
        h.file_size = struct.unpack_from(f"{e}I", self._data, 32)[0]
        h.header_size = struct.unpack_from(f"{e}I", self._data, 36)[0]
        h.endian_tag = endian_tag

        h.link_size = struct.unpack_from(f"{e}I", self._data, 44)[0]
        h.link_off = struct.unpack_from(f"{e}I", self._data, 48)[0]
        h.map_off = struct.unpack_from(f"{e}I", self._data, 52)[0]

        h.string_ids_size = struct.unpack_from(f"{e}I", self._data, 56)[0]
        h.string_ids_off = struct.unpack_from(f"{e}I", self._data, 60)[0]

        h.type_ids_size = struct.unpack_from(f"{e}I", self._data, 64)[0]
        h.type_ids_off = struct.unpack_from(f"{e}I", self._data, 68)[0]

        h.proto_ids_size = struct.unpack_from(f"{e}I", self._data, 72)[0]
        h.proto_ids_off = struct.unpack_from(f"{e}I", self._data, 76)[0]

        h.field_ids_size = struct.unpack_from(f"{e}I", self._data, 80)[0]
        h.field_ids_off = struct.unpack_from(f"{e}I", self._data, 84)[0]

        h.method_ids_size = struct.unpack_from(f"{e}I", self._data, 88)[0]
        h.method_ids_off = struct.unpack_from(f"{e}I", self._data, 92)[0]

        h.class_defs_size = struct.unpack_from(f"{e}I", self._data, 96)[0]
        h.class_defs_off = struct.unpack_from(f"{e}I", self._data, 100)[0]

        h.data_size = struct.unpack_from(f"{e}I", self._data, 104)[0]
        h.data_off = struct.unpack_from(f"{e}I", self._data, 108)[0]

    # ------------------------------------------------------------------ #
    #  String IDs table
    # ------------------------------------------------------------------ #

    def _parse_string_ids(self) -> None:
        """Parse the string_ids table and resolve all string values.

        Each string_id_item is a 4-byte offset (uint32) pointing to a
        string_data_item, which is encoded as a MUTF-8 string prefixed
        by its length in ULEB128 format.
        """
        h = self._header
        e = self._endian
        self._strings = []

        for i in range(h.string_ids_size):
            id_offset = h.string_ids_off + i * 4
            if id_offset + 4 > len(self._data):
                self._strings.append("")
                continue

            string_data_off = struct.unpack_from(f"{e}I", self._data, id_offset)[0]
            string_val = self._read_mutf8_string(string_data_off)
            self._strings.append(string_val)

    def _read_mutf8_string(self, offset: int) -> str:
        """Read a MUTF-8 encoded string from a string_data_item.

        The format is: ULEB128 length (in UTF-16 code units) followed by
        MUTF-8 encoded bytes terminated by a null byte.

        Args:
            offset: File offset of the string_data_item.

        Returns:
            Decoded string value.
        """
        if offset >= len(self._data):
            return ""

        # Read ULEB128-encoded length
        _length, bytes_consumed = self._read_uleb128(offset)
        str_start = offset + bytes_consumed

        # Find null terminator
        null_pos = self._data.find(b"\x00", str_start)
        if null_pos == -1:
            null_pos = min(str_start + 4096, len(self._data))

        raw = self._data[str_start:null_pos]

        # MUTF-8 is mostly compatible with UTF-8, but encodes null as 0xC0 0x80
        # and supplementary characters differently.  For practical purposes,
        # decode as UTF-8 with error handling.
        try:
            return raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("ascii", errors="replace")

    def _read_uleb128(self, offset: int) -> tuple[int, int]:
        """Read a ULEB128 (Unsigned Little-Endian Base 128) encoded value.

        ULEB128 is a variable-length encoding used throughout the DEX format
        for compact representation of unsigned integers.

        Args:
            offset: File offset to start reading.

        Returns:
            Tuple of (decoded_value, bytes_consumed).
        """
        result = 0
        shift = 0
        bytes_read = 0

        while offset + bytes_read < len(self._data):
            byte = self._data[offset + bytes_read]
            result |= (byte & 0x7F) << shift
            bytes_read += 1
            if (byte & 0x80) == 0:
                break
            shift += 7
            if bytes_read >= 5:
                break

        return result, bytes_read

    # ------------------------------------------------------------------ #
    #  Type IDs table
    # ------------------------------------------------------------------ #

    def _parse_type_ids(self) -> None:
        """Parse the type_ids table.

        Each type_id_item is a 4-byte index into the string_ids table,
        representing a type descriptor (e.g. ``Ljava/lang/Object;``).
        """
        h = self._header
        e = self._endian
        self._type_ids = []

        for i in range(h.type_ids_size):
            offset = h.type_ids_off + i * 4
            if offset + 4 > len(self._data):
                self._type_ids.append(0)
                continue
            descriptor_idx = struct.unpack_from(f"{e}I", self._data, offset)[0]
            self._type_ids.append(descriptor_idx)

    # ------------------------------------------------------------------ #
    #  Proto IDs table
    # ------------------------------------------------------------------ #

    def _parse_proto_ids(self) -> None:
        """Parse the proto_ids table (method prototypes).

        Each proto_id_item is 12 bytes:
            - shorty_idx: uint32 (string ID for shorty descriptor)
            - return_type_idx: uint32 (type ID for return type)
            - parameters_off: uint32 (offset to type_list, or 0)
        """
        h = self._header
        e = self._endian
        self._proto_ids = []

        for i in range(h.proto_ids_size):
            offset = h.proto_ids_off + i * 12
            if offset + 12 > len(self._data):
                break

            proto = _ProtoId()
            proto.shorty_idx = struct.unpack_from(f"{e}I", self._data, offset)[0]
            proto.return_type_idx = struct.unpack_from(f"{e}I", self._data, offset + 4)[0]
            proto.parameters_off = struct.unpack_from(f"{e}I", self._data, offset + 8)[0]
            self._proto_ids.append(proto)

    # ------------------------------------------------------------------ #
    #  Field IDs table
    # ------------------------------------------------------------------ #

    def _parse_field_ids(self) -> None:
        """Parse the field_ids table.

        Each field_id_item is 8 bytes:
            - class_idx: uint16 (type ID)
            - type_idx: uint16 (type ID)
            - name_idx: uint32 (string ID)
        """
        h = self._header
        e = self._endian
        self._field_ids = []

        for i in range(h.field_ids_size):
            offset = h.field_ids_off + i * 8
            if offset + 8 > len(self._data):
                break

            fid = _FieldId()
            fid.class_idx = struct.unpack_from(f"{e}H", self._data, offset)[0]
            fid.type_idx = struct.unpack_from(f"{e}H", self._data, offset + 2)[0]
            fid.name_idx = struct.unpack_from(f"{e}I", self._data, offset + 4)[0]
            self._field_ids.append(fid)

    # ------------------------------------------------------------------ #
    #  Method IDs table
    # ------------------------------------------------------------------ #

    def _parse_method_ids(self) -> None:
        """Parse the method_ids table.

        Each method_id_item is 8 bytes:
            - class_idx: uint16 (type ID)
            - proto_idx: uint16 (proto ID)
            - name_idx: uint32 (string ID)
        """
        h = self._header
        e = self._endian
        self._method_ids = []

        for i in range(h.method_ids_size):
            offset = h.method_ids_off + i * 8
            if offset + 8 > len(self._data):
                break

            mid = _MethodId()
            mid.class_idx = struct.unpack_from(f"{e}H", self._data, offset)[0]
            mid.proto_idx = struct.unpack_from(f"{e}H", self._data, offset + 2)[0]
            mid.name_idx = struct.unpack_from(f"{e}I", self._data, offset + 4)[0]
            self._method_ids.append(mid)

    # ------------------------------------------------------------------ #
    #  Class definitions table
    # ------------------------------------------------------------------ #

    def _parse_class_defs(self) -> None:
        """Parse the class_defs table.

        Each class_def_item is 32 bytes containing the class index,
        access flags, superclass index, interfaces, source file, and
        offsets to annotations and class data.
        """
        h = self._header
        e = self._endian
        self._class_defs = []

        for i in range(h.class_defs_size):
            offset = h.class_defs_off + i * 32
            if offset + 32 > len(self._data):
                break

            cdef = _ClassDef()
            cdef.class_idx = struct.unpack_from(f"{e}I", self._data, offset)[0]
            cdef.access_flags = struct.unpack_from(f"{e}I", self._data, offset + 4)[0]
            cdef.superclass_idx = struct.unpack_from(f"{e}I", self._data, offset + 8)[0]
            cdef.interfaces_off = struct.unpack_from(f"{e}I", self._data, offset + 12)[0]
            cdef.source_file_idx = struct.unpack_from(f"{e}I", self._data, offset + 16)[0]
            cdef.annotations_off = struct.unpack_from(f"{e}I", self._data, offset + 20)[0]
            cdef.class_data_off = struct.unpack_from(f"{e}I", self._data, offset + 24)[0]
            cdef.static_values_off = struct.unpack_from(f"{e}I", self._data, offset + 28)[0]
            self._class_defs.append(cdef)

    # ------------------------------------------------------------------ #
    #  Utility methods
    # ------------------------------------------------------------------ #

    def _get_string(self, idx: int) -> str:
        """Retrieve a string by its string_id index.

        Args:
            idx: Index into the string_ids table.

        Returns:
            String value, or empty string if index is out of bounds.
        """
        if 0 <= idx < len(self._strings):
            return self._strings[idx]
        return ""

    def _get_type_name(self, type_idx: int) -> str:
        """Retrieve a type descriptor string by its type_id index.

        Args:
            type_idx: Index into the type_ids table.

        Returns:
            Type descriptor string (e.g. ``Ljava/lang/Object;``).
        """
        if 0 <= type_idx < len(self._type_ids):
            string_idx = self._type_ids[type_idx]
            return self._get_string(string_idx)
        return ""

    @staticmethod
    def _type_to_readable(type_descriptor: str) -> str:
        """Convert a DEX type descriptor to a human-readable class name.

        Converts ``Lcom/example/MyClass;`` to ``com.example.MyClass``.

        Args:
            type_descriptor: DEX internal type descriptor.

        Returns:
            Human-readable class name.
        """
        if not type_descriptor:
            return ""

        # Array types
        if type_descriptor.startswith("["):
            inner = DEXParser._type_to_readable(type_descriptor[1:])
            return f"{inner}[]"

        # Object types: Lpackage/Class;
        if type_descriptor.startswith("L") and type_descriptor.endswith(";"):
            return type_descriptor[1:-1].replace("/", ".")

        # Primitive types
        primitives = {
            "V": "void", "Z": "boolean", "B": "byte", "S": "short",
            "C": "char", "I": "int", "J": "long", "F": "float", "D": "double",
        }
        return primitives.get(type_descriptor, type_descriptor)

    @staticmethod
    def _access_flags_str(flags: int) -> str:
        """Convert access flags to a human-readable string.

        Args:
            flags: Access flags bitmask.

        Returns:
            Space-separated flags string.
        """
        parts: list[str] = []
        flag_names = [
            (ACC_PUBLIC, "public"),
            (ACC_PRIVATE, "private"),
            (ACC_PROTECTED, "protected"),
            (ACC_STATIC, "static"),
            (ACC_FINAL, "final"),
            (ACC_SYNCHRONIZED, "synchronized"),
            (ACC_NATIVE, "native"),
            (ACC_INTERFACE, "interface"),
            (ACC_ABSTRACT, "abstract"),
            (ACC_SYNTHETIC, "synthetic"),
            (ACC_ANNOTATION, "annotation"),
            (ACC_ENUM, "enum"),
        ]
        for flag_val, flag_name in flag_names:
            if flags & flag_val:
                parts.append(flag_name)
        return " ".join(parts) if parts else ""
