"""
Magic Number File Type Identification
=======================================

Identifies file types by examining leading bytes (magic numbers / file
signatures).  Supports 80+ common binary formats spanning executables,
archives, images, audio, video, documents, databases, and cryptographic
containers.

The identification strategy follows a longest-prefix-match approach: for
each candidate signature, the file's leading bytes are compared against a
known magic byte pattern at a specified offset.  The first match in a
priority-sorted table is returned.

References:
    - Gary Kessler's File Signatures Table.
      https://www.garykessler.net/library/file_sigs.html
    - Wikipedia. (2024). List of file signatures.
    - ``file(1)`` command magic database. https://github.com/file/file
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True, slots=True)
class _Signature:
    """A single file-type magic signature entry.

    Attributes:
        magic: Byte pattern to match.
        offset: Byte offset within the file where *magic* is expected.
        description: Human-readable type description.
        extension: Canonical file extension (without leading dot).
    """
    magic: bytes
    offset: int
    description: str
    extension: str


# ---------------------------------------------------------------------------
# Signature table -- ordered by specificity (longer / rarer matches first)
# ---------------------------------------------------------------------------

_SIGNATURES: list[_Signature] = [
    # ── Executables & bytecode ──────────────────────────────────────────
    _Signature(b"\x7fELF", 0, "ELF executable", "elf"),
    _Signature(b"MZ", 0, "PE/MS-DOS executable", "exe"),
    _Signature(b"dex\n039\x00", 0, "Android DEX (version 039)", "dex"),
    _Signature(b"dex\n038\x00", 0, "Android DEX (version 038)", "dex"),
    _Signature(b"dex\n037\x00", 0, "Android DEX (version 037)", "dex"),
    _Signature(b"dex\n036\x00", 0, "Android DEX (version 036)", "dex"),
    _Signature(b"dex\n035\x00", 0, "Android DEX (version 035)", "dex"),
    _Signature(b"\xfe\xed\xfa\xce", 0, "Mach-O 32-bit", "macho"),
    _Signature(b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit", "macho"),
    _Signature(b"\xce\xfa\xed\xfe", 0, "Mach-O 32-bit (reversed)", "macho"),
    _Signature(b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit (reversed)", "macho"),
    _Signature(b"\xca\xfe\xba\xbe", 0, "Mach-O Fat Binary / Java Class", "macho"),
    _Signature(b"\xbe\xba\xfe\xca", 0, "Mach-O Fat Binary (reversed)", "macho"),
    _Signature(b"\xca\xfe\xd0\x0d", 0, "Java Class File", "class"),
    _Signature(b"\x00asm", 0, "WebAssembly binary", "wasm"),
    _Signature(b"BC\xc0\xde", 0, "LLVM Bitcode", "bc"),

    # Python bytecode (various versions)
    _Signature(b"\x42\x0d\x0d\x0a", 0, "Python 3.x bytecode", "pyc"),
    _Signature(b"\x33\x0d\x0d\x0a", 0, "Python 3.x bytecode", "pyc"),
    _Signature(b"\xa7\x0d\x0d\x0a", 0, "Python 3.x bytecode", "pyc"),
    _Signature(b"\x61\x0d\x0d\x0a", 0, "Python 3.11 bytecode", "pyc"),

    # Lua bytecode
    _Signature(b"\x1bLua", 0, "Lua bytecode", "luac"),

    # ── Archives & compressed formats ───────────────────────────────────
    _Signature(b"PK\x03\x04", 0, "ZIP archive", "zip"),
    _Signature(b"PK\x05\x06", 0, "ZIP archive (empty)", "zip"),
    _Signature(b"PK\x07\x08", 0, "ZIP archive (spanned)", "zip"),
    _Signature(b"\x1f\x8b", 0, "GZIP compressed", "gz"),
    _Signature(b"BZh", 0, "BZIP2 compressed", "bz2"),
    _Signature(b"\xfd\x37\x7a\x58\x5a\x00", 0, "XZ compressed", "xz"),
    _Signature(b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", "7z"),
    _Signature(b"Rar!\x1a\x07\x01\x00", 0, "RAR5 archive", "rar"),
    _Signature(b"Rar!\x1a\x07\x00", 0, "RAR archive", "rar"),
    _Signature(b"ustar\x0000", 257, "POSIX TAR archive", "tar"),
    _Signature(b"ustar  \x00", 257, "GNU TAR archive", "tar"),
    _Signature(b"\x28\xb5\x2f\xfd", 0, "Zstandard compressed", "zst"),
    _Signature(b"\x04\x22\x4d\x18", 0, "LZ4 compressed", "lz4"),
    _Signature(b"\x1a\x45\xdf\xa3", 0, "LZMA compressed", "lzma"),
    _Signature(b"LZIP", 0, "LZIP compressed", "lz"),
    _Signature(b"\x89LZO\x00\x0d\x0a\x1a\x0a", 0, "LZO compressed", "lzo"),

    # ── Images ──────────────────────────────────────────────────────────
    _Signature(b"\x89PNG\r\n\x1a\n", 0, "PNG image", "png"),
    _Signature(b"\xff\xd8\xff\xe0", 0, "JPEG image (JFIF)", "jpg"),
    _Signature(b"\xff\xd8\xff\xe1", 0, "JPEG image (Exif)", "jpg"),
    _Signature(b"\xff\xd8\xff\xee", 0, "JPEG image (Adobe)", "jpg"),
    _Signature(b"\xff\xd8\xff\xdb", 0, "JPEG image", "jpg"),
    _Signature(b"\xff\xd8\xff", 0, "JPEG image (generic)", "jpg"),
    _Signature(b"GIF87a", 0, "GIF image (87a)", "gif"),
    _Signature(b"GIF89a", 0, "GIF image (89a)", "gif"),
    _Signature(b"BM", 0, "BMP image", "bmp"),
    _Signature(b"II\x2a\x00", 0, "TIFF image (little-endian)", "tiff"),
    _Signature(b"MM\x00\x2a", 0, "TIFF image (big-endian)", "tiff"),
    _Signature(b"RIFF", 0, "RIFF container (WebP/AVI/WAV)", "riff"),
    _Signature(b"\x00\x00\x01\x00", 0, "ICO icon", "ico"),
    _Signature(b"\x00\x00\x02\x00", 0, "CUR cursor", "cur"),
    _Signature(b"\x00\x00\x00\x0cftyp", 0, "HEIF/HEIC image", "heif"),
    _Signature(b"\x00\x00\x00\x18ftypheic", 0, "HEIC image", "heic"),
    _Signature(b"\x00\x00\x00\x1cftypmif1", 0, "HEIF image", "heif"),

    # ── Audio ───────────────────────────────────────────────────────────
    _Signature(b"ID3", 0, "MP3 audio (ID3)", "mp3"),
    _Signature(b"\xff\xfb", 0, "MP3 audio", "mp3"),
    _Signature(b"\xff\xf3", 0, "MP3 audio", "mp3"),
    _Signature(b"\xff\xf2", 0, "MP3 audio", "mp3"),
    _Signature(b"OggS", 0, "OGG Vorbis audio", "ogg"),
    _Signature(b"fLaC", 0, "FLAC audio", "flac"),
    _Signature(b"MThd", 0, "MIDI audio", "mid"),
    _Signature(b"\xff\xf1", 0, "AAC audio (ADTS)", "aac"),
    _Signature(b"\xff\xf9", 0, "AAC audio (ADTS)", "aac"),

    # ── Video ───────────────────────────────────────────────────────────
    _Signature(b"\x00\x00\x00\x1cftypisom", 0, "MP4 video (isom)", "mp4"),
    _Signature(b"\x00\x00\x00\x18ftypmp42", 0, "MP4 video (mp42)", "mp4"),
    _Signature(b"\x00\x00\x00\x20ftypisom", 0, "MP4 video", "mp4"),
    _Signature(b"\x00\x00\x00", 0, "MP4/MOV container candidate", "mp4"),
    _Signature(b"\x1a\x45\xdf\xa3", 0, "Matroska/WebM video", "mkv"),
    _Signature(b"FLV\x01", 0, "Flash Video", "flv"),

    # ── Documents ───────────────────────────────────────────────────────
    _Signature(b"%PDF", 0, "PDF document", "pdf"),
    _Signature(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "MS Office (OLE2 Compound)", "doc"),
    _Signature(b"{\\rtf", 0, "RTF document", "rtf"),

    # OOXML -- ZIP-based, so we check for specific entries after PK
    # (handled at a higher level; this is a secondary check)

    # ── Databases & captures ────────────────────────────────────────────
    _Signature(b"SQLite format 3\x00", 0, "SQLite database", "sqlite"),
    _Signature(b"\xd4\xc3\xb2\xa1", 0, "PCAP capture (LE)", "pcap"),
    _Signature(b"\xa1\xb2\xc3\xd4", 0, "PCAP capture (BE)", "pcap"),
    _Signature(b"\x0a\x0d\x0d\x0a", 0, "PCAPNG capture", "pcapng"),

    # ── Cryptographic / key material ────────────────────────────────────
    _Signature(b"-----BEGIN PGP", 0, "PGP armored data", "pgp"),
    _Signature(b"\x85\x01", 0, "GPG binary key", "gpg"),
    _Signature(b"\x85\x02", 0, "GPG binary key", "gpg"),
    _Signature(b"\x99\x01", 0, "GPG public key", "gpg"),
    _Signature(b"-----BEGIN RSA PRIVATE KEY", 0, "PEM RSA private key", "pem"),
    _Signature(b"-----BEGIN PRIVATE KEY", 0, "PEM private key (PKCS#8)", "pem"),
    _Signature(b"-----BEGIN CERTIFICATE", 0, "PEM certificate", "pem"),
    _Signature(b"-----BEGIN OPENSSH PRIVATE KEY", 0, "OpenSSH private key", "pem"),
    _Signature(b"ssh-rsa ", 0, "SSH RSA public key", "pub"),
    _Signature(b"ssh-ed25519 ", 0, "SSH Ed25519 public key", "pub"),

    # ── Boot / firmware images ──────────────────────────────────────────
    _Signature(b"ANDROID!", 0, "Android Boot Image", "img"),
    _Signature(b"\xeb\x3c\x90", 0, "x86 boot sector (JMP)", "bin"),
    _Signature(b"\xeb\x58\x90", 0, "x86 boot sector (JMP)", "bin"),
    _Signature(b"\x55\xaa", 510, "MBR boot signature", "mbr"),

    # ── Miscellaneous ───────────────────────────────────────────────────
    _Signature(b"\x1f\x9d", 0, "compress (.Z)", "Z"),
    _Signature(b"\x1f\xa0", 0, "compress (LZH)", "Z"),
    _Signature(b"gimp xcf", 0, "GIMP XCF image", "xcf"),
    _Signature(b"\x00\x61\x73\x6d", 0, "WebAssembly binary", "wasm"),
    _Signature(b"#!", 0, "Script (shebang)", "sh"),
    _Signature(b"<?xml", 0, "XML document", "xml"),
    _Signature(b"<!DOCTYPE", 0, "HTML/XML document", "html"),
    _Signature(b"<html", 0, "HTML document", "html"),
]


class MagicIdentifier:
    """Identify file types by magic byte signatures.

    Examines the leading bytes of a file (or data buffer) and matches
    them against a curated table of 80+ known file signatures.

    Usage::

        identifier = MagicIdentifier()
        file_type = identifier.identify(raw_bytes)
        # => "ELF executable"
    """

    def __init__(self) -> None:
        """Initialise the identifier with the built-in signature table."""
        self._signatures: list[_Signature] = list(_SIGNATURES)

    def identify(self, data: bytes) -> str:
        """Identify the file type from the given byte buffer.

        The method tests each signature in priority order and returns the
        description of the first match.  If no known signature matches,
        the method attempts heuristic detection of text versus binary data.

        Args:
            data: Raw file bytes (at least the first 1024 bytes are
                  recommended for reliable identification).

        Returns:
            A human-readable file type description string, or
            ``"Unknown binary"`` if no match is found.
        """
        if not data:
            return "Empty file"

        data_len = len(data)

        for sig in self._signatures:
            end = sig.offset + len(sig.magic)
            if end > data_len:
                continue
            if data[sig.offset : end] == sig.magic:
                # RIFF sub-type detection
                if sig.description.startswith("RIFF") and data_len >= 12:
                    return self._identify_riff(data)
                return sig.description

        # Heuristic: check for OOXML (ZIP containing specific entries)
        if data_len >= 4 and data[:4] == b"PK\x03\x04":
            return self._check_ooxml(data)

        # Heuristic: check for ftyp-based containers (MP4/MOV/HEIF)
        if data_len >= 12:
            ftyp_result = self._check_ftyp(data)
            if ftyp_result:
                return ftyp_result

        # Heuristic: text vs binary
        if self._looks_like_text(data[:4096]):
            return "Text file"

        return "Unknown binary"

    def identify_format(self, data: bytes) -> str:
        """Return a normalised short format identifier.

        Unlike :meth:`identify` which returns a descriptive string,
        this method returns a machine-friendly short format tag such as
        ``"elf"``, ``"pe"``, ``"dex"``, ``"macho"``, or ``"unknown"``.

        Args:
            data: Raw file bytes.

        Returns:
            Short format string.
        """
        if not data:
            return "unknown"

        if len(data) >= 4 and data[:4] == b"\x7fELF":
            return "elf"
        if len(data) >= 2 and data[:2] == b"MZ":
            return "pe"
        if len(data) >= 4 and data[:3] == b"dex":
            return "dex"
        if len(data) >= 4:
            magic32 = data[:4]
            macho_magics = {
                b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
            }
            if magic32 in macho_magics:
                return "macho"

        return "unknown"

    # ------------------------------------------------------------------ #
    #  Private helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _identify_riff(data: bytes) -> str:
        """Sub-classify a RIFF container by its FourCC type."""
        if len(data) < 12:
            return "RIFF container"
        fourcc = data[8:12]
        riff_types = {
            b"WEBP": "WebP image",
            b"AVI ": "AVI video",
            b"WAVE": "WAV audio",
            b"AIFF": "AIFF audio",
            b"ACON": "Animated cursor (ANI)",
            b"RMID": "RIFF MIDI",
        }
        return riff_types.get(fourcc, f"RIFF container ({fourcc.decode('ascii', errors='replace')})")

    @staticmethod
    def _check_ooxml(data: bytes) -> str:
        """Attempt to detect OOXML (Office Open XML) within a ZIP."""
        # OOXML files contain "[Content_Types].xml" near the beginning
        search_window = data[:4096]
        if b"[Content_Types].xml" in search_window:
            if b"word/" in search_window:
                return "Microsoft Word (OOXML .docx)"
            if b"xl/" in search_window:
                return "Microsoft Excel (OOXML .xlsx)"
            if b"ppt/" in search_window:
                return "Microsoft PowerPoint (OOXML .pptx)"
            return "OOXML document"
        if b"META-INF/" in search_window:
            if b"classes.dex" in search_window:
                return "Android APK"
            return "Java JAR archive"
        if b"mimetype" in search_window:
            # ODF documents store mimetype as first entry
            if b"application/vnd.oasis.opendocument" in search_window:
                return "ODF document"
            if b"application/epub" in search_window:
                return "EPUB ebook"
        return "ZIP archive"

    @staticmethod
    def _check_ftyp(data: bytes) -> Optional[str]:
        """Detect ISO Base Media File Format containers (MP4, MOV, etc.)."""
        # ftyp box: first 4 bytes = size, next 4 = 'ftyp'
        if len(data) < 12:
            return None
        if data[4:8] == b"ftyp":
            brand = data[8:12].decode("ascii", errors="replace").strip("\x00")
            ftyp_brands = {
                "isom": "MP4 video (ISO)",
                "mp41": "MP4 video (v1)",
                "mp42": "MP4 video (v2)",
                "M4A ": "M4A audio",
                "M4V ": "M4V video",
                "qt  ": "QuickTime MOV",
                "3gp4": "3GPP video",
                "3gp5": "3GPP video",
                "3g2a": "3GPP2 video",
                "heic": "HEIC image",
                "heix": "HEIF image",
                "mif1": "HEIF image",
                "avif": "AVIF image",
                "dash": "MPEG-DASH",
                "f4v ": "Flash MP4 video",
            }
            return ftyp_brands.get(brand, f"ISO BMFF container (brand={brand})")
        return None

    @staticmethod
    def _looks_like_text(data: bytes) -> bool:
        """Heuristic check whether data appears to be text.

        A sample is considered text if fewer than 5% of bytes fall outside
        the printable ASCII + common whitespace range.
        """
        if not data:
            return False
        text_bytes = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
        non_text = sum(1 for b in data if b not in text_bytes)
        return non_text / len(data) < 0.05
