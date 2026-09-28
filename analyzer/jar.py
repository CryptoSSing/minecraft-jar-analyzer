"""Safe, size-limited reading of JAR files.

A JAR is a ZIP archive. This module is the ONLY place that touches archive
contents, so every protection here applies to the whole analyzer:

* Size and structure are checked BEFORE Python's zipfile parses the archive.
* Nothing is ever extracted to disk; entries are read into memory.
* Entries are decompressed in small chunks while counting the bytes that come
  out, so a zip bomb is stopped as soon as it crosses a limit. We never trust
  the sizes the archive *claims*, because an attacker can write any number there.
* All low-level parsing errors are converted into two friendly exception types:
    JarError        - the archive as a whole cannot be analyzed
    EntryReadError  - one entry could not be read (the rest may be fine)

ZIP layout in one paragraph: file data comes first; at the END of the file is
the "central directory" (a table of contents listing every entry), followed by
a small "End Of Central Directory" (EOCD) record saying how many entries exist
and how big the central directory is. Programs read a ZIP starting from the end.
"""

from __future__ import annotations

import io
import os
import struct
import zipfile
import zlib
from pathlib import Path
from typing import BinaryIO

from .limits import DEFAULT_LIMITS, Limits

READ_CHUNK = 64 * 1024

_EOCD_SIG = b"PK\x05\x06"
_ZIP64_LOCATOR_SIG = b"PK\x06\x07"
_ZIP64_EOCD_SIG = b"PK\x06\x06"
_EOCD_SIZE = 22
_MAX_COMMENT = 0xFFFF


class JarError(Exception):
    """The archive cannot be analyzed. The message is safe to show to users."""


class EntryReadError(Exception):
    """A single entry could not be read."""


class BudgetExceeded(EntryReadError):
    """The total decompression budget for this JAR is used up."""


def detect_file_type(header: bytes) -> str:
    """Identify a file from its first bytes ("magic number"), not its extension.

    A malicious .exe renamed to .jar still starts with "MZ", so this tells the
    truth even when the file name lies.
    """
    if header.startswith(b"PK\x03\x04"):
        return "ZIP/JAR archive"
    if header.startswith(b"PK\x05\x06"):
        return "ZIP/JAR archive (empty)"
    if header.startswith(b"MZ"):
        return "Windows executable (PE)"
    if header.startswith(b"\x7fELF"):
        return "Linux executable (ELF)"
    if header.startswith(b"\xca\xfe\xba\xbe"):
        return "Java class file (or Mach-O universal binary)"
    if header.startswith((b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")):
        return "macOS executable (Mach-O)"
    if header.startswith(b"Rar!"):
        return "RAR archive"
    if header.startswith(b"7z\xbc\xaf"):
        return "7-Zip archive"
    if header.startswith(b"\x1f\x8b"):
        return "GZIP archive"
    if not header:
        return "empty file"
    return "unknown"


def read_central_directory_info(fp: BinaryIO) -> tuple[int, int] | None:
    """Read (declared entry count, central directory size) from the EOCD record.

    We do this ourselves, before zipfile.ZipFile() runs, because ZipFile builds
    a Python object for every entry in the central directory. A malicious ZIP
    could list millions of fake entries and exhaust memory before we ever get
    a chance to count them. Returns None if no EOCD record can be found.
    """
    fp.seek(0, os.SEEK_END)
    file_size = fp.tell()
    # The EOCD is 22 bytes plus an optional comment of up to 65535 bytes.
    tail_size = min(file_size, _EOCD_SIZE + _MAX_COMMENT)
    fp.seek(file_size - tail_size)
    tail = fp.read(tail_size)

    pos = tail.rfind(_EOCD_SIG)
    if pos < 0 or len(tail) - pos < _EOCD_SIZE:
        return None
    # "<" = little-endian; I = 4-byte unsigned int; H = 2-byte unsigned int.
    (_sig, _disk, _cd_disk, _disk_entries, total_entries,
     cd_size, _cd_offset, _comment_len) = struct.unpack("<4sHHHHIIH", tail[pos:pos + _EOCD_SIZE])

    # 0xFFFF / 0xFFFFFFFF mean "the real value is in the ZIP64 record".
    if total_entries == 0xFFFF or cd_size == 0xFFFFFFFF:
        eocd_offset = file_size - tail_size + pos
        if eocd_offset < 20:
            return None
        fp.seek(eocd_offset - 20)
        locator = fp.read(20)
        if locator[:4] != _ZIP64_LOCATOR_SIG:
            return total_entries, cd_size
        (zip64_offset,) = struct.unpack("<Q", locator[8:16])
        if zip64_offset > file_size:
            return None
        fp.seek(zip64_offset)
        record = fp.read(56)
        if len(record) < 56 or record[:4] != _ZIP64_EOCD_SIG:
            return None
        (total_entries,) = struct.unpack("<Q", record[32:40])
        (cd_size,) = struct.unpack("<Q", record[40:48])
    return total_entries, cd_size


class DecompressionBudget:
    """Counts decompressed bytes across one JAR and every JAR nested inside it."""

    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    def consume(self, n: int) -> None:
        self.used += n
        if self.used > self.limit:
            raise BudgetExceeded(
                f"Decompression budget of {self.limit:,} bytes exceeded; "
                "remaining entries were not analyzed (possible zip bomb)."
            )


class SafeJar:
    """A read-only, limit-enforcing view of a JAR archive.

    Use it as a context manager so the file is always closed:

        with SafeJar.open("mod.jar") as jar:
            data = jar.read("fabric.mod.json")
    """

    def __init__(self, zf: zipfile.ZipFile, display_name: str, limits: Limits,
                 budget: DecompressionBudget, depth: int, fileobj: BinaryIO | None = None):
        self._zf = zf
        self._fileobj = fileobj
        self.display_name = display_name
        self.limits = limits
        self.budget = budget
        self.depth = depth
        self.infos: list[zipfile.ZipInfo] = zf.infolist()
        # Name -> ZipInfo. If a name appears twice, keep the first one but
        # remember it: duplicate names are a known trick to show different
        # content to different tools.
        self._by_name: dict[str, zipfile.ZipInfo] = {}
        self.duplicate_names: list[str] = []
        for info in self.infos:
            if info.filename in self._by_name:
                self.duplicate_names.append(info.filename)
            else:
                self._by_name[info.filename] = info

    # ---------- opening ----------

    @classmethod
    def open(cls, path: str | Path, limits: Limits = DEFAULT_LIMITS) -> SafeJar:
        path = Path(path)
        if not path.is_file():
            raise JarError("Not a regular file (it may have been moved or deleted).")
        size = path.stat().st_size
        if size > limits.max_jar_size:
            raise JarError(
                f"File is {size:,} bytes, larger than the {limits.max_jar_size:,}-byte limit. "
                "It was not analyzed."
            )
        fp = open(path, "rb")
        try:
            header = fp.read(4)
            if not header.startswith(b"PK"):
                raise JarError(
                    f"Not a valid JAR/ZIP archive. Detected file type: {detect_file_type(header)}."
                )
            zf = cls._open_zip(fp, limits)
        except BaseException:
            fp.close()
            raise
        return cls(zf, path.name, limits, DecompressionBudget(limits.max_total_decompressed),
                   depth=0, fileobj=fp)

    @classmethod
    def open_nested(cls, data: bytes, display_name: str, parent: SafeJar) -> SafeJar:
        """Open a JAR stored inside another JAR, entirely in memory."""
        depth = parent.depth + 1
        if depth > parent.limits.max_nesting_depth:
            raise JarError(f"Nesting depth limit ({parent.limits.max_nesting_depth}) reached.")
        if not data.startswith(b"PK"):
            raise JarError(f"Not a valid JAR/ZIP archive. Detected file type: {detect_file_type(data[:4])}.")
        zf = cls._open_zip(io.BytesIO(data), parent.limits)
        # Shares the parent's budget on purpose: nesting must not multiply limits.
        return cls(zf, display_name, parent.limits, parent.budget, depth)

    @staticmethod
    def _open_zip(fp: BinaryIO, limits: Limits) -> zipfile.ZipFile:
        try:
            info = read_central_directory_info(fp)
        except (OSError, struct.error) as exc:
            raise JarError(f"Could not read ZIP structure: {exc}") from exc
        if info is None:
            raise JarError("Corrupt or truncated archive: ZIP end-of-directory record not found.")
        declared_entries, cd_size = info
        if declared_entries > limits.max_entries:
            raise JarError(
                f"Archive declares {declared_entries:,} entries, more than the "
                f"{limits.max_entries:,}-entry limit. It was not analyzed."
            )
        if cd_size > limits.max_entries * limits.central_directory_bytes_per_entry:
            raise JarError("Archive directory is abnormally large for its entry limit. It was not analyzed.")

        fp.seek(0)
        try:
            zf = zipfile.ZipFile(fp)
        # Catching broad Exception is normally discouraged, but this is a trust
        # boundary: zipfile can raise many different errors (BadZipFile,
        # UnicodeDecodeError, struct.error, ValueError...) on hostile input, and
        # every one of them simply means "this archive is malformed".
        except Exception as exc:  # noqa: BLE001
            raise JarError(f"Corrupt or malformed ZIP structure: {exc}") from exc

        if len(zf.infolist()) > limits.max_entries:
            zf.close()
            raise JarError(f"Archive has more than {limits.max_entries:,} entries. It was not analyzed.")
        return zf

    # ---------- reading ----------

    def files(self) -> list[zipfile.ZipInfo]:
        """All non-directory entries, in archive order (duplicates included)."""
        return [i for i in self.infos if not i.is_dir()]

    def has(self, name: str) -> bool:
        return name in self._by_name

    def get(self, name: str) -> zipfile.ZipInfo | None:
        return self._by_name.get(name)

    def read(self, entry: str | zipfile.ZipInfo, max_bytes: int | None = None) -> bytes:
        """Decompress one entry into memory, enforcing every limit.

        `max_bytes` can lower (never raise) the per-entry limit, e.g. to 1 MB
        for metadata files.
        """
        info = self._by_name.get(entry) if isinstance(entry, str) else entry
        if info is None:
            raise EntryReadError(f"Entry not found: {entry}")
        limit = self.limits.max_entry_size
        if max_bytes is not None:
            limit = min(limit, max_bytes)
        if info.flag_bits & 0x1:
            raise EntryReadError(f"'{info.filename}' is encrypted and cannot be analyzed.")
        if self.budget.exhausted:
            raise BudgetExceeded("Decompression budget already used up.")

        chunks = []
        total = 0
        try:
            with self._zf.open(info) as stream:
                # stream.read(n) returns at most n decompressed bytes, so even a
                # bomb only ever produces one 64 KB chunk before we check it.
                while chunk := stream.read(READ_CHUNK):
                    total += len(chunk)
                    if total > limit:
                        raise EntryReadError(
                            f"'{info.filename}' is larger than the {limit:,}-byte read limit; skipped."
                        )
                    self.budget.consume(len(chunk))
                    chunks.append(chunk)
        except EntryReadError:
            raise
        # Same reasoning as in _open_zip: many different errors all mean
        # "this entry is corrupt" (bad CRC, broken deflate data, unsupported
        # compression method, overlapping entries...).
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError,
                RuntimeError, OSError, ValueError) as exc:
            raise EntryReadError(f"Could not read '{info.filename}': {exc}") from exc
        return b"".join(chunks)

    def read_header(self, info: zipfile.ZipInfo, n: int = 8) -> bytes:
        """Read only the first `n` decompressed bytes of an entry (for file-type sniffing)."""
        if info.flag_bits & 0x1:
            raise EntryReadError(f"'{info.filename}' is encrypted.")
        try:
            with self._zf.open(info) as stream:
                header = stream.read(n)
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError,
                RuntimeError, OSError, ValueError) as exc:
            raise EntryReadError(f"Could not read '{info.filename}': {exc}") from exc
        self.budget.consume(len(header))
        return header

    # ---------- cleanup ----------

    def close(self) -> None:
        self._zf.close()
        if self._fileobj is not None:
            self._fileobj.close()

    def __enter__(self) -> SafeJar:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
