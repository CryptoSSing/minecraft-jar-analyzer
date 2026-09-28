"""Inventory of what is inside a JAR.

Everything here is computed from the archive's directory listing (names and
declared sizes). No entry is decompressed, so this step is fast and cannot be
used as a zip bomb. The declared sizes may be lies, which is fine: we only use
them to *point out* oddities, never to decide how much to read (jar.py counts
real bytes for that).
"""

from __future__ import annotations

import posixpath
import re
from collections import Counter

from .jar import EntryReadError, SafeJar, detect_file_type
from .models import ContentsSummary, LargeEntry
from .sanitize import has_deceptive_chars

NATIVE_EXTENSIONS = {".dll", ".so", ".dylib", ".jnilib"}

# Files that the operating system can run directly. A Minecraft mod has no
# legitimate reason to carry these, so they get special attention.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".wsf", ".hta", ".jse", ".lnk", ".sh", ".command", ".app",
}

# Extensions that are routine in Minecraft mods and Java libraries.
COMMON_EXTENSIONS = {
    ".class", ".json", ".json5", ".mcmeta", ".toml", ".yml", ".yaml",
    ".properties", ".cfg", ".conf", ".txt", ".md", ".lang", ".xml", ".html", ".css",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ogg", ".wav",
    ".nbt", ".snbt", ".mcfunction", ".glsl", ".fsh", ".vsh", ".vert", ".frag",
    ".geo", ".bbmodel", ".obj", ".mtl", ".ttf", ".otf",
    ".accesswidener", ".aw", ".classtweaker", ".tiny", ".srg", ".mappings",
    ".mf", ".sf", ".rsa", ".dsa", ".ec", ".kotlin_module", ".kotlin_builtins",
    ".jar", ".list", ".idx", ".dat", ".bin", ".gz", ".zip",
}

# Extension-less files that are normal (licences, readmes...).
COMMON_BARE_NAMES = re.compile(
    r"^(license|licence|notice|readme|copying|changelog|authors|credits|contributors)", re.IGNORECASE
)

SIGNATURE_FILE = re.compile(r"^META-INF/[^/]+\.(SF|RSA|DSA|EC)$", re.IGNORECASE)


def extension_of(name: str) -> str:
    """Lower-case extension of the last path component, e.g. '.class', or ''."""
    return posixpath.splitext(posixpath.basename(name))[1].lower()


def is_unsafe_path(name: str) -> bool:
    """Would this name escape a folder if someone naively extracted it?

    "Zip slip": an entry named "../../AppData/evil.exe" extracted by a careless
    tool lands outside the target folder. We never extract, but such names are a
    strong sign the archive was crafted by hand.
    """
    if name.startswith(("/", "\\")) or "\\" in name:
        return True
    if re.match(r"^[A-Za-z]:", name):  # Windows drive letter, e.g. C:
        return True
    return ".." in name.split("/")


def summarize_contents(jar: SafeJar) -> ContentsSummary:
    limits = jar.limits
    summary = ContentsSummary(total_entries=len(jar.infos), duplicate_names=list(jar.duplicate_names))
    ext_counter: Counter[str] = Counter()

    for info in jar.infos:
        name = info.filename
        if is_unsafe_path(name):
            summary.unsafe_names.append(name)
        if has_deceptive_chars(name):
            summary.deceptive_names.append(name)
        if info.is_dir():
            summary.directories += 1
            continue

        summary.total_files += 1
        summary.declared_uncompressed_bytes += info.file_size
        ext = extension_of(name)
        ext_counter[ext or "(none)"] += 1

        if info.flag_bits & 0x1:
            summary.encrypted_entries.append(name)
        if SIGNATURE_FILE.match(name):
            summary.signature_files.append(name)

        if info.file_size >= limits.large_file_threshold:
            summary.large_files.append(LargeEntry(name, info.file_size, info.compress_size))
        if info.file_size >= limits.suspicious_ratio_min_size:
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > limits.suspicious_ratio:
                summary.high_ratio_entries.append(LargeEntry(name, info.file_size, info.compress_size))

        if ext in NATIVE_EXTENSIONS:
            summary.native_libraries.append(name)
        elif ext in EXECUTABLE_EXTENSIONS:
            summary.executables_and_scripts.append(name)
        elif ext == ".jar":
            summary.nested_jars.append(name)
        elif ext and ext not in COMMON_EXTENSIONS:
            summary.unusual_files.append(name)
        elif not ext:
            base = posixpath.basename(name)
            if not (COMMON_BARE_NAMES.match(base) or name.startswith("META-INF/")):
                summary.unusual_files.append(name)

    # Most common extensions first.
    summary.by_extension = dict(ext_counter.most_common())
    return summary


# Extensions where a given magic number is expected, so it is not a disguise.
_EXPECTED_MAGIC_EXTENSIONS = {
    "Windows executable (PE)": {".exe", ".dll", ".scr", ".com", ".sys"},
    "Linux executable (ELF)": {".so"},
    "Java class file (or Mach-O universal binary)": {".class", ".dylib", ".jnilib"},
    "macOS executable (Mach-O)": {".dylib", ".jnilib"},
    "ZIP/JAR archive": {".jar", ".zip", ".mcpack", ".litemod"},
}


def find_disguised_files(jar: SafeJar, max_checked: int = 50_000) -> tuple[list[str], list[str]]:
    """Find entries whose content type does not match their extension.

    Reads only the first 8 bytes of each entry. Returns (findings, errors).
    Hiding an executable or extra Java classes inside something named like an
    image is a known technique for slipping payloads past casual inspection.
    """
    disguised: list[str] = []
    errors: list[str] = []
    for info in jar.files()[:max_checked]:
        ext = extension_of(info.filename)
        if ext == ".class" or info.file_size < 4 or jar.budget.exhausted:
            continue
        try:
            header = jar.read_header(info)
        except EntryReadError as exc:
            errors.append(str(exc))
            continue
        detected = detect_file_type(header)
        expected_exts = _EXPECTED_MAGIC_EXTENSIONS.get(detected)
        if expected_exts is not None and ext not in expected_exts:
            disguised.append(f"{info.filename} (detected: {detected})")
    return disguised, errors[:20]
