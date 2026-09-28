"""Parse META-INF/MANIFEST.MF, the JAR's descriptive "cover sheet".

The format is simple but has two quirks worth knowing:

    Manifest-Version: 1.0
    Main-Class: com.example.Main
    Implementation-Title: Example Mod That Has A Really Long Name Which Nee
     ds Wrapping

1. Lines are limited to 72 bytes. A longer value continues on the next line,
   which starts with a single space (see "Nee" + "ds" above).
2. The first block of lines is the "main section" (describes the whole JAR).
   A blank line starts per-entry sections (e.g. signatures of each file).
   We only keep the main section.

Some attributes matter for security review:
  Main-Class          - the JAR can be run directly (`java -jar`). Normal for
                        installers and tools, unusual for plain mods.
  Premain-Class /     - the JAR can act as a Java *agent*, a program that can
  Agent-Class           rewrite other classes as they load. Rare in mods.
  FMLCorePlugin       - a legacy Forge "coremod" that patches Minecraft itself.
"""

from __future__ import annotations

from .jar import EntryReadError, SafeJar
from .models import ManifestInfo
from .sanitize import safe_text

MANIFEST_PATH = "META-INF/MANIFEST.MF"
MAX_ATTRIBUTES = 500
MAX_VALUE_LENGTH = 4096

# Attributes shown prominently in the GUI and reports (when present).
KEY_ATTRIBUTES = [
    "Manifest-Version",
    "Main-Class",
    "Implementation-Title",
    "Implementation-Version",
    "Implementation-Vendor",
    "Specification-Title",
    "Specification-Version",
    "Specification-Vendor",
    "Created-By",
    "Automatic-Module-Name",
    "MixinConfigs",
    "Premain-Class",
    "Agent-Class",
    "Launcher-Agent-Class",
    "FMLCorePlugin",
    "Class-Path",
]


def parse_manifest(data: bytes) -> ManifestInfo:
    """Parse manifest bytes. Never raises on bad input; garbage just yields fewer attributes."""
    # errors="replace" turns invalid UTF-8 into "�" instead of raising.
    text = data.decode("utf-8", errors="replace")
    # splitlines() understands \r\n, \n and \r line endings.
    lines = text.splitlines()

    attributes: dict[str, str] = {}
    current_key: str | None = None
    for line in lines:
        if line == "":
            break  # end of main section
        if line.startswith(" ") and current_key is not None:
            # Continuation line: append (without the leading space).
            if len(attributes[current_key]) < MAX_VALUE_LENGTH:
                attributes[current_key] += line[1:]
            continue
        key, sep, value = line.partition(":")
        if not sep:
            current_key = None  # malformed line; ignore it
            continue
        if len(attributes) >= MAX_ATTRIBUTES:
            break
        current_key = safe_text(key.strip(), max_length=200)
        attributes[current_key] = value.strip()

    cleaned = {k: safe_text(v, max_length=MAX_VALUE_LENGTH) for k, v in attributes.items()}
    return ManifestInfo(present=True, attributes=cleaned)


def find_manifest_name(jar: SafeJar) -> str | None:
    """Find the manifest. Java itself also accepts different letter case."""
    if jar.has(MANIFEST_PATH):
        return MANIFEST_PATH
    for info in jar.files():
        if info.filename.upper() == MANIFEST_PATH:
            return info.filename
    return None


def read_manifest(jar: SafeJar) -> tuple[ManifestInfo, list[str]]:
    """Return (manifest info, errors). A missing manifest is not an error."""
    name = find_manifest_name(jar)
    if name is None:
        return ManifestInfo(present=False), []
    try:
        data = jar.read(name, max_bytes=jar.limits.max_metadata_size)
    except EntryReadError as exc:
        return ManifestInfo(present=False), [f"Manifest: {exc}"]
    return parse_manifest(data), []
