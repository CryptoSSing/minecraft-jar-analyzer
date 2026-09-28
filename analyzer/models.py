"""Data structures shared by the analyzer, GUI and report exporter.

These are plain `dataclasses`: classes that mostly hold data. Python generates
`__init__`, `__repr__` and `__eq__` for us, and `dataclasses.asdict()` turns
them into dictionaries, which is exactly what the JSON exporter needs.

`StrEnum` members behave like strings ("INFO" == Severity.INFO), so they
serialize to JSON cleanly while still preventing typos in code.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "INFO"        # Noteworthy, usually normal for mods.
    REVIEW = "REVIEW"    # Unusual; a human should take a look.
    WARNING = "WARNING"  # Strongly associated with malicious mods; look closely.


SEVERITY_RANK = {Severity.INFO: 0, Severity.REVIEW: 1, Severity.WARNING: 2}


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class HashClassification(StrEnum):
    VERIFIED = "VERIFIED"      # A trusted person checked this exact file.
    UNKNOWN = "UNKNOWN"        # Not in the database. NOT a sign of malice.
    SUSPICIOUS = "SUSPICIOUS"  # A trusted person flagged this exact file.


@dataclass
class Finding:
    """One security indicator. Evidence for a human, never a verdict."""
    rule_id: str
    severity: Severity
    title: str
    location: str
    explanation: str
    confidence: Confidence


@dataclass
class FileInfo:
    name: str
    size_bytes: int = 0
    sha256: str | None = None
    modified: str | None = None  # ISO 8601, UTC
    file_type: str = "unknown"
    is_valid_jar: bool = False


@dataclass
class HashLookup:
    classification: HashClassification = HashClassification.UNKNOWN
    name: str | None = None
    version: str | None = None
    source: str | None = None
    notes: str | None = None


@dataclass
class ManifestInfo:
    present: bool = False
    # Main-section attributes, e.g. {"Manifest-Version": "1.0", ...}
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class ModInfo:
    """Metadata from one mod/plugin descriptor file."""
    loader: str                      # "Fabric", "Forge", "Bukkit/Paper plugin", ...
    source_file: str                 # e.g. "fabric.mod.json"
    mod_id: str | None = None
    name: str | None = None
    version: str | None = None
    description: str | None = None
    authors: list[str] = field(default_factory=list)
    dependencies: dict[str, str] = field(default_factory=dict)  # id -> version range
    minecraft_version: str | None = None
    loader_version: str | None = None
    extra: dict[str, str] = field(default_factory=dict)  # e.g. plugin main class
    nested_in: str | None = None     # path of the JAR-in-JAR this came from


@dataclass
class LargeEntry:
    path: str
    size_bytes: int
    compressed_bytes: int


@dataclass
class ContentsSummary:
    """Inventory of the archive, computed from its directory listing."""
    total_entries: int = 0
    total_files: int = 0
    directories: int = 0
    declared_uncompressed_bytes: int = 0
    by_extension: dict[str, int] = field(default_factory=dict)
    large_files: list[LargeEntry] = field(default_factory=list)
    high_ratio_entries: list[LargeEntry] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)
    executables_and_scripts: list[str] = field(default_factory=list)
    nested_jars: list[str] = field(default_factory=list)
    unusual_files: list[str] = field(default_factory=list)
    signature_files: list[str] = field(default_factory=list)
    encrypted_entries: list[str] = field(default_factory=list)
    duplicate_names: list[str] = field(default_factory=list)
    unsafe_names: list[str] = field(default_factory=list)  # traversal / absolute paths
    deceptive_names: list[str] = field(default_factory=list)  # hidden Unicode tricks
    # Content does not match the extension, e.g. "texture.png" that is really
    # a Windows .exe. Format: "path (detected: type)".
    disguised_files: list[str] = field(default_factory=list)


@dataclass
class ClassSummary:
    total: int = 0
    parsed: int = 0
    failed: int = 0
    skipped: int = 0  # not analyzed because a limit was reached
    # Top-level package -> number of classes, e.g. {"com/example": 42}
    packages: dict[str, int] = field(default_factory=dict)
    # e.g. {"Java 17": 120, "Java 8": 3}
    java_versions: dict[str, int] = field(default_factory=dict)
    failed_entries: list[str] = field(default_factory=list)


@dataclass
class NestedJarInfo:
    path: str
    size_bytes: int = 0
    sha256: str | None = None
    hash_classification: HashClassification = HashClassification.UNKNOWN
    loader: str = "Unknown"
    mod_ids: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class AnalysisResult:
    analyzer_name: str
    analyzer_version: str
    analyzed_at: str  # ISO 8601, UTC
    file: FileInfo
    hash_lookup: HashLookup = field(default_factory=HashLookup)
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    loader: str = "Unknown"
    loader_evidence: list[str] = field(default_factory=list)
    mods: list[ModInfo] = field(default_factory=list)
    contents: ContentsSummary = field(default_factory=ContentsSummary)
    classes: ClassSummary = field(default_factory=ClassSummary)
    nested_jars: list[NestedJarInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=SEVERITY_RANK.__getitem__)

    def primary_mod(self) -> ModInfo | None:
        """The first top-level (non-nested) mod descriptor, if any."""
        for mod in self.mods:
            if mod.nested_in is None:
                return mod
        return None

    def to_dict(self) -> dict:
        return asdict(self)
