"""Run every analysis stage for a JAR and assemble the AnalysisResult.

Order of operations for one file:

  1. File info (size, timestamp, real file type from magic bytes)
  2. SHA-256 of the whole file (streamed)
  3. Hash database lookup
  4. Open the archive safely (size / entry-count / structure checks)
  5. Manifest  6. Mod metadata  7. Contents inventory + disguised files
  8. Class scan (constant pools) -> evidence
  9. Loader detection
 10. Indicator rules
 11. Nested JARs (JAR-in-JAR) - steps 5-10 again, sharing the same budget

Each step is isolated: if one fails, its error is recorded in `result.errors`
and the remaining steps still run. A corrupt manifest should not stop you from
seeing the hash, contents and class findings.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .classes import scan_classes
from .contents import find_disguised_files, summarize_contents
from .hash_database import HashDatabase, HashDatabaseError
from .hashing import sha256_bytes, sha256_file
from .indicators import (ClassEvidence, RuleContext, add_batch_findings,
                         SEVERITY_SORT, rule_hash_database, run_rules)
from .jar import EntryReadError, JarError, SafeJar, detect_file_type
from .limits import DEFAULT_LIMITS, Limits
from .manifest import read_manifest
from .metadata import detect_loader, read_metadata
from .models import (AnalysisResult, ClassSummary, ContentsSummary, FileInfo,
                     Finding, HashLookup, ManifestInfo, ModInfo, NestedJarInfo,
                     Severity)
from .resources import hash_database_path
from .sanitize import safe_text
from .version import APP_NAME, VERSION

CancelCheck = Callable[[], bool]
ProgressCallback = Callable[[int, int, str], None]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_hash_database(path: str | Path | None = None) -> tuple[HashDatabase, list[str]]:
    """Load the hash DB, falling back to an empty one. Returns (db, messages)."""
    path = Path(path) if path else hash_database_path()
    try:
        db = HashDatabase.load(path)
    except HashDatabaseError as exc:
        return HashDatabase(), [f"Hash database unavailable: {exc}"]
    return db, [f"Hash database: {w}" for w in db.warnings]


@dataclass
class _JarAnalysis:
    """Everything learned from one open archive (top-level or nested)."""
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    mods: list[ModInfo] = field(default_factory=list)
    contents: ContentsSummary = field(default_factory=ContentsSummary)
    classes: ClassSummary = field(default_factory=ClassSummary)
    loader: str = "Unknown"
    loader_evidence: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    nested: list[NestedJarInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _analyze_jar(jar: SafeJar, hash_lookup: HashLookup, hash_db: HashDatabase,
                 should_cancel: CancelCheck) -> _JarAnalysis:
    out = _JarAnalysis()

    out.manifest, errors = read_manifest(jar)
    out.errors += errors
    out.mods, errors = read_metadata(jar, out.manifest)
    out.errors += errors
    out.contents = summarize_contents(jar)
    out.contents.disguised_files, errors = find_disguised_files(jar)
    out.errors += errors

    evidence = ClassEvidence()
    out.classes, errors = scan_classes(jar, evidence.add, should_cancel)
    out.errors += errors

    out.loader, out.loader_evidence = detect_loader(
        out.mods, out.manifest, out.classes.total > 0, evidence.references_minecraft)

    ctx = RuleContext(jar.limits, out.contents, out.manifest, out.mods, out.classes,
                      evidence, hash_lookup, {i.filename for i in jar.infos})
    out.findings, errors = run_rules(ctx)
    out.errors += errors

    for entry in out.contents.nested_jars:
        if should_cancel():
            out.errors.append("Analysis cancelled before all bundled JARs were analyzed.")
            break
        _analyze_nested(jar, entry, hash_db, should_cancel, out)
    return out


def _analyze_nested(parent: SafeJar, entry: str, hash_db: HashDatabase,
                    should_cancel: CancelCheck, out: _JarAnalysis) -> None:
    """Analyze a JAR stored inside `parent` and merge its results into `out`."""
    info = NestedJarInfo(path=entry)
    out.nested.append(info)
    try:
        data = parent.read(entry)
    except EntryReadError as exc:
        info.error = str(exc)
        out.errors.append(f"Bundled JAR {entry}: {exc}")
        return
    info.size_bytes = len(data)
    info.sha256 = sha256_bytes(data)
    lookup = hash_db.lookup(info.sha256)
    info.hash_classification = lookup.classification
    try:
        nested_jar = SafeJar.open_nested(data, entry, parent)
    except JarError as exc:
        info.error = str(exc)
        out.errors.append(f"Bundled JAR {entry}: {exc}")
        return
    del data  # free the raw bytes; the nested SafeJar keeps its own copy

    with nested_jar:
        sub = _analyze_jar(nested_jar, lookup, hash_db, should_cancel)

    info.loader = sub.loader
    info.mod_ids = [m.mod_id for m in sub.mods if m.mod_id and m.nested_in is None]
    for mod in sub.mods:
        mod.nested_in = f"{entry}!/{mod.nested_in}" if mod.nested_in else entry
    out.mods.extend(sub.mods)
    # Only REVIEW/WARNING findings from bundled JARs are merged; their INFO
    # findings ("metadata detected", "uses reflection"...) would just be noise.
    for finding in sub.findings:
        if finding.severity != Severity.INFO:
            finding.location = f"{entry} → {finding.location}"
            out.findings.append(finding)
    for deeper in sub.nested:
        deeper.path = f"{entry}!/{deeper.path}"
        out.nested.append(deeper)
    out.errors += [f"Bundled JAR {entry}: {e}" for e in sub.errors]


def analyze_file(path: str | Path, hash_db: HashDatabase | None = None,
                 limits: Limits = DEFAULT_LIMITS,
                 should_cancel: CancelCheck = lambda: False) -> AnalysisResult:
    """Analyze one JAR file. Never raises for bad input; problems go into result.errors."""
    path = Path(path)
    if hash_db is None:
        hash_db, _ = load_hash_database()
    # Only the file NAME is stored - never the full path, which can contain the
    # analyst's username (e.g. C:\Users\alice\...).
    result = AnalysisResult(APP_NAME, VERSION, _now(), FileInfo(name=safe_text(path.name, 300)))
    try:
        _run(path, result, hash_db, limits, should_cancel)
    except Exception as exc:  # noqa: BLE001 - last-resort safety net for a batch/GUI
        result.errors.append(f"Unexpected internal error: {exc!r}")
    return result


def _run(path: Path, result: AnalysisResult, hash_db: HashDatabase,
         limits: Limits, should_cancel: CancelCheck) -> None:
    # 1. File info
    try:
        st = path.stat()
    except OSError as exc:
        result.errors.append(f"Cannot access file: {exc.strerror or exc}")
        return
    if not path.is_file():
        result.errors.append("Not a regular file.")
        return
    result.file.size_bytes = st.st_size
    result.file.modified = datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds")
    try:
        with open(path, "rb") as f:
            result.file.file_type = detect_file_type(f.read(8))
    except OSError as exc:
        result.errors.append(f"Cannot read file: {exc.strerror or exc}")
        return

    # 2-3. Hash + database lookup (done even for files too big to analyze).
    try:
        result.file.sha256 = sha256_file(path)
    except OSError as exc:
        result.errors.append(f"Could not hash file: {exc.strerror or exc}")
    result.hash_lookup = hash_db.lookup(result.file.sha256)

    # 4. Open archive
    try:
        jar = SafeJar.open(path, limits)
    except JarError as exc:
        result.errors.append(str(exc))
        # Still report the hash-database verdict for files we could not open.
        ctx = RuleContext(limits, ContentsSummary(), ManifestInfo(), [], ClassSummary(),
                          ClassEvidence(), result.hash_lookup, set())
        result.findings = rule_hash_database(ctx)
        return
    result.file.is_valid_jar = True

    # 5-11.
    with jar:
        a = _analyze_jar(jar, result.hash_lookup, hash_db, should_cancel)
    result.manifest = a.manifest
    result.mods = a.mods
    result.contents = a.contents
    result.classes = a.classes
    result.loader = a.loader
    result.loader_evidence = a.loader_evidence
    result.nested_jars = a.nested
    result.findings = sorted(a.findings, key=lambda f: SEVERITY_SORT[f.severity])
    result.errors += a.errors


def collect_jars(folder: str | Path, recursive: bool = False) -> list[Path]:
    """Find .jar files in a folder (case-insensitive), sorted by name.
    Symbolic links to folders are not followed."""
    folder = Path(folder)
    found: list[Path] = []
    if recursive:
        for root, _dirs, files in os.walk(folder, followlinks=False):
            found += [Path(root) / f for f in files if f.lower().endswith(".jar")]
    else:
        found = [p for p in folder.iterdir() if p.is_file() and p.name.lower().endswith(".jar")]
    return sorted(found, key=lambda p: str(p).lower())


def analyze_files(paths: list[Path], hash_db: HashDatabase | None = None,
                  limits: Limits = DEFAULT_LIMITS, should_cancel: CancelCheck = lambda: False,
                  progress: ProgressCallback | None = None) -> list[AnalysisResult]:
    """Analyze several files, then run cross-file checks (duplicate mod IDs)."""
    if hash_db is None:
        hash_db, _ = load_hash_database()
    results = []
    for i, path in enumerate(paths):
        if should_cancel():
            break
        if progress:
            progress(i, len(paths), Path(path).name)
        results.append(analyze_file(path, hash_db, limits, should_cancel))
    if progress:
        progress(len(results), len(paths), "")
    add_batch_findings(results)
    return results
