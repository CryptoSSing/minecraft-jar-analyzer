"""Export analysis results as JSON (for tools) or TXT (for people).

Both formats contain the full result: analyzer version, timestamps, file
information, SHA-256, hash-database result, manifest, mod metadata, contents
summary, class summary, bundled JARs, findings and errors.

Privacy: reports contain only the analyzed file's NAME, never its full path
(which could include the analyst's username), and no information about the
computer running the analysis.

Safety: every value that came from a JAR passes through safe_text() before
going into the TXT report, so control characters / ANSI escape codes cannot
mess with a terminal when someone views the report with `type` or `cat`.
The json module escapes control characters by itself.
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from analyzer.models import (SEVERITY_MEANING, AnalysisResult, Finding,
                             HashClassification, Severity)
from analyzer.sanitize import safe_text
from analyzer.version import APP_NAME, VERSION

DISCLAIMER = (
    "This report lists static indicators for manual review by authorized staff. "
    "Static analysis cannot prove that a file is malicious, and it cannot prove that a file is safe. "
    "Findings are evidence to investigate, not verdicts."
)

SEVERITY_SYMBOL = {Severity.WARNING: "⚠", Severity.REVIEW: "◆", Severity.INFO: "ℹ"}
# "ℹ INFO = informational   ◆ REVIEW = inspect this behavior   ⚠ WARNING = strong security concern"
SEVERITY_LEGEND = "    ".join(f"{SEVERITY_SYMBOL[s]} {s.value} = {SEVERITY_MEANING[s]}"
                               for s in (Severity.INFO, Severity.REVIEW, Severity.WARNING))
POSITIVE_RULES = {"metadata.detected", "hash.verified"}

HASH_EXPLANATION = {
    HashClassification.VERIFIED: "this exact file was previously checked and marked as trusted",
    HashClassification.SUSPICIOUS: "this exact file was previously flagged as suspicious",
    HashClassification.UNKNOWN: "not in the local database - this is NOT an indication of malice",
}


def severity_symbol(finding: Finding) -> str:
    return "✓" if finding.rule_id in POSITIVE_RULES else SEVERITY_SYMBOL[finding.severity]


def confidence_label(finding: Finding) -> str:
    """INFO findings are facts, not concerns, so they show no confidence level."""
    return "—" if finding.severity == Severity.INFO else finding.confidence.value


def summary_sentence(result: AnalysisResult) -> str:
    """One neutral sentence summarising a result (used by the GUI too)."""
    if not result.file.is_valid_jar:
        return "The file could not be analyzed as a JAR. See the errors for details."
    counts = result.severity_counts()
    warnings, reviews = counts["WARNING"], counts["REVIEW"]
    if warnings:
        return (f"{warnings} warning(s) and {reviews} item(s) to review. "
                "Look at these closely before trusting this file.")
    if reviews:
        return f"{reviews} item(s) need manual review."
    return "No indicators requiring review were found. This does not guarantee the file is safe."


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def to_json(results: list[AnalysisResult]) -> str:
    report = {
        "report": {
            "generator": APP_NAME,
            "version": VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "file_count": len(results),
            "disclaimer": DISCLAIMER,
        },
        "results": [r.to_dict() | {"summary": summary_sentence(r)} for r in results],
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# TXT
# ---------------------------------------------------------------------------

WIDTH = 78


def _wrap(text: str, indent: str) -> list[str]:
    lines = []
    for paragraph in safe_text(text, 5000, allow_newlines=True).split("\n"):
        lines += textwrap.wrap(paragraph, WIDTH, initial_indent=indent, subsequent_indent=indent) or [indent]
    return lines


def _field(label: str, value: object, width: int = 16) -> str:
    return f"  {label + ':':<{width}}{safe_text(value if value not in (None, '') else '-', 2000)}"


def _result_to_text(r: AnalysisResult, index: int, total: int) -> list[str]:
    L: list[str] = []
    L.append(f"[{index}/{total}] {safe_text(r.file.name)}")
    L.append("-" * WIDTH)
    counts = r.severity_counts()
    L.append(f"Summary: {counts['WARNING']} WARNING, {counts['REVIEW']} REVIEW, {counts['INFO']} INFO")
    L += _wrap(summary_sentence(r), "  ")
    L.append("")

    L.append("FILE")
    L.append(_field("Name", r.file.name))
    L.append(_field("Size", f"{r.file.size_bytes:,} bytes"))
    L.append(_field("SHA-256", r.file.sha256))
    L.append(_field("Modified (UTC)", r.file.modified))
    L.append(_field("Detected type", r.file.file_type))
    L.append(_field("Valid JAR", "yes" if r.file.is_valid_jar else "no"))
    L.append(_field("Analyzed (UTC)", r.analyzed_at))
    L.append("")

    h = r.hash_lookup
    L.append("HASH DATABASE")
    L.append(_field("Classification", f"{h.classification.value} ({HASH_EXPLANATION[h.classification]})"))
    for label, value in (("Name", h.name), ("Version", h.version), ("Source", h.source), ("Notes", h.notes)):
        if value:
            L.append(_field(label, value))
    L.append("")

    L.append("MOD METADATA")
    L.append(_field("Loader", r.loader))
    for ev in r.loader_evidence:
        L.append(f"    - {safe_text(ev)}")
    for m in r.mods:
        origin = f" (inside {m.nested_in})" if m.nested_in else ""
        L.append(f"  * {safe_text(m.name or m.mod_id or '(unnamed)')} [{m.loader}, {m.source_file}]{origin}")
        L.append(_field("  Mod ID", m.mod_id, 18))
        L.append(_field("  Version", m.version, 18))
        if m.authors:
            L.append(_field("  Authors", ", ".join(m.authors), 18))
        if m.minecraft_version:
            L.append(_field("  Minecraft", m.minecraft_version, 18))
        if m.loader_version:
            L.append(_field("  Loader version", m.loader_version, 18))
        if m.dependencies:
            deps = ", ".join(f"{k} {v}" for k, v in m.dependencies.items())
            L.append(_field("  Dependencies", deps, 18))
        for key, value in m.extra.items():
            L.append(_field(f"  {key}", value, 18))
        if m.description:
            L.append("    Description:")
            L += _wrap(m.description, "      ")
    if not r.mods:
        L.append("  (no mod/plugin descriptor found)")
    L.append("")

    L.append("MANIFEST (META-INF/MANIFEST.MF)")
    if r.manifest.present and r.manifest.attributes:
        for key, value in r.manifest.attributes.items():
            L.append(_field(key, value, 26))
    else:
        L.append("  (not present)")
    L.append("")

    c = r.contents
    L.append("CONTENTS")
    L.append(_field("Entries", f"{c.total_entries:,} ({c.total_files:,} files, {c.directories:,} folders)", 22))
    L.append(_field("Declared size", f"{c.declared_uncompressed_bytes:,} bytes uncompressed", 22))
    if c.by_extension:
        exts = ", ".join(f"{ext} {n}" for ext, n in list(c.by_extension.items())[:15])
        L.append(_field("By extension", exts, 22))
    for label, items in (("Native libraries", c.native_libraries),
                         ("Executables/scripts", c.executables_and_scripts),
                         ("Disguised files", c.disguised_files),
                         ("Bundled JARs", c.nested_jars),
                         ("Unusual files", c.unusual_files),
                         ("Signature files", c.signature_files),
                         ("Encrypted entries", c.encrypted_entries),
                         ("Duplicate names", c.duplicate_names),
                         ("Unsafe names", c.unsafe_names),
                         ("Deceptive names", c.deceptive_names)):
        if items:
            L.append(f"  {label} ({len(items)}):")
            L += [f"    - {safe_text(i)}" for i in items[:50]]
            if len(items) > 50:
                L.append(f"    ... and {len(items) - 50} more")
    for label, entries in (("Large files", c.large_files), ("High compression ratio", c.high_ratio_entries)):
        if entries:
            L.append(f"  {label} ({len(entries)}):")
            L += [f"    - {safe_text(e.path)} ({e.size_bytes:,} bytes, {e.compressed_bytes:,} compressed)"
                  for e in entries[:50]]
    L.append("")

    cs = r.classes
    L.append("CLASSES")
    L.append(_field("Class files", f"{cs.total:,} total, {cs.parsed:,} parsed, "
                                   f"{cs.failed:,} invalid, {cs.skipped:,} skipped", 18))
    if cs.java_versions:
        L.append(_field("Compiled for", ", ".join(f"{k} ({v})" for k, v in cs.java_versions.items()), 18))
    if cs.packages:
        pkgs = ", ".join(f"{safe_text(k, 100)} ({v})" for k, v in list(cs.packages.items())[:10])
        L.append(_field("Top packages", pkgs, 18))
    L.append("")

    if r.nested_jars:
        L.append("BUNDLED JARS")
        for n in r.nested_jars:
            L.append(f"  * {safe_text(n.path)}")
            L.append(_field("  Size", f"{n.size_bytes:,} bytes", 18))
            L.append(_field("  SHA-256", n.sha256, 18))
            L.append(_field("  Hash DB", n.hash_classification.value, 18))
            L.append(_field("  Loader", n.loader, 18))
            if n.mod_ids:
                L.append(_field("  Mod IDs", ", ".join(n.mod_ids), 18))
            if n.error:
                L.append(_field("  Error", n.error, 18))
        L.append("")

    L.append(f"FINDINGS ({len(r.findings)})")
    if not r.findings:
        L.append("  (none)")
    for f in r.findings:
        L.append(f"  {severity_symbol(f)} {f.severity.value:<8}{safe_text(f.title)}")
        L += _wrap(f"Location: {f.location}", "      ")
        L.append(f"      Confidence: {confidence_label(f)}")
        L += _wrap(f"Why it matters: {f.explanation}", "      ")
        if f.context:
            L += _wrap(f"Context found: {f.context}", "      ")
        if f.rationale:
            L += _wrap(f"Why this rating: {f.rationale}", "      ")
        L.append("")

    L.append(f"ERRORS ({len(r.errors)})")
    L += [f"  - {line}" for e in r.errors for line in [safe_text(e, 2000)]] or ["  (none)"]
    L.append("")
    return L


def to_text(results: list[AnalysisResult]) -> str:
    L = ["=" * WIDTH,
         f"{APP_NAME} {VERSION} - Analysis Report",
         f"Generated (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
         f"Files analyzed:  {len(results)}",
         "-" * WIDTH]
    L += textwrap.wrap("IMPORTANT: " + DISCLAIMER, WIDTH)
    L += ["", "Severity levels:"] + [f"  {SEVERITY_SYMBOL[s]} {s.value:<8}{SEVERITY_MEANING[s]}"
                                     for s in (Severity.INFO, Severity.REVIEW, Severity.WARNING)]
    L.append("Confidence: how strongly the evidence shows the behavior is security-significant (INFO: —).")
    L += ["=" * WIDTH, ""]
    for i, r in enumerate(results, 1):
        L += _result_to_text(r, i, len(results))
        L.append("=" * WIDTH)
        L.append("")
    return "\n".join(L)


def write_report(path: str | Path, results: list[AnalysisResult], fmt: str) -> Path:
    """Write a report. `fmt` is "json" or "txt"."""
    path = Path(path)
    if fmt == "json":
        content = to_json(results)
    elif fmt == "txt":
        content = to_text(results)
    else:
        raise ValueError(f"Unknown report format: {fmt}")
    # Text mode turns "\n" into "\r\n" on Windows, which Notepad expects.
    path.write_text(content + "\n", encoding="utf-8")
    return path
