"""Local SHA-256 hash database (database/hashes.json).

File format:

    {
      "schema_version": 1,
      "updated": "2026-09-28",
      "entries": {
        "<64 lowercase hex characters>": {
          "classification": "VERIFIED" | "SUSPICIOUS" | "UNKNOWN",
          "name": "Example Mod",
          "version": "1.2.0",
          "source": "Official Modrinth page",
          "notes": "",
          "added": "2026-09-28"
        }
      }
    }

A hash that is not listed is reported as UNKNOWN, which simply means "we have
no record of this exact file" - it is NOT a sign of malice. Most legitimate
mods will be UNKNOWN until someone adds them.

The database itself is treated carefully too: it is size-limited, validated,
and a broken file produces a clear error while analysis continues without it.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .models import HashClassification, HashLookup
from .sanitize import safe_text

SCHEMA_VERSION = 1
MAX_DB_SIZE = 50 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class HashDatabaseError(Exception):
    """The database file could not be loaded. Message is user-friendly."""


def normalize_sha256(value: str) -> str | None:
    value = value.strip().lower()
    return value if _SHA256_RE.match(value) else None


@dataclass
class HashDatabase:
    entries: dict[str, dict] = field(default_factory=dict)
    path: Path | None = None
    updated: str | None = None
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> HashDatabase:
        path = Path(path)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise HashDatabaseError(f"Hash database not found or unreadable: {path} ({exc.strerror})") from exc
        if size > MAX_DB_SIZE:
            raise HashDatabaseError(f"Hash database is larger than {MAX_DB_SIZE:,} bytes; not loaded.")
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise HashDatabaseError(f"Hash database is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise HashDatabaseError("Hash database must be a JSON object.")
        if data.get("schema_version") != SCHEMA_VERSION:
            raise HashDatabaseError(
                f"Unsupported hash database schema_version {data.get('schema_version')!r} "
                f"(expected {SCHEMA_VERSION})."
            )
        raw_entries = data.get("entries", {})
        if not isinstance(raw_entries, dict):
            raise HashDatabaseError("'entries' must be a JSON object keyed by SHA-256.")

        db = cls(path=path, updated=data.get("updated") if isinstance(data.get("updated"), str) else None)
        valid_classes = {c.value for c in HashClassification}
        for key, entry in raw_entries.items():
            sha = normalize_sha256(key) if isinstance(key, str) else None
            if sha is None:
                db.warnings.append(f"Skipped invalid hash key: {safe_text(key, 80)}")
                continue
            if not isinstance(entry, dict):
                db.warnings.append(f"Skipped {sha[:12]}…: entry is not an object")
                continue
            classification = str(entry.get("classification", "")).upper()
            if classification not in valid_classes:
                db.warnings.append(f"Skipped {sha[:12]}…: invalid classification {safe_text(classification, 40)!r}")
                continue
            db.entries[sha] = {**entry, "classification": classification}
        return db

    def lookup(self, sha256: str | None) -> HashLookup:
        sha = normalize_sha256(sha256) if sha256 else None
        entry = self.entries.get(sha) if sha else None
        if entry is None:
            return HashLookup(classification=HashClassification.UNKNOWN)

        def text(key: str) -> str | None:
            value = entry.get(key)
            return safe_text(value, 500) if isinstance(value, (str, int, float)) and value != "" else None

        return HashLookup(
            classification=HashClassification(entry["classification"]),
            name=text("name"),
            version=text("version"),
            source=text("source"),
            notes=text("notes"),
        )

    # ---------- editing (used by tools/add_hash.py) ----------

    def set_entry(self, sha256: str, classification: HashClassification, name: str = "",
                  version: str = "", source: str = "", notes: str = "") -> str:
        sha = normalize_sha256(sha256)
        if sha is None:
            raise ValueError(f"Not a valid SHA-256: {sha256!r}")
        self.entries[sha] = {
            "classification": HashClassification(classification).value,
            "name": name, "version": version, "source": source, "notes": notes,
            "added": date.today().isoformat(),
        }
        return sha

    def remove_entry(self, sha256: str) -> bool:
        sha = normalize_sha256(sha256)
        return self.entries.pop(sha, None) is not None if sha else False

    def save(self, path: str | Path | None = None) -> Path:
        """Write atomically: to a temp file first, then rename over the original.
        A crash mid-write can therefore never leave a half-written database."""
        path = Path(path or self.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "schema_version": SCHEMA_VERSION,
            "updated": date.today().isoformat(),
            "entries": dict(sorted(self.entries.items())),
        }
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self.path = path
        return path
