"""Add, update, remove or list entries in the hash database.

Examples (run from the project folder):

    python -m tools.add_hash mods/sodium.jar --classification VERIFIED --source "Official Modrinth page"
    python -m tools.add_hash --sha256 3f5a...e9 --classification SUSPICIOUS --notes "Ticket #42"
    python -m tools.add_hash --remove 3f5a...e9
    python -m tools.add_hash --list

When given a JAR, the name and version are filled in from its metadata unless
you pass --name/--version. The JAR is only hashed and read - never executed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.hash_database import HashDatabase, HashDatabaseError  # noqa: E402
from analyzer.hashing import sha256_file  # noqa: E402
from analyzer.jar import JarError, SafeJar  # noqa: E402
from analyzer.manifest import read_manifest  # noqa: E402
from analyzer.metadata import read_metadata  # noqa: E402
from analyzer.models import HashClassification  # noqa: E402
from analyzer.resources import PROJECT_ROOT  # noqa: E402

DEFAULT_DB = PROJECT_ROOT / "database" / "hashes.json"


def guess_name_version(path: Path) -> tuple[str, str]:
    try:
        with SafeJar.open(path) as jar:
            manifest, _ = read_manifest(jar)
            mods, _ = read_metadata(jar, manifest)
    except JarError:
        return path.stem, ""
    for mod in mods:
        if mod.name or mod.mod_id:
            return mod.name or mod.mod_id or path.stem, mod.version or ""
    return path.stem, manifest.attributes.get("Implementation-Version", "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage the Minecraft JAR Analyzer hash database.")
    parser.add_argument("jars", nargs="*", type=Path, help="JAR file(s) to hash and add")
    parser.add_argument("--sha256", help="add a hash directly instead of hashing a file")
    parser.add_argument("--classification", type=str.upper,
                        choices=[c.value for c in HashClassification], help="VERIFIED, SUSPICIOUS or UNKNOWN")
    parser.add_argument("--name", default=None)
    parser.add_argument("--version", default=None)
    parser.add_argument("--source", default="", help="where the file came from")
    parser.add_argument("--notes", default="")
    parser.add_argument("--remove", metavar="SHA256", help="remove an entry")
    parser.add_argument("--list", action="store_true", help="list all entries")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"database file (default: {DEFAULT_DB})")
    args = parser.parse_args(argv)

    try:
        db = HashDatabase.load(args.db) if args.db.exists() else HashDatabase(path=args.db)
    except HashDatabaseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for warning in db.warnings:
        print(f"Warning: {warning}", file=sys.stderr)

    if args.list:
        for sha, entry in db.entries.items():
            print(f"{sha}  {entry['classification']:<10}  {entry.get('name', '')} {entry.get('version', '')}")
        print(f"{len(db.entries)} entr{'y' if len(db.entries) == 1 else 'ies'}")
        return 0

    if args.remove:
        if not db.remove_entry(args.remove):
            print("No such entry.", file=sys.stderr)
            return 1
        db.save()
        print(f"Removed {args.remove}")
        return 0

    if not args.classification or not (args.jars or args.sha256):
        parser.error("give JAR file(s) or --sha256, plus --classification")

    targets: list[tuple[str, str, str]] = []
    if args.sha256:
        targets.append((args.sha256, args.name or "", args.version or ""))
    for jar in args.jars:
        if not jar.is_file():
            print(f"Error: not a file: {jar}", file=sys.stderr)
            return 1
        name, version = guess_name_version(jar)
        targets.append((sha256_file(jar), args.name or name, args.version or version))

    for sha, name, version in targets:
        try:
            sha = db.set_entry(sha, HashClassification(args.classification), name, version, args.source, args.notes)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"{args.classification:<10} {sha}  {name} {version}")
    db.save()
    print(f"Saved {db.path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
