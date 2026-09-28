"""Command-line runner: `python -m analyzer <jar or folder> ...`

Useful for learning, debugging and scripting without the GUI. Examples:

    python -m analyzer mods/example.jar
    python -m analyzer mods/ --recursive --json report.json --txt report.txt
    python -m analyzer mods/example.jar --quiet --json report.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reports.exporter import to_text, write_report

from .pipeline import analyze_files, collect_jars, load_hash_database
from .version import APP_NAME, VERSION


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m analyzer",
                                     description=f"{APP_NAME} {VERSION} - static analysis of JAR files. "
                                                 "Files are never executed.")
    parser.add_argument("paths", nargs="+", type=Path, help="JAR files and/or folders containing JARs")
    parser.add_argument("-r", "--recursive", action="store_true", help="search folders recursively")
    parser.add_argument("--json", type=Path, metavar="FILE", help="write a JSON report")
    parser.add_argument("--txt", type=Path, metavar="FILE", help="write a TXT report")
    parser.add_argument("--db", type=Path, metavar="FILE", help="hash database to use")
    parser.add_argument("-q", "--quiet", action="store_true", help="don't print the report")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    args = parser.parse_args(argv)

    # Windows consoles may not support every character; never crash on printing.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    files: list[Path] = []
    for p in args.paths:
        if p.is_dir():
            files += collect_jars(p, args.recursive)
        elif p.is_file():
            files.append(p)
        else:
            print(f"Error: not found: {p}", file=sys.stderr)
            return 1
    if not files:
        print("No JAR files found.", file=sys.stderr)
        return 1

    db, messages = load_hash_database(args.db)
    for m in messages:
        print(m, file=sys.stderr)

    def progress(i: int, total: int, name: str) -> None:
        if name:
            print(f"Analyzing {i + 1}/{total}: {name}", file=sys.stderr)

    results = analyze_files(files, db, progress=progress)

    if not args.quiet:
        print(to_text(results))
    for path, fmt in ((args.json, "json"), (args.txt, "txt")):
        if path:
            write_report(path, results, fmt)
            print(f"Wrote {fmt.upper()} report: {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
