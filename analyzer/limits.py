"""Safety limits for analyzing untrusted JAR files.

Why limits matter: a JAR is just a ZIP file, and a ZIP file can lie. A 40 KB
"zip bomb" can claim to hold a few small files but expand to many gigabytes
when decompressed. Without limits, analyzing such a file would exhaust memory
and freeze or crash the program - which is itself a successful attack.

Every limit lives in this one dataclass so it is easy to review and adjust.
Functions receive a `Limits` object as a parameter instead of reading global
constants; that lets the tests pass tiny limits (e.g. 1 KB) and exercise the
protection logic with tiny fixture files.
"""

from dataclasses import dataclass

KB = 1024
MB = 1024 * KB


@dataclass(frozen=True)  # frozen = read-only after creation
class Limits:
    # Files larger than this are refused before we even open them.
    max_jar_size: int = 256 * MB
    # Archives with more entries than this are refused.
    max_entries: int = 50_000
    # We never decompress more than this from a single entry.
    max_entry_size: int = 32 * MB
    # Total decompressed bytes processed per top-level JAR (shared with any
    # nested JARs inside it, so nesting cannot multiply the budget).
    max_total_decompressed: int = 512 * MB
    # Metadata files (fabric.mod.json, mods.toml, MANIFEST.MF...) are a few KB
    # in real mods; anything bigger than this is not parsed.
    max_metadata_size: int = 1 * MB
    # An entry is reported when it decompresses to more than `suspicious_ratio`
    # times its compressed size AND is at least `suspicious_ratio_min_size`.
    suspicious_ratio: float = 100.0
    suspicious_ratio_min_size: int = 1 * MB
    # Entries at least this big are listed as "unusually large".
    large_file_threshold: int = 5 * MB
    # Each indicator rule reports at most this many individual findings;
    # extra matches are summarised in one additional finding.
    max_findings_per_rule: int = 50
    # JAR-in-JAR depth: 0 = the selected file, 1 = a JAR inside it, ...
    max_nesting_depth: int = 2
    # Allowed central-directory bytes per permitted entry (see jar.py).
    # Real entries need ~100-200 bytes; this blocks a directory stuffed with
    # millions of tiny fake entries that would exhaust memory while parsing.
    central_directory_bytes_per_entry: int = 512


DEFAULT_LIMITS = Limits()
