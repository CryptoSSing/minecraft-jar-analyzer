"""SHA-256 hashing.

A cryptographic hash is a fixed-length "fingerprint" of a file's bytes. If even
one bit of the file changes, the SHA-256 changes completely. That makes it a
reliable way to recognise an *exact* file you have seen before - which is how
the hash database works. (It cannot recognise a slightly modified copy.)

We read the file in 1 MB chunks rather than all at once, so hashing a 200 MB
file uses about 1 MB of memory instead of 200 MB.
"""

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: str | Path) -> str:
    """Return the lowercase hex SHA-256 of a file on disk."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of in-memory bytes (used for nested JARs)."""
    return hashlib.sha256(data).hexdigest()
