"""Shared pytest fixtures.

All test JARs are generated here with Python's zipfile module inside pytest's
temporary directory. They are data only - nothing is ever executed.
"""

import sys
import zipfile
from pathlib import Path

import pytest

# Make the project root importable when running `pytest` from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def build_jar(path: Path, files: dict[str, bytes | str],
              compression: int = zipfile.ZIP_DEFLATED) -> Path:
    """Write a ZIP/JAR at `path` containing `files` (name -> content)."""
    with zipfile.ZipFile(path, "w", compression=compression) as zf:
        for name, content in files.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(name, content)
    return path


def jar_bytes(files: dict[str, bytes | str]) -> bytes:
    """Build a JAR in memory and return its bytes (for nesting tests)."""
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content.encode() if isinstance(content, str) else content)
    return buf.getvalue()


@pytest.fixture
def make_jar(tmp_path):
    """Fixture: make_jar({"a.txt": "hi"}, name="x.jar") -> Path"""
    def _make(files: dict[str, bytes | str], name: str = "test.jar", **kwargs) -> Path:
        return build_jar(tmp_path / name, files, **kwargs)
    return _make
