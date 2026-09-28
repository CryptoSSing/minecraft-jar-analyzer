"""Locate bundled files (hash database, icon) in development AND in the .exe.

When running from source, files live next to the code. A PyInstaller one-file
.exe is different: at startup it unpacks itself into a temporary folder and
stores that folder's path in `sys._MEIPASS`. Bundled read-only files are there.

The hash database is special: staff should be able to update it without
rebuilding the .exe. So we first look for `database/hashes.json` next to the
.exe (a user-editable copy) and only fall back to the bundled copy.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def is_frozen() -> bool:
    """True when running inside a PyInstaller-built executable."""
    return getattr(sys, "frozen", False)


def bundle_dir() -> Path:
    """Folder containing read-only bundled files."""
    return Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))


def app_dir() -> Path:
    """Folder containing the .exe (or the project root when running from source)."""
    return Path(sys.executable).resolve().parent if is_frozen() else PROJECT_ROOT


def hash_database_path() -> Path:
    user_copy = app_dir() / "database" / "hashes.json"
    if user_copy.is_file():
        return user_copy
    return bundle_dir() / "database" / "hashes.json"


def asset_path(name: str) -> Path:
    return bundle_dir() / "assets" / name
