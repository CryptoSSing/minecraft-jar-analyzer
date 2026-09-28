"""Minecraft JAR Analyzer - application entry point.

Run from source:   python main.py
PyInstaller uses this file as the entry point for the Windows .exe.
"""

import sys


def main() -> int:
    from gui.app import run
    return run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
