# PyInstaller build specification for Minecraft JAR Analyzer.
#
# Build ON WINDOWS from the project root with:
#     pyinstaller --noconfirm --clean packaging\Minecraft-JAR-Analyzer.spec
# (build_windows.bat does this for you.)
#
# Output: dist\Minecraft-JAR-Analyzer.exe - a single self-contained file.
# PyInstaller bundles the Python interpreter, PySide6/Qt and our code, so the
# target PC needs no Python, pip, Java or packages.
#
# A .spec file is Python code that PyInstaller runs. SPECPATH is provided by
# PyInstaller and points at this folder (packaging/).

import os

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

# Qt Python modules we never use. Excluding them keeps the .exe smaller.
# Note: Qt may still bundle some native libraries (e.g. the QtNetwork DLL) as
# dependencies of other Qt components. That is harmless: a library does
# nothing unless code imports it, and tests/test_safety.py guarantees that our
# code never imports QtNetwork or any other networking module.
QT_EXCLUDES = [
    "PySide6.QtNetwork",
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets",
    "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtXml",
    "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtSvg", "PySide6.QtSvgWidgets",
    "PySide6.QtPrintSupport", "PySide6.QtConcurrent", "PySide6.QtDBus",
    "PySide6.QtMultimedia", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
    "PySide6.Qt3DCore", "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets", "PySide6.QtHelp", "PySide6.QtDesigner",
    "PySide6.QtUiTools",
]
PY_EXCLUDES = ["tkinter", "unittest", "pytest", "pydoc", "tests", "tools"]

a = Analysis(
    [os.path.join(ROOT, "main.py")],
    pathex=[ROOT],
    binaries=[],
    # (source, destination folder inside the bundle). resources.py finds them
    # at runtime through sys._MEIPASS.
    datas=[
        (os.path.join(ROOT, "database", "hashes.json"), "database"),
        (os.path.join(ROOT, "assets", "icon.png"), "assets"),
        (os.path.join(ROOT, "assets", "icon.ico"), "assets"),
        (os.path.join(ROOT, "LICENSE"), "."),
    ],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=QT_EXCLUDES + PY_EXCLUDES,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Minecraft-JAR-Analyzer",
    icon=os.path.join(ROOT, "assets", "icon.ico"),
    version=os.path.join(ROOT, "packaging", "version_info.txt"),
    console=False,          # windowed GUI app: no black console window
    disable_windowed_traceback=False,
    debug=False,
    strip=False,
    # UPX compression is OFF on purpose: UPX-packed executables are flagged by
    # antivirus products far more often, which would be ironic for this tool.
    upx=False,
    runtime_tmpdir=None,
)
