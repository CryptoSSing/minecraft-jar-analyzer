"""Safety guarantees, enforced by tests.

1. Static check: the application source never imports modules that run
   programs, open network connections or deserialize code, and never calls
   eval/exec, extraction or deletion functions. Uses Python's `ast` module to
   read the code's structure, so words inside strings/comments don't count.
2. Runtime check: while analyzing a hostile-looking JAR, any attempt to start
   a process, open a socket or extract files makes the test fail.
3. The analyzed file is never modified.
"""

import ast
import os
import socket
import subprocess
import zipfile
from pathlib import Path

import pytest

from analyzer.hash_database import HashDatabase
from analyzer.hashing import sha256_file
from analyzer.pipeline import analyze_file
from tests.classbuilder import build_class

ROOT = Path(__file__).resolve().parent.parent
APP_SOURCES = [p for d in ("analyzer", "gui", "reports") for p in (ROOT / d).rglob("*.py")] + [ROOT / "main.py"]

FORBIDDEN_MODULES = {
    "subprocess", "socket", "ctypes", "pickle", "marshal", "shelve", "multiprocessing",
    "urllib.request", "http.client", "http.server", "ftplib", "smtplib", "requests",
    "webbrowser", "PySide6.QtNetwork",
}
# Built-ins that run code; only dangerous when called by bare name (re.compile is fine).
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__", "QProcess"}
# Methods that run programs, extract archives or delete files (os.system, zf.extractall...).
FORBIDDEN_METHODS = {"system", "popen", "startfile", "extract", "extractall",
                     "rmtree", "remove", "unlink", "rmdir"}
# The one permitted deletion: the hash database cleaning up ITS OWN temp file
# after a failed save. It never touches analyzed files.
ALLOWED = {("hash_database.py", "unlink")}


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            if any(name == m or name.startswith(m + ".") for m in FORBIDDEN_MODULES):
                found.append(f"{path.name}:{node.lineno} imports {name}")
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
                called = func.id
            elif isinstance(func, ast.Attribute) and func.attr in FORBIDDEN_METHODS:
                called = func.attr
            else:
                continue
            if (path.name, called) not in ALLOWED:
                found.append(f"{path.name}:{node.lineno} calls {called}()")
    return found


def test_sources_found():
    assert len(APP_SOURCES) > 10 and all(p.exists() for p in APP_SOURCES)


@pytest.mark.parametrize("path", APP_SOURCES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_dangerous_code(path):
    assert _violations(path) == []


def test_static_checker_actually_catches_things(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("import subprocess\nfrom socket import socket\neval('1')\nz.extractall()\n"
                   "import re\nre.compile('x')\nfrom PySide6.QtNetwork import QTcpSocket\n")
    assert len(_violations(bad)) == 5  # re.compile is NOT a violation


@pytest.fixture
def hostile_jar(make_jar):
    evil = build_class("x/Evil", strings=["https://discord.com/api/webhooks/1/a", "cmd.exe /c calc"],
                       class_refs=["java/net/URL"], method_refs=[("java/lang/Runtime", "exec")])
    return make_jar({
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nMain-Class: x.Evil\nPremain-Class: x.Evil\n",
        "x/Evil.class": evil,
        "payload.exe": b"MZ" + b"\x00" * 100,
        "run.bat": "@echo off\ncalc.exe",
    })


def test_analysis_never_executes_connects_or_extracts(hostile_jar, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("analyzer attempted a forbidden operation")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    if hasattr(os, "startfile"):
        monkeypatch.setattr(os, "startfile", forbidden)

    result = analyze_file(hostile_jar, HashDatabase())
    assert result.errors == []  # an AssertionError would surface here as an internal error
    assert result.findings


def test_analyzed_file_is_not_modified(hostile_jar):
    before = (sha256_file(hostile_jar), os.stat(hostile_jar).st_mtime_ns, os.stat(hostile_jar).st_size)
    analyze_file(hostile_jar, HashDatabase())
    after = (sha256_file(hostile_jar), os.stat(hostile_jar).st_mtime_ns, os.stat(hostile_jar).st_size)
    assert before == after


def test_nothing_written_next_to_analyzed_file(hostile_jar):
    before = set(hostile_jar.parent.iterdir())
    analyze_file(hostile_jar, HashDatabase())
    assert set(hostile_jar.parent.iterdir()) == before
