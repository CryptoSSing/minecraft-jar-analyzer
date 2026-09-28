"""GUI smoke tests. Qt runs "offscreen" so no window appears."""

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import Qt  # noqa: E402

from analyzer.hash_database import HashDatabase  # noqa: E402
from analyzer.pipeline import analyze_files  # noqa: E402
from gui import widgets  # noqa: E402
from gui.app import MainWindow  # noqa: E402
from tests.classbuilder import build_class  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture
def window(app):
    w = MainWindow()
    yield w
    w.close()


HTML_NAME = '<b>Bold</b><img src="http://example.com/x.png">'


@pytest.fixture
def jars(make_jar):
    evil = make_jar({"fabric.mod.json": '{"id": "x", "name": "%s", "version": "1"}' % HTML_NAME.replace('"', '\\"'),
                     "a/B.class": build_class("a/B", strings=["https://discord.com/api/webhooks/1/x"])},
                    name="evil.jar")
    good = make_jar({"fabric.mod.json": '{"id": "good", "version": "1"}'}, name="good.jar")
    return [evil, good]


def test_window_builds_and_adds_files(window, jars):
    assert not window.btn_analyze.isEnabled()
    window.add_paths(jars + jars)  # duplicates ignored
    assert window.file_panel.count_label.text() == "Selected files: 2"
    assert window.btn_analyze.isEnabled() and not window.btn_json.isEnabled()


def test_results_display_and_plain_text(window, jars):
    results = analyze_files(jars, HashDatabase())
    window.add_paths(jars)
    window.show_results(results)
    assert window.result_list.count() == 2
    assert window.btn_json.isEnabled()
    window.result_list.setCurrentRow(0)
    assert window.findings.table.rowCount() == len(results[0].findings)
    assert window.findings.table.item(0, 0).text().endswith("WARNING")
    # The HTML mod name is shown literally, never rendered.
    mod_label = window.overview.values["Mod"]
    assert mod_label.textFormat() == Qt.TextFormat.PlainText
    assert "<b>Bold</b>" in mod_label.text()
    for label in window.findChildren(QtWidgets.QLabel):
        assert label.textFormat() == Qt.TextFormat.PlainText, label.text()


def test_background_analysis_thread(window, jars, app):
    window.add_paths(jars)
    window.start_analysis()
    assert window.btn_cancel.isEnabled()
    deadline = time.time() + 20
    while window.is_running() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert not window.is_running()
    assert len(window.results) == 2
    assert window.progress.format().startswith("Done")


def test_export_refuses_to_overwrite_input(window, make_jar, monkeypatch):
    # Inputs can be any file ("All files" filter), e.g. a JAR named report.txt.
    victim = make_jar({"a.txt": "x"}, name="report.txt")
    window.add_paths([victim])
    window.show_results(analyze_files([victim], HashDatabase()))
    before = victim.read_bytes()
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", lambda *a, **k: (str(victim), ""))
    shown = []
    monkeypatch.setattr(widgets.QMessageBox, "exec", lambda self: shown.append(self.text()))
    window.export("txt")
    assert victim.read_bytes() == before
    assert shown and "analyzed JARs" in shown[0]


def test_export_writes_report(window, jars, tmp_path, monkeypatch):
    window.add_paths(jars)
    window.show_results(analyze_files(jars, HashDatabase()))
    out = tmp_path / "report"
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), ""))
    window.export("txt")
    assert (tmp_path / "report.txt").read_text(encoding="utf-8").startswith("=")
