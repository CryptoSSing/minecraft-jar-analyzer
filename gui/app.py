"""Main window of Minecraft JAR Analyzer.

Layout (top to bottom):
  title  ->  file selection  ->  Analyze + progress  ->  results  ->  export
The results area is split: analyzed files on the left, details on the right
(tabs: Overview, Findings, Contents, Metadata, Errors).
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence
from PySide6.QtWidgets import (QApplication, QCheckBox, QFileDialog,
                               QHBoxLayout, QListWidget, QListWidgetItem,
                               QMainWindow, QMessageBox, QPlainTextEdit,
                               QProgressBar, QPushButton, QSplitter,
                               QTabWidget, QVBoxLayout, QWidget)

from analyzer.models import AnalysisResult
from analyzer.pipeline import collect_jars, load_hash_database
from analyzer.resources import asset_path, hash_database_path
from analyzer.sanitize import safe_text
from analyzer.version import APP_NAME, PUBLISHER, VERSION
from reports.exporter import DISCLAIMER, SEVERITY_LEGEND, write_report

from . import theme
from .widgets import (FileListPanel, FindingsPanel, OverviewPanel,
                      fill_contents_tree, fill_metadata_tree, make_tree,
                      plain_label, result_color, result_symbol, show_message)
from .worker import AnalysisWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {VERSION}")
        self.resize(1180, 820)
        self.setMinimumSize(900, 640)
        self.setAcceptDrops(True)

        self.selected: list[Path] = []
        self.results: list[AnalysisResult] = []
        self.thread: QThread | None = None
        self.worker: AnalysisWorker | None = None

        self.hash_db, db_messages = load_hash_database()
        self._build_ui()
        self._build_menu()
        db_text = f"Hash database: {len(self.hash_db.entries)} entries ({hash_database_path().name})"
        self.statusBar().showMessage(" · ".join([db_text] + db_messages))
        self._update_buttons()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(18, 14, 18, 10)
        layout.setSpacing(10)

        layout.addWidget(plain_label(APP_NAME, "Title"))
        layout.addWidget(plain_label(
            "Static analysis of Minecraft mod JARs for authorized server staff. Files are never "
            "executed, modified or uploaded. Findings are indicators for review, not verdicts.", "Subtitle"))

        buttons = QHBoxLayout()
        self.btn_jar = QPushButton("Select JAR(s)…")
        self.btn_folder = QPushButton("Select Folder…")
        self.chk_recursive = QCheckBox("Include subfolders")
        self.btn_remove = QPushButton("Remove Selected")
        self.btn_clear = QPushButton("Clear")
        self.btn_jar.clicked.connect(self.choose_jars)
        self.btn_folder.clicked.connect(self.choose_folder)
        self.btn_remove.clicked.connect(self.remove_selected)
        self.btn_clear.clicked.connect(self.clear_selection)
        for w in (self.btn_jar, self.btn_folder, self.chk_recursive):
            buttons.addWidget(w)
        buttons.addStretch()
        buttons.addWidget(self.btn_remove)
        buttons.addWidget(self.btn_clear)
        layout.addLayout(buttons)

        self.file_panel = FileListPanel()
        self.file_panel.list.itemSelectionChanged.connect(self._update_buttons)
        layout.addWidget(self.file_panel)

        run_row = QHBoxLayout()
        self.btn_analyze = QPushButton("Analyze")
        self.btn_analyze.setObjectName("Primary")
        self.btn_analyze.clicked.connect(self.start_analysis)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.cancel_analysis)
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setFormat("Ready")
        self.progress.setValue(0)
        run_row.addWidget(self.btn_analyze)
        run_row.addWidget(self.btn_cancel)
        run_row.addWidget(self.progress, 1)
        layout.addLayout(run_row)

        # Results: analyzed files | detail tabs
        splitter = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(plain_label("Results", "SectionHeader"))
        self.result_list = QListWidget()
        self.result_list.currentRowChanged.connect(self.show_result)
        left_layout.addWidget(self.result_list)
        splitter.addWidget(left)

        self.tabs = QTabWidget()
        self.overview = OverviewPanel()
        self.findings = FindingsPanel()
        self.contents_tree = make_tree()
        self.metadata_tree = make_tree()
        self.errors_view = QPlainTextEdit()
        self.errors_view.setReadOnly(True)
        self.tabs.addTab(self.overview, "Overview")
        self.tabs.addTab(self.findings, "Findings")
        self.tabs.addTab(self.contents_tree, "Contents")
        self.tabs.addTab(self.metadata_tree, "Metadata")
        self.tabs.addTab(self.errors_view, "Errors")
        self.overview.finding_activated.connect(self._jump_to_finding)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([280, 880])
        layout.addWidget(splitter, 1)

        export_row = QHBoxLayout()
        self.btn_json = QPushButton("Export JSON…")
        self.btn_txt = QPushButton("Export TXT…")
        self.btn_json.clicked.connect(lambda: self.export("json"))
        self.btn_txt.clicked.connect(lambda: self.export("txt"))
        export_row.addWidget(self.btn_json)
        export_row.addWidget(self.btn_txt)
        export_row.addStretch()
        legend = plain_label(SEVERITY_LEGEND, "Dim")
        legend.setToolTip("Confidence (Findings tab) says how strongly the evidence shows the behavior is "
                          "security-significant. INFO findings are facts, so they show no confidence (—).")
        legend.setWordWrap(False)
        export_row.addWidget(legend)
        layout.addLayout(export_row)

        self.setCentralWidget(root)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        for text, shortcut, slot in (("Select JAR(s)…", QKeySequence.StandardKey.Open, self.choose_jars),
                                     ("Select Folder…", None, self.choose_folder),
                                     (None, None, None),
                                     ("Export JSON…", None, lambda: self.export("json")),
                                     ("Export TXT…", None, lambda: self.export("txt")),
                                     (None, None, None),
                                     ("Exit", QKeySequence.StandardKey.Quit, self.close)):
            if text is None:
                file_menu.addSeparator()
                continue
            action = QAction(text, self)
            if shortcut:
                action.setShortcut(shortcut)
            action.triggered.connect(slot)
            file_menu.addAction(action)
        help_menu = self.menuBar().addMenu("&Help")
        about = QAction("About", self)
        about.triggered.connect(self.show_about)
        help_menu.addAction(about)

    # ------------------------------------------------------------------ file selection

    def add_paths(self, paths: list[Path]) -> None:
        known = {p.resolve() for p in self.selected}
        for p in paths:
            rp = p.resolve()
            if rp not in known and p.is_file():
                known.add(rp)
                self.selected.append(p)
        self._refresh_file_list()

    def _refresh_file_list(self) -> None:
        self.file_panel.list.clear()
        for p in self.selected:
            item = QListWidgetItem(safe_text(p.name))
            item.setToolTip(safe_text(str(p)))
            self.file_panel.list.addItem(item)
        self.file_panel.count_label.setText(f"Selected files: {len(self.selected)}")
        self._update_buttons()

    def choose_jars(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Select JAR files", "", "JAR files (*.jar);;All files (*)")
        self.add_paths([Path(f) for f in files])

    def choose_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select a folder containing JAR files")
        if not folder:
            return
        try:
            jars = collect_jars(Path(folder), self.chk_recursive.isChecked())
        except OSError as exc:
            show_message(self, QMessageBox.Icon.Warning, "Folder error", f"Could not read folder: {exc}")
            return
        if not jars:
            show_message(self, QMessageBox.Icon.Information, "No JAR files",
                         "No .jar files were found in that folder.")
        self.add_paths(jars)

    def remove_selected(self) -> None:
        rows = sorted((self.file_panel.list.row(i) for i in self.file_panel.list.selectedItems()), reverse=True)
        for row in rows:
            del self.selected[row]
        self._refresh_file_list()

    def clear_selection(self) -> None:
        self.selected.clear()
        self._refresh_file_list()

    # Drag & drop: accept .jar files and folders dropped onto the window.
    def dragEnterEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        if event.mimeData().hasUrls() and not self.is_running():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802
        paths: list[Path] = []
        for url in event.mimeData().urls():
            p = Path(url.toLocalFile())
            if p.is_dir():
                paths += collect_jars(p, self.chk_recursive.isChecked())
            elif p.suffix.lower() == ".jar":
                paths.append(p)
        self.add_paths(paths)

    # ------------------------------------------------------------------ analysis

    def is_running(self) -> bool:
        return self.thread is not None

    def start_analysis(self) -> None:
        if not self.selected or self.is_running():
            return
        self.results = []
        self.result_list.clear()
        self.progress.setRange(0, len(self.selected))
        self.progress.setValue(0)
        self.progress.setFormat("Starting…")

        self.thread = QThread(self)
        self.worker = AnalysisWorker(list(self.selected), self.hash_db)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self._on_thread_done)
        self.thread.start()
        self._update_buttons()

    def cancel_analysis(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.progress.setFormat("Cancelling…")

    def _on_progress(self, done: int, total: int, name: str) -> None:
        self.progress.setValue(done)
        self.progress.setFormat(f"Analyzing {done + 1}/{total}: {safe_text(name, 80)}" if name else "Finishing…")

    def _on_finished(self, results: list[AnalysisResult]) -> None:
        cancelled = self.worker.cancelled if self.worker else False
        self.show_results(results)
        state = "Cancelled" if cancelled else "Done"
        self.progress.setFormat(f"{state} — {len(results)} file(s) analyzed")

    def _on_thread_done(self) -> None:
        if self.worker:
            self.worker.deleteLater()
        if self.thread:
            self.thread.deleteLater()
        self.worker = None
        self.thread = None
        self._update_buttons()

    def show_results(self, results: list[AnalysisResult]) -> None:
        self.results = results
        self.result_list.clear()
        for r in results:
            item = QListWidgetItem(f"{result_symbol(r)}  {safe_text(r.file.name)}")
            item.setForeground(QColor(result_color(r)))
            self.result_list.addItem(item)
        if results:
            self.result_list.setCurrentRow(0)
        self._update_buttons()

    def show_result(self, row: int) -> None:
        if not (0 <= row < len(self.results)):
            return
        r = self.results[row]
        self.overview.show_result(r)
        self.findings.show_result(r)
        fill_contents_tree(self.contents_tree, r)
        fill_metadata_tree(self.metadata_tree, r)
        self.errors_view.setPlainText("\n".join(r.errors) if r.errors else "No errors.")
        self.tabs.setTabText(1, f"Findings ({len(r.findings)})")
        self.tabs.setTabText(4, f"Errors ({len(r.errors)})")

    def _jump_to_finding(self, row: int) -> None:
        self.tabs.setCurrentWidget(self.findings)
        self.findings.select(row)

    # ------------------------------------------------------------------ export

    def export(self, fmt: str) -> None:
        if not self.results:
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        suggested = f"jar-analysis-{stamp}.{fmt}"
        filters = "JSON report (*.json)" if fmt == "json" else "Text report (*.txt)"
        path_str, _ = QFileDialog.getSaveFileName(self, f"Export {fmt.upper()} report", suggested, filters)
        if not path_str:
            return
        path = Path(path_str)
        if path.suffix.lower() != f".{fmt}":
            path = path.with_name(path.name + f".{fmt}")
        # Never let a report overwrite one of the files being analyzed.
        if path.resolve() in {p.resolve() for p in self.selected}:
            show_message(self, QMessageBox.Icon.Warning, "Export refused",
                         "That file is one of the analyzed JARs. Choose a different report name.")
            return
        try:
            write_report(path, self.results, fmt)
        except OSError as exc:
            show_message(self, QMessageBox.Icon.Critical, "Export failed", f"Could not write the report:\n{exc}")
            return
        self.statusBar().showMessage(f"Saved {fmt.upper()} report: {path}", 8000)

    # ------------------------------------------------------------------ misc

    def _update_buttons(self) -> None:
        running = self.is_running()
        for w in (self.btn_jar, self.btn_folder, self.btn_clear, self.chk_recursive):
            w.setEnabled(not running)
        self.btn_remove.setEnabled(not running and bool(self.file_panel.list.selectedItems()))
        self.btn_analyze.setEnabled(not running and bool(self.selected))
        self.btn_cancel.setEnabled(running)
        self.btn_json.setEnabled(not running and bool(self.results))
        self.btn_txt.setEnabled(not running and bool(self.results))

    def show_about(self) -> None:
        show_message(self, QMessageBox.Icon.Information, f"About {APP_NAME}",
                     f"{APP_NAME} {VERSION}\nPublisher: {PUBLISHER}\n\n"
                     "A static analyzer for Minecraft mod JAR files, intended for authorized "
                     "server staff. It never executes, modifies, deletes, quarantines or uploads "
                     f"the files it analyzes.\n\n{DISCLAIMER}\n\nLicensed under the MIT License.")

    def closeEvent(self, event) -> None:  # noqa: N802
        # Stop a running analysis cleanly before the window closes.
        if self.worker:
            self.worker.cancel()
        if self.thread:
            self.thread.quit()
            self.thread.wait(10_000)
        event.accept()


def run(argv: list[str] | None = None) -> int:
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    app.setOrganizationName(PUBLISHER)
    app.setStyle("Fusion")  # consistent look on every OS; our stylesheet sits on top
    app.setStyleSheet(theme.STYLESHEET)
    icon_file = asset_path("icon.png")
    if icon_file.is_file():
        app.setWindowIcon(QIcon(str(icon_file)))
    window = MainWindow()
    window.show()
    return app.exec()
