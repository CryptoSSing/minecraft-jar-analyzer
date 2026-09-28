"""Reusable GUI pieces: overview card, findings table, detail trees.

SECURITY NOTE - plain text only
-------------------------------
QLabel and QMessageBox use "AutoText" by default: if a string looks like
HTML, Qt renders it as HTML. Mod names, descriptions and file names come
from the (untrusted) JAR, so a mod named '<img src=...>' could inject markup.
Every label here is created through plain_label(), which forces
Qt.TextFormat.PlainText. Table, tree, list and QPlainTextEdit items are always
plain text.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QGridLayout,
                               QHBoxLayout, QHeaderView, QLabel, QListWidget,
                               QListWidgetItem, QMessageBox, QPlainTextEdit,
                               QPushButton, QScrollArea, QSplitter,
                               QTableWidget, QTableWidgetItem, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from analyzer.models import AnalysisResult, Finding, HashClassification, Severity
from analyzer.sanitize import safe_text
from reports.exporter import HASH_EXPLANATION, severity_symbol, summary_sentence

from . import theme


def plain_label(text: str = "", object_name: str | None = None, selectable: bool = False) -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)  # never interpret HTML
    label.setText(text)
    label.setWordWrap(True)
    if object_name:
        label.setObjectName(object_name)
    if selectable:
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def show_message(parent: QWidget, icon: QMessageBox.Icon, title: str, text: str) -> None:
    box = QMessageBox(parent)
    box.setIcon(icon)
    box.setWindowTitle(title)
    box.setTextFormat(Qt.TextFormat.PlainText)  # file names may contain markup
    box.setText(text)
    box.exec()


def finding_color(finding: Finding) -> str:
    if finding.rule_id in ("metadata.detected", "hash.verified"):
        return theme.POSITIVE_COLOR
    return theme.SEVERITY_COLOR[finding.severity]


def result_color(result: AnalysisResult) -> str:
    if not result.file.is_valid_jar:
        return theme.SEVERITY_COLOR[Severity.REVIEW]
    worst = result.highest_severity()
    if worst in (None, Severity.INFO):
        return theme.POSITIVE_COLOR
    return theme.SEVERITY_COLOR[worst]


def result_symbol(result: AnalysisResult) -> str:
    if not result.file.is_valid_jar:
        return "✖"
    worst = result.highest_severity()
    return {Severity.WARNING: "⚠", Severity.REVIEW: "◆"}.get(worst, "✓")


def _card() -> tuple[QFrame, QGridLayout]:
    frame = QFrame()
    frame.setObjectName("Card")
    grid = QGridLayout(frame)
    grid.setContentsMargins(14, 12, 14, 12)
    grid.setHorizontalSpacing(14)
    grid.setVerticalSpacing(6)
    grid.setColumnStretch(1, 1)
    return frame, grid


class OverviewPanel(QScrollArea):
    """Summary of one result: file, mod, hash database and key findings."""

    finding_activated = Signal(int)  # row index in the findings table

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(10)

        self.file_title = plain_label("", "SectionHeader", selectable=True)
        self.summary = plain_label("", "Summary")
        self.counts = plain_label("", "Dim")
        layout.addWidget(self.file_title)
        layout.addWidget(self.summary)
        layout.addWidget(self.counts)

        self.values: dict[str, QLabel] = {}
        file_card, grid = _card()
        self._rows(grid, ["SHA-256", "Size", "Modified (UTC)", "Detected type", "Valid JAR"])
        self.copy_hash = QPushButton("Copy")
        self.copy_hash.setToolTip("Copy the SHA-256 to the clipboard")
        self.copy_hash.clicked.connect(self._copy_sha)
        grid.addWidget(self.copy_hash, 0, 2)
        layout.addWidget(plain_label("File", "SectionHeader"))
        layout.addWidget(file_card)

        mod_card, grid = _card()
        self._rows(grid, ["Mod", "Mod ID", "Version", "Loader", "Authors", "Minecraft"])
        layout.addWidget(plain_label("Minecraft metadata", "SectionHeader"))
        layout.addWidget(mod_card)

        hash_card, grid = _card()
        self._rows(grid, ["Classification", "Details"])
        layout.addWidget(plain_label("Hash database", "SectionHeader"))
        layout.addWidget(hash_card)

        layout.addWidget(plain_label("Findings  (double-click for details)", "SectionHeader"))
        self.findings = QListWidget()
        self.findings.setMinimumHeight(160)
        self.findings.itemDoubleClicked.connect(lambda item: self.finding_activated.emit(self.findings.row(item)))
        layout.addWidget(self.findings, 1)
        self.setWidget(body)
        self._sha = ""

    def _rows(self, grid: QGridLayout, labels: list[str]) -> None:
        for row, name in enumerate(labels):
            grid.addWidget(plain_label(name, "Dim"), row, 0, Qt.AlignmentFlag.AlignTop)
            value = plain_label("-", selectable=True)
            grid.addWidget(value, row, 1)
            self.values[name] = value

    def _set(self, name: str, value: object) -> None:
        self.values[name].setText(safe_text(value, 1000) if value not in (None, "", []) else "-")

    def _copy_sha(self) -> None:
        if self._sha:
            QGuiApplication.clipboard().setText(self._sha)

    def show_result(self, r: AnalysisResult) -> None:
        self._sha = r.file.sha256 or ""
        self.copy_hash.setEnabled(bool(self._sha))
        self.file_title.setText(safe_text(r.file.name))
        self.summary.setText(summary_sentence(r))
        self.summary.setStyleSheet(f"color: {result_color(r)}")
        c = r.severity_counts()
        self.counts.setText(f"⚠ {c['WARNING']} WARNING     ◆ {c['REVIEW']} REVIEW     ℹ {c['INFO']} INFO"
                            f"     •  {len(r.errors)} error(s)")

        self._set("SHA-256", r.file.sha256)
        self._set("Size", f"{r.file.size_bytes:,} bytes")
        self._set("Modified (UTC)", r.file.modified)
        self._set("Detected type", r.file.file_type)
        self._set("Valid JAR", "Yes" if r.file.is_valid_jar else "No")

        mod = r.primary_mod()
        self._set("Mod", mod.name if mod else None)
        self._set("Mod ID", mod.mod_id if mod else None)
        self._set("Version", (mod.version if mod else None) or r.manifest.attributes.get("Implementation-Version"))
        self._set("Loader", r.loader)
        self._set("Authors", ", ".join(mod.authors) if mod else None)
        self._set("Minecraft", mod.minecraft_version if mod else None)

        h = r.hash_lookup
        self._set("Classification", h.classification.value)
        color = {HashClassification.VERIFIED: theme.POSITIVE_COLOR,
                 HashClassification.SUSPICIOUS: theme.SEVERITY_COLOR[Severity.WARNING]}.get(h.classification, theme.TEXT)
        self.values["Classification"].setStyleSheet(f"color: {color}; font-weight: 600")
        details = HASH_EXPLANATION[h.classification].capitalize()
        extra = " · ".join(x for x in (h.name, h.version, h.source, h.notes) if x)
        self._set("Details", f"{details}. {extra}" if extra else details)

        self.findings.clear()
        for f in r.findings:
            item = QListWidgetItem(f"{severity_symbol(f)}  {f.severity.value:<8}  {f.title}")
            item.setForeground(QColor(finding_color(f)))
            item.setToolTip(f.location[:500])
            self.findings.addItem(item)
        if not r.findings:
            self.findings.addItem(QListWidgetItem("No findings."))


class FindingsPanel(QSplitter):
    """Table of findings with a detail pane underneath."""

    COLUMNS = ["Severity", "Finding", "Location", "Confidence"]

    def __init__(self):
        super().__init__(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(1, 340)
        self.table.itemSelectionChanged.connect(self._show_selected)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a finding to see why it matters.")
        self.addWidget(self.table)
        self.addWidget(self.details)
        self.setStretchFactor(0, 3)
        self.setStretchFactor(1, 2)
        self._findings: list[Finding] = []

    def show_result(self, r: AnalysisResult) -> None:
        self._findings = list(r.findings)
        self.table.setRowCount(len(self._findings))
        for row, f in enumerate(self._findings):
            sev = QTableWidgetItem(f"{severity_symbol(f)} {f.severity.value}")
            sev.setForeground(QColor(finding_color(f)))
            cells = [sev, QTableWidgetItem(f.title), QTableWidgetItem(f.location),
                     QTableWidgetItem(f.confidence.value)]
            for col, cell in enumerate(cells):
                cell.setToolTip(f.location[:500] if col == 2 else cell.text())
                self.table.setItem(row, col, cell)
        self.details.clear()
        if self._findings:
            self.table.selectRow(0)
            # Qt only signals a *change* of selection; if row 0 was already
            # selected for the previous file, update the details ourselves.
            self._show_selected()

    def select(self, row: int) -> None:
        if 0 <= row < self.table.rowCount():
            self.table.selectRow(row)

    def _show_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        f = self._findings[rows[0].row()]
        self.details.setPlainText(
            f"{severity_symbol(f)} {f.severity.value} — {f.title}\n\n"
            f"Confidence: {f.confidence.value}\n"
            f"Rule: {f.rule_id}\n\n"
            f"Location:\n{f.location}\n\n"
            f"Why it matters:\n{f.explanation}"
        )


def make_tree() -> QTreeWidget:
    tree = QTreeWidget()
    tree.setColumnCount(2)
    tree.setHeaderLabels(["Item", "Value"])
    tree.setAlternatingRowColors(True)
    tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
    tree.header().resizeSection(0, 280)
    tree.header().setStretchLastSection(True)
    return tree


def _node(parent, key: str, value: object = "") -> QTreeWidgetItem:
    item = QTreeWidgetItem(parent, [safe_text(key, 300), safe_text(value, 2000)])
    item.setToolTip(1, safe_text(value, 2000))
    return item


def _list_node(parent, title: str, items: list[str], limit: int = 500) -> None:
    if not items:
        return
    node = _node(parent, f"{title} ({len(items)})")
    for entry in items[:limit]:
        _node(node, entry)
    if len(items) > limit:
        _node(node, f"... and {len(items) - limit} more")


def fill_contents_tree(tree: QTreeWidget, r: AnalysisResult) -> None:
    tree.clear()
    c = r.contents
    summary = _node(tree, "Archive")
    _node(summary, "Entries", f"{c.total_entries:,} ({c.total_files:,} files, {c.directories:,} folders)")
    _node(summary, "Declared uncompressed size", f"{c.declared_uncompressed_bytes:,} bytes")
    summary.setExpanded(True)

    exts = _node(tree, f"Files by extension ({len(c.by_extension)})")
    for ext, n in c.by_extension.items():
        _node(exts, ext, f"{n:,}")
    exts.setExpanded(True)

    _list_node(tree, "Native libraries", c.native_libraries)
    _list_node(tree, "Executables / scripts", c.executables_and_scripts)
    _list_node(tree, "Disguised files", c.disguised_files)
    _list_node(tree, "Bundled JARs", c.nested_jars)
    _list_node(tree, "Large files", [f"{e.path} ({e.size_bytes:,} bytes)" for e in c.large_files])
    _list_node(tree, "High compression ratio", [f"{e.path} ({e.size_bytes:,} from {e.compressed_bytes:,} bytes)"
                                                for e in c.high_ratio_entries])
    _list_node(tree, "Unusual file types", c.unusual_files)
    _list_node(tree, "Signature files", c.signature_files)
    _list_node(tree, "Encrypted entries", c.encrypted_entries)
    _list_node(tree, "Duplicate names", c.duplicate_names)
    _list_node(tree, "Unsafe (path traversal) names", c.unsafe_names)
    _list_node(tree, "Deceptive Unicode names", c.deceptive_names)

    cs = r.classes
    classes = _node(tree, "Java classes")
    _node(classes, "Class files", f"{cs.total:,}")
    _node(classes, "Parsed", f"{cs.parsed:,}")
    _node(classes, "Invalid", f"{cs.failed:,}")
    _node(classes, "Skipped (limits/cancel)", f"{cs.skipped:,}")
    if cs.java_versions:
        _node(classes, "Compiled for", ", ".join(f"{k} ({v})" for k, v in cs.java_versions.items()))
    pk = _node(classes, f"Top packages ({len(cs.packages)})")
    for name, n in list(cs.packages.items())[:100]:
        _node(pk, name, f"{n:,} classes")
    _list_node(classes, "Invalid class files", cs.failed_entries)
    classes.setExpanded(True)

    if r.nested_jars:
        nested = _node(tree, f"Bundled JAR details ({len(r.nested_jars)})")
        for n in r.nested_jars:
            item = _node(nested, n.path, n.loader)
            _node(item, "Size", f"{n.size_bytes:,} bytes")
            _node(item, "SHA-256", n.sha256 or "-")
            _node(item, "Hash database", n.hash_classification.value)
            if n.mod_ids:
                _node(item, "Mod IDs", ", ".join(n.mod_ids))
            if n.error:
                _node(item, "Error", n.error)


def fill_metadata_tree(tree: QTreeWidget, r: AnalysisResult) -> None:
    tree.clear()
    loader = _node(tree, "Detected loader", r.loader)
    for ev in r.loader_evidence:
        _node(loader, "Evidence", ev)
    loader.setExpanded(True)

    if not r.mods:
        _node(tree, "Mod descriptors", "None found (not suspicious by itself)")
    for m in r.mods:
        title = m.name or m.mod_id or "(unnamed)"
        where = f" — inside {m.nested_in}" if m.nested_in else ""
        item = _node(tree, f"{title}{where}", f"{m.loader} · {m.source_file}")
        for key, value in (("Mod ID", m.mod_id), ("Version", m.version), ("Authors", ", ".join(m.authors)),
                           ("Minecraft", m.minecraft_version), ("Loader version", m.loader_version),
                           ("Description", m.description)):
            if value:
                _node(item, key, value)
        if m.dependencies:
            deps = _node(item, f"Dependencies ({len(m.dependencies)})")
            for dep, ver in m.dependencies.items():
                _node(deps, dep, ver)
        for key, value in m.extra.items():
            _node(item, key, value)
        item.setExpanded(m.nested_in is None)

    manifest = _node(tree, "MANIFEST.MF", "present" if r.manifest.present else "not present")
    for key, value in r.manifest.attributes.items():
        _node(manifest, key, value)
    manifest.setExpanded(True)


class FileListPanel(QWidget):
    """The list of files selected for analysis."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.list.setMaximumHeight(96)
        self.count_label = plain_label("Selected files: 0", "Dim")
        top = QHBoxLayout()
        top.addWidget(self.count_label)
        top.addStretch()
        layout.addLayout(top)
        layout.addWidget(self.list)
