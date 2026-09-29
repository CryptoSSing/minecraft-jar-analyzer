"""Dark theme: colours and the Qt stylesheet (QSS, a CSS-like language)."""

from analyzer.models import Severity

BACKGROUND = "#14181f"
PANEL = "#1b2029"
PANEL_ALT = "#202633"
BORDER = "#2c3444"
TEXT = "#d8dee9"
TEXT_DIM = "#8b95a7"
ACCENT = "#3fb68b"
ACCENT_HOVER = "#4fcb9d"

SEVERITY_COLOR = {
    Severity.WARNING: "#f0605a",
    Severity.REVIEW: "#e3b341",
    Severity.INFO: TEXT_DIM,  # informational: deliberately quieter than REVIEW/WARNING
}
POSITIVE_COLOR = "#3fb950"

STYLESHEET = f"""
QWidget {{
    background-color: {BACKGROUND};
    color: {TEXT};
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 10pt;
}}
QMainWindow::separator {{ background: {BORDER}; width: 1px; height: 1px; }}
QLabel#Title {{ font-size: 17pt; font-weight: 600; color: {TEXT}; }}
QLabel#Subtitle {{ color: {TEXT_DIM}; }}
QLabel#SectionHeader {{ font-size: 11pt; font-weight: 600; color: {TEXT}; padding-top: 4px; }}
QLabel#Dim {{ color: {TEXT_DIM}; }}
QLabel#Summary {{ font-size: 11pt; padding: 6px 0; }}

QFrame#Card {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QFrame#Card QLabel {{ background: transparent; }}

QPushButton {{
    background-color: {PANEL_ALT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 14px;
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:pressed {{ background-color: {BORDER}; }}
QPushButton:disabled {{ color: #5c6577; border-color: {PANEL_ALT}; }}
QPushButton#Primary {{
    background-color: {ACCENT};
    color: #0c1116;
    font-weight: 600;
    border: none;
    padding: 8px 22px;
}}
QPushButton#Primary:hover {{ background-color: {ACCENT_HOVER}; }}
QPushButton#Primary:disabled {{ background-color: #2b5b4a; color: #7f9a90; }}

QListWidget, QTreeWidget, QTableWidget, QPlainTextEdit {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 6px;
    alternate-background-color: {PANEL_ALT};
    selection-background-color: #2d4a63;
    selection-color: {TEXT};
}}
QListWidget::item {{ padding: 5px; }}
QHeaderView::section {{
    background-color: {PANEL_ALT};
    color: {TEXT_DIM};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 6px;
    font-weight: 600;
}}
QTableWidget {{ gridline-color: {BORDER}; }}

QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 6px; top: -1px; }}
QTabBar::tab {{
    background: {PANEL};
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-bottom: none;
    padding: 7px 14px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}}
QTabBar::tab:selected {{ background: {PANEL_ALT}; color: {TEXT}; }}

QProgressBar {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 6px;
    text-align: center;
    height: 18px;
}}
QProgressBar::chunk {{ background-color: {ACCENT}; border-radius: 5px; }}

QCheckBox {{ spacing: 6px; }}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {TEXT_DIM};
    border-radius: 3px;
    background: {PANEL};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QStatusBar {{ color: {TEXT_DIM}; }}
QSplitter::handle {{ background: {BACKGROUND}; }}
QToolTip {{ background-color: {PANEL_ALT}; color: {TEXT}; border: 1px solid {BORDER}; }}
QMenuBar {{ background: {BACKGROUND}; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {PANEL_ALT}; }}
QMenu {{ background: {PANEL}; border: 1px solid {BORDER}; }}
QScrollBar:vertical, QScrollBar:horizontal {{ background: {PANEL}; border: none; width: 10px; height: 10px; }}
QScrollBar::handle {{ background: {BORDER}; border-radius: 5px; min-height: 24px; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
"""
