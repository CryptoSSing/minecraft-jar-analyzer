"""Run the analysis on a background thread so the window never freezes.

Qt draws the window and handles clicks on the "main" (GUI) thread. If we
analyzed a 100 MB JAR there, the window would stop responding until it was
done. Instead, `AnalysisWorker` runs in a separate QThread and reports back
through *signals*. Qt delivers signals safely across threads, so the GUI
only ever gets touched from the main thread.

Cancelling uses a threading.Event: the GUI sets it, and the analyzer checks
it between files and between classes.
"""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

from analyzer.hash_database import HashDatabase
from analyzer.pipeline import analyze_files


class AnalysisWorker(QObject):
    progress = Signal(int, int, str)   # (files done, total files, current file name)
    finished = Signal(object)          # list[AnalysisResult]

    def __init__(self, paths: list[Path], hash_db: HashDatabase):
        super().__init__()
        self._paths = paths
        self._hash_db = hash_db
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    @Slot()
    def run(self) -> None:
        # analyze_files never raises for bad input; the try/except is a final
        # guarantee that the GUI always gets a `finished` signal.
        try:
            results = analyze_files(self._paths, self._hash_db,
                                    should_cancel=self._cancel.is_set,
                                    progress=self.progress.emit)
        except Exception:  # noqa: BLE001
            results = []
        self.finished.emit(results)
