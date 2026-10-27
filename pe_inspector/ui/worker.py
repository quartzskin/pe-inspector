from __future__ import annotations

from PySide6.QtCore import QObject, QRunnable, Signal

from ..analysis import PEInspectError, analyze_file


class _Signals(QObject):
    done = Signal(int, str, object)  # slot, path, PEReport
    failed = Signal(int, str, str)  # slot, path, message


class AnalysisTask(QRunnable):
    def __init__(self, slot: int, path: str) -> None:
        super().__init__()
        self.slot = slot
        self.path = path
        self.signals = _Signals()

    def run(self) -> None:
        try:
            report = analyze_file(self.path)
        except PEInspectError as exc:
            self.signals.failed.emit(self.slot, self.path, str(exc))
        except Exception as exc:  # don't let the worker die quietly
            self.signals.failed.emit(self.slot, self.path, f"Unexpected error: {exc}")
        else:
            self.signals.done.emit(self.slot, self.path, report)
