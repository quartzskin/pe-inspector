from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtGui import QAction, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFileDialog,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..analysis import PEReport
from ..report import compare_reports, summary_rows, to_json, to_markdown
from .worker import AnalysisTask


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setStretchLastSection(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    return t


def _fill(table: QTableWidget, rows: list[list[str]]) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, text in enumerate(row):
            table.setItem(r, c, QTableWidgetItem(text))
    table.resizeColumnsToContents()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PE Inspector")
        self.resize(1100, 720)
        self.setAcceptDrops(True)
        self.reports: list[PEReport | None] = [None, None]
        self._expected: list[str | None] = [None, None]
        self._tasks: set[AnalysisTask] = set()

        self._build_toolbar()
        self._build_tabs()
        self.statusBar().showMessage("Drop a .exe or .dll here, or use Open. Files are never executed.")
        self._refresh()

    def _build_toolbar(self) -> None:
        bar = QToolBar("Main")
        bar.setMovable(False)
        self.addToolBar(bar)
        self.act_open = QAction("Open…", self, shortcut="Ctrl+O", triggered=lambda: self._pick(0))
        self.act_open_b = QAction(
            "Compare with…", self, shortcut="Ctrl+Shift+O", triggered=lambda: self._pick(1)
        )
        self.act_json = QAction(
            "Export JSON", self, shortcut="Ctrl+J", triggered=lambda: self._export("json")
        )
        self.act_md = QAction(
            "Export Markdown", self, shortcut="Ctrl+M", triggered=lambda: self._export("md")
        )
        for a in (self.act_open, self.act_open_b, self.act_json, self.act_md):
            bar.addAction(a)

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.hint = QLabel("Drag and drop a PE file (.exe / .dll) here\nDrop two files to compare them")
        self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.summary = _table(["Field", "Value"])
        self.warnings = QPlainTextEdit(readOnly=True)
        self.warnings.setMaximumHeight(110)
        overview = QWidget()
        lay = QVBoxLayout(overview)
        lay.addWidget(self.summary)
        lay.addWidget(QLabel("Warnings"))
        lay.addWidget(self.warnings)

        self.sections = _table(
            ["Name", "VA", "VSize", "Raw offset", "Raw size", "Perm", "Entropy", "Level", "Notes"]
        )
        self.imports = QTreeWidget()
        self.imports.setHeaderLabels(["DLL / function", "Ordinal"])
        self.imports.setAlternatingRowColors(True)
        self.exports = _table(["Ordinal", "Name", "RVA", "Forwarder"])
        self.strings = _table(["Offset", "Encoding", "Value"])
        self.string_filter = QLineEdit(placeholderText="Filter strings…")
        self.string_filter.textChanged.connect(self._filter_strings)
        strings_tab = QWidget()
        sl = QVBoxLayout(strings_tab)
        sl.addWidget(self.string_filter)
        sl.addWidget(self.strings)

        self.compare_status = QLabel()
        self.compare_fields = _table(["Field", "A", "B", "Differs"])
        self.compare_sections = _table(["Section", "Status", "Raw A", "Raw B", "Entropy A", "Entropy B"])
        self.compare_changes = QPlainTextEdit(readOnly=True)
        compare = QWidget()
        cl = QVBoxLayout(compare)
        cl.addWidget(self.compare_status)
        cl.addWidget(self.compare_fields, 3)
        cl.addWidget(self.compare_sections, 2)
        cl.addWidget(self.compare_changes, 2)

        for widget, title in (
            (overview, "Overview"),
            (self.sections, "Sections"),
            (self.imports, "Imports"),
            (self.exports, "Exports"),
            (strings_tab, "Strings"),
            (compare, "Compare"),
        ):
            self.tabs.addTab(widget, title)

        self.stack = QStackedWidget()
        self.stack.addWidget(self.hint)
        self.stack.addWidget(self.tabs)
        self.setCentralWidget(self.stack)
        self.error_label = QLabel()
        self.statusBar().addPermanentWidget(self.error_label)

    def _pick(self, slot: int) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PE file", "", "PE files (*.exe *.dll *.sys *.ocx *.scr);;All files (*)"
        )
        if path:
            self.load_paths([path] if slot == 0 else [self._path(0) or "", path], only_slot=slot)

    def _path(self, slot: int) -> str | None:
        r = self.reports[slot]
        return r.path if r else None

    def load_paths(self, paths: list[str], only_slot: int | None = None) -> None:
        if only_slot is not None:
            self._start(only_slot, paths[only_slot])
            return
        for slot, path in enumerate(paths[:2]):
            self._start(slot, path)

    def _start(self, slot: int, path: str) -> None:
        self._expected[slot] = path
        self.error_label.clear()
        self.statusBar().showMessage(f"Analysing {Path(path).name}…")
        task = AnalysisTask(slot, path)
        task.setAutoDelete(False)
        task.signals.done.connect(self._on_done)
        task.signals.failed.connect(self._on_failed)
        self._tasks.add(task)
        QThreadPool.globalInstance().start(task)

    def _finish(self, slot: int, path: str) -> bool:
        self._tasks = {t for t in self._tasks if not (t.slot == slot and t.path == path)}
        return self._expected[slot] == path  # False if superseded by a newer load

    def _on_done(self, slot: int, path: str, report: PEReport) -> None:
        if not self._finish(slot, path):
            return
        self.reports[slot] = report
        self.statusBar().showMessage(f"Loaded {report.file_name}")
        self._refresh()

    def _on_failed(self, slot: int, path: str, message: str) -> None:
        if not self._finish(slot, path):
            return
        self.reports[slot] = None
        self.error_label.setText(f"{Path(path).name}: {message}")
        self.statusBar().showMessage("Analysis failed")
        self._refresh()

    def wait_idle(self) -> None:
        QThreadPool.globalInstance().waitForDone()
        QApplication.processEvents()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.load_paths(paths)
            event.acceptProposedAction()

    def _refresh(self) -> None:
        a, b = self.reports
        has = a is not None
        self.stack.setCurrentWidget(self.tabs if has or b else self.hint)
        self.act_open_b.setEnabled(has)
        self.act_json.setEnabled(has)
        self.act_md.setEnabled(has)
        if a is None:
            self.error_label.setToolTip("")
            return
        self._show_report(a)
        self._show_comparison(a, b)

    def _show_report(self, r: PEReport) -> None:
        self.setWindowTitle(f"PE Inspector - {r.file_name}")
        _fill(self.summary, [list(row) for row in summary_rows(r)])
        self.warnings.setPlainText("\n".join(r.warnings) or "None")

        rows = []
        for s in r.sections:
            ent = "-" if s.entropy is None else f"{s.entropy:.3f}"
            rows.append([
                s.name, f"0x{s.virtual_address:X}", f"0x{s.virtual_size:X}", f"0x{s.raw_offset:X}",
                f"0x{s.raw_size:X}", s.permissions, ent, s.entropy_level, "; ".join(s.warnings),
            ])  # fmt: skip
        _fill(self.sections, rows)

        self.imports.clear()
        for dll in r.imports:
            parent = QTreeWidgetItem([f"{dll.dll} ({len(dll.functions)})", ""])
            for fn in dll.functions:
                parent.addChild(
                    QTreeWidgetItem(
                        [fn.name or f"<ordinal {fn.ordinal}>", "" if fn.ordinal is None else str(fn.ordinal)]
                    )
                )
            self.imports.addTopLevelItem(parent)
        self.imports.expandAll()
        self.imports.resizeColumnToContents(0)

        _fill(
            self.exports,
            [[str(e.ordinal), e.name or "-", f"0x{e.rva:X}", e.forwarder or ""] for e in r.exports],
        )
        _fill(self.strings, [[f"0x{s.offset:X}", s.encoding, s.value] for s in r.strings])
        self.strings.setColumnWidth(2, 600)
        self._filter_strings(self.string_filter.text())

    def _filter_strings(self, text: str) -> None:
        needle = text.lower()
        for row in range(self.strings.rowCount()):
            item = self.strings.item(row, 2)
            self.strings.setRowHidden(row, bool(needle) and needle not in item.text().lower())

    def _show_comparison(self, a: PEReport, b: PEReport | None) -> None:
        if b is None:
            self.compare_status.setText("Drop a second file or use 'Compare with…' to compare.")
            for t in (self.compare_fields, self.compare_sections):
                t.setRowCount(0)
            self.compare_changes.clear()
            return
        c = compare_reports(a, b)
        self.compare_status.setText(
            f"A: {c['a']}    B: {c['b']}    " + ("Byte-identical." if c["identical"] else "Files differ.")
        )
        rows = [[f["field"], f["a"], f["b"], "yes" if f["differs"] else ""] for f in c["fields"]]
        _fill(self.compare_fields, rows)
        srows = [
            [
                s["name"], s["status"],
                "-" if s["raw_size_a"] is None else f"0x{s['raw_size_a']:X}",
                "-" if s["raw_size_b"] is None else f"0x{s['raw_size_b']:X}",
                "-" if s["entropy_a"] is None else f"{s['entropy_a']:.3f}",
                "-" if s["entropy_b"] is None else f"{s['entropy_b']:.3f}",
            ]
            for s in c["sections"]
        ]  # fmt: skip
        _fill(self.compare_sections, srows)
        lines = []
        for key, title in (
            ("imports_only_in_a", "Imports only in A"),
            ("imports_only_in_b", "Imports only in B"),
            ("exports_only_in_a", "Exports only in A"),
            ("exports_only_in_b", "Exports only in B"),
        ):
            lines.append(f"{title} ({len(c[key])}):")
            lines += [f"  {x}" for x in c[key]]
        lines.append(
            f"Strings: {c['strings_shared']} shared, {c['strings_only_in_a']} only in A, "
            f"{c['strings_only_in_b']} only in B"
        )
        self.compare_changes.setPlainText("\n".join(lines))

    def render_export(self, fmt: str) -> str:
        a, b = self.reports
        if a is None:
            raise ValueError("No report loaded")
        comparison = compare_reports(a, b) if b else None
        return to_json(a, comparison) if fmt == "json" else to_markdown(a, comparison)

    def _export(self, fmt: str) -> None:
        if self.reports[0] is None:
            return
        ext, label = ("json", "JSON") if fmt == "json" else ("md", "Markdown")
        default = f"{Path(self.reports[0].file_name).stem}-report.{ext}"
        path, _ = QFileDialog.getSaveFileName(self, f"Export {label}", default, f"{label} (*.{ext})")
        if not path:
            return
        try:
            Path(path).write_text(self.render_export(fmt), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", f"Could not write file: {exc.strerror or exc}")
            return
        self.statusBar().showMessage(f"Exported {path}")
