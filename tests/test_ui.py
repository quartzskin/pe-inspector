import json
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from pe_inspector.synthetic import build_synthetic_pe  # noqa: E402
from pe_inspector.ui.main_window import MainWindow  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app):
    w = MainWindow()
    yield w
    w.wait_idle()
    w.close()


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_loads_file_in_background_and_fills_tables(window, tmp_path):
    window.load_paths([_write(tmp_path, "a.exe", build_synthetic_pe())])
    window.wait_idle()
    assert window.reports[0] is not None
    assert window.sections.rowCount() == 4
    assert window.sections.item(3, 7).text() == "high"
    assert window.imports.topLevelItemCount() == 1
    assert window.exports.rowCount() == 1
    assert window.strings.rowCount() > 0
    assert window.act_json.isEnabled()


def test_string_filter_hides_rows(window, tmp_path):
    window.load_paths([_write(tmp_path, "a.exe", build_synthetic_pe())])
    window.wait_idle()
    window.string_filter.setText("synthetic pe")
    hidden = [window.strings.isRowHidden(r) for r in range(window.strings.rowCount())]
    assert hidden.count(False) == 1


def test_two_files_compare_and_export(window, tmp_path):
    a = _write(tmp_path, "a.exe", build_synthetic_pe())
    b = _write(tmp_path, "b.dll", build_synthetic_pe(dll=True))
    window.load_paths([a, b])
    window.wait_idle()
    assert "differ" in window.compare_status.text()
    assert window.compare_fields.rowCount() > 0
    assert json.loads(window.render_export("json"))["comparison"]["identical"] is False
    assert "## Comparison" in window.render_export("md")


def test_bad_file_shows_error_not_crash(window, tmp_path):
    window.load_paths([_write(tmp_path, "bad.exe", b"not a pe file at all")])
    window.wait_idle()
    assert window.reports[0] is None
    assert "MZ" in window.error_label.text()
    assert not window.act_json.isEnabled()


def test_empty_file_shows_error(window, tmp_path):
    window.load_paths([_write(tmp_path, "e.exe", b"")])
    window.wait_idle()
    assert "empty" in window.error_label.text()
