"""Save offscreen screenshots of the main window to docs/.

Usage: python scripts/make_screenshot.py [FILE_A [FILE_B]]
With no arguments it uses two synthetic PEs.
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# The offscreen platform finds no fonts on its own and draws tofu boxes.
os.environ.setdefault("QT_QPA_FONTDIR", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Fonts"))

from PySide6.QtWidgets import QApplication  # noqa: E402

from pe_inspector.synthetic import build_synthetic_pe  # noqa: E402
from pe_inspector.ui.main_window import MainWindow  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs"


def main() -> None:
    app = QApplication([])
    paths = sys.argv[1:3]
    if not paths:
        tmp = Path(tempfile.mkdtemp())
        (tmp / "sample.exe").write_bytes(build_synthetic_pe())
        (tmp / "sample_v2.dll").write_bytes(build_synthetic_pe(dll=True, text_string=b"Second build"))
        paths = [str(tmp / "sample.exe"), str(tmp / "sample_v2.dll")]
    w = MainWindow()
    w.resize(1100, 720)
    w.show()
    w.load_paths(paths)
    w.wait_idle()
    OUT.mkdir(exist_ok=True)
    for index, name in ((1, "screenshot-sections.png"), (5, "screenshot-compare.png")):
        w.tabs.setCurrentIndex(index)
        app.processEvents()
        w.grab().save(str(OUT / name))
        print("saved", OUT / name)


if __name__ == "__main__":
    main()
