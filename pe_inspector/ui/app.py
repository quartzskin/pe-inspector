from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .. import __version__
from .main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv if argv is None else argv
    app = QApplication(argv)
    app.setApplicationName("PE Inspector")
    app.setApplicationVersion(__version__)
    window = MainWindow()
    window.show()
    paths = argv[1:3]
    if paths:
        window.load_paths(paths)
    return app.exec()
