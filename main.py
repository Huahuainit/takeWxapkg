from __future__ import annotations

import multiprocessing
import sys

from PySide6.QtWidgets import QApplication

from takewxapkg.gui import MainWindow


def main() -> int:
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    app.setApplicationName("takeWxapkg")
    app.setOrganizationName("takeWxapkg")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
