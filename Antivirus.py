from __future__ import annotations
import hashlib
import logging
import math
import os
import queue
import shutil
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
    from PyQt6.QtGui import QIcon, QAction
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QLabel, QProgressBar, QTabWidget, QFileDialog, QTableWidget, QTableWidgetItem,
        QHeaderView, QMessageBox, QListWidget, QListWidgetItem, QCheckBox, QLineEdit,
        QTextEdit, QSystemTrayIcon, QMenu, QSplitter, QSizePolicy
    )
except Exception as e:
    print("PyQt6 is required: pip install PyQt6")
    raise

# --------------------- Logging ---------------------
LOG_DIR = Path.home() / ".guardianav" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "guardianav.log"
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("guardianav")

# ----------------- Simple Signature DB --------------
# Minimal set including the EICAR test pattern hash.
# You can extend this list with SHA256 hashes of known test samples.
KNOWN_BAD_SHA256 = {
    # EICAR (plain ASCII) SHA256
    "275a021bbfb6480f2c343b2b3a9e0b0b0abf3fca0cf2741d9a5a5c1f3c6f0d7a",
}

# EICAR test pattern (do not modify):
EICAR_ASCII = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".jar"}

# Utilities

def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_entropy(path: Path, sample_size: int = 1024 * 128) -> float:
    """Approximate Shannon entropy from the first sample_size bytes."""
    try:
        with path.open("rb") as f:
            data = f.read(sample_size)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        for c in freq:
            if c:
                p = c / len(data)
                entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0.0


@dataclass
class Detection:
    path: Path
    reason: str
    sha256: str
    size: int


# Scanner Worker
class ScanWorker(QThread):
    progress = pyqtSignal(int)  # files scanned
    status = pyqtSignal(str)
    found = pyqtSignal(object)  # Detection
    finished = pyqtSignal(int)  # total scanned

    def __init__(self, roots: List[Path], heuristics: bool = True, parent=None):
        super().__init__(parent)
        self.roots = roots
        self.heuristics = heuristics
        self._stop = threading.Event()
        self.scanned = 0

    def stop(self):
        self._stop.set()

    def run(self):
        try:
            for root in self.roots:
                if self._stop.is_set():
                    break
                for dirpath, _dirnames, filenames in os.walk(root):
                    if self._stop.is_set():
                        break
                    for name in filenames:
                        if self._stop.is_set():
                            break
                        path = Path(dirpath) / name
                        try:
                            det = self.inspect(path)
                            self.scanned += 1
                            self.progress.emit(self.scanned)
                            if det:
                                self.found.emit(det)
                        except Exception as e:
                            logger.warning(f"Scan error on {path}: {e}")
            self.finished.emit(self.scanned)
        except Exception as e:
            logger.exception(f"Worker crashed: {e}")
            self.finished.emit(self.scanned)

    # Core inspection logic
    def inspect(self, path: Path) -> Optional[Detection]:
        if not path.exists() or not path.is_file():
            return None
        # Skip very large files > 200 MB in MVP for speed
        try:
            size = path.stat().st_size
        except Exception:
            return None
        if size > 200 * 1024 * 1024:
            return None

        # Read small sample for EICAR check
        reason = None
        try:
            with path.open("rb") as f:
                head = f.read(1024)
        except Exception:
            head = b""

        # 1) EICAR content check (safe test string)
        try:
            if EICAR_ASCII.encode("ascii") in head:
                sha = sha256_of_file(path)
                return Detection(path, "EICAR test file detected", sha, size)
        except Exception:
            pass

        # 2) Hash match check
        try:
            sha = sha256_of_file(path)
            if sha in KNOWN_BAD_SHA256:
                return Detection(path, "Known-bad SHA256 signature", sha, size)
        except Exception:
            sha = ""

        # 3) Heuristic flags
        if self.heuristics:
            ext = path.suffix.lower()
            ent = file_entropy(path)
            flags = []
            if ext in SUSPICIOUS_EXTENSIONS:
                flags.append(f"ext:{ext}")
            if ent >= 7.5:
                flags.append(f"entropy:{ent:.2f}")
            if size > 50 * 1024 * 1024:
                flags.append(f"size:{size//(1024*1024)}MB")
            if flags:
                return Detection(path, "Heuristic: " + ", ".join(flags), sha, size)

        return None

# Main Window
class GuardianAV(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GuardianAV – Educational Antivirus (MVP)")
        self.setMinimumSize(1100, 700)
        self.setWindowIcon(QIcon())

        self.heuristics_enabled = True
        self.quarantine_dir = Path.home() / ".guardianav" / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        self.scan_thread: Optional[ScanWorker] = None
        self.detections: List[Detection] = []

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.dashboard_tab = self._build_dashboard()
        self.scan_tab = self._build_scan()
        self.quarantine_tab = self._build_quarantine()
        self.logs_tab = self._build_logs()
        self.settings_tab = self._build_settings()

        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.scan_tab, "Scan")
        self.tabs.addTab(self.quarantine_tab, "Quarantine")
        self.tabs.addTab(self.logs_tab, "Logs")
        self.tabs.addTab(self.settings_tab, "Settings")

        self._apply_qss()
        self._init_tray()

    # UI Builders
    def _build_dashboard(self) -> QWidget:
        w = QWidget(); layout = QVBoxLayout(w)
        title = QLabel("GuardianAV")
        title.setProperty("h1", True)
        subtitle = QLabel("Minimal, modern, educational antivirus.")
        grid = QHBoxLayout()

        self.quick_scan_btn = QPushButton("Quick Scan (choose folder)")
        self.quick_scan_btn.clicked.connect(self._choose_and_quick_scan)
        self.full_scan_btn = QPushButton("Custom Scan")
        self.full_scan_btn.clicked.connect(self._choose_and_custom_scan)

        grid.addWidget(self.quick_scan_btn)
        grid.addWidget(self.full_scan_btn)

        stats = QLabel("Detections in session: 0")
        self.session_stats_lbl = stats

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(grid)
        layout.addSpacing(10)
        layout.addWidget(stats)
        layout.addStretch(1)
        return w

    def _build_scan(self) -> QWidget:
        w = QWidget(); layout = QVBoxLayout(w)
        controls = QHBoxLayout()
        self.path_line = QLineEdit()
        self.path_line.setPlaceholderText("Folder to scan…")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse_folder)
        start = QPushButton("Start Scan")
        start.clicked.connect(self._start_scan)
        stop = QPushButton("Stop")
        stop.clicked.connect(self._stop_scan)
        controls.addWidget(self.path_line)
        controls.addWidget(browse)
        controls.addWidget(start)
        controls.addWidget(stop)

        self.progress = QProgressBar()
        self.scan_status = QLabel("Idle")

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Path", "Reason", "SHA256", "Size", "Action"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, 5):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)

        layout.addLayout(controls)
        layout.addWidget(self.progress)
        layout.addWidget(self.scan_status)
        layout.addWidget(self.table)
        return w

    def _build_quarantine(self) -> QWidget:
        w = QWidget(); layout = QVBoxLayout(w)
        info = QLabel(f"Quarantine directory: {self.quarantine_dir}")
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_quarantine)
        self.q_list = QListWidget()
        btns = QHBoxLayout()
        restore = QPushButton("Restore")
        restore.clicked.connect(self._restore_selected)
        delete = QPushButton("Delete")
        delete.clicked.connect(self._delete_selected)
        btns.addWidget(restore); btns.addWidget(delete)

        layout.addWidget(info)
        layout.addWidget(refresh)
        layout.addWidget(self.q_list)
        layout.addLayout(btns)
        return w

    def _build_logs(self) -> QWidget:
        w = QWidget(); layout = QVBoxLayout(w)
        self.log_view = QTextEdit(); self.log_view.setReadOnly(True)
        load = QPushButton("Load Latest Logs")
        load.clicked.connect(self._load_logs)
        layout.addWidget(load)
        layout.addWidget(self.log_view)
        return w

    def _build_settings(self) -> QWidget:
        w = QWidget(); layout = QVBoxLayout(w)
        self.heur_chk = QCheckBox("Enable heuristic detections (recommended)")
        self.heur_chk.setChecked(True)
        qpath_lbl = QLabel("Quarantine folder:")
        self.qpath_line = QLineEdit(str(self.quarantine_dir))
        qbrowse = QPushButton("Change…")
        qbrowse.clicked.connect(self._choose_quarantine)
        row = QHBoxLayout(); row.addWidget(qpath_lbl); row.addWidget(self.qpath_line); row.addWidget(qbrowse)

        layout.addWidget(self.heur_chk)
        layout.addLayout(row)
        layout.addStretch(1)
        return w

    def _apply_qss(self):
        self.setStyleSheet(
            """
            QWidget { background: #0b0f14; color: #e6edf3; font-size: 14px; }
            QLabel[h1="true"] { font-size: 28px; font-weight: 800; padding: 6px 0; }
            QTabWidget::pane { border: 1px solid #1e2630; border-radius: 12px; }
            QTabBar::tab { background: #121823; padding: 10px 14px; margin: 4px; border-radius: 10px; }
            QTabBar::tab:selected { background: #1b2330; }
            QPushButton { background: #1c2836; border: 1px solid #2a3a4e; padding: 8px 12px; border-radius: 12px; }
            QPushButton:hover { background: #223244; }
            QPushButton:pressed { background: #192533; }
            QProgressBar { background: #0f141b; border: 1px solid #233042; border-radius: 10px; text-align: center; }
            QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3aa5ff, stop:1 #7cf); border-radius: 10px; }
            QLineEdit, QTextEdit { background: #0f141b; border: 1px solid #233042; border-radius: 10px; padding: 6px; }
            QListWidget, QTableWidget { background: #0f141b; border: 1px solid #233042; border-radius: 10px; }
            QHeaderView::section { background: #121823; border: none; padding: 6px; }
            """
        )

    def _init_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(QIcon())
        menu = QMenu()
        act_show = QAction("Show", self); act_show.triggered.connect(self.showNormal)
        act_quit = QAction("Quit", self); act_quit.triggered.connect(QApplication.instance().quit)
        menu.addAction(act_show); menu.addSeparator(); menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.show()

    # Actions
    def _browse_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose folder to scan")
        if path:
            self.path_line.setText(path)

    def _choose_and_quick_scan(self):
        path = QFileDialog.getExistingDirectory(self, "Choose folder to quick scan")
        if path:
            self.path_line.setText(path)
            self.tabs.setCurrentWidget(self.scan_tab)
            self._start_scan()

    def _choose_and_custom_scan(self):
        self._browse_folder()

    def _start_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.information(self, "Scan", "A scan is already running.")
            return
        text = self.path_line.text().strip()
        if not text:
            QMessageBox.warning(self, "Scan", "Please choose a folder to scan.")
            return
        root = Path(text)
        if not root.exists() or not root.is_dir():
            QMessageBox.warning(self, "Scan", "Invalid folder.")
            return
        self.table.setRowCount(0)
        self.detections.clear()
        self.progress.setRange(0, 0)  # busy
        self.scan_status.setText("Scanning…")
        self.scan_thread = ScanWorker([root], heuristics=self.heur_chk.isChecked())
        self.scan_thread.progress.connect(self._on_progress)
        self.scan_thread.found.connect(self._on_found)
        self.scan_thread.finished.connect(self._on_finished)
        self.scan_thread.start()
        logger.info(f"Started scan on {root}")

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_status.setText("Stopping…")

    def _on_progress(self, count: int):
        # Indeterminate bar already set; we just show count in status
        self.scan_status.setText(f"Scanned files: {count}")

    def _on_found(self, det: Detection):
        self.detections.append(det)
        self.session_stats_lbl.setText(f"Detections in session: {len(self.detections)}")

        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(det.path)))
        self.table.setItem(row, 1, QTableWidgetItem(det.reason))
        self.table.setItem(row, 2, QTableWidgetItem(det.sha256))
        self.table.setItem(row, 3, QTableWidgetItem(str(det.size)))

        action_btn = QPushButton("Quarantine")
        def do_quarantine():
            self._quarantine_file(det.path)
        action_btn.clicked.connect(do_quarantine)
        self.table.setCellWidget(row, 4, action_btn)

        logger.info(f"Detection: {det.reason} | {det.path}")

    def _on_finished(self, total: int):
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.scan_status.setText(f"Finished. Total scanned: {total}")
        logger.info(f"Scan finished. Total scanned: {total}")

    # Quarantine Ops
    def _quarantine_file(self, path: Path):
        try:
            if not path.exists():
                QMessageBox.warning(self, "Quarantine", "File no longer exists.")
                return
            target = self.quarantine_dir / f"{int(time.time())}__{path.name}"
            shutil.move(str(path), str(target))
            QMessageBox.information(self, "Quarantine", f"Moved to quarantine: {target}")
            logger.info(f"Quarantined: {path} -> {target}")
            self._refresh_quarantine()
        except Exception as e:
            QMessageBox.critical(self, "Quarantine", f"Failed: {e}")
            logger.exception(f"Quarantine failed for {path}: {e}")

    def _refresh_quarantine(self):
        self.q_list.clear()
        if not self.quarantine_dir.exists():
            return
        for p in sorted(self.quarantine_dir.iterdir()):
            if p.is_file():
                item = QListWidgetItem(str(p))
                self.q_list.addItem(item)

    def _restore_selected(self):
        item = self.q_list.currentItem()
        if not item:
            return
        qpath = Path(item.text())
        dest_dir = QFileDialog.getExistingDirectory(self, "Restore to folder")
        if not dest_dir:
            return
        try:
            shutil.move(str(qpath), str(Path(dest_dir) / qpath.name))
            logger.info(f"Restored from quarantine: {qpath}")
            self._refresh_quarantine()
            QMessageBox.information(self, "Restore", "File restored.")
        except Exception as e:
            QMessageBox.critical(self, "Restore", f"Failed: {e}")
            logger.exception(f"Restore failed: {e}")

    def _delete_selected(self):
        item = self.q_list.currentItem()
        if not item:
            return
        qpath = Path(item.text())
        try:
            qpath.unlink()
            logger.info(f"Deleted from quarantine: {qpath}")
            self._refresh_quarantine()
        except Exception as e:
            QMessageBox.critical(self, "Delete", f"Failed: {e}")
            logger.exception(f"Delete failed: {e}")

    # Logs & Settings
    def _load_logs(self):
        try:
            if LOG_FILE.exists():
                self.log_view.setPlainText(LOG_FILE.read_text(encoding="utf-8", errors="ignore"))
            else:
                self.log_view.setPlainText("No logs yet.")
        except Exception as e:
            self.log_view.setPlainText(f"Error reading logs: {e}")

    def _choose_quarantine(self):
        path = QFileDialog.getExistingDirectory(self, "Choose quarantine folder")
        if path:
            self.quarantine_dir = Path(path)
            self.qpath_line.setText(str(self.quarantine_dir))
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)


# Main
def main():
    app = QApplication(sys.argv)
    win = GuardianAV()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()