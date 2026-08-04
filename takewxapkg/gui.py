from __future__ import annotations

import html
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QThread, QTimer, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices, QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .path_finder import (
    APPID_PATTERN,
    WxapkgCandidate,
    candidate_bundle_key,
    candidate_bundle_label,
    discover_wxapkg,
    find_existing_roots,
    format_mtime,
    format_size,
    scan_for_wxapkg,
)
from .wxapkg_core import BadAppIDError, NeedAppIDError, WxapkgError, extract_packages


def app_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def app_resource_path(name: str) -> Path:
    bundle_dir = getattr(sys, "_MEIPASS", None)
    if bundle_dir:
        return Path(bundle_dir) / name
    return app_base_dir() / name


def safe_dir_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    cleaned = cleaned.strip("._-")
    return cleaned or "unknown"


ExtractJob = tuple[str, list[Path], str, Path]
DeleteProgress = Callable[[int, str], None]


def build_extract_jobs(
    candidates: list[WxapkgCandidate],
    output_base: Path,
    manual_appid: str = "",
    force_appid: bool = False,
) -> tuple[list[ExtractJob], list[str]]:
    manual_appid = manual_appid.strip()
    grouped: dict[tuple[str, str], list[WxapkgCandidate]] = defaultdict(list)
    for item in candidates:
        grouped[candidate_bundle_key(item)].append(item)

    jobs: list[ExtractJob] = []
    encrypted_without_appid: list[str] = []
    for items in grouped.values():
        first = max(items, key=lambda item: item.modified)
        label = candidate_bundle_label(first)
        inferred_appid = first.appid if APPID_PATTERN.match(first.appid) else ""
        appid = manual_appid if force_appid and manual_appid else inferred_appid
        output_dir = output_base / safe_dir_name(label)
        paths = [
            item.path
            for item in sorted(
                items,
                key=lambda item: (0 if item.name == "__APP__.wxapkg" else 1, item.name.lower()),
            )
        ]
        jobs.append((label, paths, appid, output_dir))
        if not appid and any(item.mode == "encrypted" for item in items):
            encrypted_without_appid.append(label)
    return jobs, encrypted_without_appid


def expand_related_candidates(
    selected: list[WxapkgCandidate],
    all_candidates: list[WxapkgCandidate],
) -> list[WxapkgCandidate]:
    selected_keys = {candidate_bundle_key(item) for item in selected}
    if not selected_keys:
        return []
    return [item for item in all_candidates if candidate_bundle_key(item) in selected_keys]


def collect_wxapkg_delete_targets(root: Path, max_files: int = 20000) -> list[Path]:
    root = Path(root)
    if not root.exists():
        return []
    if root.is_file():
        return [root.resolve()] if root.suffix.lower() == ".wxapkg" else []

    base = root.resolve()
    targets: list[Path] = []
    seen: set[str] = set()
    for current, dirs, files in os.walk(base):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
        for filename in files:
            if not filename.lower().endswith(".wxapkg"):
                continue
            path = (current_path / filename).resolve()
            try:
                path.relative_to(base)
            except ValueError:
                continue
            key = str(path).lower()
            if key in seen:
                continue
            seen.add(key)
            targets.append(path)
            if len(targets) >= max_files:
                return sorted(targets)
    return sorted(targets)


def delete_wxapkg_files(
    root: Path,
    targets: list[Path],
    progress: DeleteProgress | None = None,
) -> tuple[int, list[str]]:
    root = Path(root)
    if root.is_file():
        base = root.parent.resolve()
    else:
        base = root.resolve()

    deleted = 0
    failures: list[str] = []
    total = max(1, len(targets))
    for index, target in enumerate(targets, start=1):
        path = Path(target).resolve()
        try:
            path.relative_to(base)
        except ValueError:
            failures.append(f"跳过目录外文件: {path}")
            continue
        if path.suffix.lower() != ".wxapkg":
            failures.append(f"跳过非 wxapkg 文件: {path}")
            continue
        try:
            path.unlink()
            deleted += 1
            if progress:
                progress(int(index / total * 100), f"已删除 {path.name}")
        except FileNotFoundError:
            if progress:
                progress(int(index / total * 100), f"文件已不存在 {path.name}")
        except OSError as exc:
            failures.append(f"{path}: {exc}")

    if root.is_dir():
        _remove_empty_dirs(base)
    return deleted, failures


def _remove_empty_dirs(root: Path) -> None:
    for current, _dirs, _files in os.walk(root, topdown=False):
        path = Path(current)
        if path == root:
            continue
        try:
            path.rmdir()
        except OSError:
            pass


class DiscoverWorker(QThread):
    done = Signal(object, object)
    failed = Signal(str)

    def run(self) -> None:
        try:
            roots, candidates = discover_wxapkg()
            self.done.emit(roots, candidates)
        except Exception as exc:
            self.failed.emit(str(exc))


class ScanWorker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, root: Path):
        super().__init__()
        self.root = root

    def run(self) -> None:
        try:
            self.done.emit(scan_for_wxapkg(self.root))
        except Exception as exc:
            self.failed.emit(str(exc))


class DeleteWorker(QThread):
    progress = Signal(int, str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, root: Path, targets: list[Path]):
        super().__init__()
        self.root = root
        self.targets = targets

    def run(self) -> None:
        try:
            deleted, failures = delete_wxapkg_files(
                self.root,
                self.targets,
                progress=lambda percent, message: self.progress.emit(percent, message),
            )
            self.done.emit((deleted, failures))
        except Exception as exc:
            self.failed.emit(f"删除失败: {exc}")


class ExtractWorker(QThread):
    progress = Signal(str, int, str)
    log = Signal(str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, jobs: list[ExtractJob]):
        super().__init__()
        self.jobs = jobs

    def run(self) -> None:
        results = []
        try:
            total = len(self.jobs)
            for job_index, (label, paths, appid, output_dir) in enumerate(self.jobs, start=1):
                self.log.emit(f"开始处理 {label}，共 {len(paths)} 个包")

                def relay(stage: str, percent: int, message: str) -> None:
                    base = int((job_index - 1) / total * 100)
                    span = max(1, int(100 / total))
                    merged = min(99, base + int(percent / 100 * span))
                    self.progress.emit(stage, merged, f"{label}: {message}")

                result = extract_packages(paths, output_dir, appid=appid, progress=relay)
                results.append(result)
                self.log.emit(
                    f"完成 {label}: 解包 {result.extracted_files} 个文件，生成 {len(result.generated_files)} 个项目文件，ZIP 已生成 {result.zip_path.name}"
                )
            self.progress.emit("completed", 100, "全部任务完成")
            self.done.emit(results)
        except NeedAppIDError as exc:
            self.failed.emit(str(exc))
        except BadAppIDError as exc:
            self.failed.emit(str(exc))
        except WxapkgError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"处理失败: {exc}")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("takeWxapkg")
        self.resize(1180, 760)
        self.setMinimumSize(980, 640)

        icon_path = app_resource_path("icon.ico")
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.base_dir = app_base_dir()
        self.output_base = self.base_dir / "output"
        self.output_base.mkdir(parents=True, exist_ok=True)
        self.candidates: list[WxapkgCandidate] = []
        self.visible_candidates: list[WxapkgCandidate] = []
        self.last_results: list[object] = []
        self.worker: QThread | None = None
        self.auto_scan_running = False

        self._build_ui()
        self._apply_theme()

        roots = find_existing_roots()
        if roots:
            self._set_path_choices(roots, roots[0])
            self._log(f"已发现 {len(roots)} 个候选微信目录，可在目录下拉框选择")
        else:
            self._log("暂未发现微信缓存目录，可点击“全盘候选搜索”或手动选择")

        QTimer.singleShot(450, self.discover_all)
        self.watch_timer = QTimer(self)
        self.watch_timer.timeout.connect(self._watch_current_dir)
        self.watch_timer.start(5000)

    def _build_ui(self) -> None:
        root = QWidget()
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(246)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(22, 24, 22, 24)
        side.setSpacing(16)

        title = QLabel("takeWxapkg")
        title.setObjectName("AppTitle")
        subtitle = QLabel("微信小程序包本地解包")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        side.addWidget(title)
        side.addWidget(subtitle)

        self.stat_found = self._metric("发现", "0")
        self.stat_selected = self._metric("选中", "0")
        self.stat_mode = self._metric("状态", "待扫描")
        side.addWidget(self.stat_found)
        side.addWidget(self.stat_selected)
        side.addWidget(self.stat_mode)
        side.addStretch()

        self.auto_watch = QCheckBox("监控目录变化")
        self.auto_watch.setChecked(True)
        side.addWidget(self.auto_watch)
        self.open_output_btn = self._button("打开输出目录")
        self.open_output_btn.clicked.connect(lambda: self._open_path(self.output_base))
        side.addWidget(self.open_output_btn)

        content = QWidget()
        main = QVBoxLayout(content)
        main.setContentsMargins(26, 24, 26, 20)
        main.setSpacing(10)

        disclaimer = QFrame()
        disclaimer.setObjectName("LegalNotice")
        disclaimer.setMaximumHeight(82)
        disclaimer_layout = QHBoxLayout(disclaimer)
        disclaimer_layout.setContentsMargins(14, 10, 14, 10)
        disclaimer_layout.setSpacing(12)
        disclaimer_title = QLabel("免责声明")
        disclaimer_title.setObjectName("LegalNoticeTitle")
        disclaimer_title.setFixedWidth(72)
        disclaimer_title.setAlignment(Qt.AlignmentFlag.AlignTop)
        disclaimer_body = QLabel(
            "该工具仅限用于: 线上代码安全审计以便快速发现漏洞, 学习反编译原理,\n"
            "请遵守国家法律, 严禁任何非法用途,\n"
            "若你使用的范围不在国家法律允许的范围内， 造成的一切法律后果与作者无关。"
        )
        disclaimer_body.setObjectName("LegalNoticeBody")
        disclaimer_body.setWordWrap(True)
        disclaimer_layout.addWidget(disclaimer_title)
        disclaimer_layout.addWidget(disclaimer_body, 1)
        main.addWidget(disclaimer)

        hero = QFrame()
        hero.setObjectName("Hero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 14, 18, 14)
        hero_layout.setSpacing(9)
        hero_title = QLabel("自动搜索本机 wxapkg，选择后直接解包")
        hero_title.setObjectName("HeroTitle")
        hero_desc = QLabel("候选目录只列出微信 4.x 的 xwechat/radium/users/*/applet/packages，可手动选择其它目录。")
        hero_desc.setObjectName("Muted")
        hero_desc.setWordWrap(True)
        hero_layout.addWidget(hero_title)
        hero_layout.addWidget(hero_desc)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        grid.setColumnStretch(1, 3)
        grid.setColumnStretch(2, 2)
        grid.setColumnStretch(4, 2)
        self.path_input = QComboBox()
        self.path_input.setEditable(True)
        self.path_input.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.path_input.setMaxVisibleItems(12)
        self.path_input.setToolTip("选择或输入要扫描的 wxapkg 目录")
        self.path_input.lineEdit().setPlaceholderText("微信 Applet/packages 目录，或任意包含 .wxapkg 的目录")
        self.path_input.lineEdit().returnPressed.connect(self.scan_current_dir)
        self.path_input.activated.connect(lambda _index: self.scan_current_dir())
        grid.addWidget(QLabel("目录"), 0, 0)
        grid.addWidget(self.path_input, 0, 1, 1, 4)
        browse_dir = self._button("选择目录")
        browse_dir.clicked.connect(self.choose_dir)
        grid.addWidget(browse_dir, 0, 5)
        browse_files = self._button("添加文件")
        browse_files.clicked.connect(self.choose_files)
        grid.addWidget(browse_files, 0, 6)

        self.appid_input = QLineEdit()
        self.appid_input.setPlaceholderText("加密包 AppID，自动识别到 wx... 时可留空")
        grid.addWidget(QLabel("AppID"), 1, 0)
        grid.addWidget(self.appid_input, 1, 1, 1, 2)
        self.force_appid_checkbox = QCheckBox("强制使用上方 AppID")
        self.force_appid_checkbox.setToolTip("默认按选中包所在目录的 AppID 解密；只有需要手动覆盖时再勾选。")
        self.force_appid_checkbox.toggled.connect(self._on_force_appid_toggled)
        grid.addWidget(self.force_appid_checkbox, 2, 1, 1, 2)
        self.appid_input.setReadOnly(True)
        self.output_input = QLineEdit(str(self.output_base))
        grid.addWidget(QLabel("输出"), 1, 3)
        grid.addWidget(self.output_input, 1, 4, 1, 2)
        choose_output = self._button("更改")
        choose_output.clicked.connect(self.choose_output)
        grid.addWidget(choose_output, 1, 6)
        hero_layout.addLayout(grid)
        main.addWidget(hero)

        actions = QHBoxLayout()
        self.discover_btn = self._primary_button("全盘候选搜索")
        self.discover_btn.clicked.connect(self.discover_all)
        actions.addWidget(self.discover_btn)
        self.scan_btn = self._button("扫描当前目录")
        self.scan_btn.clicked.connect(self.scan_current_dir)
        actions.addWidget(self.scan_btn)
        self.extract_btn = self._primary_button("反编译选中")
        self.extract_btn.clicked.connect(self.extract_selected)
        actions.addWidget(self.extract_btn)
        self.extract_all_btn = self._button("批量反编译全部")
        self.extract_all_btn.clicked.connect(self.extract_all)
        actions.addWidget(self.extract_all_btn)
        self.delete_all_btn = self._button("全部删除")
        self.delete_all_btn.setObjectName("DangerButton")
        self.delete_all_btn.setToolTip("删除当前目录下所有 wxapkg 包文件")
        self.delete_all_btn.clicked.connect(self.delete_all_packages)
        actions.addWidget(self.delete_all_btn)
        actions.addStretch()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("过滤 AppID / 文件名 / 路径")
        self.search_input.textChanged.connect(self.refresh_table)
        actions.addWidget(self.search_input, 1)
        main.addLayout(actions)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["AppID", "文件", "大小", "修改时间", "类型", "路径"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self.update_selection)
        self.table.doubleClicked.connect(lambda: self.extract_selected())
        self.table.setMinimumHeight(250)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        main.addWidget(self.table, 1)

        progress_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        progress_row.addWidget(self.progress, 1)
        self.status_label = QLabel("就绪")
        self.status_label.setObjectName("StatusLabel")
        progress_row.addWidget(self.status_label)
        main.addLayout(progress_row)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMinimumHeight(120)
        self.log_box.setMaximumHeight(170)
        self.log_box.setFont(QFont("Consolas", 9))
        main.addWidget(self.log_box)

        outer.addWidget(sidebar)
        outer.addWidget(content, 1)
        self.setCentralWidget(root)

    def _metric(self, label: str, value: str) -> QFrame:
        frame = QFrame()
        frame.setObjectName("Metric")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        label_widget = QLabel(label)
        label_widget.setObjectName("MetricLabel")
        value_widget = QLabel(value)
        value_widget.setObjectName("MetricValue")
        frame.value_widget = value_widget  # type: ignore[attr-defined]
        layout.addWidget(label_widget)
        layout.addWidget(value_widget)
        return frame

    def _button(self, text: str) -> QPushButton:
        button = QPushButton(text)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setMinimumHeight(38)
        return button

    def _primary_button(self, text: str) -> QPushButton:
        button = self._button(text)
        button.setObjectName("PrimaryButton")
        return button

    def _apply_theme(self) -> None:
        combo_arrow = app_resource_path("assets/chevron-down.svg").as_posix()
        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background: #111827;
                color: #e5e7eb;
                font-family: "Microsoft YaHei", "Segoe UI";
                font-size: 13px;
            }
            #Sidebar {
                background: #0b1220;
                border-right: 1px solid #243044;
            }
            #AppTitle {
                color: #f8fafc;
                font-size: 28px;
                font-weight: 800;
            }
            #Hero {
                background: #172033;
                border: 1px solid #2f3b52;
                border-radius: 10px;
            }
            #HeroTitle {
                color: #f8fafc;
                font-size: 20px;
                font-weight: 700;
            }
            #LegalNotice {
                background: #111c2f;
                border: 1px solid #334155;
                border-radius: 8px;
            }
            #LegalNoticeTitle {
                color: #fbbf24;
                font-size: 15px;
                font-weight: 800;
            }
            #LegalNoticeBody {
                color: #fde68a;
                font-size: 12px;
            }
            #Muted, #MetricLabel {
                color: #93a4b8;
            }
            #Metric {
                background: #121c2d;
                border: 1px solid #26354c;
                border-radius: 8px;
            }
            #MetricValue {
                color: #ffffff;
                font-size: 22px;
                font-weight: 700;
            }
            QLineEdit {
                min-height: 34px;
                padding: 0 11px;
                color: #eff6ff;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 7px;
                selection-background-color: #14b8a6;
            }
            QLineEdit:focus {
                border: 1px solid #22d3ee;
                background: #101b2e;
            }
            QComboBox {
                min-height: 34px;
                padding: 0 34px 0 11px;
                color: #eff6ff;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 7px;
                selection-background-color: #14b8a6;
            }
            QComboBox:focus {
                border: 1px solid #22d3ee;
                background: #101b2e;
            }
            QComboBox QLineEdit {
                min-height: 32px;
                padding: 0;
                border: none;
                background: transparent;
            }
            QComboBox::drop-down {
                width: 30px;
                border-left: 1px solid #334155;
            }
            QComboBox QAbstractItemView {
                color: #eff6ff;
                background: #0f172a;
                border: 1px solid #334155;
                selection-background-color: #0f766e;
            }
            QPushButton {
                color: #dbeafe;
                background: #1f2a3d;
                border: 1px solid #364762;
                border-radius: 7px;
                padding: 7px 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #27364f;
                border-color: #4f6385;
            }
            QPushButton:disabled {
                color: #64748b;
                background: #182133;
                border-color: #263248;
            }
            #PrimaryButton {
                color: #082f2e;
                background: #2dd4bf;
                border: 1px solid #5eead4;
            }
            #PrimaryButton:hover {
                background: #5eead4;
            }
            #DangerButton {
                color: #ffe4e6;
                background: #7f1d1d;
                border: 1px solid #b91c1c;
            }
            #DangerButton:hover {
                background: #991b1b;
                border-color: #ef4444;
            }
            QTableWidget {
                background: #0f172a;
                alternate-background-color: #111c2f;
                gridline-color: #26354c;
                border: 1px solid #2f3b52;
                border-radius: 8px;
            }
            QHeaderView::section {
                background: #1a2436;
                color: #cbd5e1;
                padding: 8px;
                border: none;
                border-right: 1px solid #2f3b52;
                font-weight: 700;
            }
            QTableWidget::item {
                padding: 8px;
                border: none;
            }
            QTableWidget::item:selected {
                color: #ffffff;
                background: #0f766e;
            }
            QProgressBar {
                height: 8px;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: #2dd4bf;
                border-radius: 4px;
            }
            QTextEdit {
                background: #08111f;
                border: 1px solid #2f3b52;
                border-radius: 8px;
                color: #cbd5e1;
                padding: 8px;
            }
            QCheckBox {
                color: #cbd5e1;
                spacing: 8px;
            }
            #StatusLabel {
                color: #a7f3d0;
                min-width: 96px;
            }
            """
            + f"""
            QComboBox::down-arrow {{
                image: url("{combo_arrow}");
                width: 16px;
                height: 16px;
            }}
            """
        )

    def _path_text(self) -> str:
        return self.path_input.currentText().strip()

    def _set_path_text(self, value: str | Path) -> None:
        text = str(value)
        index = self.path_input.findText(text, Qt.MatchFlag.MatchFixedString)
        if index >= 0:
            self.path_input.setCurrentIndex(index)
            return
        self.path_input.insertItem(0, text)
        self.path_input.setCurrentIndex(0)

    def _set_path_choices(self, roots: list[Path], selected: Path | None = None) -> None:
        selected_text = str(selected) if selected else self._path_text()
        existing = [self.path_input.itemText(index) for index in range(self.path_input.count())]
        choices: list[str] = []
        seen: set[str] = set()
        for value in [selected_text, *(str(root) for root in roots), *existing]:
            text = value.strip()
            key = text.lower()
            if not text or key in seen:
                continue
            seen.add(key)
            choices.append(text)
        self.path_input.clear()
        self.path_input.addItems(choices)
        for index, text in enumerate(choices):
            self.path_input.setItemData(index, text, Qt.ItemDataRole.ToolTipRole)
        if selected_text:
            self._set_path_text(selected_text)

    def choose_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "选择包含 wxapkg 的目录", self._path_text())
        if directory:
            self._set_path_text(directory)
            self.scan_current_dir()

    def choose_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "选择 wxapkg 文件", str(Path.home()), "wxapkg (*.wxapkg)")
        if not files:
            return
        added: list[WxapkgCandidate] = []
        for file in files:
            added.extend(scan_for_wxapkg(Path(file)))
        self._merge_candidates(added)
        self._log(f"已添加 {len(added)} 个文件")

    def choose_output(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "选择输出目录", self.output_input.text())
        if directory:
            self.output_input.setText(directory)
            self.output_base = Path(directory)
            self.output_base.mkdir(parents=True, exist_ok=True)

    def discover_all(self) -> None:
        if self.worker and self.worker.isRunning():
            self._log("已有任务正在运行")
            return
        self._set_busy(True, "正在搜索微信小程序缓存目录...")
        worker = DiscoverWorker()
        worker.done.connect(self._on_discover_done)
        worker.failed.connect(self._on_worker_failed)
        worker.finished.connect(lambda: self._set_busy(False))
        self.worker = worker
        worker.start()

    def scan_current_dir(self) -> None:
        if self.worker and self.worker.isRunning():
            self._log("已有任务正在运行")
            return
        value = self._path_text()
        if not value:
            self._log("请先选择目录或文件")
            return
        root = Path(value)
        if not root.exists():
            self._log(f"路径不存在: {root}")
            return
        self._set_busy(True, f"正在扫描 {root}...")
        worker = ScanWorker(root)
        worker.done.connect(self._on_scan_done)
        worker.failed.connect(self._on_worker_failed)
        worker.finished.connect(lambda: self._set_busy(False))
        self.worker = worker
        worker.start()

    def extract_selected(self) -> None:
        selected = self._selected_candidates()
        if not selected and self.visible_candidates:
            row = self.table.currentRow()
            if row >= 0:
                selected = [self.visible_candidates[row]]
        if not selected:
            self._log("请先选择要反编译的 wxapkg")
            return
        expanded = expand_related_candidates(selected, self.candidates)
        if len(expanded) > len(selected):
            self._log(f"已自动补齐同版本主包/分包: {len(selected)} -> {len(expanded)} 个包")
            selected = expanded
        self._start_extract(selected)

    def extract_all(self) -> None:
        if not self.candidates:
            self._log("当前没有可反编译的 wxapkg")
            return
        reply = QMessageBox.question(
            self,
            "批量反编译",
            f"将处理当前列表中的 {len(self.candidates)} 个 wxapkg，确定继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._start_extract(self.candidates)

    def delete_all_packages(self) -> None:
        if self.worker and self.worker.isRunning():
            self._log("已有任务正在运行")
            return

        value = self._path_text()
        if not value:
            self._log("请先选择要清理的目录")
            return
        root = Path(value)
        if not root.exists():
            self._log(f"路径不存在: {root}")
            return

        targets = collect_wxapkg_delete_targets(root)
        if not targets:
            self._log("当前目录下没有可删除的 wxapkg 包")
            return

        reply = QMessageBox.question(
            self,
            "全部删除",
            f"将删除当前目录下 {len(targets)} 个 wxapkg 包文件。\n\n目录：{root}\n\n确定继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.progress.setValue(0)
        self._set_busy(True, "正在删除 wxapkg 包...")
        worker = DeleteWorker(root, targets)
        worker.progress.connect(self._on_delete_progress)
        worker.done.connect(self._on_delete_done)
        worker.failed.connect(self._on_worker_failed)
        worker.finished.connect(lambda: self._set_busy(False))
        self.worker = worker
        worker.start()

    def _start_extract(self, candidates: list[WxapkgCandidate]) -> None:
        if self.worker and self.worker.isRunning():
            self._log("已有任务正在运行")
            return

        output_base = Path(self.output_input.text().strip() or str(self.output_base)).resolve()
        output_base.mkdir(parents=True, exist_ok=True)
        self.output_base = output_base

        force_appid = self.force_appid_checkbox.isChecked()
        manual_appid = self.appid_input.text().strip()
        if force_appid and not manual_appid:
            self._log("请先填写要强制使用的 AppID")
            self.appid_input.setFocus()
            return
        if force_appid and not APPID_PATTERN.match(manual_appid):
            self._log(f"手动 AppID 格式不正确: {manual_appid}")
            self.appid_input.setFocus()
            return

        jobs, encrypted_without_appid = build_extract_jobs(
            candidates,
            output_base,
            manual_appid=manual_appid,
            force_appid=force_appid,
        )
        if encrypted_without_appid:
            self._log(f"加密包缺少 AppID: {', '.join(encrypted_without_appid[:4])}")
            self.appid_input.setFocus()
            return

        self.progress.setValue(0)
        self._set_busy(True, "正在运行")
        worker = ExtractWorker(jobs)
        worker.progress.connect(self._on_extract_progress)
        worker.log.connect(self._log)
        worker.done.connect(self._on_extract_done)
        worker.failed.connect(self._on_worker_failed)
        worker.finished.connect(lambda: self._set_busy(False))
        self.worker = worker
        worker.start()

    def _selected_candidates(self) -> list[WxapkgCandidate]:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        return [self.visible_candidates[row] for row in rows if 0 <= row < len(self.visible_candidates)]

    def _on_discover_done(self, roots: list[Path], candidates: list[WxapkgCandidate]) -> None:
        best_root = self._best_watch_root(candidates) or (roots[0] if roots else None)
        if best_root:
            self._set_path_choices(roots, best_root)
        if roots:
            self._log(f"候选目录已更新：{len(roots)} 个，可在目录下拉框选择")
        self.candidates = candidates
        self.refresh_table()
        self._log(f"自动搜索完成，发现 {len(candidates)} 个 wxapkg")

    def _on_scan_done(self, candidates: list[WxapkgCandidate]) -> None:
        self.candidates = candidates
        self.refresh_table()
        self._log(f"扫描完成，发现 {len(candidates)} 个 wxapkg")

    def _merge_candidates(self, candidates: list[WxapkgCandidate]) -> None:
        current = {str(item.path).lower(): item for item in self.candidates}
        for item in candidates:
            current[str(item.path).lower()] = item
        self.candidates = sorted(current.values(), key=lambda item: item.modified, reverse=True)
        self.refresh_table()

    def _best_watch_root(self, candidates: list[WxapkgCandidate]) -> Path | None:
        counts: dict[Path, int] = {}
        for item in candidates:
            parts = list(item.path.parents)
            package_roots = [
                parent
                for parent in parts
                if parent.name.lower() in {"packages", "publiclib"}
            ]
            root = package_roots[0] if package_roots else item.root
            counts[root] = counts.get(root, 0) + 1
        if not counts:
            return None
        return max(counts.items(), key=lambda pair: pair[1])[0]

    def _on_extract_progress(self, _stage: str, percent: int, _message: str) -> None:
        self.progress.setValue(percent)
        self.status_label.setText("完成" if percent >= 100 else "正在运行")

    def _on_extract_done(self, results: list[object]) -> None:
        self.last_results = results
        self.progress.setValue(100)
        self.status_label.setText("完成")
        for result in results:
            self._log(f"反编译目录: {result.src_dir}")
            self._log(f"下载包: {result.zip_path}")
            if result.warnings:
                self._log(f"提示: {len(result.warnings)} 条 warning，详见 reports")

    def _on_delete_progress(self, percent: int, _message: str) -> None:
        self.progress.setValue(percent)
        self.status_label.setText("正在运行")

    def _on_delete_done(self, result: object) -> None:
        deleted, failures = result
        self.progress.setValue(100)
        if failures:
            self.status_label.setText("删除完成，有失败")
            self._log(f"全部删除完成：已删除 {deleted} 个包，{len(failures)} 个失败")
            for message in failures[:5]:
                self._log(f"删除失败: {message}")
        else:
            self.status_label.setText("删除完成")
            self._log(f"全部删除完成：已删除 {deleted} 个 wxapkg 包")
        QTimer.singleShot(250, self.scan_current_dir)

    def _on_worker_failed(self, message: str) -> None:
        self.progress.setValue(0)
        self.status_label.setText("失败")
        self._log(f"<b style='color:#fecaca'>失败:</b> {html.escape(message)}", raw_html=True)

    def refresh_table(self) -> None:
        keyword = self.search_input.text().strip().lower()
        if keyword:
            visible = [
                item
                for item in self.candidates
                if keyword in item.appid.lower()
                or keyword in item.name.lower()
                or keyword in str(item.path).lower()
            ]
        else:
            visible = list(self.candidates)
        self.visible_candidates = visible

        self.table.setRowCount(len(visible))
        for row, item in enumerate(visible):
            values = [
                item.appid,
                item.name,
                format_size(item.size),
                format_mtime(item.modified),
                self._mode_label(item.mode),
                str(item.path),
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setToolTip(value)
                if column in (0, 1, 4):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, column, cell)

        self.stat_found.value_widget.setText(str(len(self.candidates)))  # type: ignore[attr-defined]
        self.update_selection()

    def update_selection(self) -> None:
        selected = self._selected_candidates()
        count = len(selected)
        self.stat_selected.value_widget.setText(str(count))  # type: ignore[attr-defined]
        if not self.force_appid_checkbox.isChecked():
            self._auto_fill_appid(selected or self.visible_candidates)

    def _auto_fill_appid(self, items: list[WxapkgCandidate] | None = None) -> None:
        if self.force_appid_checkbox.isChecked():
            return
        items = items or self.visible_candidates
        appids = [item.appid for item in items if APPID_PATTERN.match(item.appid)]
        if not appids:
            self.appid_input.clear()
            self.appid_input.setPlaceholderText("未从路径识别到 AppID")
            return
        first = appids[0]
        if all(appid == first for appid in appids):
            self.appid_input.setText(first)
            self.appid_input.setPlaceholderText("自动使用选中包的 AppID")
        else:
            self.appid_input.clear()
            self.appid_input.setPlaceholderText("已选择多个 AppID，解包时会分别使用各自 AppID")

    def _on_force_appid_toggled(self, checked: bool) -> None:
        self.appid_input.setReadOnly(not checked)
        if checked:
            self.appid_input.setPlaceholderText("手动指定 AppID，例如 wx1234567890abcdef")
            self.appid_input.setFocus()
        else:
            self._auto_fill_appid(self._selected_candidates() or self.visible_candidates)

    def _watch_current_dir(self) -> None:
        if not self.auto_watch.isChecked():
            return
        if self.worker and self.worker.isRunning():
            return
        value = self._path_text()
        if not value:
            return
        root = Path(value)
        if not root.is_dir():
            return
        before = {str(item.path).lower() for item in self.candidates}
        found = scan_for_wxapkg(root)
        after = {str(item.path).lower() for item in found}
        if after != before:
            self.candidates = found
            self.refresh_table()
            new_count = len(after - before)
            if new_count:
                self._log(f"检测到 {new_count} 个新 wxapkg")

    def _set_busy(self, busy: bool, message: str | None = None) -> None:
        for button in (self.discover_btn, self.scan_btn, self.extract_btn, self.extract_all_btn, self.delete_all_btn):
            button.setDisabled(busy)
        if busy:
            self.status_label.setText("正在运行")
            self.stat_mode.value_widget.setText("运行中" if busy else "就绪")  # type: ignore[attr-defined]
            if message:
                self._log(message)
        elif message:
            self.status_label.setText(message)
            self.stat_mode.value_widget.setText("就绪")  # type: ignore[attr-defined]
        elif not busy:
            if self.status_label.text() == "正在运行":
                self.status_label.setText("就绪")
            self.stat_mode.value_widget.setText("就绪")  # type: ignore[attr-defined]

    def _mode_label(self, mode: str) -> str:
        return {"encrypted": "加密", "plain": "普通", "unknown": "未知"}.get(mode, mode)

    def _open_path(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _log(self, message: str, raw_html: bool = False) -> None:
        if raw_html:
            text = message
        else:
            text = html.escape(message)
        self.log_box.append(f"<span style='color:#cbd5e1'>{text}</span>")
        scrollbar = self.log_box.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())


def run() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("takeWxapkg")
    window = MainWindow()
    window.show()
    return app.exec()
