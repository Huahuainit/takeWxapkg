from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .wxapkg_core import detect_mode


APPID_PATTERN = re.compile(r"^wx[a-f0-9]{16}$")
SKIP_DIR_NAMES = {
    "$recycle.bin",
    ".git",
    ".svn",
    "node_modules",
    "__pycache__",
    "system volume information",
    "windows",
    "program files",
    "program files (x86)",
}


@dataclass(frozen=True)
class WxapkgCandidate:
    appid: str
    path: Path
    name: str
    size: int
    modified: float
    mode: str
    root: Path


def candidate_bundle_dir(item: WxapkgCandidate) -> Path:
    return infer_bundle_dir(item.path, item.appid)


def candidate_bundle_key(item: WxapkgCandidate) -> tuple[str, str]:
    return (item.appid.lower(), str(candidate_bundle_dir(item).resolve()).lower())


def candidate_bundle_version(item: WxapkgCandidate) -> str:
    bundle_dir = candidate_bundle_dir(item)
    if bundle_dir.parent.name.lower() == item.appid.lower():
        return bundle_dir.name
    return ""


def candidate_bundle_label(item: WxapkgCandidate) -> str:
    version = candidate_bundle_version(item)
    if APPID_PATTERN.match(item.appid) and version:
        return f"{item.appid}_v{version}"
    return item.appid or item.path.stem


def default_candidate_roots() -> list[Path]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    dynamic_roots: list[Path] = []
    for users_dir in (
        appdata / "Tencent" / "xwechat" / "radium" / "users",
        local_appdata / "Tencent" / "xwechat" / "radium" / "users",
    ):
        if not users_dir.is_dir():
            continue
        try:
            user_dirs = [item for item in users_dir.iterdir() if item.is_dir() and not item.name.startswith(".")]
        except OSError:
            user_dirs = []
        for user_dir in sorted(user_dirs, key=_safe_mtime, reverse=True):
            dynamic_roots.append(user_dir / "applet" / "packages")
    roots = [*dynamic_roots]
    return _dedupe_paths(roots)


def find_existing_roots() -> list[Path]:
    roots: list[Path] = []
    for root in default_candidate_roots():
        if root.is_dir():
            roots.append(root)
    return _dedupe_paths(roots)


def choose_default_root() -> Path | None:
    for root in find_existing_roots():
        if root.name.lower() == "packages":
            return root
    roots = find_existing_roots()
    return roots[0] if roots else None


def scan_for_wxapkg(root: Path, max_depth: int = 7, max_files: int = 5000) -> list[WxapkgCandidate]:
    root = Path(root)
    if not root.exists():
        return []
    if root.is_file():
        if root.suffix.lower() == ".wxapkg":
            return [_candidate_from_file(root, root.parent)]
        return []

    results: list[WxapkgCandidate] = []
    root_resolved = root.resolve()
    for current, dirs, files in os.walk(root_resolved):
        current_path = Path(current)
        depth = len(current_path.relative_to(root_resolved).parts)
        if depth >= max_depth:
            dirs[:] = []
        else:
            dirs[:] = [
                item
                for item in dirs
                if item.lower() not in SKIP_DIR_NAMES and not item.startswith(".")
            ]

        for filename in files:
            if not filename.lower().endswith(".wxapkg"):
                continue
            path = current_path / filename
            try:
                results.append(_candidate_from_file(path, root_resolved))
            except OSError:
                continue
            if len(results) >= max_files:
                return sorted(_dedupe_candidates(results), key=lambda item: item.modified, reverse=True)

    return sorted(_dedupe_candidates(results), key=lambda item: item.modified, reverse=True)


def discover_wxapkg(max_depth: int = 7, max_files: int = 5000) -> tuple[list[Path], list[WxapkgCandidate]]:
    roots = find_existing_roots()
    all_items: list[WxapkgCandidate] = []
    for root in roots:
        all_items.extend(scan_for_wxapkg(root, max_depth=max_depth, max_files=max_files))
        if len(all_items) >= max_files:
            break
    return roots, sorted(_dedupe_candidates(all_items), key=lambda item: item.modified, reverse=True)


def group_by_appid(items: list[WxapkgCandidate]) -> dict[str, list[WxapkgCandidate]]:
    grouped: dict[str, list[WxapkgCandidate]] = {}
    for item in items:
        grouped.setdefault(item.appid, []).append(item)
    for packages in grouped.values():
        packages.sort(key=lambda item: item.modified, reverse=True)
    return dict(sorted(grouped.items(), key=lambda pair: pair[1][0].modified, reverse=True))


def infer_appid(path: Path) -> str:
    for part in reversed(path.parts):
        if APPID_PATTERN.match(part):
            return part
    for part in reversed(path.parts):
        lowered = part.lower()
        if lowered.startswith("wx") and len(lowered) >= 8:
            return part
    parent = path.parent.name
    return parent if parent else "unknown"


def infer_bundle_dir(path: Path, appid: str) -> Path:
    path = Path(path)
    if not appid:
        return path.parent

    parts = list(path.parts)
    lowered = [part.lower() for part in parts]
    appid_lower = appid.lower()
    try:
        appid_index = len(lowered) - 1 - list(reversed(lowered)).index(appid_lower)
    except ValueError:
        return path.parent

    # WeChat 4.x commonly stores packages as packages/{appid}/{version}/*.wxapkg.
    # Files in the same version directory are one mini-program package set.
    if appid_index + 2 < len(parts):
        return Path(*parts[: appid_index + 2])
    return Path(*parts[: appid_index + 1])


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def format_mtime(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def _candidate_from_file(path: Path, root: Path) -> WxapkgCandidate:
    stat = path.stat()
    return WxapkgCandidate(
        appid=infer_appid(path),
        path=path,
        name=path.name,
        size=stat.st_size,
        modified=stat.st_mtime,
        mode=detect_mode(path),
        root=root,
    )


def _safe_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def _dedupe_candidates(items: list[WxapkgCandidate]) -> list[WxapkgCandidate]:
    valid_groups: dict[str, dict[str, list[WxapkgCandidate]]] = {}
    loose_latest: dict[tuple[str, str], WxapkgCandidate] = {}
    for item in items:
        if APPID_PATTERN.match(item.appid):
            appid_key = item.appid.lower()
            bundle_key = str(candidate_bundle_dir(item).resolve()).lower()
            valid_groups.setdefault(appid_key, {}).setdefault(bundle_key, []).append(item)
            continue

        key = (item.appid.lower(), item.name.lower())
        current = loose_latest.get(key)
        if current is None or item.modified > current.modified:
            loose_latest[key] = item

    result = list(loose_latest.values())
    for bundle_map in valid_groups.values():
        latest_bundle = max(
            bundle_map.values(),
            key=lambda group: max((item.modified for item in group), default=0.0),
        )
        latest_by_name: dict[str, WxapkgCandidate] = {}
        for item in latest_bundle:
            current = latest_by_name.get(item.name.lower())
            if current is None or item.modified > current.modified:
                latest_by_name[item.name.lower()] = item
        result.extend(latest_by_name.values())
    return result
