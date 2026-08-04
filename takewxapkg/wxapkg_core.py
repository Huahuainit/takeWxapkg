from __future__ import annotations

import base64
import hashlib
import json
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable

try:
    from Crypto.Cipher import AES
except Exception:  # pragma: no cover - reported at runtime with a clearer error
    AES = None


MAGIC = b"V1MMWX"
SALT = b"saltiest"
IV = b"the iv: 16 bytes"
PBKDF2_ITERATIONS = 1000
KEY_LENGTH = 32
DEFAULT_XOR_KEY = 0x66
MAX_WXAPKG_FILES = 100_000
MAX_WXAPKG_NAME_BYTES = 4 * 1024
MAX_WECHAT_SUBPACKAGES = 100
APPID_PATTERN = re.compile(r"^wx[a-f0-9]{16}$")
IMAGE_PLACEHOLDER_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}
TRANSPARENT_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
)
TRANSPARENT_GIF = base64.b64decode("R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==")
TRANSPARENT_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
    "2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAX/"
    "xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAH/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAEFAqf/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAEDAQE/ASP/"
    "xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAECAQE/ASP/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAY/Al//xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAE/IV//2gAMAwEAAgADAAAAEP/E"
    "FBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPxA//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPxA//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA//9k="
)


class WxapkgError(Exception):
    """Base class for user-facing wxapkg errors."""


class NeedAppIDError(WxapkgError):
    """Raised when an encrypted package needs an AppID."""


class BadAppIDError(WxapkgError):
    """Raised when an AppID has the wrong shape."""


class UnsafePathError(WxapkgError):
    """Raised when a package entry attempts to escape the output root."""


@dataclass(frozen=True)
class PackageEntry:
    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class UnpackResult:
    files: list[str]
    common_root: str


@dataclass
class PackageInfo:
    path: Path
    appid: str
    encrypted: bool
    plain: bool
    entries: list[PackageEntry] = field(default_factory=list)


@dataclass
class ExtractResult:
    status: str
    appid: str
    output_dir: Path
    src_dir: Path
    zip_path: Path
    reports_dir: Path
    package_count: int
    extracted_files: int
    generated_files: list[str]
    warnings: list[str]
    elapsed_seconds: float


Progress = Callable[[str, int, str], None]


def is_plain_wxapkg(data: bytes) -> bool:
    return len(data) >= 14 and data[0] == 0xBE and data[13] == 0xED


def is_encrypted_wxapkg(data: bytes) -> bool:
    return data.startswith(MAGIC)


def validate_appid(appid: str) -> str:
    value = appid.strip()
    if not APPID_PATTERN.match(value):
        raise BadAppIDError("AppID 格式错误，应为 wx 开头加 16 位小写十六进制字符")
    return value


def detect_mode(path: Path) -> str:
    try:
        data = path.read_bytes()[:14]
    except OSError:
        return "unknown"
    if data.startswith(MAGIC):
        return "encrypted"
    if len(data) >= 14 and data[0] == 0xBE and data[13] == 0xED:
        return "plain"
    return "unknown"


def decrypt_wxapkg(data: bytes, appid: str = "") -> bytes:
    if is_plain_wxapkg(data):
        return data

    if not is_encrypted_wxapkg(data):
        raise WxapkgError("不是可识别的 wxapkg 文件，缺少 0xBE/0xED 或 V1MMWX 标记")

    if not appid:
        raise NeedAppIDError("这是加密包，需要填写正确的小程序 AppID")
    appid = validate_appid(appid)

    if AES is None:
        raise WxapkgError("缺少 pycryptodome，无法解密加密 wxapkg")
    if len(data) < len(MAGIC) + 1024:
        raise WxapkgError("文件太小，无法按 V1MMWX 格式解密")

    key = hashlib.pbkdf2_hmac("sha1", appid.encode("utf-8"), SALT, PBKDF2_ITERATIONS, KEY_LENGTH)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    decrypted_header = cipher.decrypt(data[len(MAGIC) : len(MAGIC) + 1024])

    xor_key = ord(appid[-2]) if len(appid) >= 2 else DEFAULT_XOR_KEY
    tail = bytes(value ^ xor_key for value in data[len(MAGIC) + 1024 :])
    result = decrypted_header[:1023] + tail
    if not is_plain_wxapkg(result):
        raise WxapkgError("解密后仍不是标准 wxapkg，可能是 AppID 不匹配或当前微信包格式暂不支持")
    return result


def parse_entries(data: bytes) -> list[PackageEntry]:
    if len(data) < 18:
        raise WxapkgError(f"文件太小，不是有效 wxapkg: {len(data)} bytes")
    if data[0] != 0xBE:
        raise WxapkgError(f"无效 wxapkg 首标记: 0x{data[0]:02X}，期望 0xBE")
    if data[13] != 0xED:
        raise WxapkgError(f"无效 wxapkg 尾标记: 0x{data[13]:02X}，期望 0xED")

    _info1, index_len, _body_len = struct.unpack_from(">III", data, 1)
    index_end = 18 + index_len
    if index_end > len(data):
        raise WxapkgError(f"wxapkg 索引段越界: index={index_len}, dataLen={len(data)}")

    pos = 14
    file_count = struct.unpack_from(">I", data, pos)[0]
    pos += 4
    remaining_index = index_end - pos
    if file_count > MAX_WXAPKG_FILES:
        raise WxapkgError(f"文件数量过多: {file_count}，上限 {MAX_WXAPKG_FILES}")
    if file_count * 12 > remaining_index:
        raise WxapkgError(f"索引段长度与文件数量不匹配: {file_count}")

    entries: list[PackageEntry] = []
    for index in range(file_count):
        if pos + 4 > index_end:
            raise WxapkgError(f"索引项 {index} 不完整")
        name_len = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        if name_len == 0 or name_len > MAX_WXAPKG_NAME_BYTES:
            raise WxapkgError(f"索引项 {index} 文件名长度异常: {name_len}")
        if pos + name_len + 8 > index_end:
            raise WxapkgError(f"索引项 {index} 超出声明索引段")

        raw_name = data[pos : pos + name_len]
        pos += name_len
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WxapkgError(f"索引项 {index} 文件名不是 UTF-8") from exc

        offset, size = struct.unpack_from(">II", data, pos)
        pos += 8
        end = offset + size
        if offset > len(data) or end > len(data):
            raise WxapkgError(f"文件越界: {name} offset={offset}, size={size}, dataLen={len(data)}")

        normalize_package_path(name)
        entries.append(PackageEntry(name=name, offset=offset, size=size))

    return entries


def normalize_package_path(name: str) -> str:
    if not name or "\\" in name or "\x00" in name or ":" in name:
        raise UnsafePathError(f"非法包内路径: {name!r}")
    trimmed = name.lstrip("/")
    if not trimmed:
        raise UnsafePathError(f"非法包内路径: {name!r}")
    cleaned = posixpath.normpath(trimmed)
    if cleaned in {"", ".", ".."} or cleaned.startswith("../"):
        raise UnsafePathError(f"包内路径试图逃逸输出目录: {name!r}")
    if cleaned != trimmed:
        raise UnsafePathError(f"包内路径不规范: {name!r}")
    return cleaned


def safe_output_path(root: Path, package_name: str) -> Path:
    normalized = normalize_package_path(package_name)
    base = root.resolve()
    target = (base / Path(PurePosixPath(normalized))).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise UnsafePathError(f"包内路径试图逃逸输出目录: {package_name!r}") from exc
    return target


def find_common_root(paths: list[str]) -> str:
    split_paths = [path.split("/") for path in paths if path]
    split_paths = [[part for part in parts if part] for parts in split_paths if parts]
    if not split_paths:
        return ""

    common: list[str] = []
    for index, part in enumerate(split_paths[0]):
        if all(index < len(parts) and parts[index] == part for parts in split_paths):
            common.append(part)
        else:
            break
    return "/".join(common)


def unpack_to_dir(data: bytes, output_dir: Path) -> UnpackResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    entries = parse_entries(data)
    common_root = find_common_root([entry.name for entry in entries])
    extracted: list[str] = []
    for entry in entries:
        target = safe_output_path(output_dir, entry.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.is_symlink():
            raise UnsafePathError(f"拒绝覆盖符号链接: {target}")
        target.write_bytes(data[entry.offset : entry.offset + entry.size])
        extracted.append(target.relative_to(output_dir).as_posix())
    return UnpackResult(files=extracted, common_root=common_root)


def generate_decompiler_project_files(output_dir: Path) -> list[str]:
    generated: list[str] = []
    generated.extend(_generate_runtime_project_files(output_dir))
    app_json = _generate_decompiled_app_json(output_dir)
    if app_json:
        generated.append(app_json)
    generated.extend(_generate_default_app_files(output_dir))
    project_config = _generate_project_private_config(output_dir)
    if project_config:
        generated.append(project_config)
    return _dedupe(generated)


def _generate_runtime_project_files(output_dir: Path) -> list[str]:
    generated: list[str] = []
    for path in _runtime_code_files(output_dir):
        try:
            code = path.read_text("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for rel, config in _iter_wxappcode_json_assignments(code):
            saved = _write_generated_text(
                output_dir,
                rel,
                json.dumps(config, ensure_ascii=False, indent=2) + "\n",
                force=True,
            )
            if saved:
                generated.append(saved)
        for rel, body in _iter_js_define_bodies(code):
            saved = _write_generated_text(output_dir, rel, _clean_js_body(body), force=True)
            if saved:
                generated.append(saved)
        for rel in _find_wxml_refs(code):
            saved = _write_generated_text(
                output_dir,
                rel,
                _default_wxml(rel),
                force=False,
            )
            if saved:
                generated.append(saved)
    return generated


def _generate_decompiled_app_json(output_dir: Path) -> str:
    app_config_path = output_dir / "app-config.json"
    if not app_config_path.exists():
        return ""

    try:
        raw_config = app_config_path.read_text("utf-8")
        app_config = json.loads(raw_config)
    except Exception:
        return ""
    if not isinstance(app_config, dict):
        return ""

    global_config = app_config.get("global")
    if isinstance(global_config, dict):
        app_config.update(global_config)
    app_config.pop("global", None)
    app_config.pop("page", None)

    entry_page_path = app_config.get("entryPagePath")
    if isinstance(entry_page_path, str):
        app_config["entryPagePath"] = _strip_page_suffix(entry_page_path)

    renderer = app_config.get("renderer")
    if isinstance(renderer, dict):
        app_config["renderer"] = renderer.get("default") or "webview"

    if app_config.get("extAppid"):
        ext_data = {
            "extEnable": True,
            "extAppid": app_config.get("extAppid"),
            "ext": app_config.get("ext"),
        }
        (output_dir / "ext.json").write_text(
            json.dumps(ext_data, ensure_ascii=False, indent=2) + "\n",
            "utf-8",
        )

    if '"renderer": "skyline"' in raw_config or '"renderer":"skyline"' in raw_config:
        app_config["lazyCodeLoading"] = "requiredComponents"
        window_config = app_config.get("window")
        if isinstance(window_config, dict):
            for key in (
                "navigationStyle",
                "navigationBarTextStyle",
                "navigationBarTitleText",
                "navigationBarBackgroundColor",
            ):
                window_config.pop(key, None)

    pages = app_config.get("pages")
    if isinstance(pages, list):
        pages = [_strip_page_suffix(item) for item in pages if isinstance(item, str)]
        main_pack_entries = _dedupe(pages)
        subpackages = app_config.get("subPackages") or app_config.get("subpackages")
        if isinstance(subpackages, list):
            normalized_subpackages = []
            for subpackage in subpackages:
                if not isinstance(subpackage, dict):
                    continue
                subpackage = dict(subpackage)
                root = _normalize_subpackage_root(str(subpackage.get("root", "")))
                if not root:
                    continue
                new_pages: list[str] = []
                for page in pages:
                    if page.startswith(root):
                        if page in main_pack_entries:
                            main_pack_entries.remove(page)
                        new_pages.append(page.replace(root, "", 1))
                subpackage["root"] = root
                subpackage["pages"] = _dedupe(new_pages)
                if subpackage.get("plugins"):
                    subpackage["plugins"] = {}
                if subpackage["pages"]:
                    normalized_subpackages.append(subpackage)
            app_config.pop("subPackages", None)
            app_config.pop("subpackages", None)
            if normalized_subpackages:
                app_config["subPackages"] = normalized_subpackages
        app_config["pages"] = main_pack_entries

    tab_bar = app_config.get("tabBar")
    if isinstance(tab_bar, dict):
        app_config["tabBar"] = _normalize_tab_bar(output_dir, tab_bar)

    app_config["plugins"] = {}

    component_framework = app_config.get("componentFramework")
    if isinstance(component_framework, dict):
        app_config["componentFramework"] = (
            component_framework.get("default")
            or (component_framework.get("allUsed") or [None])[0]
            or component_framework
        )

    app_config.pop("ext", None)
    app_config.pop("navigateToMiniProgramAppIdList", None)

    app_json_text = json.dumps(app_config, ensure_ascii=False, indent=2)
    app_json_text = app_json_text.replace("__plugin__", "plugin_")
    (output_dir / "app.json").write_text(app_json_text + "\n", "utf-8")
    return "app.json"


def _generate_project_private_config(output_dir: Path) -> str:
    path = output_dir / "project.private.config.json"
    default_config = {"setting": {"es6": False, "urlCheck": False}}
    current: dict[str, object] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text("utf-8"))
            if isinstance(loaded, dict):
                current = loaded
        except Exception:
            current = {}
    setting = current.get("setting")
    if not isinstance(setting, dict):
        setting = {}
    setting.update(default_config["setting"])
    current["setting"] = setting
    path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", "utf-8")
    return "project.private.config.json"


def _normalize_app_json_devtools_limits(output_dir: Path) -> str:
    app_json_path = output_dir / "app.json"
    if not app_json_path.exists():
        return ""
    try:
        app_config = json.loads(app_json_path.read_text("utf-8"))
    except Exception:
        return ""
    if not isinstance(app_config, dict):
        return ""

    warnings: list[str] = []
    changed = False
    subpackages = app_config.get("subPackages")
    if not isinstance(subpackages, list):
        subpackages = []

    indexed = [(index, subpackage) for index, subpackage in enumerate(subpackages) if isinstance(subpackage, dict)]
    if len(subpackages) > MAX_WECHAT_SUBPACKAGES and len(indexed) <= MAX_WECHAT_SUBPACKAGES:
        app_config["subPackages"] = [subpackage for _, subpackage in indexed]
        changed = True
    elif len(indexed) > MAX_WECHAT_SUBPACKAGES:
        selected_indexes: set[int] = set()
        special_indexes = [
            item
            for item in indexed
            if item[1].get("independent") is True
            or item[1].get("renderer") == "skyline"
            or item[1].get("componentFramework") == "glass-easel"
        ]
        for index, _subpackage in special_indexes:
            if len(selected_indexes) >= MAX_WECHAT_SUBPACKAGES:
                break
            selected_indexes.add(index)

        normal_indexes = sorted(
            (item for item in indexed if item[0] not in selected_indexes),
            key=lambda item: (len(item[1].get("pages") or []), -item[0]),
            reverse=True,
        )
        for index, _subpackage in normal_indexes:
            if len(selected_indexes) >= MAX_WECHAT_SUBPACKAGES:
                break
            selected_indexes.add(index)

        kept_subpackages = [subpackage for index, subpackage in indexed if index in selected_indexes]
        overflow_subpackages = [subpackage for index, subpackage in indexed if index not in selected_indexes]
        flattened_pages = _flatten_subpackage_pages(output_dir, overflow_subpackages)

        pages = app_config.get("pages")
        if not isinstance(pages, list):
            pages = []
        normalized_pages = [_strip_page_suffix(item) for item in pages if isinstance(item, str)]
        app_config["pages"] = _dedupe(normalized_pages + flattened_pages)
        app_config["subPackages"] = kept_subpackages
        changed = True
        warnings.append(
            f"app.json 原有 {len(subpackages)} 个 subPackages，超过开发者工具限制 "
            f"{MAX_WECHAT_SUBPACKAGES}；已保留 {len(kept_subpackages)} 个分包，"
            f"将其余 {len(overflow_subpackages)} 个分包的 {len(flattened_pages)} 个页面转入 pages。"
        )

    preload_warning = _normalize_preload_rule(app_config)
    if preload_warning:
        warnings.append(preload_warning)
        changed = True

    if changed:
        app_json_path.write_text(json.dumps(app_config, ensure_ascii=False, indent=2) + "\n", "utf-8")

    return "；".join(warnings)


def _normalize_preload_rule(app_config: dict[str, object]) -> str:
    preload_rule = app_config.get("preloadRule")
    if not isinstance(preload_rule, dict):
        return ""

    subpackages = app_config.get("subPackages")
    valid_roots: set[str] = set()
    if isinstance(subpackages, list):
        for subpackage in subpackages:
            if not isinstance(subpackage, dict):
                continue
            root = _normalize_subpackage_root(str(subpackage.get("root", ""))).strip("/")
            if root:
                valid_roots.add(root)

    removed_packages = 0
    removed_rules = 0
    normalized_preload: dict[str, object] = {}
    for page, rule in preload_rule.items():
        if not isinstance(rule, dict):
            normalized_preload[page] = rule
            continue
        packages = rule.get("packages")
        if not isinstance(packages, list):
            normalized_preload[page] = rule
            continue

        kept_packages: list[str] = []
        for package in packages:
            if not isinstance(package, str):
                removed_packages += 1
                continue
            package_root = _normalize_subpackage_root(package).strip("/")
            if package_root == "__APP__" or package_root in valid_roots:
                kept_packages.append(package)
            else:
                removed_packages += 1

        if kept_packages:
            normalized_rule = dict(rule)
            normalized_rule["packages"] = _dedupe(kept_packages)
            normalized_preload[page] = normalized_rule
        else:
            removed_rules += 1

    if not removed_packages and not removed_rules:
        return ""

    if normalized_preload:
        app_config["preloadRule"] = normalized_preload
    else:
        app_config.pop("preloadRule", None)

    return f"已清理 preloadRule 中 {removed_packages} 个无效分包引用，删除 {removed_rules} 条空预加载规则。"


def _normalize_decompiled_reference_paths(output_dir: Path) -> str:
    changed_files = 0
    changed_refs = 0
    for path in _iter_text_project_files(output_dir):
        try:
            text = path.read_text("utf-8")
        except Exception:
            continue
        new_text, count = _normalize_reference_text(text, path.suffix.lower())
        if count:
            path.write_text(new_text, "utf-8")
            changed_files += 1
            changed_refs += count

    replaced_wxml, blank_wxml, ambiguous_wxml = _repair_default_wxml_placeholders(output_dir)
    repaired_wxs_files, repaired_wxs_requires = _repair_wxs_require_paths(output_dir)
    repaired_refs, placeholder_refs = _repair_missing_local_references(output_dir)
    missing_refs = _collect_missing_local_references(output_dir)
    invalid_wxs = _collect_invalid_wxs_require_files(output_dir)
    default_wxml = _collect_default_wxml_placeholders(output_dir)
    messages: list[str] = []
    if changed_refs:
        messages.append(f"已修正 {changed_files} 个文件中的 {changed_refs} 处本地引用反斜杠。")
    if replaced_wxml:
        messages.append(f"已用真实模板替换 {replaced_wxml} 个默认 WXML 占位。")
    if blank_wxml:
        messages.append(f"已将 {blank_wxml} 个无法还原的默认 WXML 占位改为空 block。")
    if ambiguous_wxml:
        messages.append(f"有 {ambiguous_wxml} 个默认 WXML 占位存在多个候选，已改为空 block 避免误套模板。")
    if repaired_wxs_requires:
        messages.append(f"已修正 {repaired_wxs_files} 个 WXS 文件中的 {repaired_wxs_requires} 处 require 引用。")
    if repaired_refs:
        messages.append(f"已重定向 {repaired_refs} 个缺失本地引用到实际文件。")
    if placeholder_refs:
        messages.append(f"已为 {placeholder_refs} 个缺失本地引用生成空占位文件。")
    if missing_refs:
        sample = "，".join(f"{src} -> {ref}" for src, ref in missing_refs[:5])
        messages.append(f"仍发现 {len(missing_refs)} 个本地引用缺失: {sample}")
    if invalid_wxs:
        sample = "，".join(invalid_wxs[:5])
        messages.append(f"仍发现 {len(invalid_wxs)} 个 WXS require 可疑文件: {sample}")
    malformed_wxml = _collect_malformed_wxml_attribute_files(output_dir)
    if malformed_wxml:
        sample = "，".join(malformed_wxml[:5])
        messages.append(f"仍发现 {len(malformed_wxml)} 个 WXML 属性语法可疑文件: {sample}")
    if default_wxml:
        sample = "，".join(default_wxml[:5])
        messages.append(f"仍发现 {len(default_wxml)} 个默认 WXML 占位: {sample}")
    return "；".join(messages)


def _iter_text_project_files(output_dir: Path) -> Iterable[Path]:
    for suffix in (".wxml", ".wxss", ".json"):
        yield from output_dir.rglob(f"*{suffix}")


def _repair_default_wxml_placeholders(output_dir: Path) -> tuple[int, int, int]:
    placeholder_files: list[tuple[Path, str]] = []
    real_wxml_files: list[Path] = []
    for path in output_dir.rglob("*.wxml"):
        try:
            text = path.read_text("utf-8").strip()
        except Exception:
            continue
        placeholder_rel = _default_wxml_placeholder_rel(text)
        if placeholder_rel:
            placeholder_files.append((path, placeholder_rel))
        else:
            real_wxml_files.append(path)

    replaced = 0
    blanked = 0
    ambiguous = 0
    for path, placeholder_rel in placeholder_files:
        replacement = _find_default_wxml_replacement(output_dir, path, placeholder_rel, real_wxml_files)
        if replacement is None:
            path.write_text("<block />\n", "utf-8")
            ambiguous += 1
        elif replacement:
            path.write_text(replacement.read_text("utf-8"), "utf-8")
            replaced += 1
        else:
            path.write_text("<block />\n", "utf-8")
            blanked += 1
    return replaced, blanked, ambiguous


def _default_wxml_placeholder_rel(text: str) -> str:
    match = re.fullmatch(r"<text>([^<>]+?\.wxml)</text>", text.strip())
    return match.group(1).replace("\\", "/") if match else ""


def _find_default_wxml_replacement(
    output_dir: Path,
    placeholder_path: Path,
    placeholder_rel: str,
    real_wxml_files: list[Path],
) -> Path | str | None:
    placeholder_parts = [part for part in placeholder_rel.replace("\\", "/").split("/") if part]
    if not placeholder_parts:
        return ""
    scored: list[tuple[int, int, Path]] = []
    for candidate in real_wxml_files:
        if candidate == placeholder_path or candidate.name != placeholder_path.name:
            continue
        candidate_parts = candidate.relative_to(output_dir).as_posix().split("/")
        suffix_score = 0
        for expected, actual in zip(reversed(placeholder_parts), reversed(candidate_parts)):
            if expected != actual:
                break
            suffix_score += 1
        if suffix_score == 0:
            continue
        length_penalty = abs(len(candidate_parts) - suffix_score)
        scored.append((suffix_score, -length_penalty, candidate))
    if not scored:
        return ""
    scored.sort(key=lambda item: (item[0], item[1], -len(item[2].as_posix())), reverse=True)
    best = scored[0]
    if best[0] < 2:
        return ""
    if len(scored) > 1 and scored[1][0] == best[0] and scored[1][1] == best[1]:
        return None
    return best[2]


def _collect_default_wxml_placeholders(output_dir: Path) -> list[str]:
    placeholders: list[str] = []
    for path in output_dir.rglob("*.wxml"):
        try:
            text = path.read_text("utf-8")
        except Exception:
            continue
        if _default_wxml_placeholder_rel(text):
            placeholders.append(path.relative_to(output_dir).as_posix())
    return placeholders


def _repair_wxs_require_paths(output_dir: Path) -> tuple[int, int]:
    changed_files = 0
    changed_requires = 0
    for path in output_dir.rglob("*.wxs"):
        try:
            text = path.read_text("utf-8")
        except Exception:
            continue
        new_text, count = _repair_wxs_require_text(output_dir, path, text)
        if count:
            path.write_text(new_text, "utf-8")
            changed_files += 1
            changed_requires += count
    return changed_files, changed_requires


def _repair_wxs_require_text(output_dir: Path, path: Path, text: str) -> tuple[str, int]:
    changed = 0
    repaired_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        if "require(" in line and ".wxs" in line and _is_malformed_wxs_require_line(line):
            repaired = _repair_malformed_wxs_require_line(output_dir, path, line)
            if repaired != line:
                changed += 1
                line = repaired
        repaired_lines.append(line)
    text = "".join(repaired_lines)

    def replace_valid_require(match: re.Match[str]) -> str:
        nonlocal changed
        raw_path = match.group("path")
        relative_path = _resolve_wxs_require_relative_path(output_dir, path, raw_path)
        if not relative_path:
            return match.group(0)
        replacement = f"require('{relative_path}')"
        if replacement != match.group(0):
            changed += 1
        return replacement

    text = re.sub(
        r"require\(\s*[\"'](?P<path>[^\"']*?\.wxs)[\"']\s*\)\s*(?:\(\))?",
        replace_valid_require,
        text,
    )
    return text, changed


def _is_malformed_wxs_require_line(line: str) -> bool:
    if line.count("require(") > 1:
        return True
    require_part = line[line.find("require(") :]
    return "\\" in require_part or "p_." in require_part or ")()" in require_part


def _repair_malformed_wxs_require_line(output_dir: Path, path: Path, line: str) -> str:
    raw_path = _extract_probable_wxs_require_path(line)
    if not raw_path:
        return line
    relative_path = _resolve_wxs_require_relative_path(output_dir, path, raw_path)
    if not relative_path:
        return line
    prefix_match = re.match(r"(?P<prefix>\s*(?:var|let|const)\s+[^=]+=\s*)", line)
    if not prefix_match:
        return line
    suffix_match = re.search(r"\.wxs[\"']\s*\)\s*(?:\(\))?(?P<suffix>\.[A-Za-z_$][\w$]*)?", line)
    suffix = suffix_match.group("suffix") if suffix_match and suffix_match.group("suffix") else ""
    newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
    return f"{prefix_match.group('prefix')}require('{relative_path}'){suffix};{newline}"


def _extract_probable_wxs_require_path(line: str) -> str:
    matches = re.findall(r"(?:p_)?\.?[\\/][^'\";()]*?\.wxs", line)
    if not matches:
        matches = re.findall(r"(?:[A-Za-z0-9_-]+[\\/])+[A-Za-z0-9_. -]+\.wxs", line)
    return matches[-1] if matches else ""


def _resolve_wxs_require_relative_path(output_dir: Path, source_path: Path, raw_path: str) -> str:
    normalized = _normalize_wxs_require_raw_path(raw_path)
    if not normalized:
        return ""
    candidates: list[Path] = []
    if normalized.startswith("/"):
        candidates.append(output_dir / Path(PurePosixPath(normalized.lstrip("/"))))
    else:
        candidates.append(source_path.parent / Path(PurePosixPath(normalized)))
        root_relative = normalized[2:] if normalized.startswith("./") else normalized
        candidates.append(output_dir / Path(PurePosixPath(root_relative.lstrip("/"))))
    for candidate in candidates:
        try:
            if candidate.is_file():
                return _relative_project_path(output_dir, source_path, candidate)
        except Exception:
            continue

    suffix_parts = _reference_suffix_parts(normalized)
    if not suffix_parts:
        return ""
    matches: list[Path] = []
    for candidate in output_dir.rglob(suffix_parts[-1]):
        if not candidate.is_file():
            continue
        rel_parts = candidate.relative_to(output_dir).as_posix().split("/")
        if len(rel_parts) >= len(suffix_parts) and rel_parts[-len(suffix_parts) :] == suffix_parts:
            matches.append(candidate)
    if len(matches) == 1:
        return _relative_project_path(output_dir, source_path, matches[0])
    return ""


def _normalize_wxs_require_raw_path(raw_path: str) -> str:
    value = raw_path.strip().strip("'\"")
    if value.startswith("p_"):
        value = value[2:]
    value = re.sub(r"\s+", "", value)
    return _normalize_local_reference_slashes(value)


def _relative_project_path(output_dir: Path, source_path: Path, target_path: Path) -> str:
    rel_path = posixpath.relpath(
        target_path.relative_to(output_dir).as_posix(),
        source_path.parent.relative_to(output_dir).as_posix(),
    )
    return rel_path if rel_path.startswith(".") else f"./{rel_path}"


def _collect_invalid_wxs_require_files(output_dir: Path) -> list[str]:
    invalid: list[str] = []
    for path in output_dir.rglob("*.wxs"):
        try:
            text = path.read_text("utf-8")
        except Exception:
            continue
        for line in text.splitlines():
            if "require(" in line and (line.count("require(") > 1 or "\\" in line or "p_." in line or ")()" in line):
                invalid.append(path.relative_to(output_dir).as_posix())
                break
    return invalid


def _normalize_reference_text(text: str, suffix: str) -> tuple[str, int]:
    count = 0

    def replace_match(match: re.Match[str]) -> str:
        nonlocal count
        raw_path = match.group("path")
        normalized_path = _normalize_local_reference_slashes(raw_path)
        if normalized_path == raw_path:
            return match.group(0)
        count += 1
        return f"{match.group('prefix')}{normalized_path}{match.group('suffix')}"

    if suffix == ".wxml":
        text, attr_count = _normalize_wxml_attribute_expressions(text)
        count += attr_count
        text = re.sub(
            r"(?P<prefix>\bsrc\s*=\s*[\"'])(?P<path>(?:[^\"']*(?:\\|//)[^\"']*|/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\"']*))(?P<suffix>[\"'])",
            replace_match,
            text,
        )
        return text, count

    if suffix == ".wxss":
        text = re.sub(
            r"(?P<prefix>@import\s+(?:url\(\s*)?[\"'])(?P<path>(?:[^\"']*(?:\\|//)[^\"']*|/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\"']*))(?P<suffix>[\"'])",
            replace_match,
            text,
        )
        text = re.sub(
            r"(?P<prefix>\burl\(\s*[\"']?)(?P<path>(?:[^\"')]*(?:\\|//|-do-not-use-local-path-)[^\"')]*|/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\"')]*))(?P<suffix>[\"']?\s*\))",
            replace_match,
            text,
        )
        return text, count

    if suffix == ".json":
        try:
            data = json.loads(text)
        except Exception:
            return text, count
        data, count = _normalize_json_reference_paths(data)
        if not count:
            return text, 0
        return json.dumps(data, ensure_ascii=False, indent=2) + "\n", count

    return text, count


def _normalize_wxml_attribute_expressions(text: str) -> tuple[str, int]:
    count = 0

    def replace_unquoted(match: re.Match[str]) -> str:
        nonlocal count
        expr = match.group("expr").strip()
        if not expr:
            return match.group(0)
        count += 1
        return f'{match.group("prefix")}"{{{{{expr}}}}}"'

    def replace_quoted(match: re.Match[str]) -> str:
        nonlocal count
        expr = match.group("expr").strip()
        if not expr:
            return match.group(0)
        count += 1
        return f'{match.group("prefix")}{match.group("quote")}{{{{{expr}}}}}{match.group("quote")}'

    text = re.sub(
        r"(?P<prefix>\s[\w:.-]+\s*=\s*)\{(?!\{)(?P<expr>[^{}\"'<>`\n]+)\}",
        replace_unquoted,
        text,
    )
    text = re.sub(
        r"(?P<prefix>\s[\w:.-]+\s*=\s*)(?P<quote>[\"'])\{(?!\{)(?P<expr>[^{}<>`\n]+)\}(?P=quote)",
        replace_quoted,
        text,
    )
    return text, count


def _collect_malformed_wxml_attribute_files(output_dir: Path) -> list[str]:
    invalid: list[str] = []
    unquoted = re.compile(r"\s[\w:.-]+\s*=\s*\{(?!\{)[^{}\"'<>`\n]+\}")
    quoted = re.compile(r"\s[\w:.-]+\s*=\s*([\"'])\{(?!\{)[^{}<>`\n]+\}\1")
    for path in output_dir.rglob("*.wxml"):
        try:
            text = path.read_text("utf-8")
        except Exception:
            continue
        if unquoted.search(text) or quoted.search(text):
            invalid.append(path.relative_to(output_dir).as_posix())
    return invalid


def _normalize_json_reference_paths(value: object) -> tuple[object, int]:
    if isinstance(value, dict):
        changed = 0
        normalized: dict[str, object] = {}
        for key, item in value.items():
            normalized_item, item_changed = _normalize_json_reference_paths(item)
            normalized[key] = normalized_item
            changed += item_changed
        return normalized, changed
    if isinstance(value, list):
        changed = 0
        normalized_list: list[object] = []
        for item in value:
            normalized_item, item_changed = _normalize_json_reference_paths(item)
            normalized_list.append(normalized_item)
            changed += item_changed
        return normalized_list, changed
    if isinstance(value, str) and _looks_like_local_reference(value):
        return _normalize_local_reference_slashes(value), 1
    return value, 0


def _normalize_local_reference_slashes(value: str) -> str:
    normalized = value.replace("\\", "/")
    if re.match(r"^[a-z]+://", normalized, re.IGNORECASE):
        return normalized
    normalized = re.sub(r"/{2,}", "/", normalized)
    if "-do-not-use-local-path-" in normalized:
        normalized = normalized.split("-do-not-use-local-path-", 1)[0]
    host_match = re.match(r"^/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/.*)$", normalized)
    if host_match:
        return f"https://{host_match.group(1)}{host_match.group(2)}"
    return normalized


def _looks_like_local_reference(value: str) -> bool:
    if "\\" not in value:
        return False
    if re.match(r"^[a-zA-Z]:\\", value):
        return False
    normalized = value.replace("\\", "/")
    return (
        normalized.startswith(("./", "../", "/"))
        or normalized.endswith((".wxml", ".wxss", ".wxs", ".js", ".json"))
        or "/" in normalized
    )


def _collect_missing_local_references(output_dir: Path) -> list[tuple[str, str]]:
    missing: list[tuple[str, str]] = []
    for path in output_dir.rglob("*.wxml"):
        try:
            text = path.read_text("utf-8")
        except Exception:
            continue
        for ref in re.findall(r"\bsrc\s*=\s*[\"']([^\"']+)[\"']", text):
            if _is_missing_local_reference(output_dir, path, ref):
                missing.append((path.relative_to(output_dir).as_posix(), ref))

    for path in output_dir.rglob("*.wxss"):
        try:
            text = path.read_text("utf-8")
        except Exception:
            continue
        refs = re.findall(r"@import\s+(?:url\(\s*)?[\"']([^\"']+)[\"']", text)
        refs.extend(re.findall(r"\burl\(\s*[\"']?([^\"')]+)[\"']?\s*\)", text))
        for ref in refs:
            if _is_missing_local_reference(output_dir, path, ref):
                missing.append((path.relative_to(output_dir).as_posix(), ref))
    return missing


def _repair_missing_local_references(output_dir: Path) -> tuple[int, int]:
    repaired_refs = 0
    placeholder_refs = 0
    for path in list(output_dir.rglob("*.wxml")) + list(output_dir.rglob("*.wxss")):
        try:
            text = path.read_text("utf-8")
        except Exception:
            continue
        replacements: dict[str, str] = {}
        for ref in _extract_local_reference_values(path, text):
            if not _is_missing_local_reference(output_dir, path, ref):
                continue
            replacement = _find_existing_reference_replacement(output_dir, path, ref)
            if replacement:
                replacements[ref] = replacement
                repaired_refs += 1
                continue
            if _create_placeholder_reference(output_dir, path, ref):
                placeholder_refs += 1
        if replacements:
            for old, new in replacements.items():
                text = text.replace(old, new)
            path.write_text(text, "utf-8")
    return repaired_refs, placeholder_refs


def _extract_local_reference_values(path: Path, text: str) -> list[str]:
    refs: list[str] = []
    if path.suffix.lower() == ".wxml":
        refs.extend(re.findall(r"\bsrc\s*=\s*[\"']([^\"']+)[\"']", text))
    elif path.suffix.lower() == ".wxss":
        refs.extend(re.findall(r"@import\s+(?:url\(\s*)?[\"']([^\"']+)[\"']", text))
        refs.extend(re.findall(r"\burl\(\s*[\"']?([^\"')]+)[\"']?\s*\)", text))
    return refs


def _find_existing_reference_replacement(output_dir: Path, source_path: Path, ref: str) -> str:
    ref = ref.strip().replace("\\", "/").split("?", 1)[0].split("#", 1)[0]
    suffix = Path(PurePosixPath(ref)).suffix.lower()
    if suffix not in {".wxs", ".wxml", ".wxss", ".js", ".json", *IMAGE_PLACEHOLDER_SUFFIXES}:
        return ""
    suffix_parts = _reference_suffix_parts(ref)
    if not suffix_parts:
        return ""
    basename = suffix_parts[-1]
    matches: list[Path] = []
    for candidate in output_dir.rglob(basename):
        if not candidate.is_file():
            continue
        rel_parts = candidate.relative_to(output_dir).as_posix().split("/")
        if len(rel_parts) >= len(suffix_parts) and rel_parts[-len(suffix_parts) :] == suffix_parts:
            matches.append(candidate)
    if len(matches) != 1:
        return ""
    rel_path = posixpath.relpath(matches[0].relative_to(output_dir).as_posix(), source_path.parent.relative_to(output_dir).as_posix())
    return rel_path if rel_path.startswith(".") else f"./{rel_path}"


def _reference_suffix_parts(ref: str) -> list[str]:
    normalized = ref.strip().replace("\\", "/").split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = [part for part in normalized.split("/") if part and part not in {".", ".."}]
    if not parts:
        return []
    for size in range(len(parts), 0, -1):
        if size <= 4 or size == len(parts):
            return parts[-size:]
    return parts


def _create_placeholder_reference(output_dir: Path, source_path: Path, ref: str) -> bool:
    ref = ref.strip().replace("\\", "/").split("?", 1)[0].split("#", 1)[0]
    suffix = Path(PurePosixPath(ref)).suffix.lower()
    placeholders = {
        ".wxs": "module.exports = {};\n",
        ".wxml": "\n",
        ".wxss": "\n",
        ".json": "{}\n",
        ".js": "\n",
    }
    if suffix not in placeholders and suffix not in IMAGE_PLACEHOLDER_SUFFIXES:
        return False
    try:
        target = output_dir / Path(PurePosixPath(ref.lstrip("/"))) if ref.startswith("/") else source_path.parent / Path(PurePosixPath(ref))
        target = target.resolve()
        output_root = output_dir.resolve()
        if output_root != target and output_root not in target.parents:
            return False
        if target.exists():
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        if suffix in IMAGE_PLACEHOLDER_SUFFIXES:
            target.write_bytes(_placeholder_asset_bytes(suffix))
        else:
            target.write_text(placeholders[suffix], "utf-8")
    except Exception:
        return False
    return True


def _placeholder_asset_bytes(suffix: str) -> bytes:
    suffix = suffix.lower()
    if suffix == ".svg":
        return b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>\n'
    if suffix == ".gif":
        return TRANSPARENT_GIF
    if suffix in {".jpg", ".jpeg"}:
        return TRANSPARENT_JPEG
    return TRANSPARENT_PNG


def _is_missing_local_reference(output_dir: Path, source_path: Path, ref: str) -> bool:
    ref = ref.strip().replace("\\", "/")
    if not ref or ref.startswith(("#", "data:", "http://", "https://", "wxfile://", "cloud://", "plugin://")):
        return False
    if ref.startswith("//"):
        return False
    if re.match(r"^/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/", ref):
        return False
    if any(marker in ref for marker in ("{{", "}}", "{", "}")):
        return False
    if not (
        ref.startswith(("./", "../", "/"))
        or ref.endswith((".wxs", ".wxss", ".wxml", ".js", ".json"))
    ):
        return False
    ref = ref.split("?", 1)[0].split("#", 1)[0]
    if not ref:
        return False
    try:
        target = output_dir / Path(PurePosixPath(ref.lstrip("/"))) if ref.startswith("/") else source_path.parent / Path(PurePosixPath(ref))
        target = target.resolve()
        output_root = output_dir.resolve()
        if output_root != target and output_root not in target.parents:
            return False
    except Exception:
        return False
    return not target.is_file()


def _flatten_subpackage_pages(output_dir: Path, subpackages: list[dict[str, object]]) -> list[str]:
    flattened: list[str] = []
    for subpackage in subpackages:
        root = _normalize_subpackage_root(str(subpackage.get("root", "")))
        pages = subpackage.get("pages")
        if not isinstance(pages, list):
            continue
        for page in pages:
            if not isinstance(page, str):
                continue
            normalized_page = _strip_page_suffix(page).lstrip("/")
            if not normalized_page:
                continue
            if root and normalized_page.startswith(root):
                full_page = normalized_page
            else:
                full_page = f"{root}{normalized_page}"
            try:
                normalized_full_page = normalize_package_path(full_page)
            except UnsafePathError:
                continue
            if not _page_source_exists(output_dir, normalized_full_page):
                continue
            flattened.append(normalized_full_page)
    return _dedupe(flattened)


def _page_source_exists(output_dir: Path, page_path: str) -> bool:
    return any(
        (output_dir / Path(PurePosixPath(f"{page_path}{ext}"))).is_file()
        for ext in (".wxml", ".js", ".json", ".wxss")
    )


def _generate_default_app_files(output_dir: Path) -> list[str]:
    app_config_path = output_dir / "app-config.json"
    if not app_config_path.exists():
        return []
    try:
        app_config = json.loads(app_config_path.read_text("utf-8"))
    except Exception:
        return []
    if not isinstance(app_config, dict):
        return []

    pages = app_config.get("pages")
    if not isinstance(pages, list):
        return []

    analysis_list = [_strip_page_suffix(item) for item in pages if isinstance(item, str)]
    all_pages = _collect_component_dependencies(output_dir, analysis_list)
    generated: list[str] = []
    for page in all_pages:
        if _is_plugin_path(page):
            continue
        for ext, content in (
            (".json", '{\n  "component": true\n}\n'),
            (".js", "Page({ data: {} })\n"),
            (".wxml", _default_wxml(_replace_page_ext(page, ".wxml"))),
        ):
            rel = _replace_page_ext(page, ext)
            saved = _write_generated_text(output_dir, rel, content, force=False)
            if saved:
                generated.append(saved)
    return generated


def _collect_component_dependencies(output_dir: Path, analysis_list: list[str]) -> list[str]:
    result: list[str] = []
    queue = list(analysis_list)
    while queue:
        page = _strip_page_suffix(queue.pop(0))
        if not page or page in result:
            continue
        result.append(page)

        config_path = output_dir / Path(PurePosixPath(_replace_page_ext(page, ".json")))
        if not config_path.exists():
            continue
        try:
            page_config = json.loads(config_path.read_text("utf-8"))
        except Exception:
            continue
        if not isinstance(page_config, dict):
            continue
        using_components = page_config.get("usingComponents")
        if not isinstance(using_components, dict):
            continue
        page_dir = posixpath.dirname(page)
        for component_path in using_components.values():
            if not isinstance(component_path, str) or not component_path.strip():
                continue
            if _is_plugin_path(component_path):
                result.append(component_path)
                continue
            normalized = component_path.strip().replace("\\", "/")
            if normalized.startswith("/"):
                normalized = normalized.lstrip("/")
            else:
                normalized = posixpath.normpath(posixpath.join(page_dir, normalized))
            normalized = _strip_page_suffix(normalized)
            if normalized not in result and normalized not in queue:
                queue.append(normalized)
    return result


def _runtime_code_files(output_dir: Path) -> list[Path]:
    names = {"app-service.js", "page-frame.js", "page-frame.html"}
    files = [
        path
        for path in output_dir.rglob("*")
        if path.is_file() and not path.is_symlink() and path.name in names
    ]
    return sorted(files)


def _iter_wxappcode_json_assignments(code: str) -> Iterable[tuple[str, object]]:
    pattern = re.compile(r"__wxAppCode__\s*\[\s*(['\"])(?P<name>.+?\.json)\1\s*\]\s*=")
    for match in pattern.finditer(code):
        rel = _normalize_generated_relpath(match.group("name"))
        if not rel:
            continue
        value_start = match.end()
        while value_start < len(code) and code[value_start].isspace():
            value_start += 1
        if value_start >= len(code) or code[value_start] != "{":
            continue
        value_end = _find_matching_js_bracket(code, value_start, "{", "}")
        if value_end < 0:
            continue
        raw_value = code[value_start : value_end + 1]
        try:
            parsed = json.loads(raw_value)
        except json.JSONDecodeError:
            continue
        yield rel, parsed


def _iter_js_define_bodies(code: str) -> Iterable[tuple[str, str]]:
    index = 0
    marker = "define("
    while True:
        start = code.find(marker, index)
        if start < 0:
            return
        index = start + len(marker)
        name_start = _skip_js_space(code, index)
        if name_start >= len(code) or code[name_start] not in {"'", '"'}:
            continue
        name, after_name = _read_js_string(code, name_start)
        rel = _normalize_generated_relpath(name)
        if not rel or not rel.endswith(".js"):
            continue
        func_index = code.find("function", after_name)
        if func_index < 0:
            continue
        brace_start = code.find("{", func_index)
        if brace_start < 0:
            continue
        brace_end = _find_matching_js_bracket(code, brace_start, "{", "}")
        if brace_end < 0:
            continue
        index = brace_end + 1
        yield rel, code[brace_start + 1 : brace_end]


def _find_wxml_refs(code: str) -> list[str]:
    refs: list[str] = []
    patterns = (
        re.compile(r"__wxAppCode__\s*\[\s*(['\"])(?P<name>.+?\.wxml)\1\s*\]"),
        re.compile(r"\$gwx[\w$]*\(\s*(['\"])(?P<name>.+?\.wxml)\1\s*\)"),
    )
    for pattern in patterns:
        for match in pattern.finditer(code):
            rel = _normalize_generated_relpath(match.group("name"))
            if rel:
                refs.append(rel)
    return _dedupe(refs)


def _write_generated_text(output_dir: Path, rel: str, text: str, force: bool) -> str:
    rel = _normalize_generated_relpath(rel)
    if not rel:
        return ""
    try:
        target = safe_output_path(output_dir, rel)
    except UnsafePathError:
        return ""
    if target.exists() and not force:
        try:
            if target.read_text("utf-8").strip():
                return ""
        except (OSError, UnicodeDecodeError):
            return ""
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, "utf-8")
    return target.relative_to(output_dir).as_posix()


def _normalize_generated_relpath(value: str) -> str:
    value = value.strip().replace("\\", "/")
    if value.startswith("plugin-private://"):
        value = "plugin_/" + value.removeprefix("plugin-private://")
    value = value.replace("__plugin__", "plugin_")
    value = value.lstrip("/")
    while value.startswith("./"):
        value = value[2:]
    if not value or _is_plugin_path(value):
        return ""
    try:
        return normalize_package_path(value)
    except UnsafePathError:
        return ""


def _clean_js_body(body: str) -> str:
    body = body.strip()
    for prefix in ('"use strict";', "'use strict';"):
        if body.startswith(prefix):
            body = body[len(prefix) :].strip()
    body = body.replace('require("@babel', 'require("./@babel')
    return body.rstrip() + "\n"


def _replace_page_ext(page_path: str, ext: str) -> str:
    page_path = _strip_page_suffix(page_path)
    return f"{page_path}{ext}"


def _default_wxml(rel: str) -> str:
    return f"<text>{rel}</text>\n"


def _is_plugin_path(value: str) -> bool:
    return value.startswith("plugin://") or value.startswith("plugin-private://")


def _skip_js_space(code: str, index: int) -> int:
    while index < len(code) and code[index].isspace():
        index += 1
    return index


def _read_js_string(code: str, quote_index: int) -> tuple[str, int]:
    quote = code[quote_index]
    index = quote_index + 1
    chars: list[str] = []
    escaped = False
    while index < len(code):
        char = code[index]
        if escaped:
            chars.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return "".join(chars), index + 1
        else:
            chars.append(char)
        index += 1
    return "", len(code)


def _find_matching_js_bracket(code: str, start: int, open_char: str, close_char: str) -> int:
    depth = 0
    index = start
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    while index < len(code):
        char = code[index]
        nxt = code[index + 1] if index + 1 < len(code) else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char == "/" and nxt == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _normalize_tab_bar(output_dir: Path, tab_bar: dict[str, object]) -> dict[str, object]:
    normalized_tab_bar = dict(tab_bar)
    items = tab_bar.get("list")
    if not isinstance(items, list):
        normalized_tab_bar["list"] = []
        return normalized_tab_bar

    base64_file_map = _build_base64_file_map(output_dir)
    normalized_items: list[object] = []
    for item in items:
        if not isinstance(item, dict):
            normalized_items.append(item)
            continue
        result: dict[str, object] = {}
        if "text" in item:
            result["text"] = item["text"]
        page_path = item.get("pagePath")
        if isinstance(page_path, str):
            result["pagePath"] = _strip_page_suffix(page_path)
        icon_data = item.get("iconData")
        if isinstance(icon_data, str) and icon_data in base64_file_map:
            result["iconPath"] = base64_file_map[icon_data]
        selected_icon_data = item.get("selectedIconData")
        if isinstance(selected_icon_data, str) and selected_icon_data in base64_file_map:
            result["selectedIconPath"] = base64_file_map[selected_icon_data]
        normalized_items.append(result)
    normalized_tab_bar["list"] = normalized_items
    return normalized_tab_bar


def _build_base64_file_map(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            data = base64.b64encode(path.read_bytes()).decode("ascii")
        except OSError:
            continue
        result.setdefault(data, path.relative_to(root).as_posix())
    return result


def _strip_page_suffix(value: str) -> str:
    value = value.strip().replace("\\", "/").lstrip("/")
    for suffix in (".html", ".wxml", ".js", ".json"):
        if value.endswith(suffix):
            return value[: -len(suffix)]
    return value


def _normalize_subpackage_root(value: str) -> str:
    value = value.strip().replace("\\", "/").strip("/")
    return f"{value}/" if value else ""


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def make_src_zip(src_dir: Path, zip_path: Path) -> tuple[Path, list[str]]:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = _unique_output_file(zip_path.with_suffix(zip_path.suffix + ".tmp"))
    entries: list[str] = []

    with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(src_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(src_dir).as_posix()
            normalized = normalize_package_path(rel)
            arcname = f"{src_dir.name}/{normalized}"
            normalize_package_path(arcname)
            archive.write(path, arcname)
            entries.append(arcname)

    try:
        tmp_path.replace(zip_path)
        final_zip_path = zip_path
    except PermissionError:
        final_zip_path = _unique_output_file(zip_path)
        tmp_path.replace(final_zip_path)
    return final_zip_path, entries


def _unique_output_file(path: Path) -> Path:
    if not path.exists():
        return path

    stamp = time.strftime("%Y%m%d-%H%M%S")
    for index in range(1, 1000):
        suffix = f"-{stamp}" if index == 1 else f"-{stamp}-{index}"
        candidate = path.with_name(f"{path.stem}{suffix}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise WxapkgError(f"无法创建不重名输出文件: {path}")


def _app_root() -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parents[1]


def _external_runtime_dir() -> Path:
    return _app_root() / "vendor" / "wx_decompiler_runtime"


def _runtime_node_path(runtime_dir: Path) -> str:
    bundled = runtime_dir / "node.exe"
    if bundled.exists():
        return str(bundled)
    found = shutil.which("node")
    if found:
        return found
    return ""


def _external_engine_ready() -> bool:
    runtime_dir = _external_runtime_dir()
    return bool(
        runtime_dir.exists()
        and (runtime_dir / "dist" / "decompilation-cli.js").exists()
        and (runtime_dir / "node_modules").exists()
        and _runtime_node_path(runtime_dir)
    )


def _packages_contain_compiled_runtime(package_paths: list[Path], appid: str) -> bool:
    runtime_names = {"app-service.js", "page-frame.js", "page-frame.html", "app-wxss.js"}
    for path in package_paths:
        raw = path.read_bytes()
        mode = "encrypted" if is_encrypted_wxapkg(raw) else "plain" if is_plain_wxapkg(raw) else "unknown"
        if mode == "encrypted":
            raw = decrypt_wxapkg(raw, validate_appid(appid.strip()))
        elif mode != "plain":
            continue
        try:
            entries = parse_entries(raw)
        except WxapkgError:
            continue
        for entry in entries:
            if entry.size > 1024 and PurePosixPath(entry.name.lstrip("/")).name in runtime_names:
                return True
    return False


def _extract_with_external_engine(
    package_paths: list[Path],
    output_dir: Path,
    appid: str,
    progress: Progress | None,
    started: float,
) -> ExtractResult:
    runtime_dir = _external_runtime_dir()
    node_path = _runtime_node_path(runtime_dir)
    cli_path = runtime_dir / "dist" / "decompilation-cli.js"
    if not node_path or not cli_path.exists():
        raise WxapkgError("反编译运行时未打包完整，无法执行严格反编译")

    src_dir = output_dir / "decompiled"
    legacy_src_dir = output_dir / "src"
    reports_dir = output_dir / "reports"
    if src_dir.exists():
        shutil.rmtree(src_dir)
    if legacy_src_dir.exists():
        shutil.rmtree(legacy_src_dir)
    if reports_dir.exists():
        shutil.rmtree(reports_dir)
    src_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    use_appid = appid.strip()
    package_reports: list[dict[str, object]] = []
    for path in package_paths:
        mode = detect_mode(path)
        if mode == "encrypted":
            use_appid = validate_appid(use_appid)
        package_reports.append(
            {
                "path": str(path),
                "name": path.name,
                "mode": mode,
                "size": path.stat().st_size,
            }
        )

    if progress:
        progress("engine", 10, "正在调用内置反编译引擎")

    args = [
        node_path,
        str(cli_path),
        *[str(path) for path in package_paths],
        str(src_dir),
        "",
    ]
    if use_appid:
        args.extend(["--wxid", use_appid])

    run_kwargs: dict[str, object] = {}
    if sys.platform == "win32":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        run_kwargs["startupinfo"] = startupinfo
        run_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    completed = subprocess.run(
        args,
        cwd=str(runtime_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        **run_kwargs,
    )
    stdout = _strip_ansi(completed.stdout)
    stderr = _strip_ansi(completed.stderr)
    if completed.returncode != 0:
        message = (stderr or stdout or "反编译引擎执行失败").strip()
        raise WxapkgError(f"反编译引擎执行失败: {_short_log_tail(message)}")

    if progress:
        progress("engine", 82, "反编译引擎已生成真实 WXML/WXSS/JS")

    warnings: list[str] = []
    limit_warning = _normalize_app_json_devtools_limits(src_dir)
    if limit_warning:
        warnings.append(limit_warning)
    path_warning = _normalize_decompiled_reference_paths(src_dir)
    if path_warning:
        warnings.append(path_warning)

    source_files = [
        path.relative_to(src_dir).as_posix()
        for path in sorted(src_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    ]
    zip_path = output_dir / "takeWxapkg-src.zip"
    zip_path, zip_entries = make_src_zip(src_dir, zip_path)
    if progress:
        progress("packaging", 94, "已生成反编译 ZIP")

    if "反编译失败" in stdout or "获取小程序信息失败" in stdout:
        warnings.append(_short_log_tail(stdout))
    report = {
        "tool": "takeWxapkg",
        "engine": "external-runtime",
        "status": "completed",
        "appid": appid,
        "outputDir": str(output_dir),
        "srcDir": str(src_dir),
        "zipPath": str(zip_path),
        "packageCount": len(package_paths),
        "extractedFiles": len(source_files),
        "generatedFiles": source_files,
        "warnings": warnings,
        "packages": package_reports,
        "engineLog": stdout,
        "zipEntries": zip_entries,
        "elapsedSeconds": round(time.perf_counter() - started, 3),
    }
    (reports_dir / "takeWxapkg-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        "utf-8",
    )
    if progress:
        progress("completed", 100, "处理完成")

    return ExtractResult(
        status="completed",
        appid=appid,
        output_dir=output_dir,
        src_dir=src_dir,
        zip_path=zip_path,
        reports_dir=reports_dir,
        package_count=len(package_paths),
        extracted_files=len(source_files),
        generated_files=source_files,
        warnings=warnings,
        elapsed_seconds=report["elapsedSeconds"],
    )


def _strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", value)


def _short_log_tail(value: str, max_chars: int = 1200) -> str:
    value = value.strip()
    if len(value) <= max_chars:
        return value
    return value[-max_chars:]


def extract_packages(
    package_paths: Iterable[Path],
    output_dir: Path,
    appid: str = "",
    progress: Progress | None = None,
) -> ExtractResult:
    started = time.perf_counter()
    package_paths = [Path(item) for item in package_paths]
    if not package_paths:
        raise WxapkgError("没有可处理的 wxapkg 文件")

    output_dir = output_dir.resolve()
    if _external_engine_ready() and _packages_contain_compiled_runtime(package_paths, appid):
        return _extract_with_external_engine(package_paths, output_dir, appid, progress, started)

    src_dir = output_dir / "decompiled"
    legacy_src_dir = output_dir / "src"
    reports_dir = output_dir / "reports"
    if src_dir.exists():
        shutil.rmtree(src_dir)
    if legacy_src_dir.exists():
        shutil.rmtree(legacy_src_dir)
    if reports_dir.exists():
        shutil.rmtree(reports_dir)
    src_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    warnings: list[str] = []
    all_files: list[str] = []
    package_reports: list[dict[str, object]] = []

    total = len(package_paths)
    for index, path in enumerate(package_paths, start=1):
        if progress:
            progress("reading", int((index - 1) / total * 70), f"读取 {path.name}")
        raw = path.read_bytes()
        mode = "encrypted" if is_encrypted_wxapkg(raw) else "plain" if is_plain_wxapkg(raw) else "unknown"
        use_appid = appid.strip()
        if mode == "encrypted":
            use_appid = validate_appid(use_appid)
        decrypted = decrypt_wxapkg(raw, use_appid)
        unpacked = unpack_to_dir(decrypted, src_dir)
        all_files.extend(unpacked.files)
        package_reports.append(
            {
                "path": str(path),
                "name": path.name,
                "mode": mode,
                "files": len(unpacked.files),
                "commonRoot": unpacked.common_root,
                "size": path.stat().st_size,
            }
        )
        if progress:
            progress("unpacking", int(index / total * 70), f"已解包 {path.name}: {len(unpacked.files)} 个文件")

    generated_files = generate_decompiler_project_files(src_dir)
    limit_warning = _normalize_app_json_devtools_limits(src_dir)
    if limit_warning:
        warnings.append(limit_warning)
        if "app.json" not in generated_files:
            generated_files.append("app.json")
    path_warning = _normalize_decompiled_reference_paths(src_dir)
    if path_warning:
        warnings.append(path_warning)
    if progress:
        if limit_warning:
            progress("decompiled", 82, "已修正 app.json subPackages 上限")
        elif path_warning:
            progress("decompiled", 82, "已修正 WXML/WXSS 本地引用路径")
        elif generated_files:
            progress("decompiled", 82, f"已按兼容流程生成 {len(generated_files)} 个项目文件")
        else:
            progress("decompiled", 82, "已按兼容流程完成解包")

    zip_path = output_dir / "takeWxapkg-src.zip"
    zip_path, zip_entries = make_src_zip(src_dir, zip_path)
    if progress:
        progress("packaging", 94, "已生成反编译 ZIP")

    report = {
        "tool": "takeWxapkg",
        "status": "completed",
        "appid": appid,
        "outputDir": str(output_dir),
        "srcDir": str(src_dir),
        "zipPath": str(zip_path),
        "packageCount": len(package_paths),
        "extractedFiles": len(set(all_files)),
        "generatedFiles": generated_files,
        "warnings": warnings,
        "packages": package_reports,
        "zipEntries": zip_entries,
        "elapsedSeconds": round(time.perf_counter() - started, 3),
    }
    (reports_dir / "takeWxapkg-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        "utf-8",
    )
    if progress:
        progress("completed", 100, "处理完成")

    return ExtractResult(
        status="completed",
        appid=appid,
        output_dir=output_dir,
        src_dir=src_dir,
        zip_path=zip_path,
        reports_dir=reports_dir,
        package_count=len(package_paths),
        extracted_files=len(set(all_files)),
        generated_files=generated_files,
        warnings=warnings,
        elapsed_seconds=report["elapsedSeconds"],
    )
