from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from takewxapkg.gui import (
    build_extract_jobs,
    collect_wxapkg_delete_targets,
    delete_wxapkg_files,
    expand_related_candidates,
)
from takewxapkg.path_finder import WxapkgCandidate, scan_for_wxapkg
from takewxapkg.wxapkg_core import extract_packages, parse_entries, unpack_to_dir


def make_package(files: list[tuple[str, bytes]]) -> bytes:
    index_len = 4 + sum(4 + len(name.encode("utf-8")) + 8 for name, _ in files)
    body_start = 14 + index_len
    body = bytearray()
    entries = bytearray()
    entries.extend(struct.pack(">I", len(files)))
    offset = body_start
    for name, content in files:
        raw = name.encode("utf-8")
        entries.extend(struct.pack(">I", len(raw)))
        entries.extend(raw)
        entries.extend(struct.pack(">II", offset, len(content)))
        body.extend(content)
        offset += len(content)
    header = bytearray()
    header.append(0xBE)
    header.extend(struct.pack(">III", 0, index_len, len(body)))
    header.append(0xED)
    return bytes(header + entries + body)


class CoreTest(unittest.TestCase):
    def test_unpack_valid_package(self) -> None:
        data = make_package([("/pages/index.js", b"Page({})")])
        with tempfile.TemporaryDirectory() as temp:
            result = unpack_to_dir(data, Path(temp))
            files = result.files
            self.assertEqual(files, ["pages/index.js"])
            self.assertEqual(result.common_root, "pages/index.js")
            self.assertEqual((Path(temp) / "pages" / "index.js").read_text(), "Page({})")

    def test_reject_traversal(self) -> None:
        data = make_package([("../escape.js", b"x")])
        with self.assertRaises(Exception):
            parse_entries(data)

    def test_allows_entries_that_share_payload_ranges(self) -> None:
        data = make_package([("/a.js", b"shared"), ("/b.js", b"shared")])
        # Some real wxapkg indexes reuse byte ranges. Per-entry bounds are the
        # important safety check; summing declared sizes causes false failures.
        index_len = 4 + (4 + len("/a.js") + 8) + (4 + len("/b.js") + 8)
        body_start = 14 + index_len
        raw = bytearray(data)
        second_offset_pos = 14 + 4 + (4 + len("/a.js") + 8) + 4 + len("/b.js")
        raw[second_offset_pos : second_offset_pos + 4] = struct.pack(">I", body_start)
        entries = parse_entries(bytes(raw))
        self.assertEqual(len(entries), 2)

    def test_extract_packages_uses_decompiler_project_generation(self) -> None:
        data = make_package(
            [
                (
                    "/app-config.json",
                    b'{"global":{"window":{"navigationBarTitleText":"Demo"}},'
                    b'"pages":["pages/index.html"],'
                    b'"tabBar":{"list":[{"pagePath":"pages/index.html","text":"Home"}]}}',
                ),
                ("/pages/index.js", b"Page({})"),
            ]
        )
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            legacy_src = temp_path / "out" / "src"
            legacy_src.mkdir(parents=True)
            (legacy_src / "app.json").write_text("legacy", "utf-8")
            result = extract_packages([pkg], temp_path / "out")
            self.assertEqual(result.src_dir.name, "decompiled")
            self.assertTrue((result.src_dir / "app-config.json").is_file())
            app_json = json.loads((result.src_dir / "app.json").read_text("utf-8"))
            self.assertEqual(app_json["pages"], ["pages/index"])
            self.assertEqual(app_json["tabBar"]["list"][0]["pagePath"], "pages/index")
            self.assertEqual(app_json["window"]["navigationBarTitleText"], "Demo")
            project_config = json.loads((result.src_dir / "project.private.config.json").read_text("utf-8"))
            self.assertFalse(project_config["setting"]["es6"])
            self.assertFalse(project_config["setting"]["urlCheck"])
            self.assertFalse(legacy_src.exists())
            self.assertTrue(result.zip_path.is_file())
            self.assertTrue((result.reports_dir / "takeWxapkg-report.json").is_file())
            self.assertEqual(result.extracted_files, 2)
            self.assertTrue((result.src_dir / "pages" / "index.json").is_file())
            self.assertTrue((result.src_dir / "pages" / "index.wxml").is_file())
            self.assertIn("app.json", result.generated_files)
            self.assertIn("pages/index.json", result.generated_files)
            self.assertIn("pages/index.wxml", result.generated_files)
            self.assertIn("project.private.config.json", result.generated_files)

    def test_extract_packages_writes_runtime_js_json_and_wxml_refs(self) -> None:
        data = make_package(
            [
                (
                    "/app-config.json",
                    b'{"pages":["pages/adddream/index"],"page":{"pages/adddream/index.html":{"window":{}}}}',
                ),
                (
                    "/app-service.js",
                    b'__wxAppCode__[\'pages/adddream/index.json\'] = {"usingComponents":{}};'
                    b'if (__vd_version_info__.delayedGwx) __wxAppCode__[\'pages/adddream/index.wxml\'] = '
                    b'[$gwx_XC_1, \'./pages/adddream/index.wxml\'];'
                    b'define("pages/adddream/index.js",function(require,module,exports){'
                    b'"use strict";Page({data:{ok:true}});'
                    b'},{isPage:true,currentFile:"pages/adddream/index.js"});',
                ),
                (
                    "/pages/adddream/index.html",
                    b"<script>$gwx_XC_1('./pages/adddream/index.wxml')</script>",
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            result = extract_packages([pkg], temp_path / "out")
            page_js = (result.src_dir / "pages" / "adddream" / "index.js").read_text("utf-8")
            page_json = json.loads((result.src_dir / "pages" / "adddream" / "index.json").read_text("utf-8"))
            page_wxml = (result.src_dir / "pages" / "adddream" / "index.wxml").read_text("utf-8")
            self.assertIn("Page({data:{ok:true}});", page_js)
            self.assertEqual(page_json, {"usingComponents": {}})
            self.assertEqual(page_wxml, "<block />\n")
            self.assertIn("pages/adddream/index.js", result.generated_files)
            self.assertIn("pages/adddream/index.json", result.generated_files)
            self.assertIn("pages/adddream/index.wxml", result.generated_files)

    def test_extract_packages_flattens_subpackages_over_devtools_limit(self) -> None:
        subpackages = [{"root": f"pkg{i}/"} for i in range(101)]
        pages = [f"pkg{i}/index" for i in range(101)]
        app_config = {
            "pages": pages,
            "subPackages": subpackages,
            "preloadRule": {
                "pages/index": {"packages": ["pkg0", "pkg100/"]},
                "pages/other": {"packages": ["pkg100"]},
            },
        }
        data = make_package([("/app-config.json", json.dumps(app_config).encode("utf-8"))])
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            result = extract_packages([pkg], temp_path / "out")
            app_json = json.loads((result.src_dir / "app.json").read_text("utf-8"))
            self.assertEqual(len(app_json["subPackages"]), 100)
            self.assertIn("pkg100/index", app_json["pages"])
            self.assertEqual(app_json["preloadRule"]["pages/index"]["packages"], ["pkg0"])
            self.assertNotIn("pages/other", app_json["preloadRule"])
            self.assertTrue(result.warnings)

    def test_extract_packages_prunes_invalid_preload_rule_packages(self) -> None:
        app_config = {
            "pages": ["pkg0/index"],
            "subPackages": [{"root": "pkg0/"}],
            "preloadRule": {
                "pages/index": {"packages": ["pkg0", "missing-package/"]},
                "pages/other": {"packages": ["missing-package"]},
            },
        }
        data = make_package([("/app-config.json", json.dumps(app_config).encode("utf-8"))])
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            result = extract_packages([pkg], temp_path / "out")
            app_json = json.loads((result.src_dir / "app.json").read_text("utf-8"))
            self.assertEqual(app_json["preloadRule"]["pages/index"]["packages"], ["pkg0"])
            self.assertNotIn("pages/other", app_json["preloadRule"])
            self.assertTrue(any("preloadRule" in warning for warning in result.warnings))

    def test_extract_packages_normalizes_decompiled_local_reference_paths(self) -> None:
        data = make_package(
            [
                ("/app-config.json", b'{"pages":["pages/index"]}'),
                ("/pages/index.wxml", b'<view>{{"x\\\\n"}}</view><wxs module="utils" src="..\\\\wxs\\\\utils.wxs"/>'),
                ("/pages/index.wxss", b'@import "..\\\\_commons\\\\20.wxss";'),
                ("/wxs/utils.wxs", b"module.exports = {};"),
                ("/_commons/20.wxss", b".ok{}"),
            ]
        )
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            result = extract_packages([pkg], temp_path / "out")
            page_wxml = (result.src_dir / "pages" / "index.wxml").read_text("utf-8")
            page_wxss = (result.src_dir / "pages" / "index.wxss").read_text("utf-8")
            self.assertIn('src="../wxs/utils.wxs"', page_wxml)
            self.assertIn('{{"x\\\\n"}}', page_wxml)
            self.assertIn('@import "../_commons/20.wxss"', page_wxss)
            self.assertTrue(any("本地引用反斜杠" in warning for warning in result.warnings))

    def test_extract_packages_repairs_wxml_single_brace_attributes(self) -> None:
        data = make_package(
            [
                ("/app-config.json", b'{"pages":["pages/index"]}'),
                (
                    "/pages/index.wxml",
                    b'<template is="goods-push-item" data={goodsPush}></template>\n'
                    b'<template is="goods-push-item" data="{goodsPush}"></template>\n',
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            result = extract_packages([pkg], temp_path / "out")
            page_wxml = (result.src_dir / "pages" / "index.wxml").read_text("utf-8")
            self.assertNotIn("data={goodsPush}", page_wxml)
            self.assertNotIn('data="{goodsPush}"', page_wxml)
            self.assertEqual(page_wxml.count('data="{{goodsPush}}"'), 2)

    def test_extract_packages_replaces_default_wxml_placeholders(self) -> None:
        data = make_package(
            [
                ("/app-config.json", b'{"pages":["pages/index"]}'),
                ("/components/lottery-item.wxml", b"<view class=\"lottery-item\">real</view>\n"),
                (
                    "/pages/index/components/lottery-item.wxml",
                    b"<text>pages/index/components/lottery-item.wxml</text>\n",
                ),
                (
                    "/pages/index/components/missing-item.wxml",
                    b"<text>pages/index/components/missing-item.wxml</text>\n",
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            result = extract_packages([pkg], temp_path / "out")
            replaced = (result.src_dir / "pages" / "index" / "components" / "lottery-item.wxml").read_text("utf-8")
            blanked = (result.src_dir / "pages" / "index" / "components" / "missing-item.wxml").read_text("utf-8")
            self.assertIn("lottery-item", replaced)
            self.assertNotIn("<text>pages/index/components/lottery-item.wxml</text>", replaced)
            self.assertEqual(blanked, "<block />\n")
            self.assertTrue(any("默认 WXML 占位" in warning for warning in result.warnings))

    def test_extract_packages_repairs_missing_static_assets(self) -> None:
        data = make_package(
            [
                ("/app-config.json", b'{"pages":["pages/user-center/index"]}'),
                (
                    "/pages/user-center/index.wxml",
                    b'<image src="../../images/icons/logout.png"></image>\n',
                ),
                (
                    "/pages/user-center/index.wxss",
                    b".icon{background:url(/active/static/h5/51.png-do-not-use-local-path-./pages/user-center/index.wxss&1&99)}\n",
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            result = extract_packages([pkg], temp_path / "out")
            page_wxss = (result.src_dir / "pages" / "user-center" / "index.wxss").read_text("utf-8")
            self.assertIn("url(/active/static/h5/51.png)", page_wxss)
            self.assertNotIn("do-not-use-local-path", page_wxss)
            self.assertTrue((result.src_dir / "active" / "static" / "h5" / "51.png").is_file())
            self.assertTrue((result.src_dir / "images" / "icons" / "logout.png").is_file())
            self.assertTrue(all("仍发现" not in warning for warning in result.warnings))

    def test_extract_packages_repairs_wxs_require_paths(self) -> None:
        data = make_package(
            [
                ("/app-config.json", b'{"pages":["pages/index"]}'),
                ("/wxComponents/vant/cascader/index.wxs", b"var utils = require('..\\\\..\\\\..\\\\require('.\\\\wxComponents\\\\vant\\\\wxs\\\\utils.wxs')();');\n"),
                ("/wxComponents/vant/wxs/utils.wxs", b"var bem = require('p_./wxComponents/vant/wxs/bem.wxs')().bem;\n"),
                ("/wxComponents/vant/wxs/bem.wxs", b"module.exports.bem = function(){};\n"),
            ]
        )
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pkg = temp_path / "demo.wxapkg"
            pkg.write_bytes(data)
            result = extract_packages([pkg], temp_path / "out")
            cascader = (result.src_dir / "wxComponents" / "vant" / "cascader" / "index.wxs").read_text("utf-8")
            utils = (result.src_dir / "wxComponents" / "vant" / "wxs" / "utils.wxs").read_text("utf-8")
            self.assertEqual(cascader.strip(), "var utils = require('../wxs/utils.wxs');")
            self.assertEqual(utils.strip(), "var bem = require('./bem.wxs').bem;")
            self.assertNotIn("p_.", utils)
            self.assertNotIn(")()", utils)
            self.assertTrue(any("WXS" in warning for warning in result.warnings))

    def test_scan_hides_old_duplicate_package_versions(self) -> None:
        data = make_package([("/pages/index.js", b"Page({})")])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old_pkg = root / "wx0123456789abcdef" / "1" / "__APP__.wxapkg"
            new_pkg = root / "wx0123456789abcdef" / "2" / "__APP__.wxapkg"
            old_pkg.parent.mkdir(parents=True)
            new_pkg.parent.mkdir(parents=True)
            old_pkg.write_bytes(data)
            new_pkg.write_bytes(data)
            old_time = 1_700_000_000
            new_time = 1_800_000_000
            import os

            os.utime(old_pkg, (old_time, old_time))
            os.utime(new_pkg, (new_time, new_time))

            found = scan_for_wxapkg(root)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].path, new_pkg)

    def test_scan_keeps_latest_version_package_group_only(self) -> None:
        data = make_package([("/pages/index.js", b"Page({})")])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old_app = root / "wx0123456789abcdef" / "1" / "__APP__.wxapkg"
            old_sub = root / "wx0123456789abcdef" / "1" / "_old_.wxapkg"
            new_app = root / "wx0123456789abcdef" / "2" / "__APP__.wxapkg"
            new_sub = root / "wx0123456789abcdef" / "2" / "_new_.wxapkg"
            for path in (old_app, old_sub, new_app, new_sub):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            import os

            for path in (old_app, old_sub):
                os.utime(path, (1_700_000_000, 1_700_000_000))
            for path in (new_app, new_sub):
                os.utime(path, (1_800_000_000, 1_800_000_000))

            found = scan_for_wxapkg(root)
            self.assertEqual({item.path for item in found}, {new_app, new_sub})

    def test_selected_package_expands_to_same_version_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "wx0123456789abcdef" / "2" / "__APP__.wxapkg"
            sub = root / "wx0123456789abcdef" / "2" / "_subpkg_.wxapkg"
            old = root / "wx0123456789abcdef" / "1" / "_old_.wxapkg"
            candidates = [
                WxapkgCandidate("wx0123456789abcdef", app, app.name, 1, 3.0, "encrypted", root),
                WxapkgCandidate("wx0123456789abcdef", sub, sub.name, 1, 2.0, "encrypted", root),
                WxapkgCandidate("wx0123456789abcdef", old, old.name, 1, 1.0, "encrypted", root),
            ]
            expanded = expand_related_candidates([candidates[0]], candidates)
            self.assertEqual({item.path for item in expanded}, {app, sub})

    def test_extract_jobs_use_versioned_output_and_include_subpackages(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "wx0123456789abcdef" / "2" / "__APP__.wxapkg"
            sub = root / "wx0123456789abcdef" / "2" / "_subpkg_.wxapkg"
            candidates = [
                WxapkgCandidate("wx0123456789abcdef", sub, sub.name, 1, 2.0, "encrypted", root),
                WxapkgCandidate("wx0123456789abcdef", app, app.name, 1, 3.0, "encrypted", root),
            ]
            jobs, missing = build_extract_jobs(candidates, root / "out")
            self.assertEqual(missing, [])
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0][0], "wx0123456789abcdef_v2")
            self.assertEqual(jobs[0][1], [app, sub])
            self.assertEqual(jobs[0][3], root / "out" / "wx0123456789abcdef_v2")

    def test_delete_targets_only_collect_wxapkg_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg = root / "wx0123456789abcdef" / "2" / "__APP__.wxapkg"
            other = root / "wx0123456789abcdef" / "2" / "note.txt"
            pkg.parent.mkdir(parents=True)
            pkg.write_bytes(b"pkg")
            other.write_text("keep", "utf-8")

            targets = collect_wxapkg_delete_targets(root)
            self.assertEqual(targets, [pkg])

    def test_delete_wxapkg_files_keeps_other_files_and_prunes_empty_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            empty_pkg = root / "wx0123456789abcdef" / "2" / "__APP__.wxapkg"
            kept_pkg = root / "wx1111111111111111" / "3" / "_subpkg_.wxapkg"
            keep = root / "wx1111111111111111" / "3" / "note.txt"
            for path in (empty_pkg, kept_pkg):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"pkg")
            keep.write_text("keep", "utf-8")

            deleted, failures = delete_wxapkg_files(root, [empty_pkg, kept_pkg])
            self.assertEqual(deleted, 2)
            self.assertEqual(failures, [])
            self.assertFalse(empty_pkg.exists())
            self.assertFalse(empty_pkg.parent.exists())
            self.assertFalse(kept_pkg.exists())
            self.assertTrue(keep.exists())
            self.assertTrue(keep.parent.exists())

    def test_stale_manual_appid_does_not_override_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg = root / "wx9423df5b195336f1" / "__APP__.wxapkg"
            candidate = WxapkgCandidate(
                appid="wx9423df5b195336f1",
                path=pkg,
                name=pkg.name,
                size=1,
                modified=1.0,
                mode="encrypted",
                root=root,
            )
            jobs, missing = build_extract_jobs(
                [candidate],
                root / "out",
                manual_appid="wx9b3d92a9d7eec80c",
                force_appid=False,
            )
            self.assertEqual(missing, [])
            self.assertEqual(jobs[0][0], "wx9423df5b195336f1")
            self.assertEqual(jobs[0][2], "wx9423df5b195336f1")

    def test_manual_appid_override_requires_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg = root / "wx9423df5b195336f1" / "__APP__.wxapkg"
            candidate = WxapkgCandidate(
                appid="wx9423df5b195336f1",
                path=pkg,
                name=pkg.name,
                size=1,
                modified=1.0,
                mode="encrypted",
                root=root,
            )
            jobs, missing = build_extract_jobs(
                [candidate],
                root / "out",
                manual_appid="wx9b3d92a9d7eec80c",
                force_appid=True,
            )
            self.assertEqual(missing, [])
            self.assertEqual(jobs[0][0], "wx9423df5b195336f1")
            self.assertEqual(jobs[0][2], "wx9b3d92a9d7eec80c")


if __name__ == "__main__":
    unittest.main()
