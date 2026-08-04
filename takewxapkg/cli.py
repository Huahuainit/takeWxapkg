from __future__ import annotations

import argparse
from pathlib import Path

from .wxapkg_core import extract_packages


def main() -> int:
    parser = argparse.ArgumentParser(description="takeWxapkg command line extractor")
    parser.add_argument("wxapkg", nargs="+", help="wxapkg 文件路径")
    parser.add_argument("-a", "--appid", default="", help="加密包 AppID")
    parser.add_argument("-o", "--output", default="output/manual", help="输出目录")
    args = parser.parse_args()

    result = extract_packages(
        [Path(item) for item in args.wxapkg],
        Path(args.output),
        appid=args.appid,
        progress=lambda stage, percent, msg: print(f"[{percent:3d}%] {stage}: {msg}"),
    )
    print(f"完成: {result.extracted_files} 个文件")
    print(f"源码目录: {result.src_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
