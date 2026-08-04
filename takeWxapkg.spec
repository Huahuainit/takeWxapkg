# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


datas = [("icon.ico", "."), ("assets/chevron-down.svg", "assets")]
runtime_root = Path("vendor/wx_decompiler_runtime")
if runtime_root.exists():
    for runtime_file in runtime_root.rglob("*"):
        if runtime_file.is_file():
            target = Path("vendor/wx_decompiler_runtime") / runtime_file.parent.relative_to(runtime_root)
            datas.append((str(runtime_file), str(target)))


a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    exclude_binaries=False,
    name="takeWxapkg",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="icon.ico",
)
