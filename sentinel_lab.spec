# PyInstaller spec file for Sentinel-Lab
# Build with:   pyinstaller sentinel_lab.spec
# Output:       dist/sentinel-lab(.exe)

# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

hiddenimports = (
    collect_submodules("rich")
    + collect_submodules("psutil")
    + ["yaml"]
)

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=[
        ("config/threats.yaml", "config"),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="sentinel-lab",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
