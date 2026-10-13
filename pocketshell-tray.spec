# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification to build standalone PocketShellTray.exe (GUI mode, no console)."""

block_cipher = None

a = Analysis(
    ["src/pocketshell/tray/__main__.py"],
    pathex=["src"],
    binaries=[],
    datas=[],
    hiddenimports=[
        "pystray",
        "pystray._win32",
        "pystray._xorg",
        "PIL",
        "PIL.Image",
        "PIL.ImageDraw",
        "pocketshell",
        "pocketshell.cli",
        "pocketshell.tray",
        "pocketshell.tray.app",
        "pocketshell.tray.autostart",
        "pocketshell.tray.cli",
        "pocketshell.tray.icons",
        "pocketshell.tray.model",
        "pocketshell.tray.single_instance",
        "pocketshell.tray.status_client",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
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
    name="PocketShellTray",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
