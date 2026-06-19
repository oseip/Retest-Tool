# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Nemesis Retest Tool.

Build:
    pip install pyinstaller
    pyinstaller retest.spec

Output:  dist/retest-tool   (or dist/retest-tool.exe on Windows)
"""

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

block_cipher = None

# ── Collect everything for packages that need full submodule trees ────────────
_uvicorn_d,    _uvicorn_b,    _uvicorn_h    = collect_all("uvicorn")
_starlette_d,  _starlette_b,  _starlette_h  = collect_all("starlette")
_fastapi_d,    _fastapi_b,    _fastapi_h    = collect_all("fastapi")
_paramiko_d,   _paramiko_b,   _paramiko_h   = collect_all("paramiko")
_cryptography_d, _cryptography_b, _cryptography_h = collect_all("cryptography")
_jira_d,       _jira_b,       _jira_h       = collect_all("jira")
_pydantic_d,   _pydantic_b,   _pydantic_h   = collect_all("pydantic")
_pydantic_core_d, _pydantic_core_b, _pydantic_core_h = collect_all("pydantic_core")
_yaml_d,       _yaml_b,       _yaml_h       = collect_all("yaml")

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=(
        _uvicorn_b + _starlette_b + _fastapi_b +
        _paramiko_b + _cryptography_b + _jira_b +
        _pydantic_b + _pydantic_core_b + _yaml_b
    ),
    datas=[
        # ── Bundle the entire frontend directory (read-only resources) ──────
        ("frontend",  "frontend"),
        # ── Application source (needed for string-based imports) ────────────
        ("src",       "src"),
    ] + (
        _uvicorn_d + _starlette_d + _fastapi_d +
        _paramiko_d + _cryptography_d + _jira_d +
        _pydantic_d + _pydantic_core_d + _yaml_d
    ),
    hiddenimports=[
        # App modules
        "src.main", "src.config", "src.jira_client", "src.scanner",
        "src.vuln_rules", "src.assets", "src.nessus_client",
        "src.connections", "src.setup", "src.settings_api",
        "src.shell_ws", "src.ssh_exec", "src.tunnel_api", "src.port_forward",
        # Uvicorn internals
        "uvicorn.logging", "uvicorn.loops", "uvicorn.loops.auto",
        "uvicorn.loops.asyncio", "uvicorn.protocols",
        "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets", "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.lifespan", "uvicorn.lifespan.on",
        # Standard async / networking
        "anyio", "anyio._backends._asyncio",
        "h11", "websockets", "httptools",
        # Paramiko / crypto
        "paramiko.ed25519key", "paramiko.transport",
        "cryptography.hazmat.primitives.asymmetric",
        "cryptography.hazmat.bindings._rust",
        # Jira / requests
        "requests", "requests_oauthlib", "oauthlib",
        "atlassian",
        # Misc
        "multiprocessing.freeze_support",
        "email.mime.multipart", "email.mime.text",
        "logging.handlers",
    ] + _uvicorn_h + _starlette_h + _fastapi_h + _paramiko_h + _cryptography_h
      + _jira_h + _pydantic_h + _pydantic_core_h + _yaml_h,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "pytest_mock", "tkinter", "matplotlib", "numpy"],
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
    name="retest-tool",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX can break cryptography binaries — keep off
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,       # Keep console visible so users see the URL + errors
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
