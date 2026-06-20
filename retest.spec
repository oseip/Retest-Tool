# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Nemesis Retest Tool.

Build (macOS):
    .venv/bin/pyinstaller retest.spec --noconfirm

Output:  dist/Nemesis.app   (macOS)
         dist/retest-tool   (Linux / Windows)
"""
import sys as _sys
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# ── Collect everything for packages that need full submodule trees ────────────
_uvicorn_d,      _uvicorn_b,      _uvicorn_h      = collect_all("uvicorn")
_starlette_d,    _starlette_b,    _starlette_h    = collect_all("starlette")
_fastapi_d,      _fastapi_b,      _fastapi_h      = collect_all("fastapi")
_paramiko_d,     _paramiko_b,     _paramiko_h     = collect_all("paramiko")
_cryptography_d, _cryptography_b, _cryptography_h = collect_all("cryptography")
_jira_d,         _jira_b,         _jira_h         = collect_all("jira")
_pydantic_d,     _pydantic_b,     _pydantic_h     = collect_all("pydantic")
_pydantic_core_d,_pydantic_core_b,_pydantic_core_h= collect_all("pydantic_core")
_yaml_d,         _yaml_b,         _yaml_h         = collect_all("yaml")
_openpyxl_d,     _openpyxl_b,     _openpyxl_h     = collect_all("openpyxl")

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=(
        _uvicorn_b + _starlette_b + _fastapi_b +
        _paramiko_b + _cryptography_b + _jira_b +
        _pydantic_b + _pydantic_core_b + _yaml_b + _openpyxl_b
    ),
    datas=[
        # ── Bundle the entire frontend directory (read-only resources) ──────
        ("frontend", "frontend"),
        # ── Application source (needed for string-based imports) ────────────
        ("src",      "src"),
    ] + (
        _uvicorn_d + _starlette_d + _fastapi_d +
        _paramiko_d + _cryptography_d + _jira_d +
        _pydantic_d + _pydantic_core_d + _yaml_d + _openpyxl_d
    ),
    hiddenimports=[
        # ── App modules ─────────────────────────────────────────────────────
        "src.main", "src.config", "src.jira_client", "src.jira_client_v2",
        "src.scanner", "src.vuln_rules", "src.assets", "src.nessus_client",
        "src.connections", "src.setup", "src.settings_api",
        "src.shell_ws", "src.ssh_exec", "src.tunnel_api", "src.port_forward",
        # ── Uvicorn internals ───────────────────────────────────────────────
        "uvicorn.logging", "uvicorn.loops", "uvicorn.loops.auto",
        "uvicorn.loops.asyncio", "uvicorn.protocols",
        "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets", "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.lifespan", "uvicorn.lifespan.on",
        # ── Async / networking ──────────────────────────────────────────────
        "anyio", "anyio._backends._asyncio",
        "h11", "websockets", "httptools",
        # ── Paramiko / crypto ───────────────────────────────────────────────
        "paramiko.ed25519key", "paramiko.transport",
        "cryptography.hazmat.primitives.asymmetric",
        "cryptography.hazmat.bindings._rust",
        # ── Jira / requests ─────────────────────────────────────────────────
        "requests", "requests_oauthlib", "oauthlib",
        "jira", "jira.client", "jira.config", "jira.exceptions",
        "jira.resilientsession", "jira.resources", "jira.utils", "jira.jirashell",
        # ── Excel / CSV ─────────────────────────────────────────────────────
        "openpyxl", "openpyxl.styles", "openpyxl.utils", "openpyxl.reader",
        # ── Misc ────────────────────────────────────────────────────────────
        "multiprocessing",
        "email.mime.multipart", "email.mime.text",
        "logging.handlers",
        "webbrowser", "threading",
    ] + _uvicorn_h + _starlette_h + _fastapi_h + _paramiko_h + _cryptography_h
      + _jira_h + _pydantic_h + _pydantic_core_h + _yaml_h + _openpyxl_h,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "pytest_mock", "tkinter", "matplotlib", "numpy"],
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
    name="retest-tool-macos",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX can break cryptography binaries — keep off
    console=True,       # Keep terminal so users see the URL + any errors
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
