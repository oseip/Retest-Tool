"""Ongoing Settings page: lets an already-set-up user view and edit their own
config.yaml from the dashboard — rotate the Jira token, jump-server password,
or any client's Kali/Nessus credentials, and add/remove clients — without
hand-editing YAML.

Secrets already on disk are never sent back to the browser, only whether
they're set. Submitted secret fields are optional: omit/blank to keep the
existing value, or send a new value to rotate it. After writing, the running
Jira client and poller thread are reloaded in place — no app restart needed.
"""
import logging
import os
from typing import List, Optional

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .setup import _test_jira, _test_jump_server

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings")

CONFIG_PATH = "config/config.yaml"


def _load_raw() -> dict:
    if not os.path.exists(CONFIG_PATH):
        raise HTTPException(400, f"{CONFIG_PATH} does not exist yet — complete first-run setup first.")
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


@router.get("")
def get_settings():
    data = _load_raw()
    jira = data.get("jira", {})
    jump = data.get("jump_server", {})
    clients = data.get("clients", [])
    return {
        "jira": {
            "url": jira.get("url", ""),
            "username": jira.get("username", ""),
            "project": jira.get("project", ""),
            "retest_status": jira.get("retest_status", "Remediated"),
            "poll_interval": jira.get("poll_interval", 300),
            "api_token_set": bool(jira.get("api_token")),
        },
        "jump_server": {
            "host": jump.get("host", ""),
            "port": jump.get("port", 22),
            "user": jump.get("user", ""),
            "password_set": bool(jump.get("password")),
        },
        "clients": [
            {
                "label": c.get("label", ""),
                "name": c.get("name", ""),
                "kali_port": c.get("kali_port", 22),
                "kali_user": c.get("kali_user", ""),
                "kali_password_set": bool(c.get("kali_password")),
                "nessus_access_key_set": bool(c.get("nessus_access_key")),
                "nessus_secret_key_set": bool(c.get("nessus_secret_key")),
            }
            for c in clients
        ],
    }


class JiraSettings(BaseModel):
    url: str
    username: str
    api_token: Optional[str] = None   # blank/omitted = keep existing
    project: str
    retest_status: str = "Remediated"
    poll_interval: int = 300


class JumpSettings(BaseModel):
    host: str
    port: int = 22
    user: str
    password: Optional[str] = None    # blank/omitted = keep existing


class ClientSettings(BaseModel):
    label: str
    name: str
    kali_port: int = 22
    kali_user: str = "kali"
    kali_password: Optional[str] = None          # blank/omitted = keep existing
    nessus_access_key: Optional[str] = None       # blank/omitted = keep existing
    nessus_secret_key: Optional[str] = None       # blank/omitted = keep existing


class SettingsUpdate(BaseModel):
    jira: JiraSettings
    jump_server: JumpSettings
    clients: List[ClientSettings]


@router.post("")
def update_settings(req: SettingsUpdate):
    existing = _load_raw()
    existing_jira = existing.get("jira", {})
    existing_jump = existing.get("jump_server", {})
    existing_clients = {c["label"]: c for c in existing.get("clients", [])}

    if not req.clients:
        raise HTTPException(400, "At least one client is required.")

    jira_token = req.jira.api_token or existing_jira.get("api_token")
    if not jira_token:
        raise HTTPException(400, "Jira API token is required.")

    jump_password = req.jump_server.password or existing_jump.get("password")
    if not jump_password:
        raise HTTPException(400, "Jump server password is required.")

    merged_clients = []
    for c in req.clients:
        label = c.label.strip()
        if not label:
            raise HTTPException(400, "Every client needs a label.")
        old = existing_clients.get(label, {})
        kali_password = c.kali_password or old.get("kali_password")
        if not kali_password:
            raise HTTPException(400, f"Client '{label}' is missing a Kali password.")
        merged_clients.append({
            "label": label,
            "name": c.name or old.get("name") or label,
            "kali_port": c.kali_port,
            "kali_user": c.kali_user,
            "kali_password": kali_password,
            "nessus_access_key": c.nessus_access_key if c.nessus_access_key is not None else old.get("nessus_access_key", ""),
            "nessus_secret_key": c.nessus_secret_key if c.nessus_secret_key is not None else old.get("nessus_secret_key", ""),
        })

    _test_jira(req.jira.url, req.jira.username, jira_token)
    _test_jump_server(req.jump_server.host, req.jump_server.port, req.jump_server.user, jump_password)

    config = {
        "jira": {
            "url": req.jira.url,
            "username": req.jira.username,
            "api_token": jira_token,
            "project": req.jira.project,
            "retest_status": req.jira.retest_status,
            "poll_interval": req.jira.poll_interval,
        },
        "jump_server": {
            "host": req.jump_server.host,
            "port": req.jump_server.port,
            "user": req.jump_server.user,
            "password": jump_password,
        },
        "clients": merged_clients,
    }
    if "app" in existing:
        config["app"] = existing["app"]

    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)

    log.info("Settings updated via UI — %d client(s) configured.", len(merged_clients))

    from . import main as main_mod
    try:
        main_mod.reload_runtime_config()
    except Exception as exc:
        log.exception("Settings saved but live reload failed")
        return {
            "ok": True,
            "message": f"Settings saved, but applying them live failed ({exc}) — restart the app to be safe.",
        }

    return {"ok": True, "message": "Settings saved and applied — no restart needed."}
