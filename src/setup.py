"""First-run Settings page: collects a colleague's personal Jira + jump-server
credentials and their opco selection, validates them live against the real
services, then writes config/config.yaml — so nobody has to hand-edit YAML.

Kali box credentials are never typed in here — they're pulled server-side
from the shared clients_catalog.yaml based on which opco labels are picked,
and never sent to the browser.
"""
import logging
import os
import socket
from typing import List

import paramiko
import requests
import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .config import load_catalog

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/setup")

CONFIG_PATH = "config/config.yaml"
CATALOG_PATH = "config/clients_catalog.yaml"


@router.get("/catalog")
def get_catalog():
    if not os.path.exists(CATALOG_PATH):
        raise HTTPException(
            400,
            f"Catalog file not found at {CATALOG_PATH}. Ask whoever administers "
            "this tool to share clients_catalog.yaml with you and drop it in the "
            "config/ folder, then reload this page.",
        )
    try:
        catalog = load_catalog(CATALOG_PATH)
    except Exception as exc:
        raise HTTPException(400, f"Could not read catalog file: {exc}")

    defaults = catalog.get("defaults", {})
    clients = catalog.get("clients", [])
    return {
        "jira_url": defaults.get("jira", {}).get("url", ""),
        "jump_host": defaults.get("jump_server", {}).get("host", ""),
        "clients": [
            {"label": c["label"], "name": c.get("name", c["label"])}
            for c in clients
        ],
    }


class SetupRequest(BaseModel):
    jira_email: str
    jira_api_token: str
    jump_user: str
    jump_password: str
    client_labels: List[str]


def _test_jira(url: str, email: str, token: str):
    try:
        resp = requests.get(
            f"{url}/rest/api/3/myself",
            auth=(email, token),
            headers={"Accept": "application/json"},
            timeout=15,
        )
    except Exception as exc:
        raise HTTPException(400, f"Could not reach Jira at {url}: {exc}")
    if resp.status_code == 401:
        raise HTTPException(400, "Jira login failed — check your email and API token.")
    if not resp.ok:
        raise HTTPException(400, f"Jira returned an error ({resp.status_code}) — check the URL/project setup.")


def _test_jump_server(host: str, port: int, user: str, password: str):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=user, password=password,
            timeout=15, look_for_keys=False, allow_agent=False,
        )
    except paramiko.AuthenticationException:
        raise HTTPException(400, "Jump server login failed — check your username and password.")
    except (socket.error, paramiko.SSHException) as exc:
        raise HTTPException(400, f"Could not reach jump server {host}:{port} — {exc}")
    finally:
        client.close()


@router.post("/submit")
def submit_setup(req: SetupRequest):
    if os.path.exists(CONFIG_PATH):
        raise HTTPException(400, "config.yaml already exists — setup has already been completed.")
    if not os.path.exists(CATALOG_PATH):
        raise HTTPException(400, f"Catalog file not found at {CATALOG_PATH}.")
    if not req.client_labels:
        raise HTTPException(400, "Select at least one opco.")

    try:
        catalog = load_catalog(CATALOG_PATH)
    except Exception as exc:
        raise HTTPException(400, f"Could not read catalog file: {exc}")

    defaults = catalog.get("defaults", {})
    catalog_clients = {c["label"]: c for c in catalog.get("clients", [])}

    missing = [l for l in req.client_labels if l not in catalog_clients]
    if missing:
        raise HTTPException(400, f"Unknown opco label(s): {', '.join(missing)}")

    jira_defaults = defaults.get("jira", {})
    jump_defaults = defaults.get("jump_server", {})

    jira_url = jira_defaults.get("url")
    if not jira_url:
        raise HTTPException(400, "Catalog is missing defaults.jira.url")
    jump_host = jump_defaults.get("host")
    if not jump_host:
        raise HTTPException(400, "Catalog is missing defaults.jump_server.host")
    jump_port = jump_defaults.get("port", 22)

    _test_jira(jira_url, req.jira_email, req.jira_api_token)
    _test_jump_server(jump_host, jump_port, req.jump_user, req.jump_password)

    config = {
        "jira": {
            "url": jira_url,
            "username": req.jira_email,
            "api_token": req.jira_api_token,
            "project": jira_defaults.get("project", ""),
            "retest_status": jira_defaults.get("retest_status", "Remediated"),
            "poll_interval": jira_defaults.get("poll_interval", 300),
        },
        "jump_server": {
            "host": jump_host,
            "port": jump_port,
            "user": req.jump_user,
            "password": req.jump_password,
        },
        "clients": [catalog_clients[l] for l in req.client_labels],
    }

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)

    log.info(
        "Setup complete — config.yaml written for %s (%d opco(s))",
        req.jira_email, len(req.client_labels),
    )
    return {"ok": True, "message": "Setup complete. Restart the app to load your configuration."}
