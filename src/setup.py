"""First-run Settings page: collects a colleague's Jira, jump-server, and
Kali credentials, validates the Jira/jump-server login live against the real
services, then writes config/config.yaml — so nobody has to hand-edit YAML
and nothing ever needs to be shared with them out-of-band.
"""
import logging
import os
import socket
from typing import List, Optional

import paramiko
import requests
import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/setup")

CONFIG_PATH = "config/config.yaml"


class ClientInput(BaseModel):
    label: str
    name: str
    kali_port: int = 22
    kali_user: str = "kali"
    kali_password: str
    nessus_access_key: Optional[str] = None
    nessus_secret_key: Optional[str] = None


class JiraSecondaryInput(BaseModel):
    url: str
    api_token: str          # Personal Access Token (Bearer auth — no email needed)
    retest_status: str = "Remediated"
    poll_interval: int = 300


class SetupRequest(BaseModel):
    jira_url: str
    jira_email: str
    jira_api_token: str
    jira_project: str
    jira_retest_status: str = "Remediated"
    jira_poll_interval: int = 300
    jump_host: str
    jump_port: int = 22
    jump_user: str
    jump_password: str
    clients: List[ClientInput]
    # Optional non-Axian / secondary Jira
    jira_secondary: Optional[JiraSecondaryInput] = None
    clients_secondary: Optional[List[ClientInput]] = None


def _test_jira(url: str, email: str, token: str):
    """Validate Axian / Cloud Jira using Basic auth (email + API token)."""
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


def _test_jira_pat(url: str, token: str):
    """Validate a Jira Server / Data Centre instance using a Personal Access Token (Bearer)."""
    try:
        resp = requests.get(
            f"{url}/rest/api/2/myself",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=15,
            verify=False,  # some on-prem instances use self-signed certs
        )
    except Exception as exc:
        raise HTTPException(400, f"Could not reach Non-Axian Jira at {url}: {exc}")
    if resp.status_code == 401:
        raise HTTPException(400, "Non-Axian Jira: PAT authentication failed — check your Personal Access Token.")
    if not resp.ok:
        raise HTTPException(400, f"Non-Axian Jira returned an error ({resp.status_code}) — check the URL.")


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
    if not req.clients:
        raise HTTPException(400, "Add at least one client.")

    clients = []
    for c in req.clients:
        label = c.label.strip()
        if not label:
            raise HTTPException(400, "Every client needs a label.")
        if not c.kali_password:
            raise HTTPException(400, f"Client '{label}' is missing a Kali password.")
        clients.append({
            "label": label,
            "name": c.name.strip() or label,
            "kali_port": c.kali_port,
            "kali_user": c.kali_user,
            "kali_password": c.kali_password,
            "nessus_access_key": c.nessus_access_key or "",
            "nessus_secret_key": c.nessus_secret_key or "",
        })

    _test_jira(req.jira_url, req.jira_email, req.jira_api_token)
    _test_jump_server(req.jump_host, req.jump_port, req.jump_user, req.jump_password)

    # Validate secondary Jira credentials if provided
    sec = req.jira_secondary
    sec_clients: list = []
    if sec and sec.url:
        _test_jira_pat(sec.url, sec.api_token)
        for c in (req.clients_secondary or []):
            label = c.label.strip()
            if not label:
                raise HTTPException(400, "Non-Axian Jira: every client needs a label.")
            if not c.kali_password:
                raise HTTPException(400, f"Non-Axian Jira client '{label}' is missing a Kali password.")
            sec_clients.append({
                "label": label,
                "name": c.name.strip() or label,
                "kali_port": c.kali_port,
                "kali_user": c.kali_user,
                "kali_password": c.kali_password,
                "nessus_access_key": c.nessus_access_key or "",
                "nessus_secret_key": c.nessus_secret_key or "",
            })

    config = {
        "jira": {
            "url": req.jira_url,
            "username": req.jira_email,
            "api_token": req.jira_api_token,
            "project": req.jira_project,
            "retest_status": req.jira_retest_status,
            "poll_interval": req.jira_poll_interval,
        },
        "jump_server": {
            "host": req.jump_host,
            "port": req.jump_port,
            "user": req.jump_user,
            "password": req.jump_password,
        },
        "clients": clients,
    }

    if sec and sec.url:
        config["jira_secondary"] = {
            "url": sec.url,
            "api_token": sec.api_token,
            "retest_status": sec.retest_status,
            "poll_interval": sec.poll_interval,
        }
        config["clients_secondary"] = sec_clients

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)

    secondary_msg = f" + Non-Axian ({len(sec_clients)} client(s))" if sec and sec.url else ""
    log.info(
        "Setup complete — config.yaml written for %s (%d client(s))%s",
        req.jira_email, len(clients), secondary_msg,
    )
    return {"ok": True, "message": "Setup complete. Loading the app…"}
