"""Nessus Pro API client — executes curl via existing SSH connection to Kali."""
import json
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


def _req(conn, method: str, path: str, access_key: str, secret_key: str, body=None) -> Any:
    """Run a Nessus API request via curl on the remote Kali box (localhost:8834)."""
    auth = f"accessKey={access_key}; secretKey={secret_key}"
    cmd = (
        f"curl -sk --connect-timeout 10 -m 55 -X {method} "
        f"-H 'X-ApiKeys: {auth}' "
        f"-H 'Accept: application/json'"
    )
    if body:
        safe = json.dumps(body).replace("'", r"'\''")
        cmd += f" -H 'Content-Type: application/json' -d '{safe}'"
    cmd += f" 'https://localhost:8834{path}'"

    out, err, _code = conn.exec(cmd, timeout=60)
    text = out.strip()
    log.debug("Nessus %s %s → %d bytes (stderr: %d bytes)", method, path, len(text), len(err.strip()))
    if not text:
        raise ValueError(
            f"Empty response from Nessus ({method} {path}) — "
            "check API keys or SSH connectivity"
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise ValueError(
            f"Non-JSON response from Nessus ({method} {path}): "
            f"{len(text)} bytes received — "
            f"first 200: {text[:200]!r} … last 100: {text[-100:]!r}"
        )


def get_folders(conn, access_key: str, secret_key: str) -> List[Dict]:
    data = _req(conn, "GET", "/folders", access_key, secret_key)
    return data.get("folders", [])


def get_scans(conn, access_key: str, secret_key: str, folder_id: Optional[int] = None) -> List[Dict]:
    path = f"/scans?folder_id={folder_id}" if folder_id is not None else "/scans"
    data = _req(conn, "GET", path, access_key, secret_key)
    scans = data.get("scans") or []
    return [
        {
            "id": s["id"],
            "name": s.get("name", ""),
            "status": s.get("status", ""),
            "folder_id": s.get("folder_id"),
            "last_modification_date": s.get("last_modification_date"),
        }
        for s in scans
    ]


def get_scan_hosts(conn, access_key: str, secret_key: str, scan_id: int) -> List[Dict]:
    """Return all hosts found in a completed Nessus scan."""
    data = _req(conn, "GET", f"/scans/{scan_id}", access_key, secret_key)
    hosts = data.get("hosts") or []
    return [
        {"ip": h.get("hostname", ""), "status": h.get("status", "")}
        for h in hosts
        if h.get("hostname")
    ]
