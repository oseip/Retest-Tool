"""Nessus Pro API client — executes curl via existing SSH connection to Kali."""
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


def _req(conn, method: str, path: str, access_key: str, secret_key: str, body=None) -> Any:
    """Run a Nessus API request via curl using API key auth."""
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


def _raw_download(conn, path: str, access_key: str, secret_key: str) -> str:
    """Download raw (non-JSON) content from Nessus — used for CSV exports."""
    auth = f"accessKey={access_key}; secretKey={secret_key}"
    cmd = (
        f"curl -sk --connect-timeout 10 -m 120 "
        f"-H 'X-ApiKeys: {auth}' "
        f"'https://localhost:8834{path}'"
    )
    out, _err, _code = conn.exec(cmd, timeout=130)
    return out


# ── Read-only helpers ─────────────────────────────────────────────────────────

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
            "total_hosts": s.get("total_hosts"),
        }
        for s in scans
    ]


def _get_fallback_history_id(data: Dict) -> Optional[int]:
    """Return the history_id of the most recent completed run if current is incomplete."""
    info = data.get("info", {})
    if info.get("status") == "completed":
        return None
    history = data.get("history", [])
    completed = [h for h in history if h.get("status") == "completed"]
    if not completed:
        return None
    completed.sort(key=lambda x: x.get("last_modification_date", 0), reverse=True)
    return completed[0].get("history_id")


def get_scan_host_count(conn, access_key: str, secret_key: str, scan_id: int) -> int:
    """Return just the host count for a scan without fetching all host details."""
    data = _req(conn, "GET", f"/scans/{scan_id}", access_key, secret_key)
    hid = _get_fallback_history_id(data)
    if hid:
        log.info("Scan %s incomplete/failed. Falling back to history_id %s for host count.", scan_id, hid)
        data = _req(conn, "GET", f"/scans/{scan_id}?history_id={hid}", access_key, secret_key)
        
    hosts = data.get("hosts") or []
    info  = data.get("info") or {}
    # Try info.hosts_total first (faster), fall back to counting hosts array
    return info.get("hosts_total") or len(hosts)


def get_scan_hosts(conn, access_key: str, secret_key: str, scan_id: int) -> Tuple[List[Dict], Optional[str]]:
    """Return (hosts, fallback_warning) for a Nessus scan."""
    data = _req(conn, "GET", f"/scans/{scan_id}", access_key, secret_key)
    hid = _get_fallback_history_id(data)
    warning = None
    if hid:
        warning = f"Scan {scan_id} was {data.get('info', {}).get('status')}; automatically fell back to last successful run ({hid})"
        log.info(warning)
        data = _req(conn, "GET", f"/scans/{scan_id}?history_id={hid}", access_key, secret_key)

    hosts = data.get("hosts") or []
    return [
        {"ip": h.get("hostname", ""), "status": h.get("status", "")}
        for h in hosts
        if h.get("hostname")
    ], warning


def get_scan_info(conn, access_key: str, secret_key: str, scan_id: int) -> Dict:
    """Return basic info (name, status, targets) for a scan."""
    data = _req(conn, "GET", f"/scans/{scan_id}", access_key, secret_key)
    info = data.get("info") or {}
    return {
        "id": scan_id,
        "name": info.get("name", f"Scan {scan_id}"),
        "status": info.get("status", "unknown"),
        "targets": info.get("targets", ""),
    }


# ── Export ────────────────────────────────────────────────────────────────────

def export_scan_csv(
    conn, access_key: str, secret_key: str, scan_id: int
) -> Tuple[str, str]:
    """
    Export a Nessus scan as CSV.

    Returns (csv_text, scan_name).
    Three-step Nessus flow:
      1. POST /scans/{id}/export  → file_id
      2. Poll /export/{file_id}/status until "ready"
      3. GET  /export/{file_id}/download → CSV text
    """
    info = get_scan_info(conn, access_key, secret_key, scan_id)
    scan_name = info["name"]

    resp = _req(conn, "POST", f"/scans/{scan_id}/export", access_key, secret_key,
                body={"format": "csv"})
    file_id = resp.get("file")
    if not file_id:
        raise ValueError(f"Nessus did not return a file ID for scan {scan_id}")

    # Poll until ready (max 4 min)
    for attempt in range(80):
        st = _req(conn, "GET", f"/scans/{scan_id}/export/{file_id}/status",
                  access_key, secret_key)
        if st.get("status") == "ready":
            break
        log.debug("Export scan %s: status=%s (attempt %d)", scan_id, st.get("status"), attempt)
        time.sleep(3)
    else:
        raise ValueError(f"Export for scan '{scan_name}' timed out after 4 minutes")

    csv_text = _raw_download(conn, f"/scans/{scan_id}/export/{file_id}/download",
                             access_key, secret_key)
    if not csv_text.strip():
        raise ValueError(f"Empty CSV downloaded for scan '{scan_name}'")

    return csv_text, scan_name


# ── API key generation via username/password ──────────────────────────────────

def fetch_api_keys(conn, username: str, password: str) -> Tuple[str, str]:
    """
    Log in to Nessus with username+password, generate a new API key pair,
    then destroy the session.  Returns (access_key, secret_key).

    Requires Nessus 8.x+.  Runs all calls as curl over the existing SSH
    connection to Kali (Nessus listens on localhost:8834 on that box).
    """
    # Escape single-quotes in credentials for shell safety
    def _sh(s: str) -> str:
        return s.replace("'", r"'\''")

    # 1. Create session → token
    login_cmd = (
        f"curl -sk --connect-timeout 10 -m 30 -X POST "
        f"https://localhost:8834/session "
        f"-H 'Content-Type: application/json' "
        f"-d '{{\"username\":\"{_sh(username)}\",\"password\":\"{_sh(password)}\"}}'")
    out, _err, _code = conn.exec(login_cmd, timeout=35)
    try:
        session = json.loads(out.strip())
    except json.JSONDecodeError:
        raise ValueError(f"Nessus login returned non-JSON: {out[:200]!r}")

    token = session.get("token")
    if not token:
        err_msg = session.get("error", session.get("message", "invalid credentials"))
        raise ValueError(f"Nessus login failed: {err_msg}")

    try:
        # 2. Generate new API keys
        keys_cmd = (
            f"curl -sk --connect-timeout 10 -m 30 -X PUT "
            f"https://localhost:8834/session/keys "
            f"-H 'X-Cookie: token={_sh(token)}' "
            f"-H 'Content-Type: application/json'")
        out2, _err2, _code2 = conn.exec(keys_cmd, timeout=35)
        try:
            keys = json.loads(out2.strip())
        except json.JSONDecodeError:
            raise ValueError(f"Nessus key generation returned non-JSON: {out2[:200]!r}")

        access_key = keys.get("accessKey") or keys.get("access_key")
        secret_key = keys.get("secretKey") or keys.get("secret_key")
        if not access_key or not secret_key:
            raise ValueError(f"Nessus did not return access/secret keys: {keys}")

        return str(access_key), str(secret_key)
    finally:
        # 3. Always clean up the session
        try:
            del_cmd = (
                f"curl -sk --connect-timeout 10 -m 15 -X DELETE "
                f"https://localhost:8834/session "
                f"-H 'X-Cookie: token={_sh(token)}'")
            conn.exec(del_cmd, timeout=20)
        except Exception:
            pass
