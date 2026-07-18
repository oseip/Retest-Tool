"""Intake pipeline — pull Nessus scan CSVs, normalise to vulnerability format,
dedup against live Jira tickets, export ready-to-upload CSV.

All code lives here so the feature can be reverted by removing this file and
the three lines that wire it into main.py / index.html / app.js.
"""
import csv
import io
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

log = logging.getLogger(__name__)
router = APIRouter()

# ── In-memory Jira index (one per client label) ───────────────────────────
# {label: {"status": "idle|loading|ready|error", "index": {...}, "count": int, "error": str|None}}
_JIRA_INDEXES: Dict[str, dict] = {}
_INDEX_LOCK = threading.Lock()

# ── Persistent cache ───────────────────────────────────────────────────────
# Survives app restarts and browser refreshes so tickets/scans aren't re-pulled
# from Jira/Nessus every single time. data/ is git-ignored.
_CACHE_DIR        = os.path.join("data", "intake_cache")
_JIRA_CACHE_DIR   = os.path.join(_CACHE_DIR, "jira")
_NESSUS_CACHE_DIR = os.path.join(_CACHE_DIR, "nessus")

# How long a cached Jira index is considered "fresh". Older caches still load
# instantly (so the UI never blocks) but trigger a silent background refresh.
_JIRA_CACHE_TTL = 12 * 3600   # 12 hours


def _safe_name(label: str) -> str:
    """Filesystem-safe version of a client label for use in cache filenames."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(label))


def _ensure_cache_dirs() -> None:
    for d in (_JIRA_CACHE_DIR, _NESSUS_CACHE_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as exc:
            log.warning("Intake cache: could not create %s — %s", d, exc)


def _atomic_write_json(path: str, data: dict) -> None:
    """Write JSON atomically so a crash mid-write can't corrupt the cache."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


# ── Request models ─────────────────────────────────────────────────────────

class PullRequest(BaseModel):
    scan_ids: List[int]
    impact_type: str  = "Internal operations impact"
    actor:       str  = "Unauthenticated user"
    vector:      str  = "Internal network"
    test_type:   str  = "IPT"
    duration:    str  = ""
    force:       bool = False   # bypass the per-scan cache and re-export from Nessus
    project_key: str  = ""
    customer:    str  = ""
    contact_person:    str = ""
    technical_contact: str = ""
    purchaser:   str  = ""
    tester:      str  = ""
    date_started:str  = ""


class CheckDupRequest(BaseModel):
    findings: List[dict]


class ExportRequest(BaseModel):
    findings:          List[dict]
    impact_type:       str = "Internal operations impact"
    actor:             str = "Unauthenticated user"
    vector:            str = "Internal network"
    test_type:         str = "IPT"
    duration:          str = ""
    project_key:       str = ""
    customer:          str = ""
    contact_person:    str = ""
    technical_contact: str = ""
    purchaser:         str = ""
    tester:            str = ""
    date_started:      str = ""
    munit_id:          str = ""


# ── Nessus CSV → vulnerability normaliser ─────────────────────────────────

# Risk values to discard (informational / no risk)
_SKIP_RISKS = {"none", "info", "informational", ""}

# Known service prefixes — checked left-to-right against lowercase vuln title
_SERVICES = [
    ("Apache",      ["apache"]),
    ("nginx",       ["nginx"]),
    ("IIS",         ["iis", "internet information"]),
    ("Tomcat",      ["tomcat"]),
    ("OpenSSL",     ["openssl"]),
    ("SSH",         ["ssh"]),
    ("SSL",         ["ssl certificate", "ssl self-signed", "ssl/tls"]),
    ("TLS",         ["tls version", "tls 1.", "tls renegotiation"]),
    ("RDP",         ["rdp", "remote desktop protocol", "ms rdp"]),
    ("SMB",         ["smb", "samba", "ms17-010", "eternalblue"]),
    ("FTP",         ["ftp"]),
    ("SMTP",        ["smtp"]),
    ("HTTP",        ["http", "web server"]),
    ("PHP",         ["php"]),
    ("MySQL",       ["mysql"]),
    ("PostgreSQL",  ["postgresql", "postgres"]),
    ("MSSQL",       ["mssql", "sql server", "microsoft sql"]),
    ("Oracle",      ["oracle"]),
    ("VNC",         ["vnc"]),
    ("Telnet",      ["telnet"]),
    ("SNMP",        ["snmp"]),
    ("LDAP",        ["ldap"]),
    ("NTP",         ["ntp"]),
    ("DNS",         ["dns"]),
    ("OpenVPN",     ["openvpn"]),
    ("Cisco",       ["cisco"]),
    ("VMware",      ["vmware"]),
    ("Java",        ["java", "jvm"]),
    ("Kubernetes",  ["kubernetes", "k8s"]),
    ("Docker",      ["docker"]),
]


def _service_from_title(title: str) -> str:
    tl = title.lower()
    for svc, patterns in _SERVICES:
        if any(p in tl for p in patterns):
            return svc
    return ""


def _technology(title: str, port: str, protocol: str) -> str:
    svc = _service_from_title(title)
    parts = []
    if svc:
        parts.append(svc)
    elif protocol:
        parts.append(protocol.upper())
    if port and port not in ("0", ""):
        parts.append(port)
    return ",".join(parts) if parts else "TCP"


def _col(row: dict, *names: str) -> str:
    """Case-insensitive column lookup across all provided aliases.

    Rows are pre-normalised to lowercase keys once in _parse_nessus_csv, so this
    is a plain O(1) dict lookup rather than rebuilding a lowercased copy of the
    whole row on every one of the ~15 field accesses per row.
    """
    for n in names:
        v = row.get(n.lower())
        if v is not None:
            return (v or "").strip()
    return ""

_PLUGIN_CACHE = {}


def _parse_nessus_csv(csv_text: str, vector: str = "", actor: str = "", conn=None, ak=None, sk=None) -> List[dict]:
    """Parse one Nessus CSV export into normalised finding dicts."""
    from . import nessus_client as nc
    from concurrent.futures import ThreadPoolExecutor
    # Normalise every header to lowercase once so _col() can do O(1) lookups
    # instead of re-lowercasing the whole row on each field access.
    rows = [
        {(k or "").strip().lower(): v for k, v in r.items()}
        for r in csv.DictReader(io.StringIO(csv_text))
    ]

    # --- Pass 1: Extract OS Mapping ---
    ip_to_os = {}
    for row in rows:
        host = _col(row, "Host")
        if not host:
            continue
        
        # Explicit OS column (if present)
        os_val = _col(row, "OS", "Operating System")
        if os_val:
            ip_to_os[host] = os_val
            continue
            
        # Plugin-based OS identification
        pid = _col(row, "Plugin ID")
        if pid in ("11936", "33850", "108791", "108792"):
            p_out = _col(row, "Plugin Output")
            m = re.search(r"(?i)Remote operating system\s*:\s*(.+)", p_out)
            if m:
                ip_to_os[host] = m.group(1).split("\n")[0].strip()
            elif p_out and host not in ip_to_os:
                ip_to_os[host] = p_out.split("\n")[0].strip()[:50]

    # --- Pass 1.5: Prefetch Plugins ---
    if conn and ak and sk:
        needed_plugins = set()
        for row in rows:
            if _col(row, "Risk").lower() in _SKIP_RISKS: continue
            pid = _col(row, "Plugin ID")
            if pid:
                try:
                    p = int(pid)
                    if p not in _PLUGIN_CACHE:
                        needed_plugins.add(p)
                except ValueError: pass
                
        if needed_plugins:
            def _fetch_plug(p):
                try:
                    _PLUGIN_CACHE[p] = nc.get_plugin_details(conn, ak, sk, p)
                except Exception:
                    _PLUGIN_CACHE[p] = {"attributes": []}
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                list(executor.map(_fetch_plug, needed_plugins))

    # --- Helpers for CIA & Risk ---
    def get_plugin_attributes(plugin_id: str):
        if not plugin_id: return []
        try:
            return _PLUGIN_CACHE.get(int(plugin_id), {}).get("attributes", [])
        except ValueError:
            return []

    def parse_cia(cvss_vector: str) -> str:
        if not cvss_vector:
            return ""
        c = re.search(r"/C:([NLMHCP])", cvss_vector)
        i = re.search(r"/I:([NLMHCP])", cvss_vector)
        a = re.search(r"/A:([NLMHCP])", cvss_vector)
        
        parts = []
        if c and c.group(1) != "N":
            parts.append("Confidentiality")
        if i and i.group(1) != "N":
            parts.append("Integrity")
        if a and a.group(1) != "N":
            parts.append("Availability")
            
        return ",".join(parts)

    def calc_risk(cvss_vector: str, cvss_score: str, exploitable: float) -> str:
        if not cvss_vector:
            return ""
        try:
            cvss_val = float(cvss_score)
        except (ValueError, TypeError):
            return ""
            
        c_match = re.search(r"/C:([NLMHCP])", cvss_vector)
        i_match = re.search(r"/I:([NLMHCP])", cvss_vector)
        a_match = re.search(r"/A:([NLMHCP])", cvss_vector)
        
        c = 0.0
        if c_match:
            v = c_match.group(1)
            if v in ("P", "L"): c = 0.22
            elif v in ("H", "C"): c = 0.56
            
        i = 0.0
        if i_match:
            v = i_match.group(1)
            if v in ("P", "L"): i = 0.22
            elif v in ("H", "C"): i = 0.56
            
        a = 0.0
        if a_match:
            v = a_match.group(1)
            if v in ("P", "L"): a = 0.22
            elif v in ("H", "C"): a = 0.56
            
        ciaValue = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        ac = 0.62 if vector == "Internal network" else 0.85
        av = 0.85 if actor == "Unauthenticated user" else 0.27
        
        riskValue = 1 * exploitable * ciaValue * 6.97 * cvss_val * ac * av
        return f"{riskValue:g}"

    # --- Pass 2: Generate Findings ---
    findings: List[dict] = []
    for row in rows:
        risk = _col(row, "Risk").lower()
        if risk in _SKIP_RISKS:
            continue

        name  = _col(row, "Name")
        host  = _col(row, "Host")
        port  = _col(row, "Port")
        proto = _col(row, "Protocol")
        cve   = _col(row, "CVE")
        desc  = _col(row, "Description")
        soln  = _col(row, "Solution")
        cvss_vector = _col(row, "CVSS v3.0 Vector", "CVSS v2.0 Vector", "CVSS Vector")
        plugin_id   = _col(row, "Plugin ID")
        
        cvss = (_col(row, "CVSS v3.0 Base Score")
                or _col(row, "CVSS v3.0 Temporal Score")
                or _col(row, "CVSS v2.0 Base Score")
                or _col(row, "CVSS"))

        exploitable = 0.7
        if plugin_id:
            attrs = get_plugin_attributes(plugin_id)
            for attr in attrs:
                aname = attr.get("attribute_name", "").lower()
                avalue = attr.get("attribute_value", "")
                if aname in ("exploitability_ease", "exploit_framework_canvas", "exploit_framework_metasploit", "exploit_framework_core"):
                    exploitable = 1.0
                
                if not cvss_vector and aname in ("cvss3_vector", "cvss_vector"):
                    cvss_vector = avalue
                    
                if not cvss and aname in ("cvss3_base_score", "cvss_base_score"):
                    cvss = avalue

        if not name or not host:
            continue

        os_val = ip_to_os.get(host, "")

        if desc:
            desc = re.sub(r"(?i)nessus", "mUnit", desc)
        if soln:
            soln = re.sub(r"(?i)nessus", "mUnit", soln)

        findings.append({
            "Vulnerability_Title":       name,
            "Vulnerability_Description": desc,
            "Recommendation":            soln,
            "Affected_System":           os_val,
            "System_IP":                 host,
            "OS":                        os_val,
            "Assignee":                  "",
            "OWASP_Top_10_Category":     "",
            "Vulnerability_Rating":      risk.capitalize(),
            "CVE":                       cve,
            "CVSS":                      cvss,
            "Impact_Type":               "",   # filled per engagement
            "Technology":                _technology(name, port, proto),
            "Vector":                    "",   # filled per engagement
            "Actor":                     "",   # filled per engagement
            "CIA_Damage":                parse_cia(cvss_vector),
            "Risk_Value":                calc_risk(cvss_vector, cvss, exploitable),
            # Internal helpers (stripped before export)
            "_port": port,
            "_ip":   host,
        })
    return findings


_NORMALIZATION_PATTERNS = [
    (re.compile(r"(?i)^Apache(?:\s+HTTP\s+Server)?\s+\d+(?:\.\d+)+.*"), "Apache HTTP Server Multiple Vulnerabilities"),
    (re.compile(r"(?i)^PHP\s+\d+(?:\.\d+)+.*"), "PHP Multiple Vulnerabilities"),
    (re.compile(r"(?i)^OpenSSL\s+\d+(?:\.\d+)*[a-z]?\s+.*"), "OpenSSL Multiple Vulnerabilities"),
    (re.compile(r"(?i)^nginx\s+\d+(?:\.\d+)+.*"), "nginx Multiple Vulnerabilities"),
    (re.compile(r"(?i)^Apache\s+Tomcat\s+\d+(?:\.\d+)+.*"), "Apache Tomcat Multiple Vulnerabilities"),
    (re.compile(r"(?i)^Node\.js\s+\d+(?:\.\d+)+.*"), "Node.js Multiple Vulnerabilities"),
    (re.compile(r"(?i)^MySQL\s+\d+(?:\.\d+)+.*"), "MySQL Multiple Vulnerabilities"),
    (re.compile(r"(?i)^PostgreSQL\s+\d+(?:\.\d+)+.*"), "PostgreSQL Multiple Vulnerabilities"),
    (re.compile(r"(?i)^Oracle\s+Java\s+SE\s+\d+.*"), "Oracle Java SE Multiple Vulnerabilities"),
    (re.compile(r"(?i)^VMware\s+ESXi.*"), "VMware ESXi Multiple Vulnerabilities"),
    (re.compile(r"(?i)^VMware\s+vCenter\s+Server.*"), "VMware vCenter Server Multiple Vulnerabilities"),
]


def _normalize_title(title: str) -> str:
    """Normalize vulnerability titles to group similar version vulnerabilities."""
    for pattern, replacement in _NORMALIZATION_PATTERNS:
        if pattern.match(title.strip()):
            return replacement
    return title.strip()


def _merge_dedup(all_findings: List[dict]) -> List[dict]:
    """Deduplicate by (title, IP) — same vuln on multiple ports merges into one
    row with all ports combined in the Technology field, e.g. SSL,443,8443."""
    # Ordered dict preserves first-seen order
    seen: dict = {}   # (title_lower, ip) → index in `out`
    out: List[dict] = []
    
    # Rating mapped to severity levels for merging to highest severity
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0, "Info": 0}

    for f in all_findings:
        raw_title = f["Vulnerability_Title"]
        norm_title = _normalize_title(raw_title)
        
        # Update title so UI and exported CSV show the grouped family title
        f["Vulnerability_Title"] = norm_title
        
        key = (norm_title.lower().strip(), f["_ip"].strip())
        port = f["_port"].strip()

        if key in seen:
            # Merge port into the existing row's Technology field
            existing = out[seen[key]]
            _merge_port(existing, port)
            
            # Combine CVEs
            if f.get("CVE"):
                existing_cves = [c.strip() for c in existing.get("CVE", "").split(",") if c.strip()]
                new_cves = [c.strip() for c in f["CVE"].split(",") if c.strip()]
                for cve in new_cves:
                    if cve not in existing_cves:
                        existing_cves.append(cve)
                existing["CVE"] = ",".join(existing_cves)
                
            # Take the highest CVSS
            try:
                e_cvss = float(existing.get("CVSS") or 0.0)
            except ValueError:
                e_cvss = 0.0
            try:
                f_cvss = float(f.get("CVSS") or 0.0)
            except ValueError:
                f_cvss = 0.0
            if f_cvss > e_cvss:
                existing["CVSS"] = f.get("CVSS", "")
                
            # Take highest Rating
            e_rating = existing.get("Vulnerability_Rating", "Info").capitalize()
            f_rating = f.get("Vulnerability_Rating", "Info").capitalize()
            if severity_map.get(f_rating, 0) > severity_map.get(e_rating, 0):
                existing["Vulnerability_Rating"] = f_rating
        else:
            seen[key] = len(out)
            out.append(f)

    return out


def _merge_port(finding: dict, new_port: str) -> None:
    """Add *new_port* to an existing finding's Technology field if not already present."""
    if not new_port or new_port == "0":
        return
    tech = finding.get("Technology", "")
    parts = [p.strip() for p in tech.split(",")]
    if new_port not in parts:
        parts.append(new_port)
    finding["Technology"] = ",".join(parts)
    # Keep _port as the first port for Jira dedup matching
    if not finding.get("_port"):
        finding["_port"] = new_port


def _parse_cve_list(cve_field: str) -> List[str]:
    """Extract CVE-YYYY-NNNN tokens from a comma/space-separated field."""
    if not cve_field:
        return []
    out = []
    for part in re.split(r"[,;\s]+", str(cve_field)):
        p = part.strip().upper()
        if p.startswith("CVE-"):
            out.append(p)
    return out


def _match_finding_to_index(
    finding: dict,
    title_index: dict,
    cve_index: dict,
) -> Tuple[Optional[str], Optional[str]]:
    """Return (jira_key, match_kind) where match_kind is 'title' or 'cve'."""
    title = _normalize_title(finding.get("Vulnerability_Title") or "").strip().lower()
    ip = (finding.get("System_IP") or finding.get("_ip") or "").strip()
    port = str(finding.get("_port") or "").strip()

    dup_key = title_index.get((title, ip, port)) or title_index.get((title, ip, ""))
    if dup_key:
        return dup_key, "title"

    for cve in _parse_cve_list(finding.get("CVE") or ""):
        dup_key = cve_index.get((cve, ip))
        if dup_key:
            return dup_key, "cve"
    return None, None


# ── Jira index builder ──────────────────────────────────────────────────────

def _index_from_tickets(tickets: List[dict]) -> Tuple[dict, dict]:
    """Build the fast-lookup title/CVE indexes from a list of serialized tickets.

    Shared by fresh Jira fetches and disk-cache loads so both produce identical
    lookup structures.
      • Title index: (normalised_title, ip, port) → ticket key
      • CVE index:   (CVE-ID, ip)                 → ticket key
    """
    title_index: dict = {}
    cve_index: dict = {}
    for t in tickets:
        title = _normalize_title(t.get("summary") or "").strip().lower()
        ips = [i.strip() for i in (t.get("ips") or []) if i.strip()]
        ports = [str(p).strip() for p in (t.get("ports") or []) if str(p).strip()]
        cves = [c.strip().upper() for c in (t.get("cves") or []) if c.strip()]

        for ip in ips:
            for port in ports:
                title_index[(title, ip, port)] = t["key"]
            title_index.setdefault((title, ip, ""), t["key"])
            for cve in cves:
                cve_index.setdefault((cve, ip), t["key"])
        if not ips:
            title_index[(title, "", "")] = t["key"]

    return title_index, cve_index


def _jira_cache_path(label: str) -> str:
    return os.path.join(_JIRA_CACHE_DIR, f"{_safe_name(label)}.json")


def _save_jira_cache(label: str, tickets: List[dict], jira_url: str,
                     fetched_at: float) -> None:
    """Persist a slim ticket list (only fields needed for dedup matching)."""
    _ensure_cache_dirs()
    slim = [
        {
            "key":     t.get("key"),
            "summary": t.get("summary") or "",
            "ips":     t.get("ips") or [],
            "ports":   t.get("ports") or [],
            "cves":    t.get("cves") or [],
        }
        for t in tickets if t.get("key")
    ]
    try:
        _atomic_write_json(_jira_cache_path(label), {
            "label":      label,
            "jira_url":   jira_url,
            "fetched_at": fetched_at,
            "count":      len(slim),
            "tickets":    slim,
        })
    except OSError as exc:
        log.warning("Intake: could not write Jira cache for '%s' — %s", label, exc)


def _read_jira_cache(label: str) -> Optional[dict]:
    """Read the raw cache file for *label*, or None if missing/corrupt."""
    path = _jira_cache_path(label)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Intake: ignoring corrupt Jira cache for '%s' — %s", label, exc)
        return None


def _load_jira_cache_into_memory(label: str) -> bool:
    """Populate _JIRA_INDEXES[label] from disk. Returns True on success."""
    data = _read_jira_cache(label)
    if not data:
        return False
    tickets = data.get("tickets") or []
    title_index, cve_index = _index_from_tickets(tickets)
    with _INDEX_LOCK:
        _JIRA_INDEXES[label] = {
            "status":     "ready",
            "index":      title_index,
            "cve_index":  cve_index,
            "count":      data.get("count", len(tickets)),
            "error":      None,
            "jira_url":   data.get("jira_url"),
            "fetched_at": data.get("fetched_at"),
            "from_cache": True,
        }
    log.info("Intake: Jira index '%s' loaded from cache — %d tickets", label, len(tickets))
    return True


def _build_index(label: str) -> None:
    """Fetch all Jira tickets for *label*, build indexes, and persist to disk.
    Runs in a daemon thread; result stored in _JIRA_INDEXES[label]."""
    from . import main as m

    # Preserve any already-ready cached index while refreshing so the UI can
    # keep serving results instead of dropping to a blank "loading" state.
    with _INDEX_LOCK:
        prev = _JIRA_INDEXES.get(label, {})
        if prev.get("status") == "ready":
            prev = dict(prev)
            prev["refreshing"] = True
            _JIRA_INDEXES[label] = prev
        else:
            _JIRA_INDEXES[label] = {
                "status": "loading", "index": {}, "cve_index": {},
                "count": 0, "error": None,
            }

    try:
        _, session = m._get_client(label)
        jc = m._jira_for_label(label)

        if session == "non_axian":
            jql = f'project = {label} ORDER BY created ASC'
        else:
            jql = (
                f'project = {m.cfg.jira.project} AND labels = "{label}" '
                f'ORDER BY created ASC'
            )

        tickets = jc.search_jql(jql)
        title_index, cve_index = _index_from_tickets(tickets)
        jira_url = jc.cfg.url.rstrip("/")
        fetched_at = time.time()

        with _INDEX_LOCK:
            _JIRA_INDEXES[label] = {
                "status": "ready",
                "index": title_index,
                "cve_index": cve_index,
                "count": len(tickets),
                "error": None,
                "jira_url": jira_url,
                "fetched_at": fetched_at,
                "from_cache": False,
            }
        _save_jira_cache(label, tickets, jira_url, fetched_at)
        log.info("Intake: Jira index '%s' ready — %d tickets indexed", label, len(tickets))

    except Exception as exc:
        log.warning("Intake: Jira index '%s' failed — %s", label, exc)
        # Fall back to any cached copy so a transient Jira outage doesn't wipe
        # a perfectly good index the user was relying on.
        if _load_jira_cache_into_memory(label):
            with _INDEX_LOCK:
                info = _JIRA_INDEXES.get(label, {})
                info["error"] = f"Refresh failed ({exc}); showing cached copy"
                _JIRA_INDEXES[label] = info
            return
        with _INDEX_LOCK:
            _JIRA_INDEXES[label] = {
                "status": "error",
                "index": {},
                "cve_index": {},
                "count": 0,
                "error": str(exc),
            }


def _index_is_stale(info: dict) -> bool:
    fetched_at = info.get("fetched_at")
    if not fetched_at:
        return True
    return (time.time() - fetched_at) > _JIRA_CACHE_TTL


# ── Nessus scan cache ────────────────────────────────────────────────────────
# Parsed findings for a scan are cached so re-pulling the same scan is instant
# and doesn't re-run the slow Nessus CSV export over SSH. Risk values depend on
# vector/actor, so those are part of the cache key.

def _nessus_cache_path(label: str, scan_id: int, vector: str, actor: str) -> str:
    key = _safe_name(f"{label}_{scan_id}_{vector}_{actor}")
    return os.path.join(_NESSUS_CACHE_DIR, f"{key}.json")


def _load_nessus_cache(label: str, scan_id: int, vector: str, actor: str) -> Optional[dict]:
    path = _nessus_cache_path(label, scan_id, vector, actor)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Intake: ignoring corrupt Nessus cache for scan %s — %s", scan_id, exc)
        return None


def _save_nessus_cache(label: str, scan_id: int, vector: str, actor: str,
                       scan_name: str, rows: List[dict]) -> None:
    _ensure_cache_dirs()
    try:
        _atomic_write_json(_nessus_cache_path(label, scan_id, vector, actor), {
            "label":      label,
            "scan_id":    scan_id,
            "scan_name":  scan_name,
            "vector":     vector,
            "actor":      actor,
            "fetched_at": time.time(),
            "count":      len(rows),
            "findings":   rows,
        })
    except OSError as exc:
        log.warning("Intake: could not write Nessus cache for scan %s — %s", scan_id, exc)


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.post("/api/intake/{label}/prefetch-jira")
def intake_prefetch_jira(label: str, force: bool = False):
    """Make the Jira index available as fast as possible.

    Order of preference (fast → slow):
      1. force=True            → always rebuild from Jira in the background.
      2. Already ready in RAM  → serve instantly; refresh in background if stale.
      3. On disk (prev run)    → load instantly; refresh in background if stale.
      4. Nothing cached        → build from Jira in the background.
    """
    from . import main as m
    if not m.cfg:
        raise HTTPException(400, "App not configured yet")
    if not m._find_client(label):
        raise HTTPException(400, f"Unknown client: {label}")

    if force:
        threading.Thread(target=_build_index, args=(label,), daemon=True).start()
        return {"ok": True, "status": "loading"}

    with _INDEX_LOCK:
        info = _JIRA_INDEXES.get(label, {})
        st = info.get("status", "idle")

    # Already in memory
    if st == "ready":
        if _index_is_stale(info):
            threading.Thread(target=_build_index, args=(label,), daemon=True).start()
        return {"ok": True, "status": "ready", "cached": True}
    if st == "loading":
        return {"ok": True, "status": "loading"}

    # Not in memory — try the on-disk cache from a previous run
    if _load_jira_cache_into_memory(label):
        with _INDEX_LOCK:
            info = _JIRA_INDEXES.get(label, {})
        if _index_is_stale(info):
            threading.Thread(target=_build_index, args=(label,), daemon=True).start()
        return {"ok": True, "status": "ready", "cached": True}

    # Nothing cached anywhere — build fresh
    threading.Thread(target=_build_index, args=(label,), daemon=True).start()
    return {"ok": True, "status": "loading"}


@router.post("/api/intake/{label}/refresh-jira")
def intake_refresh_jira(label: str):
    """Force a fresh rebuild of the Jira index from the live project."""
    from . import main as m
    if not m.cfg:
        raise HTTPException(400, "App not configured yet")
    if not m._find_client(label):
        raise HTTPException(400, f"Unknown client: {label}")
    threading.Thread(target=_build_index, args=(label,), daemon=True).start()
    return {"ok": True, "status": "loading"}


@router.post("/api/intake/{label}/clear-cache")
def intake_clear_cache(label: str):
    """Delete all on-disk caches (Jira index + Nessus scans) for this client."""
    removed = 0
    safe = _safe_name(label)
    with _INDEX_LOCK:
        _JIRA_INDEXES.pop(label, None)
    for d, prefix in ((_JIRA_CACHE_DIR, f"{safe}.json"), (_NESSUS_CACHE_DIR, f"{safe}_")):
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if fname == prefix or fname.startswith(prefix):
                try:
                    os.remove(os.path.join(d, fname))
                    removed += 1
                except OSError:
                    pass
    return {"ok": True, "removed": removed}


@router.get("/api/intake/{label}/jira-index-status")
def intake_jira_index_status(label: str):
    with _INDEX_LOCK:
        info = _JIRA_INDEXES.get(label, {})

    # Nothing in memory yet — surface a cheap "is there a disk cache?" hint so
    # the UI can load it via prefetch without a network round-trip.
    if not info:
        cached = _read_jira_cache(label)
        if cached:
            fetched_at = cached.get("fetched_at")
            return {
                "status": "cached",
                "count":  cached.get("count", 0),
                "error":  None,
                "jira_url": cached.get("jira_url"),
                "fetched_at": fetched_at,
                "age_seconds": (time.time() - fetched_at) if fetched_at else None,
            }

    fetched_at = info.get("fetched_at")
    return {
        "status":      info.get("status", "idle"),
        "count":       info.get("count", 0),
        "error":       info.get("error"),
        "jira_url":    info.get("jira_url"),
        "fetched_at":  fetched_at,
        "age_seconds": (time.time() - fetched_at) if fetched_at else None,
        "from_cache":  info.get("from_cache", False),
        "refreshing":  info.get("refreshing", False),
        "stale":       _index_is_stale(info) if info.get("status") == "ready" else False,
    }


@router.get("/api/intake/{label}/engagement-defaults")
def intake_engagement_defaults(label: str):
    """Return sensible defaults from config for the engagement settings form."""
    from . import main as m
    if not m.cfg:
        raise HTTPException(400, "App not configured yet")
    client_cfg = m._find_client(label)
    if not client_cfg:
        raise HTTPException(400, f"Unknown client: {label}")

    _, session = m._get_client(label)
    project_key = label if session == "non_axian" else m.cfg.jira.project
    tester = m.cfg.jira.username if session == "axian" else ""

    return {
        "project_key": project_key,
        "tester":      tester,
        "customer":    client_cfg.name,
        "date_started": date.today().strftime("%d/%m/%Y"),
        "munit_id":    label,
    }


@router.post("/api/intake/{label}/pull")
def intake_pull(label: str, req: PullRequest):
    """Pull selected Nessus scans in parallel, merge, dedup within the set."""
    from . import main as m, connections as conn_mod, nessus_client as nc

    if not m.cfg:
        raise HTTPException(400, "App not configured yet")
    client_cfg = m._find_client(label)
    if not client_cfg:
        raise HTTPException(400, f"Unknown client: {label}")
    if not getattr(client_cfg, "nessus_access_key", None):
        raise HTTPException(400, f"Nessus keys not configured for {label}")
    conn = conn_mod.get_connection(label)
    if not conn:
        raise HTTPException(400, f"SSH not connected for '{label}' — connect in the Shell tab first")

    ak, sk = client_cfg.nessus_access_key, client_cfg.nessus_secret_key
    all_findings: List[dict] = []
    errors: List[str] = []
    cached_scans = 0
    pulled_scans = 0

    # Sequential export — large Nessus CSV responses can corrupt parallel SSH
    # channels (same issue as Assets pull). Slower but reliable. Each scan's
    # parsed findings are cached on disk (keyed by scan + vector/actor) so a
    # re-pull of the same scan is instant and skips the slow Nessus export.
    for scan_id in req.scan_ids:
        cached = None if req.force else _load_nessus_cache(label, scan_id, req.vector, req.actor)
        if cached:
            rows = cached.get("findings") or []
            all_findings.extend(rows)
            cached_scans += 1
            log.info("Intake pull: scan %d ('%s') → %d vuln rows (from cache)",
                     scan_id, cached.get("scan_name", ""), len(rows))
            continue
        try:
            csv_text, sname = nc.export_scan_csv(conn, ak, sk, scan_id)
            rows = _parse_nessus_csv(
                csv_text, vector=req.vector, actor=req.actor, conn=conn, ak=ak, sk=sk,
            )
            log.info("Intake pull: scan %d ('%s') → %d vuln rows", scan_id, sname, len(rows))
            _save_nessus_cache(label, scan_id, req.vector, req.actor, sname, rows)
            all_findings.extend(rows)
            pulled_scans += 1
        except Exception as exc:
            errors.append(f"Scan {scan_id}: {exc}")

    merged = _merge_dedup(all_findings)

    # Apply engagement-level values
    for f in merged:
        f["Impact_Type"] = req.impact_type
        f["Vector"]      = req.vector
        f["Actor"]       = req.actor

    # Add stable IDs and initial UI state
    for i, f in enumerate(merged):
        f["_id"]           = i
        f["_status"]       = "pending"
        f["_duplicate_of"] = None

    return {
        "ok":           True,
        "total_raw":    len(all_findings),
        "total_merged": len(merged),
        "errors":       errors,
        "findings":     merged,
        "cached_scans": cached_scans,
        "pulled_scans": pulled_scans,
    }


@router.post("/api/intake/{label}/check-duplicates")
def intake_check_duplicates(label: str, req: CheckDupRequest):
    """Tag each finding as 'new' or 'duplicate' against the Jira index."""
    from . import main as m
    if not m.cfg:
        raise HTTPException(400, "App not configured yet")

    with _INDEX_LOCK:
        info = _JIRA_INDEXES.get(label, {})

    # If nothing in memory, try to hydrate from the on-disk cache before giving up.
    if not info:
        if _load_jira_cache_into_memory(label):
            with _INDEX_LOCK:
                info = _JIRA_INDEXES.get(label, {})

    if info.get("status") != "ready":
        # Auto-trigger build if not started
        if info.get("status") not in ("loading",):
            threading.Thread(target=_build_index, args=(label,), daemon=True).start()
        raise HTTPException(503, "Jira index not ready — retry in a moment")

    index = info.get("index") or {}
    cve_index = info.get("cve_index") or {}
    results = []

    for f in req.findings:
        dup_key, match_kind = _match_finding_to_index(f, index, cve_index)

        results.append({
            "_id":          f.get("_id"),
            "status":       "duplicate" if dup_key else "new",
            "duplicate_of": dup_key,
            "match_kind":   match_kind,
        })

    new_ct  = sum(1 for r in results if r["status"] == "new")
    dup_ct  = sum(1 for r in results if r["status"] == "duplicate")

    return {
        "ok":                   True,
        "results":              results,
        "new_count":            new_ct,
        "duplicate_count":      dup_ct,
        "jira_tickets_checked": info.get("count", 0),
    }


@router.post("/api/intake/export")
def intake_export(req: ExportRequest):
    """Export only the NEW (non-duplicate) findings as a properly formatted CSV."""

    # Only export rows the user has marked as new (not duplicate)
    to_export = [f for f in req.findings if f.get("_status") != "duplicate"]
    if not to_export:
        raise HTTPException(400, "No new findings to export")

    COLUMNS = [
        "Attachments", "Vulnerability_Title", "Vulnerability_Description",
        "Recommendation", "Affected_System", "System_IP", "OS", "Assignee",
        "OWASP_Top_10_Category", "Vulnerability_Rating", "CVE", "CVSS",
        "Impact_Type", "Technology", "Vector", "Actor", "CIA_Damage",
        "Risk_Value", "Project_Key", "Testers", "Date_Started", "Duration",
        "Test_Type", "Purchaser", "Customer", "Contact_Person",
        "Technical_Contact", "mUnit_ID",
    ]

    META_COLS = [
        "Project_Key", "Testers", "Date_Started", "Duration", "Test_Type",
        "Purchaser", "Customer", "Contact_Person", "Technical_Contact", "mUnit_ID",
    ]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()

    for idx, f in enumerate(to_export):
        row = {col: f.get(col, "") for col in COLUMNS}
        row["Attachments"] = ""

        if idx == 0:
            # First row carries all engagement metadata
            row["Project_Key"]       = req.project_key
            row["Testers"]           = req.tester
            row["Date_Started"]      = req.date_started
            row["Duration"]          = req.duration
            row["Test_Type"]         = req.test_type
            row["Purchaser"]         = req.purchaser
            row["Customer"]          = req.customer
            row["Contact_Person"]    = req.contact_person
            row["Technical_Contact"] = req.technical_contact
            row["mUnit_ID"]          = req.munit_id
        else:
            for col in META_COLS:
                row[col] = ""

        writer.writerow(row)

    buf.seek(0)
    fname = f"intake_{date.today().isoformat()}.csv"
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),   # UTF-8 BOM for Excel
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )
