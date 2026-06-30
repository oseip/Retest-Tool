"""Intake pipeline — pull Nessus scan CSVs, normalise to vulnerability format,
dedup against live Jira tickets, export ready-to-upload CSV.

All code lives here so the feature can be reverted by removing this file and
the three lines that wire it into main.py / index.html / app.js.
"""
import csv
import io
import logging
import re
import threading
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


# ── Request models ─────────────────────────────────────────────────────────

class PullRequest(BaseModel):
    scan_ids: List[int]
    impact_type: str  = "Internal operations impact"
    actor:       str  = "Unauthenticated user"
    vector:      str  = "Internal network"
    test_type:   str  = "IPT"
    duration:    str  = ""
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
    """Case-insensitive column lookup across all provided aliases."""
    row_lower = {(k or "").strip().lower(): v for k, v in row.items()}
    for n in names:
        v = row_lower.get(n.lower())
        if v is not None:
            return (v or "").strip()
    return ""


def _parse_nessus_csv(csv_text: str) -> List[dict]:
    """Parse one Nessus CSV export into normalised finding dicts."""
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    
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

    # --- Helpers for CIA & Risk ---
    def parse_cia(cvss_vector: str) -> str:
        if not cvss_vector:
            return ""
        c_map = {"N": "None", "L": "Low", "M": "Medium", "H": "High", "C": "Complete", "P": "Partial"}
        c = re.search(r"/C:([NLMHCP])", cvss_vector)
        i = re.search(r"/I:([NLMHCP])", cvss_vector)
        a = re.search(r"/A:([NLMHCP])", cvss_vector)
        if not c and not i and not a:
            return ""
        c_val = c_map.get(c.group(1), "None") if c else "None"
        i_val = c_map.get(i.group(1), "None") if i else "None"
        a_val = c_map.get(a.group(1), "None") if a else "None"
        return f"Confidentiality: {c_val}, Integrity: {i_val}, Availability: {a_val}"

    def calc_risk(score: str) -> str:
        try:
            s = float(score)
        except ValueError:
            return ""
        if s >= 9.0: return "5 - Critical"
        if s >= 7.0: return "4 - High"
        if s >= 4.0: return "3 - Medium"
        if s > 0.0:  return "2 - Low"
        return "1 - Info"

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
        cvss_vector = _col(row, "CVSS v3.0 Vector", "CVSS Vector")

        # Prefer CVSS v3, fall back to v2
        cvss = (_col(row, "CVSS v3.0 Base Score")
                or _col(row, "CVSS v3.0 Temporal Score")
                or _col(row, "CVSS v2.0 Base Score")
                or _col(row, "CVSS"))

        if not name or not host:
            continue

        findings.append({
            "Vulnerability_Title":       name,
            "Vulnerability_Description": desc,
            "Recommendation":            soln,
            "Affected_System":           "",
            "System_IP":                 host,
            "OS":                        ip_to_os.get(host, ""),
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
            "Risk_Value":                calc_risk(cvss),
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


# ── Jira index builder ──────────────────────────────────────────────────────

def _build_index(label: str) -> None:
    """Fetch all open Jira tickets for *label* and build a fast-lookup index.
    Runs in a daemon thread; result stored in _JIRA_INDEXES[label]."""
    from . import main as m

    with _INDEX_LOCK:
        _JIRA_INDEXES[label] = {"status": "loading", "index": {}, "count": 0, "error": None}

    try:
        _, session = m._get_client(label)
        jc = m._jira_for_label(label)

        if session == "non_axian":
            jql = f'project = {label} ORDER BY created ASC'
        else:
            jql = f'project = {m.cfg.jira.project} AND labels = "{label}" ORDER BY created ASC'

        # Optimize: only fetch fields necessary for deduplication (massive speedup)
        jc._fetch_fields = "summary,labels"
        tickets = jc.search_jql(jql)

        # Build index: (normalised_title, ip, port) → ticket key
        index: dict = {}
        for t in tickets:
            title = (t.get("summary") or "").strip().lower()
            ips   = [i.strip() for i in (t.get("ips")   or []) if i.strip()]
            ports = [str(p).strip() for p in (t.get("ports") or []) if str(p).strip()]

            for ip in ips:
                for port in ports:
                    index[(title, ip, port)] = t["key"]
                # Also index without port so a mismatch there doesn't miss a dup
                index.setdefault((title, ip, ""), t["key"])
            if not ips:
                index[(title, "", "")] = t["key"]

        with _INDEX_LOCK:
            _JIRA_INDEXES[label] = {
                "status": "ready",
                "index":  index,
                "count":  len(tickets),
                "error":  None,
            }
        log.info("Intake: Jira index '%s' ready — %d tickets indexed", label, len(tickets))

    except Exception as exc:
        log.warning("Intake: Jira index '%s' failed — %s", label, exc)
        with _INDEX_LOCK:
            _JIRA_INDEXES[label] = {
                "status": "error",
                "index":  {},
                "count":  0,
                "error":  str(exc),
            }


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.post("/api/intake/{label}/prefetch-jira")
def intake_prefetch_jira(label: str, force: bool = False):
    """Kick off background Jira index build. Call as soon as user picks a client."""
    from . import main as m
    if not m.cfg:
        raise HTTPException(400, "App not configured yet")
    if not m._find_client(label):
        raise HTTPException(400, f"Unknown client: {label}")

    with _INDEX_LOCK:
        st = _JIRA_INDEXES.get(label, {}).get("status", "idle")
    if st == "loading" and not force:
        return {"ok": True, "status": "loading"}

    threading.Thread(target=_build_index, args=(label,), daemon=True).start()
    return {"ok": True, "status": "loading"}


@router.get("/api/intake/{label}/jira-index-status")
def intake_jira_index_status(label: str):
    with _INDEX_LOCK:
        info = _JIRA_INDEXES.get(label, {})
    return {
        "status": info.get("status", "idle"),
        "count":  info.get("count", 0),
        "error":  info.get("error"),
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

    def _pull_one(sid: int) -> Tuple[List[dict], Optional[str]]:
        try:
            csv_text, sname = nc.export_scan_csv(conn, ak, sk, sid)
            rows = _parse_nessus_csv(csv_text)
            log.info("Intake pull: scan %d ('%s') → %d vuln rows", sid, sname, len(rows))
            return rows, None
        except Exception as exc:
            return [], f"Scan {sid}: {exc}"

    # Parallel pull — each scan's export/poll/download runs in its own thread
    workers = min(len(req.scan_ids), 5)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_pull_one, sid): sid for sid in req.scan_ids}
        for fut in as_completed(futs):
            rows, err = fut.result()
            if err:
                errors.append(err)
            else:
                all_findings.extend(rows)

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
    }


@router.post("/api/intake/{label}/check-duplicates")
def intake_check_duplicates(label: str, req: CheckDupRequest):
    """Tag each finding as 'new' or 'duplicate' against the Jira index."""
    from . import main as m
    if not m.cfg:
        raise HTTPException(400, "App not configured yet")

    with _INDEX_LOCK:
        info = _JIRA_INDEXES.get(label, {})

    if info.get("status") != "ready":
        # Auto-trigger build if not started
        if info.get("status") not in ("loading",):
            threading.Thread(target=_build_index, args=(label,), daemon=True).start()
        raise HTTPException(503, "Jira index not ready — retry in a moment")

    index = info["index"]
    results = []

    for f in req.findings:
        title = (f.get("Vulnerability_Title") or "").strip().lower()
        ip    = (f.get("System_IP") or "").strip()
        port  = str(f.get("_port") or "").strip()

        # Try exact (title, ip, port) then (title, ip, no-port)
        dup_key = index.get((title, ip, port)) or index.get((title, ip, ""))

        results.append({
            "_id":          f.get("_id"),
            "status":       "duplicate" if dup_key else "new",
            "duplicate_of": dup_key,
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
            row["mUnit_ID"]          = ""
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
