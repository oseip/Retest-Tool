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
from datetime import date
from functools import lru_cache
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
_PLUGIN_CACHE_DIR   = os.path.join(_CACHE_DIR, "plugins")
_INTAKE_DATA_DIR  = os.path.join("data", "intake")
_IRRELEVANT_PATH  = os.path.join(_INTAKE_DATA_DIR, "irrelevant_vulnerabilities.txt")
_RECOMMENDATIONS_PATH = os.path.join(_INTAKE_DATA_DIR, "recommendations.csv")
_SEED_IRRELEVANT  = os.path.join("automation-tool-bright-features", "irrelevant_vulnerabilities.txt")
_SEED_IRRELEVANT_ALT = (
    os.path.join("config", "intake", "irrelevant_vulnerabilities.txt"),
    os.path.join("config", "intake_irrelevant_vulnerabilities.txt"),
)
_SEED_RECOMMENDATIONS = os.path.join(
    "automation-tool-bright-features", "Data", "vulnerabilityData.csv",
)

# How long a cached Jira index is considered "fresh". Older caches still load
# instantly (so the UI never blocks) but trigger a silent background refresh.
_JIRA_CACHE_TTL = 12 * 3600   # 12 hours
_JIRA_CACHE_VERSION = 2       # bump when cache schema changes (v2 adds status)

# Loaded once on first use — OS|Title → custom recommendation text
_RECOMMENDATION_MAP: Dict[str, str] = {}
_RECOMMENDATIONS_LOADED = False
_IRRELEVANT_SET: set = set()
_IRRELEVANT_LOADED = False


def _safe_name(label: str) -> str:
    """Filesystem-safe version of a client label for use in cache filenames."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(label))


def _ensure_cache_dirs() -> None:
    for d in (_JIRA_CACHE_DIR, _NESSUS_CACHE_DIR, _PLUGIN_CACHE_DIR, _INTAKE_DATA_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as exc:
            log.warning("Intake cache: could not create %s — %s", d, exc)


def _seed_file(dest: str, *sources: str, default_text: str = "") -> None:
    """Copy the first existing *sources* file to *dest*, or write *default_text*."""
    if os.path.exists(dest):
        return
    _ensure_cache_dirs()
    for src in sources:
        if src and os.path.exists(src):
            try:
                with open(src, encoding="utf-8", errors="replace") as inf:
                    data = inf.read()
                tmp = f"{dest}.tmp"
                with open(tmp, "w", encoding="utf-8") as outf:
                    outf.write(data)
                os.replace(tmp, dest)
                return
            except OSError as exc:
                log.warning("Intake: could not seed %s from %s — %s", dest, src, exc)
    if default_text:
        try:
            with open(dest, "w", encoding="utf-8") as f:
                f.write(default_text)
        except OSError as exc:
            log.warning("Intake: could not write default %s — %s", dest, exc)


_DEFAULT_IRRELEVANT = "\n".join([
    "ICMP Timestamp Request Remote Date Disclosure",
    "SSL Certificate Cannot Be Trusted",
    "SSL Self-Signed Certificate",
    "SSL Certificate with Wrong Hostname",
]) + "\n"


def _load_irrelevant() -> set:
    """Return the set of vulnerability titles to exclude from Intake entirely."""
    global _IRRELEVANT_SET, _IRRELEVANT_LOADED
    if _IRRELEVANT_LOADED:
        return _IRRELEVANT_SET
    _seed_file(_IRRELEVANT_PATH, *_SEED_IRRELEVANT_ALT, _SEED_IRRELEVANT, default_text=_DEFAULT_IRRELEVANT)
    out: set = set()
    try:
        with open(_IRRELEVANT_PATH, encoding="utf-8") as f:
            for line in f:
                t = line.strip()
                if t and not t.startswith("#"):
                    out.add(t.lower())
    except OSError as exc:
        log.warning("Intake: could not read irrelevant list — %s", exc)
    _IRRELEVANT_SET = out
    _IRRELEVANT_LOADED = True
    return out


def _load_recommendations() -> Dict[str, str]:
    """Load OS|Title → recommendation mappings from the local CSV library."""
    global _RECOMMENDATION_MAP, _RECOMMENDATIONS_LOADED
    if _RECOMMENDATIONS_LOADED:
        return _RECOMMENDATION_MAP
    _seed_file(_RECOMMENDATIONS_PATH, _SEED_RECOMMENDATIONS)
    out: Dict[str, str] = {}
    if os.path.exists(_RECOMMENDATIONS_PATH):
        try:
            with open(_RECOMMENDATIONS_PATH, encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    title = (row.get("Vulnerability_Title") or "").strip()
                    rec = (row.get("Recommendation") or "").strip()
                    os_val = (row.get("OS") or "Unknown").strip() or "Unknown"
                    if title and rec:
                        out[f"{os_val}|{title}"] = rec
                        out[f"|{title}"] = rec
            log.info("Intake: loaded %d custom recommendations", len(out))
        except OSError as exc:
            log.warning("Intake: could not read recommendations CSV — %s", exc)
    _RECOMMENDATION_MAP = out
    _RECOMMENDATIONS_LOADED = True
    return out


def _sanitize_report_text(text: str) -> str:
    """Replace scanner-specific wording with mUnit terminology (old automation tool)."""
    if not text:
        return ""
    repl = [
        (r"(?i)nessus", "mUnit"),
        (r"(?i)this plugin", "MUNIT"),
        (r"(?i)tenable", "MUNIT"),
        (r"(?i)\bplugins\b", "IDs"),
        (r"(?i)\bplugin\b", "MUNIT"),
    ]
    out = text
    for pat, sub in repl:
        out = re.sub(pat, sub, out)
    return out


def _atomic_write_json(path: str, data: dict) -> None:
    """Write JSON atomically so a crash mid-write can't corrupt the cache."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


# ── Request models ─────────────────────────────────────────────────────────

class PullRequest(BaseModel):
    scan_ids: List[int]
    scan_host_counts: Dict[int, int] = {}   # scan_id → host count (for large-scan timeouts)
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
    export_mode:       str = "new"   # "new" = upload-ready rows only; "all" = incl. duplicates


class CreateJiraRequest(BaseModel):
    findings:          List[dict]
    create_mode:       str = "new"   # "new" | "selected" — exportable rows only
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


class IrrelevantConfigRequest(BaseModel):
    lines: List[str]


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
    ("OpenSSH",     ["openssh"]),
    ("SSH",         ["ssh"]),
    ("IPMI",        ["ipmi"]),
    ("TLS",         ["tls version", "tls 1.0", "tls 1.1", "tls 1.2", "tls deprecated",
                      "tls protocol detection", "ssl/tls"]),
    ("SSL",         ["ssl certificate", "ssl self-signed", "ssl medium", "ssl weak",
                      "ssl cipher", "ssl version", "sweet32"]),
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
    ("mDNS",        ["mdns", "bonjour", "zeroconf"]),
    ("OpenVPN",     ["openvpn"]),
    ("Cisco",       ["cisco"]),
    ("VMware",      ["vmware"]),
    ("Java",        ["java", "jvm"]),
    ("Kubernetes",  ["kubernetes", "k8s"]),
    ("Docker",        ["docker"]),
    ("Kibana",        ["kibana"]),
    ("Grafana",       ["grafana", "grafana labs"]),
    ("Elasticsearch", ["elasticsearch"]),
    ("GitLab",        ["gitlab"]),
    ("Jenkins",       ["jenkins"]),
    ("MongoDB",       ["mongodb"]),
    ("Confluence",    ["confluence"]),
    ("RabbitMQ",      ["rabbitmq"]),
    ("MariaDB",       ["mariadb"]),
]


# Products whose Nessus findings merge by (product, IP, port) and dedup against
# Jira regardless of version strings in the title.  Order matters — more specific
# patterns (Tomcat) must come before broader ones (Apache).
_PRODUCT_REGISTRY: List[Tuple[str, str, List[str]]] = [
    ("tomcat", "Apache Tomcat Multiple Vulnerabilities",
     [r"(?i)^Apache\s+Tomcat\b"]),
    ("apache", "Apache HTTP Server Multiple Vulnerabilities",
     [r"(?i)^Apache(?:\s+HTTP\s+Server)?\b"]),
    ("kibana", "Kibana Multiple Vulnerabilities",
     [r"(?i)^Kibana\b"]),
    ("grafana", "Grafana Multiple Vulnerabilities",
     [r"(?i)^Grafana(?:\s+Labs)?\b"]),
    ("elasticsearch", "Elasticsearch Multiple Vulnerabilities",
     [r"(?i)^Elasticsearch\b"]),
    ("mongodb", "MongoDB Multiple Vulnerabilities",
     [r"(?i)^MongoDB\b"]),
    ("gitlab", "GitLab Multiple Vulnerabilities",
     [r"(?i)^GitLab\b"]),
    ("jenkins", "Jenkins Multiple Vulnerabilities",
     [r"(?i)^Jenkins\b"]),
    ("nginx", "nginx Multiple Vulnerabilities",
     [r"(?i)^nginx\b"]),
    ("openssl", "OpenSSL Multiple Vulnerabilities",
     [r"(?i)^OpenSSL\b"]),
    ("openssh", "OpenSSH Multiple Vulnerabilities",
     [r"(?i)^OpenSSH\b"]),
    ("php", "PHP Multiple Vulnerabilities",
     [r"(?i)^PHP\b"]),
    ("mysql", "MySQL Multiple Vulnerabilities",
     [r"(?i)^MySQL\b"]),
    ("mariadb", "MariaDB Multiple Vulnerabilities",
     [r"(?i)^MariaDB\b"]),
    ("postgresql", "PostgreSQL Multiple Vulnerabilities",
     [r"(?i)^PostgreSQL\b"]),
    ("redis", "Redis Multiple Vulnerabilities",
     [r"(?i)^Redis\b"]),
    ("rabbitmq", "RabbitMQ Multiple Vulnerabilities",
     [r"(?i)^RabbitMQ\b"]),
    ("confluence", "Confluence Multiple Vulnerabilities",
     [r"(?i)^Confluence\b"]),
    ("wordpress", "WordPress Multiple Vulnerabilities",
     [r"(?i)^WordPress\b"]),
    ("drupal", "Drupal Multiple Vulnerabilities",
     [r"(?i)^Drupal\b"]),
    ("node", "Node.js Multiple Vulnerabilities",
     [r"(?i)^Node\.js\b"]),
    ("vmware_esxi", "VMware ESXi Multiple Vulnerabilities",
     [r"(?i)^VMware\s+ESXi\b"]),
    ("vmware_vcenter", "VMware vCenter Server Multiple Vulnerabilities",
     [r"(?i)^VMware\s+vCenter\b"]),
    ("java", "Oracle Java SE Multiple Vulnerabilities",
     [r"(?i)^Oracle\s+Java\b"]),
    ("iis", "Microsoft IIS Multiple Vulnerabilities",
     [r"(?i)^Microsoft\s+IIS\b"]),
    ("exchange", "Microsoft Exchange Server Multiple Vulnerabilities",
     [r"(?i)^Microsoft\s+Exchange\b"]),
    ("fortios", "FortiOS Multiple Vulnerabilities",
     [r"(?i)^FortiOS\b"]),
    ("tls", "TLS Deprecated Protocol",
     [r"(?i)^TLS\s+Version\s+1\.[01]\b",
      r"(?i)^TLS\s+1\.[01]\b",
      r"(?i)^TLS\s+.*Deprecated",
      r"(?i)TLS.*Protocol\s+Detection"]),
]


# Titles repeat heavily across hosts and each of these walks the whole product
# registry, so the same strings would otherwise be re-scanned thousands of times
# per pull (and again for every Jira ticket when building the index).
@lru_cache(maxsize=8192)
def _product_slug(title: str) -> Optional[str]:
    """Return the product slug when *title* is a mergeable version-style finding."""
    t = (title or "").strip()
    if not t:
        return None
    for slug, _, patterns in _PRODUCT_REGISTRY:
        if any(re.search(p, t) for p in patterns):
            return slug
    return None


@lru_cache(maxsize=8192)
def _service_from_title(title: str) -> str:
    tl = title.lower()
    for svc, patterns in _SERVICES:
        if any(p in tl for p in patterns):
            return svc
    return ""


@lru_cache(maxsize=8192)
def _product_display_name(title: str) -> str:
    """Short technology label aligned with the vulnerability family name."""
    slug = _product_slug(title)
    if slug:
        for s, canonical, _ in _PRODUCT_REGISTRY:
            if s == slug:
                name = canonical.replace(" Multiple Vulnerabilities", "")
                if slug == "tls":
                    return "TLS"
                if slug == "nginx":
                    return "nginx"
                return name
    svc = _service_from_title(title)
    return svc


# Transport-layer names — never use these as the Technology label.
_PROTOCOL_NAMES = frozenset({"tcp", "udp", "icmp", "sctp", "dccp"})


@lru_cache(maxsize=8192)
def _technology_label(title: str) -> str:
    """Derive the technology name from a vulnerability title (never TCP/UDP)."""
    label = _product_display_name(title)
    if label:
        return label
    t = (title or "").strip()
    m = re.match(r"^([A-Za-z][A-Za-z0-9.+/-]*)", t)
    if m:
        word = m.group(1)
        if word.lower() not in _PROTOCOL_NAMES:
            return word
    return ""


def _technology(title: str, port: str, protocol: str) -> str:
    label = _technology_label(title)
    if not label:
        label = "Unknown"
    parts = [label]
    if port and port not in ("0", ""):
        parts.append(port)
    return ",".join(parts)


def _ports_from_technology(tech: str) -> List[str]:
    """Extract numeric port tokens from a Technology field."""
    ports = []
    for part in (tech or "").split(","):
        p = part.strip()
        if p.isdigit():
            ports.append(p)
    return ports


def _rebuild_technology(finding: dict) -> None:
    """Rebuild Technology as ``Product,port,port,…`` using the vulnerability family name."""
    title = finding.get("Vulnerability_Title") or ""
    label = _technology_label(title) or _technology_label(_normalize_title(title))
    ports = set(_ports_from_technology(finding.get("Technology", "")))
    p = str(finding.get("_port") or "").strip()
    if p and p != "0":
        ports.add(p)
    if not label:
        label = "Unknown"
    if ports:
        finding["Technology"] = label + "," + ",".join(sorted(ports, key=lambda x: int(x)))
    else:
        finding["Technology"] = label


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

# Nessus CSV exports include CVSS scores but not CVSS vectors — CIA impact and
# risk values need plugin metadata. Use parallel fetch + disk cache; scale
# workers on large scans (many unique plugins).
_PLUGIN_FETCH_WORKERS = 4
_PLUGIN_FETCH_WORKERS_LARGE = 8
_LARGE_SCAN_MIN_ROWS = 3000
_LARGE_SCAN_MIN_HOSTS = 100


def _count_csv_hosts(rows: List[dict]) -> int:
    return len({_col(row, "Host") for row in rows if _col(row, "Host")})


def _plugin_fetch_workers(
    pending_count: int, row_count: int, host_count: Optional[int], csv_hosts: int,
) -> int:
    hosts = max(host_count or 0, csv_hosts)
    large = row_count >= _LARGE_SCAN_MIN_ROWS or hosts >= _LARGE_SCAN_MIN_HOSTS
    cap = _PLUGIN_FETCH_WORKERS_LARGE if large else _PLUGIN_FETCH_WORKERS
    if pending_count <= 0:
        return cap
    return min(cap, max(_PLUGIN_FETCH_WORKERS, (pending_count + 24) // 25))


def _load_plugin_disk_cache(plugin_id: int) -> Optional[dict]:
    path = os.path.join(_PLUGIN_CACHE_DIR, f"{plugin_id}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _save_plugin_disk_cache(plugin_id: int, data: dict) -> None:
    _ensure_cache_dirs()
    try:
        _atomic_write_json(os.path.join(_PLUGIN_CACHE_DIR, f"{plugin_id}.json"), data)
    except OSError as exc:
        log.warning("Intake: could not cache plugin %s — %s", plugin_id, exc)


def _prefetch_plugin_details(
    cfg, label: str, ak: str, sk: str, plugin_ids: List[int],
    *, row_count: int = 0, host_count: Optional[int] = None, csv_hosts: int = 0,
) -> None:
    """Fetch Nessus plugin metadata in parallel (disk + memory cached)."""
    from . import connections as conn_mod, nessus_client as nc

    pending: List[int] = []
    for pid in plugin_ids:
        if pid in _PLUGIN_CACHE:
            continue
        cached = _load_plugin_disk_cache(pid)
        if cached is not None:
            _PLUGIN_CACHE[pid] = cached
        else:
            pending.append(pid)

    if not pending:
        return

    log.info(
        "Intake parse: fetching %d plugin detail(s) in parallel (%d cached)",
        len(pending), len(plugin_ids) - len(pending),
    )

    def _fetch_one(conn, pid: int) -> dict:
        try:
            data = nc.get_plugin_details(conn, ak, sk, pid)
        except Exception:
            data = {"attributes": []}
        _PLUGIN_CACHE[pid] = data
        _save_plugin_disk_cache(pid, data)
        return data

    workers = _plugin_fetch_workers(len(pending), row_count, host_count, csv_hosts)
    conn_mod.parallel_nessus_map(cfg, label, pending, _fetch_one, max_workers=workers)


def _parse_nessus_csv(
    csv_text: str,
    vector: str = "",
    actor: str = "",
    conn=None,
    ak=None,
    sk=None,
    cfg=None,
    label: str = "",
    host_count: Optional[int] = None,
) -> List[dict]:
    """Parse one Nessus CSV export into normalised finding dicts."""
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

    # --- Pass 1.5: Plugin metadata (optional — skipped on large scans) ---
    csv_hosts = len(ip_to_os) or _count_csv_hosts(rows)
    fetch_plugins = bool(conn and ak and sk and cfg and label)
    csv_hosts = _count_csv_hosts(rows)

    if fetch_plugins:
        needed_plugins: List[int] = []
        seen: set = set()
        for row in rows:
            if _col(row, "Risk").lower() in _SKIP_RISKS:
                continue
            if _col(row, "CVSS v3.0 Vector", "CVSS v2.0 Vector", "CVSS Vector"):
                continue
            pid = _col(row, "Plugin ID")
            if not pid:
                continue
            try:
                p = int(pid)
            except ValueError:
                continue
            if p in _PLUGIN_CACHE or p in seen:
                continue
            seen.add(p)
            needed_plugins.append(p)

        if needed_plugins:
            _prefetch_plugin_details(
                cfg, label, ak, sk, needed_plugins,
                row_count=len(rows), host_count=host_count, csv_hosts=csv_hosts,
            )

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

        if _is_irrelevant(name):
            continue

        os_val = ip_to_os.get(host, "")

        plugin_out = _col(row, "Plugin Output")
        if plugin_out:
            desc = f"{desc}\n{plugin_out}" if desc else plugin_out
        desc = _sanitize_report_text(desc)
        soln = _enhance_recommendation(name, os_val, soln)

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
    (re.compile(r"(?i)Apache(?:\s+HTTP\s+Server)?\s+\d+(?:\.\d+)+"), "Apache HTTP Server Multiple Vulnerabilities"),
    (re.compile(r"(?i)Apache\s+Tomcat\s+\d+(?:\.\d+)+"), "Apache Tomcat Multiple Vulnerabilities"),
    (re.compile(r"(?i)PHP\s+\d+(?:\.\d+)+"), "PHP Multiple Vulnerabilities"),
    (re.compile(r"(?i)OpenSSL\s+\d+(?:\.\d+)*[a-z]?"), "OpenSSL Multiple Vulnerabilities"),
    (re.compile(r"(?i)OpenSSH\s+(?:<\s*)?\d+(?:\.\d+)*"), "OpenSSH Multiple Vulnerabilities"),
    (re.compile(r"(?i)nginx\s+\d+(?:\.\d+)+"), "nginx Multiple Vulnerabilities"),
    (re.compile(r"(?i)Node\.js\s+\d+(?:\.\d+)+"), "Node.js Multiple Vulnerabilities"),
    (re.compile(r"(?i)MySQL\s+\d+(?:\.\d+)+"), "MySQL Multiple Vulnerabilities"),
    (re.compile(r"(?i)MariaDB\s+\d+(?:\.\d+)+"), "MariaDB Multiple Vulnerabilities"),
    (re.compile(r"(?i)PostgreSQL\s+\d+(?:\.\d+)+"), "PostgreSQL Multiple Vulnerabilities"),
    (re.compile(r"(?i)Oracle\s+Java\s+SE\s+\d+"), "Oracle Java SE Multiple Vulnerabilities"),
    (re.compile(r"(?i)VMware\s+ESXi"), "VMware ESXi Multiple Vulnerabilities"),
    (re.compile(r"(?i)VMware\s+vCenter\s+Server"), "VMware vCenter Server Multiple Vulnerabilities"),
]


@lru_cache(maxsize=8192)
def _normalize_title(title: str) -> str:
    """Normalize vulnerability titles to group similar version vulnerabilities."""
    t = (title or "").strip()
    if not t:
        return t
    slug = _product_slug(t)
    if slug:
        for s, canonical, _ in _PRODUCT_REGISTRY:
            if s == slug:
                return canonical
    for pattern, replacement in _NORMALIZATION_PATTERNS:
        if pattern.search(t):
            return replacement
    return t


@lru_cache(maxsize=8192)
def _family_key(title: str) -> Optional[str]:
    """Return the canonical family name when *title* is a version-style finding."""
    slug = _product_slug(title)
    if slug:
        return _normalize_title(title).lower()
    norm = _normalize_title(title)
    if norm.lower() != (title or "").strip().lower():
        return norm.lower()
    return None


def _merge_row_into(existing: dict, incoming: dict, severity_map: dict,
                    cve_seen: Optional[dict] = None) -> None:
    """Combine *incoming* into *existing* (CVEs, CVSS, rating, ports).

    *cve_seen* is an optional insertion-ordered accumulator of the CVEs already
    on *existing*. Passing it keeps merging linear; without it every merge
    re-parses and linearly scans the joined CVE string, which is quadratic for
    families that collapse hundreds of rows onto one host.
    """
    _merge_port(existing, str(incoming.get("_port") or "").strip())
    if incoming.get("CVE"):
        if cve_seen is None:
            cve_seen = dict.fromkeys(
                c.strip() for c in existing.get("CVE", "").split(",") if c.strip()
            )
        for cve in incoming["CVE"].split(","):
            cve = cve.strip()
            if cve:
                cve_seen[cve] = None
        existing["CVE"] = ",".join(cve_seen)
    try:
        e_cvss = float(existing.get("CVSS") or 0.0)
    except ValueError:
        e_cvss = 0.0
    try:
        f_cvss = float(incoming.get("CVSS") or 0.0)
    except ValueError:
        f_cvss = 0.0
    if f_cvss > e_cvss:
        existing["CVSS"] = incoming.get("CVSS", "")
    e_rating = existing.get("Vulnerability_Rating", "Info").capitalize()
    f_rating = incoming.get("Vulnerability_Rating", "Info").capitalize()
    if severity_map.get(f_rating, 0) > severity_map.get(e_rating, 0):
        existing["Vulnerability_Rating"] = f_rating
    existing["_merged_count"] = int(existing.get("_merged_count") or 1) + 1
    _rebuild_technology(existing)


def _is_irrelevant(title: str) -> bool:
    """True when *title* (raw or normalised) is on the exclusion list."""
    if not title:
        return False
    irrelevant = _load_irrelevant()
    raw = title.strip().lower()
    if raw in irrelevant:
        return True
    norm = _normalize_title(title).strip().lower()
    return norm in irrelevant


def _enhance_recommendation(title: str, os_val: str, nessus_solution: str) -> str:
    """Prefer a curated recommendation; fall back to the Nessus solution text."""
    lib = _load_recommendations()
    os_val = (os_val or "Unknown").strip() or "Unknown"
    norm_title = _normalize_title(title)
    for key in (f"{os_val}|{norm_title}", f"{os_val}|{title.strip()}",
                f"|{norm_title}", f"|{title.strip()}"):
        if key in lib:
            return _sanitize_report_text(lib[key])
    return _sanitize_report_text(nessus_solution)


def _index_hit(key: str, status: str = "") -> dict:
    return {"key": key, "status": status or ""}


def _resolve_hit(hit) -> Tuple[Optional[str], str]:
    if not hit:
        return None, ""
    if isinstance(hit, str):
        return hit, ""
    return hit.get("key"), hit.get("status") or ""


def _lookup_hit(index: dict, *keys) -> Tuple[Optional[str], str]:
    for k in keys:
        if k in index:
            return _resolve_hit(index[k])
    return None, ""


def _merge_dedup(all_findings: List[dict]) -> List[dict]:
    """Merge findings that share the same product family + IP, or title + IP.

    Version-style products (Kibana, Grafana, nginx, TLS, …) collapse to one row
    per host regardless of differing Nessus version strings or ports.
    """
    seen: dict = {}
    out: List[dict] = []
    # out-index → insertion-ordered CVE accumulator, so repeated merges onto the
    # same row don't re-parse and re-scan an ever-growing CVE string.
    cve_acc: Dict[int, dict] = {}
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0, "Info": 0}

    for f in all_findings:
        raw_title = f["Vulnerability_Title"]
        norm_title = _normalize_title(raw_title)
        f["Vulnerability_Title"] = norm_title
        f["_product"] = _product_slug(raw_title) or _product_slug(norm_title) or ""

        ip = f["_ip"].strip()
        slug = f["_product"]
        if slug:
            key = ("product", slug, ip)
        else:
            key = ("title", norm_title.lower(), ip)

        if key in seen:
            idx = seen[key]
            _merge_row_into(out[idx], f, severity_map, cve_acc[idx])
        else:
            f["_merged_count"] = 1
            _rebuild_technology(f)
            idx = len(out)
            seen[key] = idx
            cve_acc[idx] = dict.fromkeys(
                c.strip() for c in (f.get("CVE") or "").split(",") if c.strip()
            )
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
    family_index: dict,
    product_index: dict,
) -> Tuple[Optional[str], Optional[str], str]:
    """Return (jira_key, match_kind, jira_status)."""
    raw_title = finding.get("Vulnerability_Title") or ""
    title = _normalize_title(raw_title).strip().lower()
    ip = (finding.get("System_IP") or finding.get("_ip") or "").strip()
    port = str(finding.get("_port") or "").strip()
    slug = _product_slug(raw_title) or finding.get("_product") or ""

    # Product + IP + port — any Kibana/Grafana/etc. on this host/port is a dup
    if slug:
        key, status = _lookup_hit(
            product_index,
            (slug, ip, port),
            (slug, ip, ""),
        )
        if key:
            return key, "product", status

    key, status = _lookup_hit(
        title_index,
        (title, ip, port),
        (title, ip, ""),
    )
    if key:
        return key, "title", status

    family = _family_key(raw_title)
    if family:
        key, status = _lookup_hit(
            family_index,
            (family, ip, port),
            (family, ip, ""),
        )
        if key:
            return key, "family", status

    for cve in _parse_cve_list(finding.get("CVE") or ""):
        dup_key = cve_index.get((cve, ip))
        if dup_key:
            k, st = _resolve_hit(dup_key)
            return k, "cve", st
    return None, None, ""


# Jira statuses meaning "already remediated" — a new scan hit against these is a
# recurrence (re-open / new upload), not a duplicate of an open backlog item.
_JIRA_FIXED_STATUSES = frozenset({"fixed", "closed", "done", "resolved"})


def _is_fixed_jira_status(status: str) -> bool:
    return (status or "").strip().lower() in _JIRA_FIXED_STATUSES


def _classify_against_jira(
    dup_key: Optional[str],
    dup_status: str,
    match_kind: Optional[str],
) -> dict:
    """Map a Jira index hit to intake status fields."""
    if not dup_key:
        return {
            "status": "new",
            "duplicate_of": None,
            "duplicate_status": "",
            "recurrence_of": None,
            "previous_jira_status": "",
            "match_kind": match_kind,
        }
    if _is_fixed_jira_status(dup_status):
        return {
            "status": "recurrence",
            "duplicate_of": None,
            "duplicate_status": "",
            "recurrence_of": dup_key,
            "previous_jira_status": dup_status,
            "match_kind": match_kind,
        }
    return {
        "status": "duplicate",
        "duplicate_of": dup_key,
        "duplicate_status": dup_status,
        "recurrence_of": None,
        "previous_jira_status": "",
        "match_kind": match_kind,
    }


# ── Jira index builder ──────────────────────────────────────────────────────

def _index_from_tickets(tickets: List[dict]) -> Tuple[dict, dict, dict, dict]:
    """Build lookup indexes from serialized Jira tickets.

    Returns (title_index, cve_index, family_index, product_index).
    Index values are ``{"key": ticket_key, "status": jira_status}``.
    """
    title_index: dict = {}
    cve_index: dict = {}
    family_index: dict = {}
    product_index: dict = {}
    for t in tickets:
        raw_summary = t.get("summary") or ""
        title = _normalize_title(raw_summary).strip().lower()
        family = _family_key(raw_summary)
        slug = _product_slug(raw_summary)
        status = t.get("status") or ""
        hit = _index_hit(t["key"], status)
        ips = [i.strip() for i in (t.get("ips") or []) if i.strip()]
        ports = [str(p).strip() for p in (t.get("ports") or []) if str(p).strip()]
        cves = [c.strip().upper() for c in (t.get("cves") or []) if c.strip()]

        port_list = ports or [""]
        for ip in ips:
            for port in port_list:
                title_index[(title, ip, port)] = hit
                if family:
                    family_index[(family, ip, port)] = hit
                if slug:
                    product_index[(slug, ip, port)] = hit
            title_index.setdefault((title, ip, ""), hit)
            if family:
                family_index.setdefault((family, ip, ""), hit)
            if slug:
                product_index.setdefault((slug, ip, ""), hit)
            for cve in cves:
                cve_index.setdefault((cve, ip), hit)
        if not ips:
            title_index[(title, "", "")] = hit
            if family:
                family_index[(family, "", "")] = hit
            if slug:
                product_index[(slug, "", "")] = hit

    return title_index, cve_index, family_index, product_index


def _key_index_from_tickets(tickets: List[dict]) -> dict:
    """Map Jira issue key → workflow status (Fixed, Reported, Open, …)."""
    return {
        t["key"]: (t.get("status") or "").strip()
        for t in tickets
        if t.get("key")
    }


def _cache_has_statuses(tickets: List[dict]) -> bool:
    """True when cached tickets include at least one non-empty Jira status."""
    if not tickets:
        return True
    sample = tickets[:100]
    return any((t.get("status") or "").strip() for t in sample)


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
            "status":  t.get("status") or "",
            "ips":     t.get("ips") or [],
            "ports":   t.get("ports") or [],
            "cves":    t.get("cves") or [],
        }
        for t in tickets if t.get("key")
    ]
    try:
        _atomic_write_json(_jira_cache_path(label), {
            "cache_version": _JIRA_CACHE_VERSION,
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
    if data.get("cache_version", 1) < _JIRA_CACHE_VERSION:
        log.info("Intake: Jira cache '%s' outdated — will rebuild for ticket statuses", label)
        return False
    tickets = data.get("tickets") or []
    if not _cache_has_statuses(tickets):
        log.info("Intake: Jira cache '%s' missing ticket statuses — will rebuild", label)
        return False
    title_index, cve_index, family_index, product_index = _index_from_tickets(tickets)
    key_index = _key_index_from_tickets(tickets)
    with _INDEX_LOCK:
        _JIRA_INDEXES[label] = {
            "status":     "ready",
            "index":      title_index,
            "cve_index":  cve_index,
            "family_index": family_index,
            "product_index": product_index,
            "key_index":  key_index,
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
                "family_index": {}, "product_index": {},
                "count": 0, "error": None,
            }

    try:
        _, session = m._get_client(label)
        jc = m._jira_for_label(label)
        try:
            jc._load_fields()
        except Exception:
            pass

        if session == "non_axian":
            jql = f'project = {label} ORDER BY created ASC'
        else:
            jql = (
                f'project = {m.cfg.jira.project} AND labels = "{label}" '
                f'ORDER BY created ASC'
            )

        tickets = jc.search_jql(jql)
        title_index, cve_index, family_index, product_index = _index_from_tickets(tickets)
        key_index = _key_index_from_tickets(tickets)
        jira_url = jc.cfg.url.rstrip("/")
        fetched_at = time.time()

        with _INDEX_LOCK:
            _JIRA_INDEXES[label] = {
                "status": "ready",
                "index": title_index,
                "cve_index": cve_index,
                "family_index": family_index,
                "product_index": product_index,
                "key_index": key_index,
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
                "family_index": {},
                "product_index": {},
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


def _nessus_raw_csv_path(label: str, scan_id: int) -> str:
    return os.path.join(_NESSUS_CACHE_DIR, f"{_safe_name(label)}_{scan_id}_raw.csv")


def _load_nessus_raw_csv(label: str, scan_id: int) -> Optional[dict]:
    """Return cached Nessus CSV export metadata, or None."""
    path = _nessus_raw_csv_path(label, scan_id)
    meta_path = path + ".meta.json"
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            csv_text = f.read()
        scan_name = f"Scan {scan_id}"
        if os.path.exists(meta_path):
            with open(meta_path, encoding="utf-8") as f:
                scan_name = json.load(f).get("scan_name") or scan_name
        return {"csv": csv_text, "scan_name": scan_name}
    except OSError as exc:
        log.warning("Intake: ignoring corrupt raw CSV cache for scan %s — %s", scan_id, exc)
        return None


def _save_nessus_raw_csv(label: str, scan_id: int, scan_name: str, csv_text: str) -> None:
    _ensure_cache_dirs()
    path = _nessus_raw_csv_path(label, scan_id)
    try:
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(csv_text)
        os.replace(tmp, path)
        _atomic_write_json(path + ".meta.json", {
            "scan_id": scan_id,
            "scan_name": scan_name,
            "fetched_at": time.time(),
            "bytes": len(csv_text.encode("utf-8")),
        })
    except OSError as exc:
        log.warning("Intake: could not write raw CSV cache for scan %s — %s", scan_id, exc)


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


@router.get("/api/intake/config/irrelevant")
def intake_get_irrelevant():
    """Return the list of vulnerability titles excluded from Intake."""
    _load_irrelevant()
    try:
        with open(_IRRELEVANT_PATH, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        text = _DEFAULT_IRRELEVANT
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return {"lines": lines, "count": len(lines)}


@router.put("/api/intake/config/irrelevant")
def intake_save_irrelevant(req: IrrelevantConfigRequest):
    """Update the irrelevant-vulnerability exclusion list."""
    global _IRRELEVANT_SET, _IRRELEVANT_LOADED
    _ensure_cache_dirs()
    body = "\n".join(ln.strip() for ln in req.lines if ln.strip()) + "\n"
    try:
        tmp = f"{_IRRELEVANT_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(body)
        os.replace(tmp, _IRRELEVANT_PATH)
    except OSError as exc:
        raise HTTPException(500, f"Could not save irrelevant list: {exc}") from exc
    _IRRELEVANT_SET = set()
    _IRRELEVANT_LOADED = False
    return {"ok": True, "count": len(_load_irrelevant())}


@router.get("/api/intake/config/recommendations-status")
def intake_recommendations_status():
    """Report whether the curated recommendation library is loaded."""
    lib = _load_recommendations()
    return {
        "loaded": bool(lib),
        "count": len(lib),
        "path": _RECOMMENDATIONS_PATH,
        "seed_available": os.path.exists(_SEED_RECOMMENDATIONS),
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
    if not conn_mod.get_connection(label):
        raise HTTPException(400, f"SSH not connected for '{label}' — connect in the Shell tab first")

    ak, sk = client_cfg.nessus_access_key, client_cfg.nessus_secret_key
    all_findings: List[dict] = []
    errors: List[str] = []
    cached_scans = 0
    pulled_scans = 0

    def _pull_one(conn, scan_id: int) -> dict:
        cached = None if req.force else _load_nessus_cache(label, scan_id, req.vector, req.actor)
        if cached:
            rows = cached.get("findings") or []
            log.info("Intake pull: scan %d ('%s') → %d vuln rows (from cache)",
                     scan_id, cached.get("scan_name", ""), len(rows))
            return {"rows": rows, "cached": True, "scan_name": cached.get("scan_name", "")}
        log.info("Intake pull: exporting scan %d from Nessus%s…",
                 scan_id, " (forced)" if req.force else "")
        host_count = (req.scan_host_counts or {}).get(scan_id) or None
        csv_text: Optional[str] = None
        sname = f"Scan {scan_id}"

        if not req.force:
            raw = _load_nessus_raw_csv(label, scan_id)
            if raw:
                csv_text = raw["csv"]
                sname = raw.get("scan_name") or sname
                log.info(
                    "Intake pull: scan %d ('%s') — reusing cached CSV export (%d bytes)",
                    scan_id, sname, len(csv_text),
                )

        if csv_text is None:
            csv_text, sname = nc.export_scan_csv(conn, ak, sk, scan_id, host_count=host_count)
            _save_nessus_raw_csv(label, scan_id, sname, csv_text)

        log.info("Intake pull: parsing scan %d ('%s')…", scan_id, sname)
        rows = _parse_nessus_csv(
            csv_text,
            vector=req.vector,
            actor=req.actor,
            conn=conn,
            ak=ak,
            sk=sk,
            cfg=m.cfg,
            label=label,
            host_count=host_count,
        )
        log.info("Intake pull: scan %d ('%s') → %d vuln rows", scan_id, sname, len(rows))
        _save_nessus_cache(label, scan_id, req.vector, req.actor, sname, rows)
        return {"rows": rows, "cached": False, "scan_name": sname}

    try:
        workers = conn_mod.nessus_parallel_workers(req.scan_ids, req.scan_host_counts)
        if workers < conn_mod.NESSUS_PARALLEL_WORKERS:
            log.info("Intake pull: large scan(s) detected — using %d parallel worker(s)", workers)
        results = conn_mod.parallel_nessus_map(
            m.cfg, label, req.scan_ids, _pull_one, max_workers=workers,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    for scan_id, result, err in results:
        if err:
            errors.append(f"Scan {scan_id}: {err}")
            continue
        if not result:
            continue
        all_findings.extend(result["rows"])
        if result["cached"]:
            cached_scans += 1
        else:
            pulled_scans += 1

    merged = _merge_dedup(all_findings)

    # Drop irrelevant titles (covers cached scans parsed before the list was updated)
    before = len(merged)
    merged = [f for f in merged if not _is_irrelevant(f.get("Vulnerability_Title", ""))]
    excluded_irrelevant = before - len(merged)

    # Apply engagement-level values and curated recommendations
    for f in merged:
        f["Impact_Type"] = req.impact_type
        f["Vector"]      = req.vector
        f["Actor"]       = req.actor
        f["Recommendation"] = _enhance_recommendation(
            f.get("Vulnerability_Title", ""),
            f.get("OS", ""),
            f.get("Recommendation", ""),
        )

    # Add stable IDs and initial UI state
    for i, f in enumerate(merged):
        f["_id"]           = i
        f["_status"]       = "pending"
        f["_duplicate_of"] = None

    return {
        "ok":           True,
        "total_raw":    len(all_findings),
        "total_merged": len(merged),
        "excluded_irrelevant": excluded_irrelevant,
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
    family_index = info.get("family_index") or {}
    product_index = info.get("product_index") or {}
    key_index = info.get("key_index") or {}
    results = []

    for f in req.findings:
        dup_key, match_kind, dup_status = _match_finding_to_index(
            f, index, cve_index, family_index, product_index,
        )
        if dup_key and not dup_status:
            dup_status = key_index.get(dup_key, "")

        row = _classify_against_jira(dup_key, dup_status, match_kind)
        results.append({"_id": f.get("_id"), **row})

    new_ct        = sum(1 for r in results if r["status"] == "new")
    dup_ct        = sum(1 for r in results if r["status"] == "duplicate")
    recurrence_ct = sum(1 for r in results if r["status"] == "recurrence")

    return {
        "ok":                   True,
        "results":              results,
        "new_count":            new_ct,
        "duplicate_count":      dup_ct,
        "recurrence_count":     recurrence_ct,
        "exportable_count":     new_ct + recurrence_ct,
        "jira_tickets_checked": info.get("count", 0),
    }


@router.post("/api/intake/export")
def intake_export(req: ExportRequest):
    """Export findings as CSV. ``export_mode=new`` skips duplicates; ``all`` includes them."""

    if req.export_mode == "all":
        to_export = list(req.findings)
    elif req.export_mode == "selected":
        to_export = list(req.findings)
    else:
        to_export = [f for f in req.findings if f.get("_status") != "duplicate"]
    if not to_export:
        raise HTTPException(400, "No findings to export")

    COLUMNS = [
        "Attachments", "Vulnerability_Title", "Vulnerability_Description",
        "Recommendation", "Affected_System", "System_IP", "OS", "Assignee",
        "OWASP_Top_10_Category", "Vulnerability_Rating", "CVE", "CVSS",
        "Impact_Type", "Technology", "Vector", "Actor", "CIA_Damage",
        "Risk_Value", "Project_Key", "Testers", "Date_Started", "Duration",
        "Test_Type", "Purchaser", "Customer", "Contact_Person",
        "Technical_Contact", "mUnit_ID",
        "JIRA_Duplicate", "JIRA_Duplicate_Status",
        "JIRA_Recurrence_Of", "JIRA_Previous_Status",
    ]
    if req.export_mode == "all":
        COLUMNS += ["Intake_Status", "JIRA_Key", "JIRA_Status"]

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
        is_dup = f.get("_status") == "duplicate"
        row["Intake_Status"] = f.get("_status") or "pending"
        row["JIRA_Key"] = f.get("_duplicate_of") or ""
        row["JIRA_Status"] = f.get("_duplicate_status") or ""
        row["JIRA_Duplicate"] = "Yes" if is_dup else "No"
        row["JIRA_Duplicate_Status"] = f.get("_duplicate_status") or ""
        row["JIRA_Recurrence_Of"] = f.get("_recurrence_of") or ""
        row["JIRA_Previous_Status"] = f.get("_previous_jira_status") or ""

        if idx == 0 and req.export_mode not in ("all", "selected"):
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
        elif req.export_mode not in ("all", "selected"):
            for col in META_COLS:
                row[col] = ""

        writer.writerow(row)

    buf.seek(0)
    suffix = {"all": "full", "selected": "selected"}.get(req.export_mode, "new")
    fname = f"intake_{suffix}_{date.today().isoformat()}.csv"
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),   # UTF-8 BOM for Excel
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


def _intake_exportable(f: dict) -> bool:
    """Rows we can upload or create in Jira (same rule as CSV export, minus already created)."""
    if f.get("_jira_key"):
        return False
    return f.get("_status") != "duplicate"


def _intake_pick_for_create(findings: List[dict], mode: str) -> List[dict]:
    if mode == "selected":
        pool = list(findings)
    else:
        pool = [f for f in findings if _intake_exportable(f)]
    return [f for f in pool if _intake_exportable(f)]


@router.post("/api/intake/{label}/create-jira")
def intake_create_jira(label: str, req: CreateJiraRequest):
    """Create Jira issues directly from Intake findings (NEW + REOPEN only)."""
    from . import main as m
    from .intake_jira import build_intake_issue_fields

    if not m.cfg:
        raise HTTPException(400, "App not configured yet")
    client_cfg = m._find_client(label)
    if not client_cfg:
        raise HTTPException(400, f"Unknown client: {label}")

    to_create = _intake_pick_for_create(req.findings, req.create_mode)
    if not to_create:
        raise HTTPException(400, "No exportable findings to create in Jira")

    jira_client = m._jira_for_label(label)
    _, session = m._get_client(label)
    is_v3 = session == "axian"
    default_project = label if session == "non_axian" else m.cfg.jira.project
    project_key = (req.project_key or default_project).strip()
    if not project_key:
        raise HTTPException(400, "Project key is required")

    engagement = {
        "test_type": req.test_type,
        "duration": req.duration,
        "tester": req.tester,
        "date_started": req.date_started,
        "purchaser": req.purchaser,
        "customer": req.customer or client_cfg.name,
        "contact_person": req.contact_person,
        "technical_contact": req.technical_contact,
        "munit_id": req.munit_id or label,
    }

    jira_url = jira_client.cfg.url.rstrip("/")
    results: List[dict] = []
    created = 0
    failed = 0

    for f in to_create:
        fid = f.get("_id")
        try:
            row = dict(f)
            row.setdefault("Impact_Type", req.impact_type)
            row.setdefault("Vector", req.vector)
            row.setdefault("Actor", req.actor)
            row["Recommendation"] = _enhance_recommendation(
                row.get("Vulnerability_Title", ""),
                row.get("OS", ""),
                row.get("Recommendation", ""),
            )
            fields = build_intake_issue_fields(
                jira_client,
                row,
                engagement,
                project_key=project_key,
                client_label=label,
                tag_client_label=is_v3,
                is_v3=is_v3,
            )
            key = jira_client.create_issue(fields)
            created += 1
            results.append({
                "_id": fid,
                "ok": True,
                "jira_key": key,
                "jira_url": f"{jira_url}/browse/{key}",
                "recurrence_of": row.get("_recurrence_of"),
            })
        except Exception as exc:
            failed += 1
            log.warning("Intake create-jira failed for _id=%s: %s", fid, exc)
            results.append({"_id": fid, "ok": False, "error": str(exc)})

    return {
        "ok": created > 0 or failed == 0,
        "created": created,
        "failed": failed,
        "results": results,
        "jira_url": jira_url,
        "project_key": project_key,
    }
