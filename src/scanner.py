"""
Job queue, Jira polling, and scan execution.
"""

import logging
import queue as _queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .config import Config
from .jira_client import JiraClient
from . import connections
from .vuln_rules import match_rule

log = logging.getLogger(__name__)

_lock = threading.RLock()

# All scan jobs keyed by job_id
JOBS: Dict[str, Dict[str, Any]] = {}

# Ticket keys that have already been queued (so we don't re-add on next poll)
SEEN_KEYS: set = set()

# System-level application logs
APP_LOGS: List[str] = []

@dataclass
class SweepState:
    status: str = "stopped"  # stopped, running, paused
    pending_job_ids: List[str] = field(default_factory=list)

# Sweep states keyed by client_label
SWEEPS: Dict[str, SweepState] = {}

# Signals the background poll thread to wake up immediately
_wake_poll = threading.Event()
_wake_poll_secondary = threading.Event()

# Set to tell the current poll_jira() thread to exit its loop (used when
# reloading config at runtime — see main.reload_runtime_config())
_poll_stop = threading.Event()
_poll_stop_secondary = threading.Event()

# Incremented after every completed poll cycle — lets the frontend detect completion
_poll_count: int = 0
_poll_count_secondary: int = 0

# Per-client queues — one worker per client, but scan and triage jobs are
# kept in separate queues so a manual scan never waits behind a triage
# backlog. The worker always drains the scan queue first.
_scan_queues: Dict[str, _queue.Queue] = {}
_triage_queues: Dict[str, _queue.Queue] = {}
_scan_workers: Dict[str, threading.Thread] = {}

# Stop events keyed by job_id — kept separate so JOBS stays JSON-serialisable
_stop_events: Dict[str, threading.Event] = {}
_sweep_stop_events: Dict[str, threading.Event] = {}

# Job IDs that should be skipped by the scan worker (stop-all was called)
_cancelled_ids: set = set()

# Triage job IDs currently sitting in a triage queue, not yet picked up by
# the worker — lets "Stop Triage" cancel the backlog without touching scans.
_pending_triage_ids: set = set()


def _app_log(msg: str):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] {msg}"
    with _lock:
        APP_LOGS.append(entry)
        if len(APP_LOGS) > 500:
            APP_LOGS.pop(0)
    log.info(msg)


def _job_line(job_id: str, line: str):
    with _lock:
        JOBS[job_id]["output_lines"].append(line)


def _build_triage_command(rule, ip: Optional[str], port: Optional[int]) -> Optional[str]:
    """Lightweight port-reachability check — no version-detection scripts, no PTY.
    Used to flag likely-already-fixed tickets before committing to the full scan.
    Skipped for curl-based rules since those scans are already fast."""
    if not (rule and ip and port) or rule.tool == "curl":
        return None
    parts = ["sudo nmap" if rule.requires_root else "nmap",
              "-Pn", "-T4", "--max-retries", "1", "--host-timeout", "10s"]
    if rule.requires_root:
        parts.append("-sU")
    parts += ["-p", str(port), "--open", ip]
    return " ".join(parts)


def _queue_ticket(ticket: Dict[str, Any], client_label: str,
                  source: str = "poll", manual: bool = False,
                  session: str = "axian") -> str:
    """Create a queued job from a Jira ticket. Returns job_id.

    manual=True marks the job status as 'manual' (no scan command will be run;
    the user reviews and sets the verdict themselves). Used for sweep tickets
    that have no matching automated scan rule.
    """
    rule = match_rule(ticket["summary"])

    # Determine target IP
    ip: Optional[str] = ticket["ips"][0] if ticket["ips"] else None

    # Determine target port
    port: Optional[int] = None
    if ticket["ports"]:
        try:
            port = int(ticket["ports"][0])
        except ValueError:
            pass
    if port is None and rule and rule.default_port:
        port = rule.default_port

    # Build scan command (nmap or curl)
    nmap_cmd: Optional[str] = None
    if rule and ip:
        if rule.tool == "curl":
            scheme = rule.curl_scheme or ("https" if port in (443, 8443) else "http")
            # extra_args can inject additional curl flags (e.g. -H 'Origin: ...' for CORS)
            curl_extra = f" {rule.extra_args}" if rule.extra_args else ""
            status_suffix = '-w "\\n[STATUS:%{http_code}][URL:%{url_effective}]\\n"'
            url = f"{scheme}://{ip}:{port}{rule.curl_path}"
            if rule.curl_method == "POST" and rule.curl_post_data:
                body = rule.curl_post_data.replace("'", "'\\''")
                nmap_cmd = (
                    f"curl -sk --max-time 15 -X POST "
                    f'-H "Content-Type: text/xml" '
                    f"-d '{body}' "
                    f"{status_suffix} "
                    f"{url}"
                )
            elif rule.curl_paths:
                urls = " ".join(f"{scheme}://{ip}:{port}{p}" for p in rule.curl_paths)
                nmap_cmd = (
                    f'curl -sk --max-time 15 '
                    f'-w "\\n[STATUS:%{{http_code}}][URL:%{{url_effective}}]\\n" '
                    f'-o /dev/null{curl_extra} {urls}'
                )
            else:
                nmap_cmd = (
                    f'curl -sk -L --max-time 15 '
                    f'-w "\\n[STATUS:%{{http_code}}][URL:%{{url_effective}}]\\n" '
                    f'-D -{curl_extra} {scheme}://{ip}:{port}{rule.curl_path}'
                )
        elif rule.tool == "redis-cli":
            # Manual flow: redis-cli -h <ip> [-p <port>]  →  info
            # Non-interactive equivalent passes info on the same invocation.
            redis_port = port or 6379
            nmap_cmd = f"timeout 15 redis-cli -h {ip} -p {redis_port} info"
        else:
            parts = ["sudo nmap" if rule.requires_root else "nmap"]
            if rule.extra_args:
                parts.append(rule.extra_args)
            if rule.nmap_script:
                parts += ["--script", rule.nmap_script]
            if port:
                parts += ["-p", str(port)]
            parts += [ip, "-oX", f"/tmp/retest_{{JOB_ID}}.xml", "-v"]
            # Embed the XML read and cleanup in the same PTY session to avoid
            # opening a second SSH channel (which deadlocks after a PTY session).
            nmap_cmd = (
                " ".join(parts)
                + f'; echo "###XML###"; cat /tmp/retest_{{JOB_ID}}.xml; rm -f /tmp/retest_{{JOB_ID}}.xml'
            )

    job_id = str(uuid.uuid4())
    if nmap_cmd:
        nmap_cmd = nmap_cmd.replace("{JOB_ID}", job_id)

    job: Dict[str, Any] = {
        "id": job_id,
        "ticket_key": ticket["key"],
        "ticket_summary": ticket["summary"],
        "ticket_description": ticket.get("description", ""),
        "ticket_status": ticket.get("status", ""),
        "ticket_cvss": ticket.get("cvss"),
        "ticket_severity": ticket.get("severity"),
        "ticket_technology": ticket.get("technology"),
        "ticket_testtype": (ticket.get("testtype") or "").upper(),
        "ticket_cves": ticket.get("cves", []),
        "client_label": client_label,
        "ip": ip,
        "port": port,
        "rule_name": rule.name if rule else None,
        "scan_tool": rule.tool if rule else "nmap",
        "nmap_script": rule.nmap_script if rule else None,
        "nmap_command": nmap_cmd,
        "triage_command": _build_triage_command(rule, ip, port),
        "triage": None,              # None | running | open | closed | host_down | error | skipped
        "triage_note": None,
        "status": "manual" if manual else "queued",  # queued | scanning | completed | error | manual
        "verdict": None,             # fixed | not_fixed | inconclusive | None
        "verdict_reason": None,
        "output_lines": [],
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "jira_updated": False,
        "source": source,            # "poll" | "sweep" | "manual"
        "session": session,          # "axian" | "non_axian"
    }

    with _lock:
        JOBS[job_id] = job

    return job_id


def _reconcile_manual_jobs(tag: str = "") -> int:
    """Promote manual jobs to queued when a scan rule now matches their summary."""
    promoted = 0
    with _lock:
        candidates = [
            (job_id, job) for job_id, job in JOBS.items()
            if job.get("status") == "manual"
        ]
    for job_id, job in candidates:
        rule = match_rule(job.get("ticket_summary") or "")
        if not rule:
            continue
        ticket = {
            "key": job["ticket_key"],
            "summary": job["ticket_summary"],
            "description": job.get("ticket_description", ""),
            "status": job.get("ticket_status", ""),
            "cvss": job.get("ticket_cvss"),
            "severity": job.get("ticket_severity"),
            "technology": job.get("ticket_technology"),
            "testtype": job.get("ticket_testtype", ""),
            "cves": job.get("ticket_cves", []),
            "ips": [job["ip"]] if job.get("ip") else [],
            "ports": [str(job["port"])] if job.get("port") is not None else [],
        }
        with _lock:
            JOBS.pop(job_id, None)
        _queue_ticket(
            ticket, job["client_label"],
            source=job.get("source", "poll"),
            manual=False,
            session=job.get("session", "axian"),
        )
        promoted += 1
    if promoted:
        _app_log(f"{tag}Reconciled {promoted} manual job(s) — now auto-scan")
    return promoted


def _local_exec_stream(command: str, emit, timeout: int = 600, stop_event=None) -> int:
    import subprocess
    import select
    import time

    proc = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    
    deadline = time.time() + timeout
    exit_code = -1
    cancelled = False
    
    try:
        while True:
            if stop_event and stop_event.is_set():
                cancelled = True
                proc.terminate()
                break
            if time.time() > deadline:
                emit(f"[ERROR] Command timed out after {timeout}s")
                proc.terminate()
                break
                
            rlist, _, _ = select.select([proc.stdout], [], [], 0.1)
            if proc.stdout in rlist:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        exit_code = proc.returncode
                        break
                    continue
                emit(line.rstrip('\r\n'))
            elif proc.poll() is not None:
                for line in proc.stdout:
                    emit(line.rstrip('\r\n'))
                exit_code = proc.returncode
                break
                
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
            
    if exit_code == -1 and proc.returncode is not None:
        exit_code = proc.returncode
        
    return -9 if cancelled else exit_code


def run_scan(job_id: str, cfg: Config):
    """Run a single scan job. Called sequentially by the per-client worker."""
    job = JOBS[job_id]
    client_label = job["client_label"]
    all_clients = list(cfg.clients) + list(cfg.clients_secondary or [])
    client_cfg = next((c for c in all_clients if c.label == client_label), None)
    if not client_cfg:
        with _lock:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = f"Client '{client_label}' not in config"
        return

    # Register a stop event for this job before marking it scanning
    stop_event = threading.Event()
    with _lock:
        _stop_events[job_id] = stop_event
        JOBS[job_id]["status"] = "scanning"

    # XML lines from nmap command are intercepted here so they never appear
    # in the terminal output, but are available for parsing.
    _collecting_xml = [False]
    _xml_chunks: List[str] = []

    def emit(line: str):
        # Match the sentinel exactly — the [INFO] Command display line also contains
        # this string as a substring, so substring matching would silence all output.
        if line.strip() == "###XML###":
            _collecting_xml[0] = True
            return
        if _collecting_xml[0]:
            _xml_chunks.append(line)
            return
        _job_line(job_id, line)

    try:
        tool = job.get("scan_tool", "nmap")
        emit(f"[INFO] Ticket  : {job['ticket_key']} — {job['ticket_summary']}")
        emit(f"[INFO] Client  : {client_label}")
        emit(f"[INFO] Target  : {job['ip']}:{job['port']}")
        emit(f"[INFO] Rule    : {job['rule_name'] or 'No matching rule'}")
        emit(f"[INFO] Tool    : {tool.upper()}")
        emit(f"[INFO] Command : {job['nmap_command'] or 'N/A'}")
        emit("─" * 70)

        if not job["ip"]:
            raise ValueError("No IP address found in ticket labels — cannot run scan")

        if not job["nmap_command"]:
            raise ValueError(
                "No scan rule matched this vulnerability. "
                "This may be a manual finding — mark Fixed/Not Fixed manually."
            )

        is_ept = job.get("ticket_testtype", "") == "EPT"

        kali = None
        if not is_ept:
            kali = connections.get_connection(client_label)
            if not kali:
                raise ValueError(
                    f"SSH not connected for '{client_label}' — "
                    "click Connect in the SSH panel first."
                )
            emit("[SSH] Using existing connection ✓")
        else:
            emit("[LOCAL] EPT scan detected — running locally without SSH ✓")

        rule = match_rule(job["ticket_summary"])

        if tool == "curl":
            emit("[CURL] Starting request...")
            emit("")
            if is_ept:
                exit_code = _local_exec_stream(job["nmap_command"], emit, timeout=120, stop_event=stop_event)
            else:
                exit_code = kali.exec_stream(job["nmap_command"], emit, timeout=120, stop_event=stop_event)
            emit("")
            if stop_event.is_set():
                emit("[CANCELLED] Scan stopped by user")
                with _lock:
                    JOBS[job_id].update({
                        "status": "error",
                        "verdict": "inconclusive",
                        "verdict_reason": "Scan cancelled by user",
                        "completed_at": datetime.utcnow().isoformat(),
                    })
                return
            emit(f"[CURL] Request complete (exit code: {exit_code})")
            emit("[PARSE] Analysing response...")
            xml_out = ""
        else:
            emit("[NMAP] Starting scan...")
            emit("")
            if is_ept:
                exit_code = _local_exec_stream(job["nmap_command"], emit, timeout=600, stop_event=stop_event)
            else:
                exit_code = kali.exec_stream(job["nmap_command"], emit, timeout=600, stop_event=stop_event)
            emit("")
            if stop_event.is_set():
                emit("[CANCELLED] Scan stopped by user")
                with _lock:
                    JOBS[job_id].update({
                        "status": "error",
                        "verdict": "inconclusive",
                        "verdict_reason": "Scan cancelled by user",
                        "completed_at": datetime.utcnow().isoformat(),
                    })
                return
            emit(f"[NMAP] Scan complete (exit code: {exit_code})")

            # ── Auto-retry with -Pn if host blocked ICMP ping ─────────────────
            _DOWN_PHRASES = ("host seems down", "0 hosts up", "skipping host")
            _scan_text = "\n".join(JOBS[job_id]["output_lines"]).lower()
            _host_blocked = (
                any(p in _scan_text for p in _DOWN_PHRASES)
                and "-Pn" not in job["nmap_command"]
            )
            if _host_blocked:
                emit("")
                emit("[NMAP] ⚠  Host appears to be blocking ICMP ping — retrying with -Pn ...")
                emit("")
                # Insert -Pn immediately after the nmap binary name
                _orig = job["nmap_command"]
                if _orig.startswith("sudo nmap "):
                    _pn_cmd = "sudo nmap -Pn " + _orig[len("sudo nmap "):]
                else:
                    _pn_cmd = "nmap -Pn " + _orig[len("nmap "):]

                # Reset XML collector so the retry result is clean
                _collecting_xml[0] = False
                _xml_chunks.clear()

                if is_ept:
                    exit_code = _local_exec_stream(_pn_cmd, emit, timeout=600, stop_event=stop_event)
                else:
                    exit_code = kali.exec_stream(_pn_cmd, emit, timeout=600, stop_event=stop_event)
                emit("")
                if stop_event.is_set():
                    emit("[CANCELLED] Scan stopped by user")
                    with _lock:
                        JOBS[job_id].update({
                            "status": "error",
                            "verdict": "inconclusive",
                            "verdict_reason": "Scan cancelled by user",
                            "completed_at": datetime.utcnow().isoformat(),
                        })
                    return
                emit(f"[NMAP] Retry (-Pn) complete (exit code: {exit_code})")
            # ──────────────────────────────────────────────────────────────────

            emit("[PARSE] Analysing results...")
            # XML was collected inline by the emit interceptor — no second channel needed
            xml_out = "\n".join(_xml_chunks)

        # Parsers should only see tool output, not the [INFO] header block
        # (ticket summary, target info, command). Split on the ─ separator
        # that is emitted between the header and the actual scan output.
        all_lines = "\n".join(JOBS[job_id]["output_lines"])
        _sep = "─" * 70
        _parts = all_lines.split(_sep, 1)
        text_output = _parts[1].strip() if len(_parts) > 1 else all_lines

        if rule and rule.parse:
            ticket_desc = job.get("ticket_description", "")
            ticket_ctx = f"{ticket_desc}\n{job.get('ticket_summary', '')}"
            verdict, reason = rule.parse(text_output, xml_out, ticket_ctx)
        else:
            verdict, reason = "inconclusive", "No parser for this rule — review output manually"

        emit("")
        emit("─" * 70)
        emit(f"[VERDICT] {verdict.upper().replace('_', ' ')}")
        emit(f"[REASON]  {reason}")

        with _lock:
            JOBS[job_id]["verdict"] = verdict
            JOBS[job_id]["verdict_reason"] = reason
            JOBS[job_id]["status"] = "completed"
            JOBS[job_id]["completed_at"] = datetime.utcnow().isoformat()

        _app_log(f"Scan complete: {job['ticket_key']} → {verdict} ({reason})")

    except Exception as exc:
        log.exception("Scan job %s failed", job_id)
        emit(f"[ERROR] {exc}")
        
        # Check if it's an SSH/connection error
        exc_str = str(exc).lower()
        if "ssh" in exc_str or "connection" in exc_str or "socket" in exc_str or "eof" in exc_str:
            emit("[SYSTEM] SSH error detected. Pausing queue to prevent cascading failures.")
            emit("[SYSTEM] Please reconnect via the SSH panel and restart this scan manually.")
            with _lock:
                _worker_paused[client_label] = True
        
        with _lock:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = str(exc)
            JOBS[job_id]["verdict"] = "inconclusive"
            JOBS[job_id]["verdict_reason"] = f"Scan error: {exc}"
            JOBS[job_id]["completed_at"] = datetime.utcnow().isoformat()
        _app_log(f"Scan FAILED: {job['ticket_key']} — {exc}")
    finally:
        _stop_events.pop(job_id, None)


def run_triage(job_id: str, cfg: Config):
    """Fast reachability check (no PTY, no version scripts) — flags whether the
    vulnerable port still looks open before committing to a full scan. Lets a
    sweep surface likely-already-fixed tickets in seconds instead of minutes,
    without needing the post-scan PTY cooldown."""
    job = JOBS[job_id]
    client_label = job["client_label"]
    cmd = job.get("triage_command")
    if not cmd:
        with _lock:
            JOBS[job_id]["triage"] = "skipped"
            JOBS[job_id]["triage_note"] = "No triage check for this rule"
        return

    with _lock:
        JOBS[job_id]["triage"] = "running"

    is_ept = job.get("ticket_testtype", "") == "EPT"

    kali = None
    if not is_ept:
        kali = connections.get_connection(client_label)
        if not kali:
            with _lock:
                JOBS[job_id]["triage"] = "error"
                JOBS[job_id]["triage_note"] = "SSH not connected"
            return

    proto = "udp" if "-sU" in cmd else "tcp"
    try:
        if is_ept:
            import subprocess
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            out = proc.stdout
        else:
            out, _err, _code = kali.exec(cmd, timeout=20)
        if "Host seems down" in out or "0 hosts up" in out:
            result, note = "host_down", "Host unreachable — review manually"
        elif f"/{proto} open" in out:
            result, note = "open", "Port still open — likely still vulnerable"
        else:
            result, note = "closed", (
                "Port closed/filtered — likely fixed. Excluded from Scan All "
                "(most rules treat a closed port as inconclusive too); scan "
                "individually if you want a full-scan verdict on this one"
            )
        with _lock:
            JOBS[job_id]["triage"] = result
            JOBS[job_id]["triage_note"] = note
    except Exception as exc:
        with _lock:
            JOBS[job_id]["triage"] = "error"
            JOBS[job_id]["triage_note"] = str(exc)


_worker_paused: Dict[str, bool] = {}

def _scan_worker(client_label: str, scan_q: _queue.Queue, triage_q: _queue.Queue):
    """Worker thread: one job at a time per client. Always prefers the scan
    queue over the triage queue, so a manually-triggered scan only ever
    waits behind the single triage check currently in flight (if any),
    never the whole triage backlog."""
    while True:
        if _worker_paused.get(client_label):
            time.sleep(1)
            continue
            
        try:
            job_id, cfg = scan_q.get_nowait()
            kind = "scan"
        except _queue.Empty:
            try:
                job_id, cfg = triage_q.get(timeout=0.5)
                kind = "triage"
            except _queue.Empty:
                continue

        if job_id is None:  # shutdown sentinel
            break

        if kind == "triage":
            _pending_triage_ids.discard(job_id)

        did_scan = False
        try:
            if job_id in _cancelled_ids:
                _cancelled_ids.discard(job_id)
                with _lock:
                    JOBS[job_id]["status"] = "error"
                    JOBS[job_id]["error"] = "Cancelled by user"
            elif kind == "triage":
                run_triage(job_id, cfg)
            else:
                run_scan(job_id, cfg)
                did_scan = True
        except Exception:
            pass
        finally:
            (scan_q if kind == "scan" else triage_q).task_done()
        if did_scan:
            # Give the SSH server time to finish PTY session cleanup before the
            # next scan opens a new channel on the same transport. Triage uses
            # exec() (no PTY) so it doesn't need this cooldown.
            time.sleep(2)


def _ensure_worker(client_label: str):
    with _lock:
        worker = _scan_workers.get(client_label)
        if worker is None or not worker.is_alive():
            scan_q: _queue.Queue = _queue.Queue()
            triage_q: _queue.Queue = _queue.Queue()
            _scan_queues[client_label] = scan_q
            _triage_queues[client_label] = triage_q
            t = threading.Thread(target=_scan_worker, args=(client_label, scan_q, triage_q), daemon=True)
            _scan_workers[client_label] = t
            t.start()


def trigger_scan(job_id: str, cfg: Config):
    """Enqueue a scan job on the high-priority scan queue."""
    job = JOBS[job_id]
    client_label = job["client_label"]
    _ensure_worker(client_label)
    _scan_queues[client_label].put((job_id, cfg))

def _sweep_driver(client_label: str, cfg: Config, stop_event: threading.Event):
    """Driver thread for running a sweep batch serially with health checks."""
    _app_log(f"[Sweep Driver] Started for {client_label}")
    while True:
        with _lock:
            state = SWEEPS.get(client_label)
            if not state or state.status != "running" or not state.pending_job_ids:
                if state and state.status == "running":
                    state.status = "completed"
                    _app_log(f"[Sweep Driver] {client_label}: Sweep completed.")
                else:
                    _app_log(f"[Sweep Driver] {client_label}: Exiting loop (state={state.status if state else 'None'}, pending={len(state.pending_job_ids) if state else 0})")
                break
            job_id = state.pending_job_ids[0]

        # Check SSH before sending to scan queue
        _app_log(f"[Sweep Driver] {client_label}: Checking SSH for job {job_id}...")
        kali = connections.get_connection(client_label)
        if not kali:
            with _lock:
                state.status = "paused"
            _app_log(f"[Sweep Driver] {client_label}: Paused due to disconnected SSH")
            break
        try:
            _, _, code = kali.exec("echo 1", timeout=5)
            if code != 0:
                raise Exception("SSH ping failed")
            _app_log(f"[Sweep Driver] {client_label}: SSH check passed for job {job_id}")
        except Exception as e:
            with _lock:
                state.status = "paused"
            _app_log(f"[Sweep Driver] {client_label}: Paused due to SSH error ({e})")
            break
        
        # Check if sweep was stopped
        if stop_event.is_set():
            _app_log(f"[Sweep Driver] {client_label}: Stopped by user")
            break

        # Remove from pending and trigger
        with _lock:
            state.pending_job_ids.pop(0)
            
        _app_log(f"[Sweep Driver] {client_label}: Triggering scan for job {job_id}")
        # Give the job to the worker
        trigger_scan(job_id, cfg)
        
        _app_log(f"[Sweep Driver] {client_label}: Waiting for job {job_id} to finish...")
        # Wait for this job to finish before queuing the next.
        while True:
            if stop_event.is_set():
                break
            time.sleep(1)
            with _lock:
                status = JOBS.get(job_id, {}).get("status")
            if status not in ("queued", "scanning"):
                break
        _app_log(f"[Sweep Driver] {client_label}: Job {job_id} finished with status {status}")


def start_sweep(client_label: str, cfg: Config, job_ids: List[str]):
    """Start a new resilient sweep for a list of job IDs."""
    with _lock:
        if _sweep_stop_events.get(client_label):
            _sweep_stop_events[client_label].set()
        evt = threading.Event()
        _sweep_stop_events[client_label] = evt
        state = SweepState(status="running", pending_job_ids=job_ids)
        SWEEPS[client_label] = state
    threading.Thread(target=_sweep_driver, args=(client_label, cfg, evt), daemon=True).start()

def resume_sweep(client_label: str, cfg: Config):
    """Resume a paused sweep."""
    with _lock:
        state = SWEEPS.get(client_label)
        if not state or state.status != "paused":
            return False
        state.status = "running"
        if _sweep_stop_events.get(client_label):
            _sweep_stop_events[client_label].set()
        evt = threading.Event()
        _sweep_stop_events[client_label] = evt
    threading.Thread(target=_sweep_driver, args=(client_label, cfg, evt), daemon=True).start()
    return True

def pause_sweep(client_label: str):
    """Manually pause an active sweep."""
    with _lock:
        state = SWEEPS.get(client_label)
        if state and state.status == "running":
            state.status = "paused"
            _app_log(f"[Sweep] {client_label}: Sweep paused by user")



def trigger_triage(job_id: str, cfg: Config):
    """Enqueue a fast reachability check on the low-priority triage queue."""
    job = JOBS[job_id]
    client_label = job["client_label"]
    _ensure_worker(client_label)
    with _lock:
        _pending_triage_ids.add(job_id)
    _triage_queues[client_label].put((job_id, cfg))


def stop_scan(job_id: str) -> bool:
    """Signal a running scan to stop. Returns True if the event was found."""
    stop_event = _stop_events.get(job_id)
    if stop_event:
        stop_event.set()
        return True
    return False


def cancel_all_active() -> dict:
    """Stop running scans and cancel all queued jobs (worker will skip them)."""
    with _lock:
        for event in _sweep_stop_events.values():
            event.set()
        stopped_running = len(_stop_events)
        for event in _stop_events.values():
            event.set()
        cancelled_queued = 0
        for job in JOBS.values():
            if job["status"] == "queued":
                _cancelled_ids.add(job["id"])
                cancelled_queued += 1
    return {"stopped_running": stopped_running, "cancelled_queued": cancelled_queued}


def cancel_all_triage(client_label: Optional[str] = None) -> dict:
    """Cancel pending (not-yet-started) triage checks — leaves queued scans
    and the one triage check currently in flight (if any) untouched; that
    one just finishes naturally since it's a short, bounded nmap call."""
    with _lock:
        pending = [
            job_id for job_id in _pending_triage_ids
            if not client_label or JOBS.get(job_id, {}).get("client_label") == client_label
        ]
        for job_id in pending:
            _cancelled_ids.add(job_id)
            _pending_triage_ids.discard(job_id)
    return {"cancelled_triage": len(pending)}


def run_poll_cycle(cfg: Config, jira_client, session: str = "axian") -> None:
    """Fetch current Remediated tickets from Jira, queue new ones, remove stale ones."""
    global _poll_count, _poll_count_secondary
    tag = "" if session == "axian" else "[Secondary] "
    clients = cfg.clients if session == "axian" else (cfg.clients_secondary or [])
    if not clients:
        return
    _app_log(f"{tag}Polling Jira for remediated tickets…")
    for client in clients:
        try:
            tickets = jira_client.get_remediated_tickets(client.label)
            current_keys = {t["key"] for t in tickets}

            new_count = 0
            for ticket in tickets:
                key = ticket["key"]
                with _lock:
                    if key in SEEN_KEYS:
                        continue
                    SEEN_KEYS.add(key)
                testtype = (ticket.get("testtype") or "").upper()
                summary = ticket.get("summary") or ""
                rule_obj = match_rule(summary)
                
                # If we have a scan rule, it's auto-scan. Otherwise, it's manual.
                is_manual = rule_obj is None
                job_id = _queue_ticket(ticket, client.label, manual=is_manual, session=session)
                new_count += 1
                rule = JOBS[job_id].get("rule_name")
                if is_manual:
                    _app_log(
                        f"{tag}Queued (manual): {key} ({client.label}) | "
                        f"TestType: {testtype or 'unknown'}"
                    )
                else:
                    _app_log(
                        f"{tag}Queued: {key} ({client.label}) | "
                        f"IP: {JOBS[job_id].get('ip')} | Rule: {rule or 'none'}"
                    )

            total = len(tickets)
            if new_count:
                _app_log(f"{tag}[{client.label}] {new_count} new ticket(s) queued ({total} remediated total)")
            else:
                _app_log(f"{tag}[{client.label}] {total} remediated ticket(s) found — 0 new")

            with _lock:
                for job_id, job in list(JOBS.items()):
                    if (job["client_label"] == client.label
                            and job.get("session", "axian") == session
                            and job.get("source", "poll") == "poll"
                            and job["ticket_key"] not in current_keys
                            and job["status"] != "scanning"):
                        del JOBS[job_id]
                        SEEN_KEYS.discard(job["ticket_key"])
                        _app_log(f"{tag}Cleared: {job['ticket_key']} — no longer Remediated in Jira")

        except Exception as exc:
            _app_log(f"[ERROR] {tag}Poll failed for {client.label}: {exc}")

    _reconcile_manual_jobs(tag)

    if session == "axian":
        _poll_count += 1
    else:
        _poll_count_secondary += 1


def poll_jira(cfg: Config):
    """Background thread: run a poll cycle every poll_interval seconds.
    Exits when _poll_stop is set, so a runtime config reload can retire this
    thread and start a fresh one against the new config."""
    jira_client = JiraClient(cfg.jira)
    _app_log("Jira poller started — polling every %ds" % cfg.jira.poll_interval)
    while not _poll_stop.is_set():
        _wake_poll.clear()
        run_poll_cycle(cfg, jira_client, session="axian")
        _wake_poll.wait(timeout=cfg.jira.poll_interval)
    _app_log("Jira poller stopped")


def poll_jira_secondary(cfg: Config):
    """Background thread for the Non-Axian (Jira Server/DC) session."""
    from .jira_client_v2 import JiraClientV2
    jira_client = JiraClientV2(cfg.jira_secondary)
    _app_log(f"Secondary Jira poller started — polling every {cfg.jira_secondary.poll_interval}s")
    while not _poll_stop_secondary.is_set():
        _wake_poll_secondary.clear()
        run_poll_cycle(cfg, jira_client, session="non_axian")
        _wake_poll_secondary.wait(timeout=cfg.jira_secondary.poll_interval)
    _app_log("Secondary Jira poller stopped")
