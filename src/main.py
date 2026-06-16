import asyncio
import calendar
import json
import logging
import os
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import load_config
from .jira_client import JiraClient
from . import scanner, connections

LOG_DIR = "data/logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(
            os.path.join(LOG_DIR, "nemesis.log"),
            maxBytes=5_000_000,
            backupCount=5,
        ),
    ],
)
log = logging.getLogger(__name__)

CONFIG_PATH = "config/config.yaml"
SETUP_NEEDED = not os.path.exists(CONFIG_PATH)

if not SETUP_NEEDED:
    cfg = load_config(CONFIG_PATH)
    jira = JiraClient(cfg.jira)
else:
    cfg = None
    jira = None
    log.warning("No %s found — serving first-run Settings page until setup completes.", CONFIG_PATH)

app = FastAPI(title="Nemesis")
app.mount("/static", StaticFiles(directory="frontend"), name="static")

from . import setup as setup_mod
app.include_router(setup_mod.router)

from . import settings_api
app.include_router(settings_api.router)

from . import shell_ws
app.include_router(shell_ws.router)

from . import tunnel_api
app.include_router(tunnel_api.router)

_poller_thread: Optional[threading.Thread] = None
_reload_lock = threading.Lock()


def _start_poller_thread():
    global _poller_thread
    # Seed all clients as disconnected
    for c in cfg.clients:
        connections._status[c.label] = "disconnected"
    t = threading.Thread(target=scanner.poll_jira, args=(cfg,), daemon=True)
    t.start()
    _poller_thread = t


@app.on_event("startup")
def _start_poller():
    if SETUP_NEEDED:
        return
    _start_poller_thread()
    scanner._app_log("Retest Tool API ready")


def reload_runtime_config():
    """Re-read config.yaml and swap in a fresh Jira client + poller thread,
    so a Settings save takes effect immediately without restarting the app."""
    global cfg, jira
    with _reload_lock:
        scanner._poll_stop.set()
        scanner._wake_poll.set()  # wake the old thread so it notices the stop right away
        if _poller_thread is not None:
            _poller_thread.join(timeout=10)

        cfg = load_config(CONFIG_PATH)
        jira = JiraClient(cfg.jira)

        scanner._poll_stop.clear()
        _start_poller_thread()
        scanner._app_log("Configuration reloaded — Jira client and poller restarted with new settings")


# ── Static / UI ────────────────────────────────────────────────────────────

_NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"}

@app.get("/")
def index():
    if SETUP_NEEDED:
        return FileResponse("frontend/setup.html", headers=_NO_CACHE)
    return FileResponse("frontend/index.html", headers=_NO_CACHE)

@app.get("/static/app.js")
def serve_app_js():
    return FileResponse("frontend/app.js", headers=_NO_CACHE)

@app.get("/static/style.css")
def serve_style_css():
    return FileResponse("frontend/style.css", headers=_NO_CACHE)


# ── Config ─────────────────────────────────────────────────────────────────

@app.get("/api/config")
def get_config():
    return {"retest_status": cfg.jira.retest_status}


# ── Clients ────────────────────────────────────────────────────────────────

@app.get("/api/clients")
def list_clients():
    return [{"label": c.label, "name": c.name} for c in cfg.clients]


# ── Jobs ───────────────────────────────────────────────────────────────────

# Fields needed to render the job list/cards. Excludes heavy per-job data
# (output_lines, ticket_description, nmap_command, ticket_cves) which only
# matter for the single selected job's detail view — fetched separately via
# GET /api/jobs/{job_id}. At sweep scale (1000+ jobs) sending the full dict
# for every job on every 5s poll was a multi-MB payload that froze the UI.
_SLIM_JOB_FIELDS = [
    "id", "ticket_key", "ticket_summary", "ticket_status", "ticket_cvss",
    "ticket_severity", "ticket_technology", "client_label", "ip", "port",
    "rule_name", "scan_tool", "status", "verdict", "verdict_reason",
    "created_at", "completed_at", "jira_updated", "source",
    "triage", "triage_note",
]


@app.get("/api/jobs")
def list_jobs():
    with scanner._lock:
        return [
            {k: job.get(k) for k in _SLIM_JOB_FIELDS}
            for job in scanner.JOBS.values()
        ]


# ── Static job sub-routes MUST be registered before /{job_id} ─────────────
# FastAPI matches routes in registration order; without this, "transition-preview"
# would be captured by the /{job_id} parameter route and return 404.

@app.get("/api/jobs/transition-preview")
def transition_preview():
    to_fixed, to_not_fixed = _bulk_transition_candidates()
    def _slim(job):
        return {
            "job_id":         job["id"],
            "ticket_key":     job["ticket_key"],
            "ticket_summary": job["ticket_summary"],
            "ticket_status":  job.get("ticket_status", ""),
            "client_label":   job["client_label"],
        }
    return {
        "to_fixed":     [_slim(j) for j in to_fixed],
        "to_not_fixed": [_slim(j) for j in to_not_fixed],
    }


@app.post("/api/jobs/stop-all")
def stop_all_jobs():
    result = scanner.cancel_all_active()
    return {"ok": True, **result}


@app.post("/api/jobs/stop-triage")
def stop_triage_jobs(client_label: Optional[str] = None):
    result = scanner.cancel_all_triage(client_label)
    return {"ok": True, **result}


def _triage_fixed_candidates(client_label: Optional[str] = None) -> List[dict]:
    """Queued jobs flagged 'likely fixed' by triage (port closed) — no full
    scan run on these. Used for the fast triage→transition shortcut."""
    return [
        job for job in scanner.JOBS.values()
        if job["status"] == "queued"
        and job.get("triage") == "closed"
        and (not client_label or job["client_label"] == client_label)
    ]


@app.get("/api/jobs/triage-transition-preview")
def triage_transition_preview(client_label: Optional[str] = None):
    candidates = _triage_fixed_candidates(client_label)
    return {
        "to_fixed": [
            {
                "job_id": j["id"],
                "ticket_key": j["ticket_key"],
                "ticket_summary": j["ticket_summary"],
                "client_label": j["client_label"],
            }
            for j in candidates
        ]
    }


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = scanner.JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@app.post("/api/jobs/{job_id}/scan")
def start_scan(job_id: str):
    job = scanner.JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != "queued":
        raise HTTPException(400, f"Cannot scan — job status is '{job['status']}'")
    scanner.trigger_scan(job_id, cfg)
    return {"ok": True, "job_id": job_id}


@app.post("/api/jobs/{job_id}/triage")
def start_triage(job_id: str):
    job = scanner.JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != "queued":
        raise HTTPException(400, f"Cannot triage — job status is '{job['status']}'")
    scanner.trigger_triage(job_id, cfg)
    return {"ok": True, "job_id": job_id}


@app.delete("/api/jobs/{job_id}")
def remove_job(job_id: str):
    """Remove a job from the queue and allow its ticket to be re-queued on next poll."""
    job = scanner.JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    with scanner._lock:
        del scanner.JOBS[job_id]
        scanner.SEEN_KEYS.discard(job["ticket_key"])
    scanner._app_log(f"Removed: {job['ticket_key']} removed from queue")
    return {"ok": True}


@app.post("/api/jobs/{job_id}/stop")
def stop_scan_job(job_id: str):
    """Signal a running scan to stop."""
    job = scanner.JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != "scanning":
        raise HTTPException(400, f"Job is not scanning (status: {job['status']})")
    scanner.stop_scan(job_id)
    return {"ok": True}


@app.post("/api/jobs/{job_id}/reset")
def reset_job(job_id: str):
    """Reset a completed/error job back to queued so it can be re-scanned."""
    job = scanner.JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    with scanner._lock:
        job["status"] = "queued"
        job["verdict"] = None
        job["verdict_reason"] = None
        job["output_lines"] = []
        job["error"] = None
        job["completed_at"] = None
        job["jira_updated"] = False
        job["triage"] = None
        job["triage_note"] = None
    return {"ok": True}


# ── Live scan output stream (SSE) ──────────────────────────────────────────

@app.get("/api/jobs/{job_id}/stream")
async def stream_output(job_id: str):
    async def generate():
        last = 0
        while True:
            job = scanner.JOBS.get(job_id)
            if not job:
                yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
                break

            lines = job.get("output_lines", [])
            if len(lines) > last:
                for line in lines[last:]:
                    yield f"data: {json.dumps({'line': line})}\n\n"
                last = len(lines)

            if job["status"] in ("completed", "error"):
                yield f"data: {json.dumps({'done': True, 'verdict': job.get('verdict'), 'reason': job.get('verdict_reason')})}\n\n"
                break

            await asyncio.sleep(0.3)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── Manual ticket add ──────────────────────────────────────────────────────

class AddTicketsRequest(BaseModel):
    keys: List[str]
    client_label: str


@app.post("/api/tickets/add")
def add_tickets(req: AddTicketsRequest):
    """Fetch one or more tickets from Jira by key and queue them for scanning,
    regardless of their current Jira status."""
    if not any(c.label == req.client_label for c in cfg.clients):
        raise HTTPException(400, f"Unknown client label: {req.client_label}")

    results = []
    for raw in req.keys:
        key = raw.strip().upper()
        if not key:
            continue
        if key in scanner.SEEN_KEYS:
            existing = next(
                (j for j in scanner.JOBS.values() if j["ticket_key"] == key), None
            )
            results.append({
                "key": key, "status": "already_queued",
                "summary": existing["ticket_summary"] if existing else "",
            })
            continue
        try:
            ticket = jira.get_ticket(key)
            scanner.SEEN_KEYS.add(key)
            job_id = scanner._queue_ticket(ticket, req.client_label, source="manual")
            rule = scanner.JOBS[job_id].get("rule_name")
            scanner._app_log(
                f"Manual add: {key} ({req.client_label}) | "
                f"IP: {scanner.JOBS[job_id].get('ip')} | Rule: {rule or 'none'}"
            )
            results.append({
                "key": key, "status": "queued", "job_id": job_id,
                "summary": ticket["summary"], "rule": rule,
            })
        except Exception as exc:
            log.warning("Manual add failed for %s: %s", key, exc)
            results.append({"key": key, "status": "error", "error": str(exc)})

    return {"results": results}


# ── Jira transitions ───────────────────────────────────────────────────────

class TransitionRequest(BaseModel):
    job_id: str
    to_status: str          # "Fixed" or "Not Fixed"
    comment: Optional[str] = None


class SweepRunRequest(BaseModel):
    filter_rules: Optional[List[str]] = None  # None = queue all matching rules


@app.post("/api/transition")
def transition_ticket(req: TransitionRequest):
    job = scanner.JOBS.get(req.job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    ticket_key = job["ticket_key"]
    try:
        if req.comment:
            jira.add_comment(ticket_key, req.comment)
        jira.transition(ticket_key, req.to_status)
        # Remove job immediately — don't wait for poll to clean it up.
        # Jira's search index lags after a transition, so the poll would
        # still see the ticket as Remediated and leave it in the queue.
        with scanner._lock:
            scanner.JOBS.pop(req.job_id, None)
            scanner.SEEN_KEYS.discard(ticket_key)
        scanner._app_log(f"Jira updated: {ticket_key} → {req.to_status} (removed from queue)")
        return {"ok": True, "ticket": ticket_key, "status": req.to_status}
    except Exception as exc:
        raise HTTPException(500, str(exc))



# ── Bulk transition ────────────────────────────────────────────────────────

def _bulk_transition_candidates():
    """
    Return (to_fixed, to_not_fixed) job lists based on verdict + ticket status.

    Rules:
      verdict=fixed     → always transition to Fixed
      verdict=not_fixed + ticket was Remediated → transition to Not Fixed
      verdict=not_fixed + ticket was Open       → skip (already correct state)
      verdict=inconclusive / error              → skip
    """
    retest = cfg.jira.retest_status
    to_fixed, to_not_fixed = [], []
    for job in scanner.JOBS.values():
        if job["status"] != "completed" or job.get("jira_updated"):
            continue
        verdict = job.get("verdict")
        ticket_status = job.get("ticket_status", "")
        if verdict == "fixed":
            to_fixed.append(job)
        elif verdict == "not_fixed" and ticket_status == retest:
            to_not_fixed.append(job)
    return to_fixed, to_not_fixed


class TriageTransitionRequest(BaseModel):
    client_label: Optional[str] = None
    comment: Optional[str] = None


@app.post("/api/jobs/triage-transition-bulk")
def triage_transition_bulk(req: TriageTransitionRequest):
    """Bulk-transition triage-flagged 'likely fixed' tickets straight to Fixed.
    No full scan is run — the human reviews the ticket list in the confirm
    modal before this is called, which is the required confirmation step."""
    candidates = _triage_fixed_candidates(req.client_label)
    succeeded, failed = [], []

    def _do(job):
        key = job["ticket_key"]
        try:
            if req.comment:
                jira.add_comment(key, req.comment)
            jira.transition(key, "Fixed")
            with scanner._lock:
                scanner.JOBS.pop(job["id"], None)
                scanner.SEEN_KEYS.discard(key)
            scanner._app_log(f"Triage bulk transition: {key} → Fixed (port closed)")
            succeeded.append({"ticket_key": key})
        except Exception as exc:
            err = str(exc)
            scanner._app_log(f"[ERROR] Triage transition failed: {key} → Fixed: {err}")
            failed.append({"ticket_key": key, "error": err})

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_do, j) for j in candidates]
        for f in as_completed(futures):
            f.result()

    scanner._app_log(
        f"Triage bulk transition complete: {len(succeeded)} succeeded, {len(failed)} failed"
    )
    return {"ok": True, "succeeded": succeeded, "failed": failed}


@app.post("/api/jobs/transition-bulk")
def transition_bulk():
    to_fixed, to_not_fixed = _bulk_transition_candidates()
    succeeded, failed = [], []

    def _do(job, target_status):
        key = job["ticket_key"]
        try:
            jira.transition(key, target_status)
            with scanner._lock:
                scanner.JOBS[job["id"]]["jira_updated"] = True
            scanner._app_log(f"Bulk transition: {key} → {target_status}")
            succeeded.append({"ticket_key": key, "to_status": target_status})
        except Exception as exc:
            err = str(exc)
            scanner._app_log(f"[ERROR] Transition failed: {key} → {target_status}: {err}")
            failed.append({"ticket_key": key, "to_status": target_status, "error": err})

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = (
            [pool.submit(_do, j, "Fixed")     for j in to_fixed] +
            [pool.submit(_do, j, "Not Fixed") for j in to_not_fixed]
        )
        for f in as_completed(futures):
            f.result()  # propagate any unexpected exception to logs

    scanner._app_log(
        f"Bulk transition complete: {len(succeeded)} succeeded, {len(failed)} failed"
    )
    return {"ok": True, "succeeded": succeeded, "failed": failed}


# ── Monthly Report ─────────────────────────────────────────────────────────

_report_cache: dict = {}   # (client, month) → result; past months never change


def _to_report_item(issue: dict) -> dict:
    return {
        "key": issue["key"],
        "vuln_name": issue.get("summary", ""),
        "ip": (issue.get("ips") or [""])[0],
        "rating": issue.get("rating") or "",
    }


@app.get("/api/report")
def generate_report(client: str, month: str):
    """
    Run 13 JQL count queries for a completed month and return the report data.
    month format: YYYY-MM  (must be a past month — data not available mid-month)
    """
    try:
        year, mon = map(int, month.split("-"))
        if not (1 <= mon <= 12):
            raise ValueError()
    except (ValueError, AttributeError):
        raise HTTPException(400, "month must be YYYY-MM (e.g. 2026-05)")

    today = date.today()
    if (year, mon) >= (today.year, today.month):
        raise HTTPException(400, "Report data is only available after the month has ended")

    cache_key = (client, month)
    if cache_key in _report_cache:
        return _report_cache[cache_key]

    last_day = calendar.monthrange(year, mon)[1]
    start = f"{year}/{mon:02d}/01 00:00"
    end   = f"{year}/{mon:02d}/{last_day} 23:59"

    base = f'project = {cfg.jira.project} AND labels = "{client}"'
    rf   = '"vulnerability_Rating[Short text]"'
    nr   = f'AND created >= "{start}" AND created <= "{end}"'
    or_  = f'AND created <= "{end}" AND status NOT IN (Fixed, "Risk Accepted")'

    # All 13 queries keyed by name
    queries = {
        "new_total":          nr,
        "new_critical":       f'{nr} AND {rf} ~ critical',
        "new_high":           f'{nr} AND {rf} ~ high',
        "new_medium":         f'{nr} AND {rf} ~ medium',
        "new_low":            f'{nr} AND {rf} ~ low',
        "fixed_this_month":   f'AND resolutiondate >= "{start}" AND resolutiondate <= "{end}" AND status = Fixed',
        "open_total":         or_,
        "open_critical":      f'{or_} AND {rf} ~ critical',
        "open_high":          f'{or_} AND {rf} ~ high',
        "open_medium":        f'{or_} AND {rf} ~ medium',
        "open_low":           f'{or_} AND {rf} ~ low',
        "risk_accepted":      f'AND created <= "{end}" AND status = "Risk Accepted"',
        "total_fixed":        f'AND created <= "{end}" AND status = Fixed',
    }

    results: dict = {}

    def run_query(key: str, extra: str) -> tuple:
        try:
            return key, jira.count_jql(f"{base} {extra}")
        except Exception as exc:
            log.warning("Report query failed [%s]: %s", key, exc)
            return key, -1

    with ThreadPoolExecutor(max_workers=13) as pool:
        futures = {pool.submit(run_query, k, v): k for k, v in queries.items()}
        for fut in as_completed(futures):
            k, v = fut.result()
            results[k] = v

    # New discovered vulnerabilities: full list of tickets created this month.
    # If none were created, fall back to a random sample of currently-open
    # tickets — 2 per severity tier (critical/high/medium/low), cascading any
    # shortfall in a tier down to the next one so the sample still totals 8
    # whenever enough open tickets exist anywhere in the backlog.
    new_vulnerabilities = {"is_sample": False, "items": []}
    try:
        if results["new_total"] > 0:
            issues = jira.search_jql(f"{base} {nr}")
            new_vulnerabilities["items"] = [_to_report_item(i) for i in issues]
        else:
            sample: list = []
            carry = 0
            for tier in ("critical", "high", "medium", "low"):
                needed = 2 + carry
                pool = jira.search_jql(f'{base} {or_} AND {rf} ~ {tier}')
                random.shuffle(pool)
                taken = pool[:needed]
                sample.extend(taken)
                carry = needed - len(taken)
            new_vulnerabilities["is_sample"] = True
            new_vulnerabilities["items"] = [_to_report_item(i) for i in sample]
    except Exception as exc:
        log.warning("New vulnerabilities query failed: %s", exc)
        new_vulnerabilities["error"] = str(exc)

    report = {
        "client": client,
        "month":  month,
        "period": {"start": start, "end": end, "last_day": last_day},
        "new_vulnerabilities": new_vulnerabilities,
        "new_tickets": {
            "total":    results["new_total"],
            "critical": results["new_critical"],
            "high":     results["new_high"],
            "medium":   results["new_medium"],
            "low":      results["new_low"],
        },
        "fixed_this_month": results["fixed_this_month"],
        "open_tickets": {
            "total":         results["open_total"],
            "critical":      results["open_critical"],
            "high":          results["open_high"],
            "medium":        results["open_medium"],
            "low":           results["open_low"],
            "risk_accepted": results["risk_accepted"],
        },
        "total_fixed_to_date": results["total_fixed"],
    }
    _report_cache[cache_key] = report
    return report


# ── SSH connection pool ────────────────────────────────────────────────────

@app.get("/api/ssh/status")
def ssh_status():
    return connections.get_status()


@app.post("/api/ssh/{label}/connect")
def ssh_connect(label: str):
    def _do():
        try:
            connections.connect(cfg, label)
            scanner._app_log(f"[SSH] Connected to {label}")
        except Exception as exc:
            scanner._app_log(f"[SSH] Connection to {label} failed: {exc}")
    threading.Thread(target=_do, daemon=True).start()
    return {"ok": True, "status": "connecting"}


@app.post("/api/ssh/{label}/disconnect")
def ssh_disconnect(label: str):
    connections.disconnect(label)
    scanner._app_log(f"[SSH] Disconnected from {label}")
    return {"ok": True}


# ── Sweep ──────────────────────────────────────────────────────────────────

@app.get("/api/sweep/{label}/preview")
def sweep_preview(label: str):
    if not any(c.label == label for c in cfg.clients):
        raise HTTPException(400, f"Unknown client: {label}")
    from .vuln_rules import match_rule
    tickets = jira.get_sweep_tickets(label, max_results=100)
    by_rule: Dict[str, List[dict]] = {}
    skipped_no_rule = 0
    skipped_queued = 0
    for t in tickets:
        if t["key"] in scanner.SEEN_KEYS:
            skipped_queued += 1
        else:
            rule = match_rule(t["summary"])
            if not rule:
                skipped_no_rule += 1
            else:
                by_rule.setdefault(rule.name, []).append({
                    "key": t["key"],
                    "summary": t["summary"],
                    "ip": t["ips"][0] if t.get("ips") else None,
                })
    to_queue = sum(len(v) for v in by_rule.values())
    is_partial = len(tickets) >= 100
    return {
        "total": len(tickets),
        "to_queue": to_queue,
        "skipped_no_rule": skipped_no_rule,
        "skipped_queued": skipped_queued,
        "by_rule": by_rule,
        "is_partial": is_partial,
        "sample_size": len(tickets),
    }


@app.post("/api/sweep/{label}/run")
def sweep_run(label: str, body: Optional[SweepRunRequest] = None):
    if not any(c.label == label for c in cfg.clients):
        raise HTTPException(400, f"Unknown client: {label}")
    from .vuln_rules import match_rule
    filter_set = set(body.filter_rules) if (body and body.filter_rules) else None

    def _do():
        scanner._app_log(f"[Sweep] {label}: fetching all open tickets…")
        try:
            tickets = jira.get_sweep_tickets(label)
        except Exception as exc:
            scanner._app_log(f"[Sweep] {label}: fetch failed — {exc}")
            return
        queued = 0
        for ticket in tickets:
            key = ticket["key"]
            rule = match_rule(ticket["summary"])
            if key in scanner.SEEN_KEYS or not rule:
                continue
            if filter_set and rule.name not in filter_set:
                continue
            scanner.SEEN_KEYS.add(key)
            job_id = scanner._queue_ticket(ticket, label, source="sweep")
            scanner._app_log(
                f"Sweep: {key} ({label}) | "
                f"IP: {scanner.JOBS[job_id].get('ip')} | Rule: {rule.name}"
            )
            queued += 1
        scanner._app_log(f"[Sweep] {label}: done — {queued} ticket(s) queued")

    threading.Thread(target=_do, daemon=True).start()
    return {"ok": True}


@app.delete("/api/sweep/jobs")
def clear_sweep_jobs():
    """Remove all non-scanning sweep jobs and allow them to be re-swept."""
    with scanner._lock:
        to_remove = [
            jid for jid, j in scanner.JOBS.items()
            if j.get("source") == "sweep" and j["status"] != "scanning"
        ]
        removed = 0
        for jid in to_remove:
            scanner.SEEN_KEYS.discard(scanner.JOBS[jid]["ticket_key"])
            del scanner.JOBS[jid]
            removed += 1
    scanner._app_log(f"Cleared {removed} sweep job(s) from queue")
    return {"ok": True, "removed": removed}


# ── Assets ─────────────────────────────────────────────────────────────────

class AssetListRequest(BaseModel):
    entries: List[str]


@app.get("/api/assets/{label}")
def get_assets(label: str):
    if not any(c.label == label for c in cfg.clients):
        raise HTTPException(400, f"Unknown client: {label}")
    from . import assets as assets_mod
    return assets_mod.load_asset_list(label)


@app.post("/api/assets/{label}")
def save_assets(label: str, req: AssetListRequest):
    if not any(c.label == label for c in cfg.clients):
        raise HTTPException(400, f"Unknown client: {label}")
    from . import assets as assets_mod
    count = assets_mod.save_asset_list(label, req.entries)
    scanner._app_log(f"[Assets] {label}: saved {count} IP/subnet entries")
    return {"ok": True, "saved": count}


# ── Nessus ─────────────────────────────────────────────────────────────────

class NessusPullRequest(BaseModel):
    scan_ids: List[int]


@app.get("/api/nessus/{label}/folders")
def nessus_folders(label: str):
    client_cfg = next((c for c in cfg.clients if c.label == label), None)
    if not client_cfg:
        raise HTTPException(400, f"Unknown client: {label}")
    if not getattr(client_cfg, "nessus_access_key", None):
        raise HTTPException(400, f"Nessus API keys not configured for {label}")
    conn = connections.get_connection(label)
    if not conn:
        raise HTTPException(400, f"SSH not connected for '{label}' — connect in the SSH panel first")
    from . import nessus_client as nc
    try:
        folders = nc.get_folders(conn, client_cfg.nessus_access_key, client_cfg.nessus_secret_key)
        return {"folders": folders}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/api/nessus/{label}/scans")
def nessus_scans(label: str, folder_id: Optional[int] = None):
    client_cfg = next((c for c in cfg.clients if c.label == label), None)
    if not client_cfg:
        raise HTTPException(400, f"Unknown client: {label}")
    if not getattr(client_cfg, "nessus_access_key", None):
        raise HTTPException(400, f"Nessus API keys not configured for {label}")
    conn = connections.get_connection(label)
    if not conn:
        raise HTTPException(400, f"SSH not connected for '{label}' — connect in the SSH panel first")
    from . import nessus_client as nc
    try:
        scans = nc.get_scans(conn, client_cfg.nessus_access_key, client_cfg.nessus_secret_key, folder_id)
        return {"scans": scans}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/api/nessus/{label}/pull")
def nessus_pull(label: str, req: NessusPullRequest):
    """Pull hosts from selected Nessus scans and cross-reference against saved asset list."""
    client_cfg = next((c for c in cfg.clients if c.label == label), None)
    if not client_cfg:
        raise HTTPException(400, f"Unknown client: {label}")
    if not getattr(client_cfg, "nessus_access_key", None):
        raise HTTPException(400, f"Nessus API keys not configured for {label}")
    conn = connections.get_connection(label)
    if not conn:
        raise HTTPException(400, f"SSH not connected for '{label}' — connect in the SSH panel first")
    from . import nessus_client as nc, assets as assets_mod

    all_hosts: list = []
    errors: list = []

    # Sequential fetch: large Nessus scan responses (1 MB+) can cause one channel
    # to flood the SSH transport, corrupting a parallel channel's data stream.
    # Sequential is slower but eliminates that interference entirely.
    for scan_id in req.scan_ids:
        try:
            hosts = nc.get_scan_hosts(
                conn, client_cfg.nessus_access_key, client_cfg.nessus_secret_key, scan_id
            )
            all_hosts.extend(hosts)
        except Exception as exc:
            errors.append(f"Scan {scan_id}: {exc}")

    asset_data = assets_mod.load_asset_list(label)
    result = assets_mod.cross_reference(asset_data["entries"], all_hosts)
    result["total_hosts_pulled"] = len(all_hosts)
    result["errors"] = errors

    scanner._app_log(
        f"[Assets] {label}: {len(all_hosts)} hosts from {len(req.scan_ids)} scan(s) — "
        f"in-scope: {result['counts']['in_scope_scanned']}, "
        f"missed: {result['counts']['in_scope_missed']}, "
        f"OOS: {result['counts']['out_of_scope']}"
    )
    return result


# ── Force poll ─────────────────────────────────────────────────────────────

@app.post("/api/poll")
def force_poll():
    # Wake the background thread immediately and return — never blocks.
    # Returns the current poll count so the frontend knows when the next
    # cycle completes.
    count_before = scanner._poll_count
    scanner._wake_poll.set()
    return {"ok": True, "count": count_before}


@app.get("/api/poll/status")
def poll_status():
    return {"count": scanner._poll_count}


# ── Debug snapshot ────────────────────────────────────────────────────────

@app.get("/api/debug/state")
def debug_state():
    """Dump current in-memory state for debugging."""
    with scanner._lock:
        jobs_summary = [
            {
                "id": j["id"],
                "key": j["ticket_key"],
                "client": j["client_label"],
                "status": j["status"],
                "source": j.get("source", "poll"),
                "jira_updated": j.get("jira_updated", False),
                "verdict": j.get("verdict"),
            }
            for j in scanner.JOBS.values()
        ]
        seen = list(scanner.SEEN_KEYS)
    return {
        "poll_count": scanner._poll_count,
        "jobs_total": len(jobs_summary),
        "seen_keys_total": len(seen),
        "jobs": jobs_summary,
        "seen_keys": seen,
        "last_logs": scanner.APP_LOGS[-20:],
    }


# ── System logs ────────────────────────────────────────────────────────────

@app.get("/api/logs")
def get_logs():
    with scanner._lock:
        return scanner.APP_LOGS[-200:]
