"""Jira Server / Data Centre client using PAT (Bearer token) auth and REST API v2.

Used for the "Non-Axian" session (e.g. tickets.munit.ai).  The public interface
mirrors JiraClient so the rest of the app can use either interchangeably.
"""
import logging
import re
from typing import Any, Dict, List, Optional

import requests

from .config import JiraSecondaryConfig
from .jira_client import _extract_tester

log = logging.getLogger(__name__)

_IP_RE  = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_PORT_RE = re.compile(r'^\d{2,5}$')
_CVE_RE  = re.compile(r'^CVE-\d{4}-\d+$', re.I)


class JiraClientV2:
    """Jira Server v2 REST API client with Bearer token auth.

    Each Non-Axian client's label IS its Jira project key, so JQL uses
    ``project = {label}`` instead of ``labels = "{label}"``.
    """

    # Test-types that support automated scanning.  Same set as JiraClient.
    SCANNABLE_TYPES = {"SCN", "IPT"}

    # Fast-track chains — ONLY intermediate steps to escape the current status.
    # The target ("Remediated" for phase 1, or "Fixed"/"Not Fixed" for phase 2)
    # is appended by fast_track() via  full_chain = chain + [target].
    FAST_TRACK_CHAINS: Dict[str, List[str]] = {
        "reported":    ["In Progress"],          # → Remediated (phase 1 target)
        "in progress": [],                       # → Remediated directly
        "not fixed":   ["Refix", "Fix Issue"],   # Refix unlocks; Fix Issue reaches Remediated
        "remediated":  [],                       # → Fixed / Not Fixed directly (phase 2)
    }

    _TRANSITION_ALIASES = {
        "fixed":      {"fixed", "fix issue", "fix", "mark fixed", "mark as fixed",
                       "resolve", "resolved", "done", "close", "closed"},
        "not fixed":  {"not fixed", "not fix", "not fix issue", "mark as not fixed",
                       "won't fix", "wontfix", "reopen", "reopened", "reject"},
        "in progress":{"in progress", "start progress", "start", "start work",
                       "begin", "begin work", "take", "assign", "wip"},
        "remediated": {"remediated", "mark remediated", "mark as remediated",
                       "client remediated", "remediate", "ready for retest"},
    }

    def __init__(self, cfg: JiraSecondaryConfig):
        self.cfg = cfg
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {cfg.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self._fields: Dict[str, str] = {}
        self._fetch_fields = "*all"
        self._load_fields()

    # ── Field discovery ────────────────────────────────────────────────────

    def _load_fields(self):
        try:
            resp = self._session.get(f"{self.cfg.url}/rest/api/2/field", timeout=15)
            resp.raise_for_status()
            for f in resp.json():
                self._fields[f["name"].lower()] = f["id"]
            log.info("Secondary Jira: loaded %d fields", len(self._fields))
            self._fetch_fields = self._build_fetch_fields()
        except Exception as e:
            log.warning("Secondary Jira: could not load field map: %s", e)

    def _build_fetch_fields(self) -> str:
        standard = ["summary", "status", "priority", "assignee", "reporter",
                    "updated", "labels", "description"]
        custom_names = ["cvss", "severity", "technology", "vulnerability_rating",
                        "testtype[short text]", "testtype", "tester",
                        "otherinformation[paragraph]", "otherinformation",
                        "other information"]
        custom_ids = [self._fid(n) for n in custom_names if self._fid(n)]
        return ",".join(standard + custom_ids)

    def _fid(self, name: str) -> Optional[str]:
        return self._fields.get(name.lower())

    @property
    def severity_jql_field(self) -> str:
        """JQL field reference for severity filtering on this Jira instance.

        Tries (in order):
          1. "vulnerability_rating" custom field  → cf[id]
          2. "severity" custom/standard field     → cf[id]
          3. falls back to standard "priority"
        """
        for candidate in ("vulnerability_rating", "vulnerability_Rating[Short text]",
                          "severity"):
            fid = self._fid(candidate)
            if fid:
                # Extract numeric id from e.g. "customfield_10024" → cf[10024]
                if fid.startswith("customfield_"):
                    return f'cf[{fid.split("_", 1)[1]}]'
                return f'"{fid}"'
        return "priority"

    # ── JQL builders ──────────────────────────────────────────────────────

    def _jql(self, client_label: str) -> str:
        return (
            f'project = {client_label} '
            f'AND status = "{self.cfg.retest_status}" '
            f'ORDER BY updated DESC'
        )

    def _sweep_jql(self, client_label: str) -> str:
        return (
            f'project = {client_label} '
            f'AND status NOT IN (Fixed, "Risk Accepted", "{self.cfg.retest_status}") '
            f'ORDER BY updated DESC'
        )

    # ── Search (v2 uses startAt pagination, not cursor) ───────────────────

    def _search_jql(self, jql: str, max_results: Optional[int] = None) -> List[Dict]:
        url = f"{self.cfg.url}/rest/api/2/search"
        log.info("Secondary JQL → %s", jql)
        fields = self._fetch_fields
        all_issues: List[Dict] = []
        start_at = 0
        while True:
            resp = self._session.get(url, params={
                "jql": jql, "maxResults": 100, "startAt": start_at, "fields": fields,
            }, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("issues", [])
            all_issues.extend(batch)
            if max_results and len(all_issues) >= max_results:
                return all_issues[:max_results]
            total = data.get("total", 0)
            start_at += len(batch)
            if not batch or start_at >= total:
                break
        return all_issues

    def search_jql(self, jql: str, max_results: Optional[int] = None) -> List[Dict[str, Any]]:
        issues = self._search_jql(jql, max_results=max_results)
        return [self._serialize(i) for i in issues]

    _v2_search_gone: bool = False

    def count_jql(self, jql: str) -> int:
        if not self._v2_search_gone:
            try:
                resp = self._session.get(
                    f"{self.cfg.url}/rest/api/2/search",
                    params={"jql": jql, "maxResults": 0, "fields": ""},
                    timeout=30,
                )
                if resp.status_code == 410:
                    self.__class__._v2_search_gone = True
                else:
                    resp.raise_for_status()
                    return resp.json().get("total", 0)
            except Exception:
                self.__class__._v2_search_gone = True

        # v3 fallback — also returns 'total' on first page
        resp = self._session.get(
            f"{self.cfg.url}/rest/api/3/search/jql",
            params={"jql": jql, "maxResults": 1, "fields": "id"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("total", 0)

    # ── Public ticket methods ─────────────────────────────────────────────

    def get_remediated_tickets(self, client_label: str) -> List[Dict[str, Any]]:
        return [self._serialize(i) for i in self._search_jql(self._jql(client_label))]

    def get_sweep_tickets(self, client_label: str,
                          max_results: Optional[int] = None) -> List[Dict[str, Any]]:
        return [self._serialize(i) for i in
                self._search_jql(self._sweep_jql(client_label), max_results=max_results)]

    def get_ticket(self, key: str) -> Dict[str, Any]:
        resp = self._session.get(
            f"{self.cfg.url}/rest/api/2/issue/{key}",
            params={"fields": self._fetch_fields},
            timeout=30,
        )
        resp.raise_for_status()
        return self._serialize(resp.json())

    # ── Transitions ───────────────────────────────────────────────────────

    def transition(self, key: str, to_status: str):
        resp = self._session.get(
            f"{self.cfg.url}/rest/api/2/issue/{key}/transitions",
            timeout=15,
        )
        resp.raise_for_status()
        transitions = resp.json().get("transitions", [])
        target = to_status.lower().strip()

        candidates = {target}
        for canonical, aliases in self._TRANSITION_ALIASES.items():
            if target == canonical or target in aliases:
                candidates |= aliases
                candidates.add(canonical)

        for t in transitions:
            if t["name"].lower() in candidates:
                self._session.post(
                    f"{self.cfg.url}/rest/api/2/issue/{key}/transitions",
                    json={"transition": {"id": t["id"]}},
                    timeout=15,
                ).raise_for_status()
                return

        available = [t["name"] for t in transitions]
        raise ValueError(
            f"Transition '{to_status}' not available for {key}. "
            f"Available: {available}"
        )

    def fast_track(self, key: str, target: str, comment: str = "") -> List[str]:
        """Mirror of JiraClient.fast_track — see that docstring for full details.

        Intermediate steps are non-fatal (skipped if unavailable).
        Live status is re-checked before the final target step so that:
          • stale-cache tickets already at target exit cleanly
          • intermediates that reach the target (e.g. "Fix Issue" → Remediated)
            don't cause a spurious failure on the now-redundant final step.
        """
        resp = self._session.get(
            f"{self.cfg.url}/rest/api/2/issue/{key}?fields=status",
            timeout=15,
        )
        resp.raise_for_status()
        current_status = resp.json()["fields"]["status"]["name"].lower().strip()
        chain = self.FAST_TRACK_CHAINS.get(current_status)
        if chain is None:
            raise ValueError(
                f"No fast-track chain defined for status '{current_status}'. "
                f"Defined for: {list(self.FAST_TRACK_CHAINS)}"
            )

        _TERMINAL = {"fixed", "not fixed", "risk accepted", "closed", "done"}

        full_chain = chain + [target]
        completed: List[str] = []

        def _live_status() -> str:
            r = self._session.get(
                f"{self.cfg.url}/rest/api/2/issue/{key}?fields=status",
                timeout=15,
            )
            r.raise_for_status()
            return r.json()["fields"]["status"]["name"].lower().strip()

        for i, step in enumerate(full_chain):
            is_final = (i == len(full_chain) - 1)

            # Before the target step, re-check live status — an intermediate
            # may have already landed the ticket at or past the target.
            # Only treat a _TERMINAL status as "done" if the ticket actually
            # moved away from its starting state; if it's still at the starting
            # state we should proceed and apply the target normally.
            if is_final:
                live = _live_status()
                if live == target.lower() or (live in _TERMINAL and live != current_status):
                    break  # already at/past target — done

            try:
                self.transition(key, step)
                completed.append(step)
            except Exception as exc:
                if is_final:
                    # Last-chance live check: ticket may have reached a terminal
                    # state even though the target transition isn't available.
                    try:
                        live_after = _live_status()
                        if live_after == target.lower() or live_after in _TERMINAL:
                            break
                    except Exception:
                        pass
                    err = ValueError(
                        f"Fast-track failed at step '{step}' "
                        f"(completed: {completed}): {exc}"
                    )
                    err.completed = completed  # type: ignore[attr-defined]
                    raise err
                # Intermediate step not available in this workflow — skip it.

        # Comment posted only after every transition succeeds — no spurious
        # comments left on the ticket if the transition chain fails.
        if comment:
            self.add_comment(key, comment)

        return completed

    def add_comment(self, key: str, body: str):
        """Add a plain-text comment (v2 uses plain text, not ADF)."""
        self._session.post(
            f"{self.cfg.url}/rest/api/2/issue/{key}/comment",
            json={"body": body},
            timeout=15,
        ).raise_for_status()

    # ── Serialise ─────────────────────────────────────────────────────────

    def _serialize(self, issue: Dict) -> Dict[str, Any]:
        f = issue.get("fields", {})
        labels: List[str] = list(f.get("labels") or [])

        ips   = [l for l in labels if _IP_RE.match(l)]
        ports = [l for l in labels if _PORT_RE.match(l) and not _IP_RE.match(l)]
        cves  = [l for l in labels if _CVE_RE.match(l)]

        def get_custom(field_name: str):
            fid = self._fid(field_name)
            if not fid:
                return None
            val = f.get(fid)
            if isinstance(val, dict):
                simple = val.get("value") or val.get("name")
                if simple:
                    return simple
                # ADF rich-text fields (paragraph, text area)
                from .jira_client import _adf_to_text
                return _adf_to_text(val) or None
            return val

        # v2 description is a plain string (not ADF)
        desc = f.get("description") or ""
        if isinstance(desc, dict):
            # Shouldn't happen on v2, but be safe
            from .jira_client import _adf_to_text
            desc = _adf_to_text(desc)

        return {
            "key":         issue["key"],
            "summary":     f.get("summary", ""),
            "status":      (f.get("status") or {}).get("name"),
            "priority":    (f.get("priority") or {}).get("name"),
            "assignee":    (f.get("assignee") or {}).get("displayName"),
            "reporter":    (f.get("reporter") or {}).get("displayName"),
            "updated":     str(f.get("updated", "")),
            "labels":      labels,
            "ips":         ips,
            "ports":       ports,
            "cves":        cves,
            "cvss":        get_custom("cvss"),
            "severity":    get_custom("severity"),
            "rating":      get_custom("vulnerability_rating"),
            "technology":  get_custom("technology"),
            "testtype":    get_custom("testtype[short text]") or get_custom("testtype"),
            "tester":      _extract_tester(f, self._fid("tester")),
            "other_information": (
                get_custom("otherinformation[paragraph]")
                or get_custom("otherinformation")
                or get_custom("other information")
            ),
            "description": desc,
        }
