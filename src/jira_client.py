import re
import logging
import requests
from typing import List, Dict, Any, Optional

from jira import JIRA

from .config import JiraConfig

log = logging.getLogger(__name__)

_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_PORT_RE = re.compile(r'^\d{2,5}$')
_CVE_RE = re.compile(r'^CVE-\d{4}-\d+$', re.I)


def _adf_to_text(node) -> str:
    """Recursively extract plain text from Atlassian Document Format (ADF) JSON."""
    if not node:
        return ""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return " ".join(_adf_to_text(c) for c in node if c)
    if isinstance(node, dict):
        if node.get("type") == "text":
            return node.get("text", "")
        return " ".join(_adf_to_text(c) for c in node.get("content", []) if c)
    return ""


class JiraClient:
    def __init__(self, cfg: JiraConfig):
        self.cfg = cfg
        self._auth = (cfg.username, cfg.api_token)
        self._j = JIRA(
            server=cfg.url,
            basic_auth=self._auth,
        )
        self._session = requests.Session()
        self._session.auth = self._auth
        self._session.headers.update({"Accept": "application/json"})
        self._fields: Dict[str, str] = {}
        self._load_fields()

    def _load_fields(self):
        try:
            for f in self._j.fields():
                self._fields[f["name"].lower()] = f["id"]
            log.info("Loaded %d Jira fields", len(self._fields))
            self._fetch_fields = self._build_fetch_fields()
        except Exception as e:
            log.warning("Could not load Jira field map: %s", e)
            self._fetch_fields = "*all"

    def _build_fetch_fields(self) -> str:
        """Minimal field list so search/issue responses are small and fast."""
        standard = ["summary", "status", "priority", "assignee",
                    "updated", "labels", "description"]
        custom_names = ["cvss", "severity", "technology", "vulnerability_rating",
                        "testtype[short text]", "testtype"]
        custom_ids = [self._fid(n) for n in custom_names if self._fid(n)]
        return ",".join(standard + custom_ids)

    def _fid(self, name: str) -> Optional[str]:
        return self._fields.get(name.lower())

    # TestTypes that support automated scanning (nmap / curl)
    SCANNABLE_TYPES = {"SCN", "IPT"}

    def _jql(self, client_label: str) -> str:
        # Pull ALL remediated tickets regardless of TestType.
        # SCN/IPT → auto-scan job; everything else → manual review job.
        return (
            f'project = {self.cfg.project} '
            f'AND status = "{self.cfg.retest_status}" '
            f'AND labels = "{client_label}" '
            f'ORDER BY updated DESC'
        )

    def _sweep_jql(self, client_label: str) -> str:
        # Pull ALL open tickets regardless of TestType.
        # SCN/IPT without a matching rule → manual; non-SCN/IPT → always manual.
        return (
            f'project = {self.cfg.project} '
            f'AND labels = "{client_label}" '
            f'AND status NOT IN (Fixed, "Risk Accepted", "{self.cfg.retest_status}") '
            f'ORDER BY updated DESC'
        )

    def get_sweep_tickets(self, client_label: str, max_results: Optional[int] = None) -> List[Dict[str, Any]]:
        jql = self._sweep_jql(client_label)
        issues = self._search_jql(jql, max_results=max_results)
        return [self._serialize(issue) for issue in issues]

    def _search_jql(self, jql: str, max_results: Optional[int] = None) -> List[Dict]:
        """Fetch issues matching JQL, paging with nextPageToken (v3 caps at 100/page).
        Pass max_results to stop after N issues instead of fetching all pages."""
        url = f"{self.cfg.url}/rest/api/3/search/jql"
        log.info("JQL → %s", jql)
        fields = getattr(self, "_fetch_fields", "*all")
        params: dict = {"jql": jql, "maxResults": 100, "fields": fields}
        all_issues: List[Dict] = []
        while True:
            resp = self._session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("issues", [])
            all_issues.extend(batch)
            if max_results and len(all_issues) >= max_results:
                return all_issues[:max_results]
            if data.get("isLast", True) or not batch:
                break
            params = {"jql": jql, "maxResults": 100, "fields": fields,
                      "nextPageToken": data["nextPageToken"]}
        return all_issues

    def search_jql(self, jql: str, max_results: Optional[int] = None) -> List[Dict[str, Any]]:
        """Run a full JQL search (not just a count) and return serialized issues."""
        issues = self._search_jql(jql, max_results=max_results)
        return [self._serialize(issue) for issue in issues]

    def count_jql(self, jql: str) -> int:
        """
        Count issues matching a JQL query in a single HTTP request.
        v2 /search returns a 'total' field even with maxResults=0 so we get
        the count without transferring any issue data. Falls back to cursor
        pagination if the v2 endpoint is unavailable (HTTP 410).
        """
        try:
            resp = self._session.get(
                f"{self.cfg.url}/rest/api/2/search",
                params={"jql": jql, "maxResults": 0, "fields": ""},
                timeout=30,
            )
            if resp.status_code == 410:
                raise requests.HTTPError("v2 gone")
            resp.raise_for_status()
            return resp.json()["total"]
        except Exception as exc:
            log.warning("count_jql v2 failed (%s) — cursor fallback", exc)
            return self._count_cursor(jql)

    def _count_cursor(self, jql: str) -> int:
        """Cursor-based page-counting fallback for count_jql."""
        url = f"{self.cfg.url}/rest/api/3/search/jql"
        count = 0
        params: dict = {"jql": jql, "maxResults": 200, "fields": "id"}
        while True:
            resp = self._session.get(url, params=params, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("issues", [])
            count += len(batch)
            if data.get("isLast", True) or not batch:
                break
            params = {
                "jql": jql, "maxResults": 200, "fields": "id",
                "nextPageToken": data["nextPageToken"],
            }
        return count

    def get_remediated_tickets(self, client_label: str) -> List[Dict[str, Any]]:
        jql = self._jql(client_label)
        issues = self._search_jql(jql)
        return [self._serialize(issue) for issue in issues]

    def get_ticket(self, key: str) -> Dict[str, Any]:
        url = f"{self.cfg.url}/rest/api/3/issue/{key}"
        resp = self._session.get(
            url,
            params={"fields": getattr(self, "_fetch_fields", "*all")},
            timeout=30,
        )
        resp.raise_for_status()
        return self._serialize(resp.json())

    def add_comment(self, key: str, body: str):
        self._j.add_comment(key, body)

    # Maps our button labels to the range of names Jira workflows actually use
    _TRANSITION_ALIASES = {
        "fixed": {
            "fixed", "fix issue", "fix", "mark fixed", "mark as fixed",
            "resolve", "resolved", "done", "close", "closed",
        },
        "not fixed": {
            "not fixed", "not fix", "not fix issue", "mark as not fixed",
            "won't fix", "wontfix", "reopen", "reopened", "reject",
        },
        "in progress": {
            "in progress", "start progress", "start", "start work",
            "begin", "begin work", "take", "assign", "wip",
        },
        "remediated": {
            "remediated", "mark remediated", "mark as remediated",
            "client remediated", "remediate", "ready for retest",
        },
    }

    # Fast-track chains: what intermediate transitions are needed before the
    # final Fixed / Not Fixed step, keyed by current ticket status (lower-case).
    FAST_TRACK_CHAINS: Dict[str, List[str]] = {
        "reported":    ["In Progress", "Remediated"],
        "in progress": ["Remediated"],
        "not fixed":   ["Remediated"],
        "remediated":  [],   # direct — no intermediates needed
    }

    def fast_track(self, key: str, target: str, comment: str = "") -> List[str]:
        """
        Chain all intermediate transitions required to reach *target* from the
        ticket's current status, then apply *target* itself.

        Returns the list of transition names that were successfully applied.
        Raises ValueError if any step fails, with the completed list attached
        as the ``completed`` attribute so callers can report partial progress.
        """
        current_status = self._j.issue(key).fields.status.name.lower().strip()
        chain = self.FAST_TRACK_CHAINS.get(current_status)
        if chain is None:
            raise ValueError(
                f"No fast-track chain defined for status '{current_status}'. "
                f"Defined for: {list(self.FAST_TRACK_CHAINS)}"
            )

        full_chain = chain + [target]
        completed: List[str] = []

        # Optional comment goes on the ticket before any transitions fire
        if comment:
            self.add_comment(key, comment)

        for step in full_chain:
            try:
                self.transition(key, step)
                completed.append(step)
            except Exception as exc:
                err = ValueError(
                    f"Fast-track failed at step '{step}' "
                    f"(completed: {completed}): {exc}"
                )
                err.completed = completed  # type: ignore[attr-defined]
                raise err

        return completed

    def transition(self, key: str, to_status: str):
        transitions = self._j.transitions(key)
        target = to_status.lower().strip()

        # Build full candidate set: exact name + all aliases for this label
        candidates = {target}
        for canonical, aliases in self._TRANSITION_ALIASES.items():
            if target == canonical or target in aliases:
                candidates |= aliases
                candidates.add(canonical)

        for t in transitions:
            if t["name"].lower() in candidates:
                self._j.transition_issue(key, t["id"])
                return

        available = [t["name"] for t in transitions]
        raise ValueError(
            f"Transition '{to_status}' not available for {key}. "
            f"Available transitions: {available}"
        )

    def _serialize(self, issue: Dict) -> Dict[str, Any]:
        """Serialize a raw Jira v3 API issue dict."""
        f = issue.get("fields", {})
        labels: List[str] = list(f.get("labels") or [])

        ips = [l for l in labels if _IP_RE.match(l)]
        ports = [l for l in labels if _PORT_RE.match(l) and not _IP_RE.match(l)]
        cves = [l for l in labels if _CVE_RE.match(l)]

        def get_custom(field_name: str):
            fid = self._fid(field_name)
            if not fid:
                return None
            val = f.get(fid)
            if isinstance(val, dict):
                return val.get("value") or val.get("name")
            return val

        return {
            "key": issue["key"],
            "summary": f.get("summary", ""),
            "status": (f.get("status") or {}).get("name"),
            "priority": (f.get("priority") or {}).get("name"),
            "assignee": (f.get("assignee") or {}).get("displayName"),
            "updated": str(f.get("updated", "")),
            "labels": labels,
            "ips": ips,
            "ports": ports,
            "cves": cves,
            "cvss": get_custom("cvss"),
            "severity": get_custom("severity"),
            "rating": get_custom("vulnerability_rating"),
            "technology": get_custom("technology"),
            "testtype": get_custom("testtype[short text]") or get_custom("testtype"),
            "description": _adf_to_text(f.get("description")) if isinstance(f.get("description"), dict) else (f.get("description") or ""),
        }
