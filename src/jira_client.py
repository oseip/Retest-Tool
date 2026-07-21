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


def _extract_tester(fields: dict, field_id: Optional[str]) -> Optional[str]:
    """
    Extract the 'tester' custom field value.
    Handles: user object {displayName/name}, plain string, or list of the above.
    """
    if not field_id:
        return None
    val = fields.get(field_id)
    if not val:
        return None
    # List of users (multi-user picker)
    if isinstance(val, list):
        names = []
        for item in val:
            if isinstance(item, dict):
                names.append(item.get("displayName") or item.get("name") or "")
            elif isinstance(item, str):
                names.append(item)
        return ", ".join(n for n in names if n) or None
    # Single user object
    if isinstance(val, dict):
        return val.get("displayName") or val.get("name")
    # Plain string
    return str(val) if val else None


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
            get_server_info=False,
        )
        self._session = requests.Session()
        self._session.auth = self._auth
        self._session.headers.update({"Accept": "application/json"})
        self._fields: Dict[str, str] = {}
        self._fields_loaded = False
        # Safe default so the client is usable immediately. The real field map is
        # loaded lazily on first use (see _fid) or proactively by the app in a
        # background thread — constructing the client must never block on the
        # network, otherwise app startup stalls until Jira answers.
        self._fetch_fields = "*all"

    def _load_fields(self):
        try:
            for f in self._j.fields():
                self._fields[f["name"].lower()] = f["id"]
            # Only mark as loaded after a *successful* fetch so that a transient
            # startup failure (network blip, auth hiccup) can be retried on the
            # next _fid() call instead of permanently degrading to "*all" fields
            # and losing every custom field (cvss/severity/testtype/tester).
            self._fields_loaded = True
            log.info("Loaded %d Jira fields", len(self._fields))
            self._fetch_fields = self._build_fetch_fields()
        except Exception as e:
            log.warning("Could not load Jira field map: %s", e)
            self._fetch_fields = "*all"

    def _build_fetch_fields(self) -> str:
        """Minimal field list so search/issue responses are small and fast."""
        standard = ["summary", "status", "priority", "assignee", "reporter",
                    "updated", "labels", "description"]
        custom_names = ["cvss", "severity", "technology", "vulnerability_rating",
                        "testtype[short text]", "testtype", "tester",
                        "otherinformation[paragraph]", "otherinformation",
                        "other information",
                        "affected_system[paragraph]", "affected_system", "affected system",
                        "os[short text]", "os"]
        custom_ids = [self._fid(n) for n in custom_names if self._fid(n)]
        return ",".join(standard + custom_ids)

    def _fid(self, name: str) -> Optional[str]:
        if not self._fields_loaded:
            self._load_fields()
        return self._fields.get(name.lower())

    @property
    def severity_jql_field(self) -> str:
        """JQL field reference for severity/vulnerability rating filtering."""
        fid = self._fid("vulnerability_rating") or self._fid("severity")
        if fid:
            if fid.startswith("customfield_"):
                return f'cf[{fid.split("_", 1)[1]}]'
            return f'"{fid}"'
        return '"Severity"'

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
        fields_str = getattr(self, "_fetch_fields", "*all")
        fields_list = fields_str.split(",") if fields_str else []
        all_issues: List[Dict] = []
        next_page_token = None
        
        while True:
            payload = {
                "jql": jql,
                "maxResults": 100,
                "fields": fields_list
            }
            if next_page_token:
                payload["nextPageToken"] = next_page_token
                
            resp = self._session.post(url, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            batch = data.get("issues", [])
            all_issues.extend(batch)
            
            if max_results and len(all_issues) >= max_results:
                return all_issues[:max_results]
                
            next_page_token = data.get("nextPageToken")
            if not batch:
                break
            # Default isLast from nextPageToken — missing isLast must not stop early
            # when Jira still returns a continuation token.
            if data.get("isLast", not next_page_token) or not next_page_token:
                break
        return all_issues

    def search_jql(self, jql: str, max_results: Optional[int] = None) -> List[Dict[str, Any]]:
        """Run a full JQL search (not just a count) and return serialized issues."""
        issues = self._search_jql(jql, max_results=max_results)
        return [self._serialize(issue) for issue in issues]

    def count_jql(self, jql: str) -> int:
        """Count issues matching a JQL query using API v3 approximate-count."""
        resp = self._session.post(
            f"{self.cfg.url}/rest/api/3/search/approximate-count",
            json={"jql": jql},
            timeout=30,
        )
        if not resp.ok:
            log.error("JQL failed: %s | Resp: %s", jql, resp.text)
        resp.raise_for_status()
        try:
            return resp.json().get("count", 0)
        except Exception as e:
            log.error("JiraClient JSONDecodeError! Status: %s, Body: %s", resp.status_code, resp.text)
            raise

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

    def add_attachment(
        self, key: str, filename: str, content: bytes, mime_type: str = "image/png"
    ) -> str:
        """Upload a file attachment; return the filename Jira stored."""
        import io
        bio = io.BytesIO(content)
        bio.name = filename
        result = self._j.add_attachment(issue=key, attachment=bio, filename=filename)
        if isinstance(result, list) and result:
            att = result[0]
            return getattr(att, "filename", None) or filename
        return getattr(result, "filename", None) or filename

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

    # Fast-track chains: ONLY the intermediate steps needed to escape the current
    # status. The actual target ("Remediated" or "Fixed"/"Not Fixed") is appended
    # by fast_track() via  full_chain = chain + [target].
    #
    # Phase-1 target is always "Remediated" (advance to it, then stop).
    # Phase-2 target is "Fixed" or "Not Fixed" (only when already at Remediated).
    #
    # "Not Fixed" → "Refix" unlocks the ticket back to In Progress, then
    #   "Remediated" completes phase 1.
    FAST_TRACK_CHAINS: Dict[str, List[str]] = {
        "reported":    ["In Progress"],          # → Remediated (phase 1 target)
        "in progress": [],                       # → Remediated directly
        "not fixed":   ["Refix", "Fix Issue"],   # Refix unlocks; Fix Issue reaches Remediated
        "remediated":  [],                       # → Fixed / Not Fixed directly (phase 2)
    }

    def fast_track(self, key: str, target: str, comment: str = "") -> List[str]:
        """
        Chain all intermediate transitions required to reach *target* from the
        ticket's current status, then apply *target* itself.

        Intermediate steps are non-fatal — if one is unavailable for this
        ticket's workflow (e.g. "Fix Issue" not present in every Jira instance)
        it is skipped and the chain continues.

        Before applying the final target transition, the live Jira status is
        re-checked: if an intermediate already landed the ticket at *target*
        (common when "Fix Issue" → Remediated), we stop early and return
        without error.  This also handles stale-cache: if the ticket was
        manually moved to *target* in Jira, the early-exit fires cleanly.

        The comment (if any) is only posted AFTER all transitions succeed so
        that a failed transition does not leave a spurious comment on the ticket.

        Returns the list of transition names that were successfully applied.
        Raises ValueError if the final target step fails, with the completed
        list attached as the ``completed`` attribute.
        """
        current_status = self._j.issue(key).fields.status.name.lower().strip()
        chain = self.FAST_TRACK_CHAINS.get(current_status)
        if chain is None:
            raise ValueError(
                f"No fast-track chain defined for status '{current_status}'. "
                f"Defined for: {list(self.FAST_TRACK_CHAINS)}"
            )

        # States that mean "the ticket is fully resolved" — used to detect when
        # an intermediate transition (e.g. Fix Issue) jumped past the target.
        _TERMINAL = {"fixed", "not fixed", "risk accepted", "closed", "done"}

        full_chain = chain + [target]
        completed: List[str] = []

        for i, step in enumerate(full_chain):
            is_final = (i == len(full_chain) - 1)

            # Before the final (target) step, re-check live status.
            # An intermediate (e.g. "Fix Issue") may have already landed
            # the ticket at *target* or even past it — stop cleanly.
            # Only treat a _TERMINAL status as "done" if the ticket actually
            # moved away from its starting state; if it's still at the starting
            # state we should proceed and apply the target normally.
            if is_final:
                live = self._j.issue(key).fields.status.name.lower().strip()
                if live == target.lower() or (live in _TERMINAL and live != current_status):
                    break  # already at/past target — done

            try:
                self.transition(key, step)
                completed.append(step)
            except Exception as exc:
                if is_final:
                    # Before raising, do one last live check: the ticket may have
                    # reached a terminal state via the intermediates even though the
                    # target transition is not available (e.g. Fix Issue → Fixed
                    # when the declared target was Remediated).
                    try:
                        live_after = self._j.issue(key).fields.status.name.lower().strip()
                        # Only swallow the error if the ticket genuinely reached
                        # the target or moved to a *different* terminal state.
                        # Without the "!= current_status" guard, a ticket that
                        # started at a terminal-named status (e.g. "not fixed")
                        # and never moved would be reported as success (silent
                        # no-op).
                        if (live_after == target.lower()
                                or (live_after in _TERMINAL and live_after != current_status)):
                            break  # already done — swallow the error
                    except Exception:
                        pass
                    err = ValueError(
                        f"Fast-track failed at step '{step}' "
                        f"(completed: {completed}): {exc}"
                    )
                    err.completed = completed  # type: ignore[attr-defined]
                    raise err
                # Intermediate step unavailable in this Jira workflow — skip it.
                # The subsequent steps (including the target) will still be tried.

        # Comment is posted only after every transition has succeeded
        if comment:
            self.add_comment(key, comment)

        return completed

    def transition(self, key: str, to_status: str):
        transitions = self._j.transitions(key)
        target = to_status.lower().strip()
        by_name = {}
        for t in transitions:
            by_name.setdefault(t["name"].lower().strip(), t)

        # Build a PRIORITY-ORDERED candidate list rather than a flat set:
        #   1. the exact requested status name
        #   2. the canonical name of its alias group
        #   3. the remaining aliases (last resort)
        # Matching in this order guarantees we fire the *literal* target
        # transition when Jira offers it, instead of an equivalent-but-different
        # one that merely shares the alias group (e.g. requesting "Fixed" must
        # never fire "Done"/"Closed"/"Resolve" while a real "Fixed" exists).
        ranked = [target]
        for canonical, aliases in self._TRANSITION_ALIASES.items():
            if target == canonical or target in aliases:
                if canonical not in ranked:
                    ranked.append(canonical)
                for a in sorted(aliases):
                    if a not in ranked:
                        ranked.append(a)

        for name in ranked:
            t = by_name.get(name)
            if t:
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
                # Simple select / radio fields
                simple = val.get("value") or val.get("name")
                if simple:
                    return simple
                # ADF (Atlassian Document Format) — paragraph / rich text fields
                # e.g. OtherInformation[Paragraph] comes back as ADF from search API
                return _adf_to_text(val) or None
            return val

        return {
            "key": issue["key"],
            "summary": f.get("summary", ""),
            "status": (f.get("status") or {}).get("name"),
            "priority": (f.get("priority") or {}).get("name"),
            "assignee": (f.get("assignee") or {}).get("displayName"),
            "reporter": (f.get("reporter") or {}).get("displayName"),
            "updated": str(f.get("updated", "")),
            "labels": labels,
            "ips": ips,
            "ports": ports,
            "cves": cves,
            "cvss": get_custom("cvss"),
            "severity": get_custom("severity"),
            "rating": get_custom("vulnerability_rating") or get_custom("severity"),
            "technology": get_custom("technology"),
            "testtype": get_custom("testtype[short text]") or get_custom("testtype"),
            "tester": _extract_tester(f, self._fid("tester")),
            "other_information": (
                get_custom("otherinformation[paragraph]")
                or get_custom("otherinformation")
                or get_custom("other information")
            ),
            "affected_system": (
                get_custom("affected_system[paragraph]")
                or get_custom("affected_system")
                or get_custom("affected system")
            ),
            "os": get_custom("os[short text]") or get_custom("os"),
            "description": _adf_to_text(f.get("description")) if isinstance(f.get("description"), dict) else (f.get("description") or ""),
        }
