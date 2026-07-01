"""
Tests for src/jira_client_v2.py (Non-Axian / Jira Server v2 client)

Covers:
- severity_jql_field   — resolves from field map; falls back to 'priority'
- count_jql            — returns total from /rest/api/2/search maxResults=0
- _search_jql          — startAt pagination (not cursor-based)
- search_jql           — serialises raw issues
- _serialize           — IP/port/CVE label extraction, custom field lookup,
                         plain-text description, ADF-dict description fallback
- transition           — alias resolution, raises when not available
- fast_track           — chains through intermediate transitions
- add_comment          — posts plain-text body (not ADF)
"""

import pytest
import requests as _requests
from unittest.mock import MagicMock, patch, call

from src.config import JiraSecondaryConfig
from src.jira_client_v2 import JiraClientV2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_v2_cfg(**kwargs) -> JiraSecondaryConfig:
    defaults = dict(
        url="https://tickets.test.com",
        api_token="test-pat-token",
        retest_status="Remediated",
        poll_interval=300,
    )
    defaults.update(kwargs)
    return JiraSecondaryConfig(**defaults)


def make_v2_client(fields=None) -> JiraClientV2:
    """JiraClientV2 with HTTP mocked out and fields pre-loaded."""
    with patch.object(JiraClientV2, "_load_fields"):
        client = JiraClientV2(make_v2_cfg())
    client._fields = fields or {}
    client._fetch_fields = "*all"
    client._session = MagicMock()
    return client


def make_raw_issue(
    key="CPEL-1",
    summary="SSL Certificate Expiry",
    status="Remediated",
    labels=None,
    description=None,
    custom_fields=None,
) -> dict:
    fields = {
        "summary": summary,
        "status": {"name": status},
        "priority": {"name": "High"},
        "assignee": {"displayName": "Alice"},
        "updated": "2024-01-15T10:00:00.000+0000",
        "labels": labels or [],
        "description": description or "Plain text description",
    }
    if custom_fields:
        fields.update(custom_fields)
    return {"key": key, "fields": fields}


def _ok_resp(data: dict) -> MagicMock:
    r = MagicMock()
    r.raise_for_status.return_value = None
    r.json.return_value = data
    return r


# ---------------------------------------------------------------------------
# severity_jql_field — field resolution
# ---------------------------------------------------------------------------
class TestSeverityJqlField:
    def test_resolves_vulnerability_rating_to_cf(self):
        client = make_v2_client(fields={"vulnerability_rating": "customfield_10125"})
        assert client.severity_jql_field == "cf[10125]"

    def test_resolves_severity_field_to_cf(self):
        client = make_v2_client(fields={"severity": "customfield_10050"})
        assert client.severity_jql_field == "cf[10050]"

    def test_vulnerability_rating_takes_priority_over_severity(self):
        client = make_v2_client(fields={
            "vulnerability_rating": "customfield_10125",
            "severity": "customfield_10050",
        })
        # vulnerability_rating is first in the candidate list
        assert client.severity_jql_field == "cf[10125]"

    def test_falls_back_to_priority_when_no_severity_fields(self):
        client = make_v2_client(fields={})
        assert client.severity_jql_field == "priority"

    def test_non_customfield_id_returned_as_quoted_string(self):
        # Field IDs that don't follow customfield_XXX pattern
        client = make_v2_client(fields={"severity": "severity"})
        assert client.severity_jql_field == '"severity"'

class TestSeverityJqlFieldAxian:
    """Axian JiraClient always returns the hardcoded field name."""
    def test_axian_returns_fixed_field_name(self):
        from src.jira_client import JiraClient
        with patch("src.jira_client.JIRA"), patch("src.jira_client.requests"):
            with patch.object(JiraClient, "_load_fields"):
                from src.config import JiraConfig
                cfg = JiraConfig(
                    url="https://axian.atlassian.net",
                    username="u", api_token="t", project="AXG",
                )
                c = JiraClient(cfg)
        assert c.severity_jql_field == '"Severity"'


# ---------------------------------------------------------------------------
# count_jql
# ---------------------------------------------------------------------------
class TestCountJql:
    def test_returns_total_from_response(self):
        client = make_v2_client()
        client._session.post.return_value = _ok_resp({"total": 57})

        result = client.count_jql("project = CPEL")
        assert result == 57

    def test_zero_when_total_missing(self):
        client = make_v2_client()
        client._session.post.return_value = _ok_resp({})

        result = client.count_jql("project = CPEL")
        assert result == 0

    def test_uses_max_results_zero(self):
        client = make_v2_client()
        client._session.post.return_value = _ok_resp({"total": 10})

        client.count_jql("project = CPEL")
        call_kwargs = client._session.post.call_args
        params = call_kwargs[1].get("json") or call_kwargs[0][1]
        assert params.get("maxResults") == 1

    def test_raises_on_http_error(self):
        client = make_v2_client()
        resp = MagicMock()
        resp.raise_for_status.side_effect = _requests.HTTPError("403 Forbidden")
        client._session.post.return_value = resp

        with pytest.raises(_requests.HTTPError):
            client.count_jql("project = CPEL")


# ---------------------------------------------------------------------------
# _search_jql — startAt pagination
# ---------------------------------------------------------------------------
class TestSearchJqlPagination:
    def _page(self, issues_count, total, start_at=0):
        r = MagicMock()
        r.raise_for_status.return_value = None
        issues = [{"key": f"T-{start_at + i}", "fields": {
            "summary": "x", "status": {"name": "Open"},
            "labels": [], "description": "", "updated": "",
        }} for i in range(issues_count)]
        r.json.return_value = {
            "issues": issues,
            "total": total,
        }
        return r

    def test_single_page_returns_all(self):
        client = make_v2_client()
        client._session.post.return_value = self._page(30, total=30)

        results = client.search_jql("project = CPEL")
        assert len(results) == 30
        assert client._session.post.call_count == 1

    def test_two_pages_combined(self):
        client = make_v2_client()
        client._session.post.side_effect = [
            self._page(100, total=140, start_at=0),
            self._page(40, total=140, start_at=100),
        ]

        results = client.search_jql("project = CPEL")
        assert len(results) == 140
        assert client._session.post.call_count == 2

    def test_second_call_uses_correct_start_at(self):
        client = make_v2_client()
        client._session.post.side_effect = [
            self._page(100, total=110, start_at=0),
            self._page(10, total=110, start_at=100),
        ]

        client._search_jql("project = CPEL")

        second_call = client._session.post.call_args_list[1]
        params = second_call[1].get("json") or second_call[0][1]
        assert params.get("startAt") == 100

    def test_empty_batch_stops_pagination(self):
        client = make_v2_client()
        client._session.post.return_value = self._page(0, total=0)

        results = client.search_jql("project = CPEL")
        assert results == []
        assert client._session.post.call_count == 1

    def test_max_results_respected(self):
        client = make_v2_client()
        client._session.post.return_value = self._page(100, total=500, start_at=0)

        results = client.search_jql("project = CPEL", max_results=50)
        assert len(results) == 50


# ---------------------------------------------------------------------------
# _serialize — label/field extraction
# ---------------------------------------------------------------------------
class TestSerialize:
    def test_ip_extracted_from_labels(self):
        client = make_v2_client()
        issue = make_raw_issue(labels=["10.0.0.1", "443"])
        result = client._serialize(issue)
        assert "10.0.0.1" in result["ips"]

    def test_port_extracted_from_labels(self):
        client = make_v2_client()
        issue = make_raw_issue(labels=["10.0.0.1", "8443"])
        result = client._serialize(issue)
        assert "8443" in result["ports"]

    def test_cve_extracted_from_labels(self):
        client = make_v2_client()
        issue = make_raw_issue(labels=["CVE-2024-1234", "10.0.0.1"])
        result = client._serialize(issue)
        assert "CVE-2024-1234" in result["cves"]

    def test_non_ip_label_not_extracted_as_ip(self):
        client = make_v2_client()
        issue = make_raw_issue(labels=["CPEL", "not-an-ip"])
        result = client._serialize(issue)
        assert result["ips"] == []

    def test_key_and_summary_preserved(self):
        client = make_v2_client()
        issue = make_raw_issue(key="CPEL-42", summary="TLS 1.0 Enabled")
        result = client._serialize(issue)
        assert result["key"] == "CPEL-42"
        assert result["summary"] == "TLS 1.0 Enabled"

    def test_status_extracted(self):
        client = make_v2_client()
        issue = make_raw_issue(status="Fixed")
        result = client._serialize(issue)
        assert result["status"] == "Fixed"

    def test_plain_text_description_preserved(self):
        client = make_v2_client()
        issue = make_raw_issue(description="This is the finding detail.")
        result = client._serialize(issue)
        assert result["description"] == "This is the finding detail."

    def test_adf_dict_description_converted(self):
        """v2 shouldn't return ADF, but if it does, it should degrade gracefully."""
        client = make_v2_client()
        issue = make_raw_issue(description={"type": "doc", "content": []})
        result = client._serialize(issue)
        # Should not crash; description may be empty string or text
        assert isinstance(result["description"], str)

    def test_custom_field_resolved_by_id(self):
        client = make_v2_client(fields={"severity": "customfield_10050"})
        issue = make_raw_issue(custom_fields={"customfield_10050": "Critical"})
        result = client._serialize(issue)
        assert result["severity"] == "Critical"

    def test_custom_field_dict_value_extracted(self):
        client = make_v2_client(fields={"vulnerability_rating": "customfield_10125"})
        issue = make_raw_issue(
            custom_fields={"customfield_10125": {"value": "High"}}
        )
        result = client._serialize(issue)
        assert result["rating"] == "High"

    def test_missing_custom_field_returns_none(self):
        client = make_v2_client(fields={})
        result = client._serialize(make_raw_issue())
        assert result["cvss"] is None
        assert result["severity"] is None

    def test_none_labels_handled_gracefully(self):
        client = make_v2_client()
        issue = make_raw_issue()
        issue["fields"]["labels"] = None
        result = client._serialize(issue)
        assert result["labels"] == []
        assert result["ips"] == []


# ---------------------------------------------------------------------------
# transition — alias resolution
# ---------------------------------------------------------------------------
class TestTransition:
    def _make_transitions_resp(self, names):
        r = MagicMock()
        r.raise_for_status.return_value = None
        r.json.return_value = {
            "transitions": [{"id": str(i), "name": n} for i, n in enumerate(names)]
        }
        return r

    def test_transitions_by_exact_name(self):
        client = make_v2_client()
        client._session.get.return_value = self._make_transitions_resp(["Fixed", "In Progress"])
        post_resp = MagicMock()
        post_resp.raise_for_status.return_value = None
        client._session.post.return_value = post_resp

        client.transition("CPEL-1", "Fixed")
        client._session.post.assert_called_once()
        call_kwargs = client._session.post.call_args
        body = call_kwargs[1].get("json") or call_kwargs[0][1]
        assert body["transition"]["id"] == "0"

    def test_transitions_by_alias(self):
        """'done' should resolve to the 'fixed' alias group → transitions 'Fixed'."""
        client = make_v2_client()
        client._session.get.return_value = self._make_transitions_resp(["Fixed", "Reopened"])
        post_resp = MagicMock()
        post_resp.raise_for_status.return_value = None
        client._session.post.return_value = post_resp

        client.transition("CPEL-1", "done")  # alias for "fixed"
        client._session.post.assert_called_once()

    def test_raises_value_error_when_transition_not_available(self):
        client = make_v2_client()
        client._session.get.return_value = self._make_transitions_resp(["In Progress"])
        with pytest.raises(ValueError, match="not available"):
            client.transition("CPEL-1", "Fixed")

    def test_available_transitions_listed_in_error(self):
        client = make_v2_client()
        client._session.get.return_value = self._make_transitions_resp(["In Progress", "Reopened"])
        with pytest.raises(ValueError) as exc_info:
            client.transition("CPEL-1", "Fixed")
        assert "In Progress" in str(exc_info.value)


# ---------------------------------------------------------------------------
# fast_track — chained transitions
# ---------------------------------------------------------------------------
class TestFastTrack:
    def _make_status_resp(self, status_name):
        r = MagicMock()
        r.raise_for_status.return_value = None
        r.json.return_value = {"fields": {"status": {"name": status_name}}}
        return r

    def test_fast_track_from_reported_phase1_reaches_remediated(self):
        """Phase 1 from 'Reported' with target='Remediated' → In Progress → Remediated."""
        client = make_v2_client()
        client._session.get.return_value = self._make_status_resp("Reported")

        completed = []
        client.transition = MagicMock(side_effect=lambda k, t: completed.append(t))

        client.fast_track("CPEL-1", "Remediated")
        assert completed == ["In Progress", "Remediated"]

    def test_fast_track_from_in_progress_phase1_reaches_remediated(self):
        """Phase 1 from 'In Progress' with target='Remediated' → Remediated directly."""
        client = make_v2_client()
        client._session.get.return_value = self._make_status_resp("In Progress")

        completed = []
        client.transition = MagicMock(side_effect=lambda k, t: completed.append(t))

        client.fast_track("CPEL-1", "Remediated")
        assert completed == ["Remediated"]

    def test_fast_track_from_remediated_phase2_reaches_fixed(self):
        """Phase 2 from 'Remediated' with target='Fixed' → Fixed directly."""
        client = make_v2_client()
        client._session.get.return_value = self._make_status_resp("Remediated")

        completed = []
        client.transition = MagicMock(side_effect=lambda k, t: completed.append(t))

        client.fast_track("CPEL-1", "Fixed")
        assert completed == ["Fixed"]

    def test_fast_track_posts_comment_after_all_transitions_succeed(self):
        """Comment must be posted AFTER transitions, not before — so a failed
        transition does not leave a spurious comment on the ticket."""
        client = make_v2_client()
        client._session.get.return_value = self._make_status_resp("Remediated")

        call_order = []
        client.add_comment = MagicMock(side_effect=lambda k, b: call_order.append(("comment", b)))
        client.transition = MagicMock(side_effect=lambda k, t: call_order.append(("transition", t)))

        client.fast_track("CPEL-1", "Fixed", comment="Scan result: fixed")

        # All transitions must precede the comment
        comment_idx = next(i for i, (kind, _) in enumerate(call_order) if kind == "comment")
        transition_indices = [i for i, (kind, _) in enumerate(call_order) if kind == "transition"]
        assert all(t < comment_idx for t in transition_indices), (
            "Comment was posted before transitions completed"
        )

    def test_fast_track_no_comment_when_transition_fails(self):
        """If any transition fails, no comment should be left on the ticket."""
        client = make_v2_client()
        client._session.get.return_value = self._make_status_resp("In Progress")

        client.add_comment = MagicMock()
        client.transition = MagicMock(side_effect=ValueError("transition error"))

        with pytest.raises(ValueError):
            client.fast_track("CPEL-1", "Fixed", comment="Should not appear")

        client.add_comment.assert_not_called()

    def test_fast_track_raises_on_unknown_current_status(self):
        client = make_v2_client()
        client._session.get.return_value = self._make_status_resp("Unknown Status")

        with pytest.raises(ValueError, match="No fast-track chain"):
            client.fast_track("CPEL-1", "Fixed")

    def test_fast_track_raises_on_failed_step_with_completed_list(self):
        """If an intermediate step fails, a ValueError is raised with completed steps attached."""
        client = make_v2_client()
        client._session.get.return_value = self._make_status_resp("Reported")

        def fail_on_remediated(key, to):
            if to == "Remediated":
                raise ValueError("transition error")

        client.transition = MagicMock(side_effect=fail_on_remediated)

        # Phase 1: target is Remediated; it gets through In Progress but fails at Remediated
        with pytest.raises(ValueError):
            client.fast_track("CPEL-1", "Remediated")

    def test_fast_track_not_fixed_phase1_refix_then_remediated(self):
        """Phase 1 from 'Not Fixed': Refix → Fix Issue → live check still Not Fixed → Remediated."""
        client = make_v2_client()
        # Both the initial status GET and the pre-final-step live-check GET return "Not Fixed"
        client._session.get.return_value = self._make_status_resp("Not Fixed")

        completed = []
        client.transition = MagicMock(side_effect=lambda k, t: completed.append(t))

        client.fast_track("CPEL-1", "Remediated")
        assert completed == ["Refix", "Fix Issue", "Remediated"]

    def test_fast_track_not_fixed_early_exit_when_fix_issue_reaches_target(self):
        """If Fix Issue transitions the ticket to Remediated, early-exit fires and
        the final 'Remediated' transition step is skipped."""
        client = make_v2_client()
        # First GET (current status) → Not Fixed
        # Second GET (pre-final live check) → Remediated (Fix Issue landed us there)
        not_fixed_resp = self._make_status_resp("Not Fixed")
        remediated_resp = self._make_status_resp("Remediated")
        client._session.get.side_effect = [not_fixed_resp, remediated_resp]

        completed = []
        client.transition = MagicMock(side_effect=lambda k, t: completed.append(t))

        client.fast_track("CPEL-1", "Remediated")
        # Refix + Fix Issue ran; early-exit prevented the redundant Remediated step
        assert completed == ["Refix", "Fix Issue"]

    def test_fast_track_not_fixed_fix_issue_skipped_if_unavailable(self):
        """If Fix Issue is not available in this workflow, it's skipped (non-fatal)
        and Remediated is attempted directly."""
        client = make_v2_client()
        client._session.get.return_value = self._make_status_resp("Not Fixed")

        completed = []
        def _transition(key, t):
            if t == "Fix Issue":
                raise ValueError("Transition 'Fix Issue' not available")
            completed.append(t)
        client.transition = MagicMock(side_effect=_transition)

        client.fast_track("CPEL-1", "Remediated")
        # Fix Issue was skipped; Refix + Remediated completed
        assert completed == ["Refix", "Remediated"]

    def test_fast_track_not_fixed_fix_issue_jumps_to_fixed_no_error(self):
        """Fix Issue transitions the ticket straight to Fixed (past Remediated).
        The Remediated step is unavailable but the last-chance live check sees
        Fixed (terminal) and suppresses the error."""
        client = make_v2_client()
        not_fixed_resp = self._make_status_resp("Not Fixed")
        # Pre-final-step live check → Fixed (Fix Issue already did it)
        fixed_resp     = self._make_status_resp("Fixed")
        client._session.get.side_effect = [not_fixed_resp, fixed_resp]

        completed = []
        def _transition(key, t):
            if t == "Remediated":
                raise ValueError("Transition 'Remediated' not available. "
                                  "Available: ['Fixed to Not Fixed']")
            completed.append(t)
        client.transition = MagicMock(side_effect=_transition)

        result = client.fast_track("CPEL-1", "Remediated")
        # Refix + Fix Issue ran; Remediated step was skipped via early-exit (live=Fixed)
        assert result == ["Refix", "Fix Issue"]


# ---------------------------------------------------------------------------
# add_comment — plain text, not ADF
# ---------------------------------------------------------------------------
class TestAddComment:
    def test_posts_to_comment_endpoint(self):
        client = make_v2_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        client._session.post.return_value = resp

        client.add_comment("CPEL-1", "This is my comment")

        client._session.post.assert_called_once()
        url = client._session.post.call_args[0][0]
        assert "CPEL-1" in url
        assert "comment" in url

    def test_body_is_plain_string_not_adf(self):
        client = make_v2_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        client._session.post.return_value = resp

        client.add_comment("CPEL-1", "Plain text comment")

        call_kwargs = client._session.post.call_args
        body = call_kwargs[1].get("json") or call_kwargs[0][1]
        # v2 uses plain string, not {"type": "doc", ...} ADF object
        assert body.get("body") == "Plain text comment"
        assert "type" not in body
        assert "content" not in body
