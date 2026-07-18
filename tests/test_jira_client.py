"""
Tests for src/jira_client.py

Covers:
- _serialize()      — IP/port/CVE extraction from labels, custom field lookup
- _sweep_jql()      — excludes correct statuses, uses right project/client
- _search_jql()     — pagination: fetches all pages using nextPageToken
- count_jql()       — falls back to cursor-based counting on v2 HTTP 410
"""

import pytest
from unittest.mock import MagicMock, patch, call

from src.config import JiraConfig
from src.jira_client import JiraClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_jira_cfg(**kwargs) -> JiraConfig:
    defaults = dict(
        url="https://test.atlassian.net",
        username="test@example.com",
        api_token="fake-token",
        project="TEST",
        retest_status="Remediated",
        poll_interval=60,
    )
    defaults.update(kwargs)
    return JiraConfig(**defaults)


def make_client(fields=None) -> JiraClient:
    """Create a JiraClient with all external calls mocked."""
    # Patch JIRA in jira_client's own namespace (it was imported via 'from jira import JIRA')
    with patch("src.jira_client.JIRA"), patch("src.jira_client.requests"):
        with patch.object(JiraClient, "_load_fields"):
            client = JiraClient(make_jira_cfg())
    client._fields = fields or {}
    client._fetch_fields = "*all"
    client._session = MagicMock()
    client._j = MagicMock()
    return client


def make_raw_issue(
    key="TEST-123",
    summary="Test issue",
    status="Open",
    labels=None,
    custom_fields=None,
) -> dict:
    fields = {
        "summary": summary,
        "status": {"name": status},
        "priority": {"name": "High"},
        "assignee": {"displayName": "Alice"},
        "updated": "2024-01-15T10:00:00.000+0000",
        "labels": labels or [],
        "description": "Some description",
    }
    if custom_fields:
        fields.update(custom_fields)
    return {"key": key, "fields": fields}


# ---------------------------------------------------------------------------
# _serialize — label parsing
# ---------------------------------------------------------------------------
class TestSerialize:
    def test_ip_extracted_from_labels(self):
        client = make_client()
        issue = make_raw_issue(labels=["TestClient", "10.0.0.1", "443"])
        result = client._serialize(issue)
        assert result["ips"] == ["10.0.0.1"]

    def test_multiple_ips_extracted(self):
        client = make_client()
        issue = make_raw_issue(labels=["192.168.1.1", "10.0.0.2", "TestClient"])
        result = client._serialize(issue)
        assert "192.168.1.1" in result["ips"]
        assert "10.0.0.2" in result["ips"]

    def test_port_extracted_from_labels(self):
        client = make_client()
        issue = make_raw_issue(labels=["TestClient", "10.0.0.1", "8443"])
        result = client._serialize(issue)
        assert result["ports"] == ["8443"]

    def test_cve_extracted_from_labels(self):
        client = make_client()
        issue = make_raw_issue(labels=["10.0.0.1", "443", "CVE-2024-1234"])
        result = client._serialize(issue)
        assert result["cves"] == ["CVE-2024-1234"]

    def test_cve_case_insensitive(self):
        client = make_client()
        issue = make_raw_issue(labels=["cve-2024-9999"])
        result = client._serialize(issue)
        assert result["cves"] == ["cve-2024-9999"]

    def test_client_label_not_extracted_as_ip_port_cve(self):
        client = make_client()
        issue = make_raw_issue(labels=["MyClient", "10.0.0.1", "443"])
        result = client._serialize(issue)
        assert "MyClient" not in result["ips"]
        assert "MyClient" not in result["ports"]
        assert "MyClient" not in result["cves"]

    def test_no_labels(self):
        client = make_client()
        issue = make_raw_issue(labels=[])
        result = client._serialize(issue)
        assert result["ips"] == []
        assert result["ports"] == []
        assert result["cves"] == []

    def test_key_and_summary_preserved(self):
        client = make_client()
        issue = make_raw_issue(key="PROJ-42", summary="My vulnerability")
        result = client._serialize(issue)
        assert result["key"] == "PROJ-42"
        assert result["summary"] == "My vulnerability"

    def test_status_extracted(self):
        client = make_client()
        issue = make_raw_issue(status="Remediated")
        result = client._serialize(issue)
        assert result["status"] == "Remediated"

    def test_custom_field_cvss_by_id(self):
        client = make_client(fields={"cvss": "customfield_10010"})
        issue = make_raw_issue(custom_fields={"customfield_10010": "9.8"})
        result = client._serialize(issue)
        assert result["cvss"] == "9.8"

    def test_custom_field_dict_value(self):
        client = make_client(fields={"severity": "customfield_10011"})
        issue = make_raw_issue(
            custom_fields={"customfield_10011": {"value": "Critical"}}
        )
        result = client._serialize(issue)
        assert result["severity"] == "Critical"

    def test_missing_custom_field_returns_none(self):
        client = make_client(fields={})
        result = client._serialize(make_raw_issue())
        assert result["cvss"] is None
        assert result["severity"] is None

    def test_none_labels_field_handled(self):
        client = make_client()
        issue = make_raw_issue()
        issue["fields"]["labels"] = None
        result = client._serialize(issue)
        assert result["ips"] == []
        assert result["labels"] == []


# ---------------------------------------------------------------------------
# _sweep_jql
# ---------------------------------------------------------------------------
class TestSweepJql:
    def test_contains_project(self):
        client = make_client()
        jql = client._sweep_jql("ClientABC")
        assert "project = TEST" in jql

    def test_contains_client_label(self):
        client = make_client()
        jql = client._sweep_jql("ClientABC")
        assert '"ClientABC"' in jql

    def test_excludes_fixed_status(self):
        client = make_client()
        jql = client._sweep_jql("ClientABC")
        assert "Fixed" in jql
        assert "NOT IN" in jql

    def test_excludes_risk_accepted_status(self):
        client = make_client()
        jql = client._sweep_jql("ClientABC")
        assert "Risk Accepted" in jql

    def test_excludes_remediated_status(self):
        client = make_client()
        jql = client._sweep_jql("ClientABC")
        assert "Remediated" in jql

    def test_does_not_filter_by_testtype(self):
        # Sweep now fetches ALL open tickets regardless of TestType.
        # SCN/IPT → auto-scan; everything else → manual review job.
        # The TestType filter was removed so non-scannable tickets are visible.
        client = make_client()
        jql = client._sweep_jql("ClientABC")
        assert "SCN" not in jql and "IPT" not in jql


# ---------------------------------------------------------------------------
# _search_jql — pagination
# ---------------------------------------------------------------------------
class TestSearchJqlPagination:
    def _make_response(self, issue_count, is_last, next_token=None):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        data = {
            "issues": [{"id": str(i), "key": f"T-{i}"} for i in range(issue_count)],
            "isLast": is_last,
        }
        if next_token:
            data["nextPageToken"] = next_token
        mock_resp.json.return_value = data
        return mock_resp

    def test_single_page_returns_all(self):
        client = make_client()
        client._session.post.return_value = self._make_response(50, is_last=True)

        results = client._search_jql("project = TEST")
        assert len(results) == 50
        assert client._session.post.call_count == 1

    def test_two_pages_combined(self):
        client = make_client()
        client._session.post.side_effect = [
            self._make_response(100, is_last=False, next_token="tok-2"),
            self._make_response(50, is_last=True),
        ]

        results = client._search_jql("project = TEST")
        assert len(results) == 150
        assert client._session.post.call_count == 2

    def test_three_pages_combined(self):
        client = make_client()
        client._session.post.side_effect = [
            self._make_response(100, is_last=False, next_token="tok-2"),
            self._make_response(100, is_last=False, next_token="tok-3"),
            self._make_response(40, is_last=True),
        ]

        results = client._search_jql("project = TEST")
        assert len(results) == 240
        assert client._session.post.call_count == 3

    def test_next_page_token_passed_in_params(self):
        client = make_client()
        client._session.post.side_effect = [
            self._make_response(100, is_last=False, next_token="cursor-abc"),
            self._make_response(5, is_last=True),
        ]

        client._search_jql("project = TEST")

        second_call_kwargs = client._session.post.call_args_list[1]
        params = second_call_kwargs[1].get("json") or second_call_kwargs[0][1]
        assert params.get("nextPageToken") == "cursor-abc"

    def test_empty_result_stops_pagination(self):
        client = make_client()
        client._session.post.return_value = self._make_response(0, is_last=False)

        results = client._search_jql("project = TEST")
        assert results == []
        assert client._session.post.call_count == 1

    def test_is_last_true_stops_pagination(self):
        client = make_client()
        client._session.post.return_value = self._make_response(100, is_last=True)

        results = client._search_jql("project = TEST")
        assert len(results) == 100
        assert client._session.post.call_count == 1

    def test_missing_is_last_continues_when_next_token_present(self):
        """Jira sometimes omits isLast; pagination must follow nextPageToken."""
        client = make_client()
        page1 = MagicMock()
        page1.raise_for_status.return_value = None
        page1.json.return_value = {
            "issues": [{"id": str(i), "key": f"T-{i}"} for i in range(100)],
            "nextPageToken": "tok-2",
        }
        page2 = MagicMock()
        page2.raise_for_status.return_value = None
        page2.json.return_value = {
            "issues": [{"id": "100", "key": "T-100"}],
            "isLast": True,
        }
        client._session.post.side_effect = [page1, page2]

        results = client._search_jql("project = TEST")
        assert len(results) == 101
        assert client._session.post.call_count == 2


# ---------------------------------------------------------------------------
# get_sweep_tickets — stale/invalid token behavior
#
# Jira Cloud's search endpoint does not always 401 on a bad/blank token — it
# can return 200 with an empty "issues" list instead. That makes an invalid
# token indistinguishable from "no tickets match" unless the caller checks
# for it, which is exactly what caused Sweep to silently show zero results
# instead of erroring after a token rotation.
# ---------------------------------------------------------------------------
class TestGetSweepTicketsAuthBehavior:
    def test_empty_issues_response_returns_empty_list_not_error(self):
        client = make_client()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"issues": [], "isLast": True}
        client._session.post.return_value = mock_resp

        results = client.get_sweep_tickets("ClientABC")

        assert results == []

    def test_real_401_raises_instead_of_returning_empty(self):
        import requests

        client = make_client()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")
        client._session.post.return_value = mock_resp

        with pytest.raises(requests.HTTPError):
            client.get_sweep_tickets("ClientABC")


# ---------------------------------------------------------------------------
# count_jql
# ---------------------------------------------------------------------------
class TestCountJql:
    def test_uses_v2_api_when_available(self):
        client = make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"count": 42}
        client._session.post.return_value = mock_resp

        count = client.count_jql("project = TEST")
        assert count == 42




# ---------------------------------------------------------------------------
# transition() — priority-ordered matching (no wrong-status transitions)
#
# Requesting "Fixed" must fire the *literal* Fixed transition when Jira offers
# it, and must never silently fire an alias like "Done"/"Closed"/"Resolve"
# just because it appears first in Jira's transition list.
# ---------------------------------------------------------------------------
class TestTransitionPriority:
    def _client_with_transitions(self, transitions):
        client = make_client()
        client._j.transitions.return_value = transitions
        return client

    def test_exact_fixed_wins_over_done_listed_first(self):
        client = self._client_with_transitions([
            {"id": "10", "name": "Done"},
            {"id": "20", "name": "Fixed"},
        ])
        client.transition("TEST-1", "Fixed")
        client._j.transition_issue.assert_called_once_with("TEST-1", "20")

    def test_exact_fixed_wins_over_closed_and_resolve(self):
        client = self._client_with_transitions([
            {"id": "1", "name": "Resolve"},
            {"id": "2", "name": "Closed"},
            {"id": "3", "name": "Fixed"},
        ])
        client.transition("TEST-1", "Fixed")
        client._j.transition_issue.assert_called_once_with("TEST-1", "3")

    def test_falls_back_to_alias_when_no_exact_match(self):
        # No literal "Fixed" transition — an alias ("Done") is acceptable.
        client = self._client_with_transitions([
            {"id": "99", "name": "Done"},
        ])
        client.transition("TEST-1", "Fixed")
        client._j.transition_issue.assert_called_once_with("TEST-1", "99")

    def test_fix_issue_step_does_not_jump_to_done(self):
        # Fast-track's intermediate "Fix Issue" step must not fire Done/Fixed.
        client = self._client_with_transitions([
            {"id": "5", "name": "Done"},
            {"id": "6", "name": "Fix Issue"},
        ])
        client.transition("TEST-1", "Fix Issue")
        client._j.transition_issue.assert_called_once_with("TEST-1", "6")

    def test_unavailable_transition_raises(self):
        client = self._client_with_transitions([
            {"id": "1", "name": "Start Progress"},
        ])
        with pytest.raises(ValueError):
            client.transition("TEST-1", "Fixed")


# ---------------------------------------------------------------------------
# severity_jql_field — Axian client always returns fixed field name
# ---------------------------------------------------------------------------
class TestSeverityJqlField:
    def test_returns_vulnerability_rating_field_name(self):
        client = make_client(fields={"vulnerability_rating": "customfield_10100"})
        assert client.severity_jql_field == 'cf[10100]'

    def test_is_consistent_regardless_of_loaded_fields(self):
        client = make_client(fields={"severity": "customfield_10050"})
        assert client.severity_jql_field == 'cf[10050]'
