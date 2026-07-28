"""Tests for src/intake_jira.py — Jira create payload from Intake findings."""

from unittest.mock import MagicMock

from src.intake_jira import (
    build_intake_issue_fields,
    _description_text,
    _issue_labels,
    _other_information_block,
    _cvss_select_value,
)


class _FakeJira:
    def __init__(self, fields=None):
        self._fields = {k.lower(): v for k, v in (fields or {}).items()}

    def _fid(self, name: str):
        return self._fields.get(name.lower())


def test_issue_labels_axian_client_tag():
    finding = {
        "System_IP": "10.0.0.1",
        "_port": "22",
        "Technology": "SSH,22",
        "CVE": "CVE-2024-1000",
    }
    labels = _issue_labels(finding, "YasMGTel", tag_client=True)
    assert "YasMGTel" in labels
    assert "10.0.0.1" in labels
    assert "22" in labels
    assert "SSH" in labels
    assert "CVE-2024-1000" in labels


def test_recurrence_note_in_description():
    text = _description_text({
        "Vulnerability_Description": "Vuln text",
        "Recommendation": "Fix it",
        "_recurrence_of": "AXG-100",
        "_previous_jira_status": "Fixed",
    })
    assert "Recurrence" in text
    assert "AXG-100" in text
    assert "Fix it" in text


def test_build_fields_v3_maps_custom_fields():
    jira = _FakeJira({
        "technology": "customfield_10001",
        "cvss": "customfield_10002",
        "vulnerability_rating": "customfield_10003",
        "otherinformation[paragraph]": "customfield_10004",
    })
    finding = {
        "Vulnerability_Title": "SSH Weak MAC",
        "Vulnerability_Description": "Desc",
        "Recommendation": "Rec",
        "System_IP": "10.0.0.5",
        "_port": "22",
        "Technology": "SSH,22",
        "Vulnerability_Rating": "Low",
        "CVSS": "3.0",
        "Impact_Type": "Internal operations impact",
        "Vector": "Internal network",
        "Actor": "Unauthenticated user",
        "CIA_Damage": "Confidentiality",
        "Risk_Value": "1.2",
        "OS": "Linux",
        "Affected_System": "Linux server",
    }
    engagement = {
        "test_type": "IPT",
        "tester": "test@example.com",
        "date_started": "25/07/2026",
        "customer": "Acme",
    }
    fields = build_intake_issue_fields(
        jira, finding, engagement,
        project_key="AXG",
        client_label="TestClient",
        tag_client_label=True,
        is_v3=True,
    )
    assert fields["project"] == {"key": "AXG"}
    assert fields["issuetype"] == {"name": "Bug"}
    assert fields["summary"] == "SSH Weak MAC"
    assert "TestClient" in fields["labels"]
    assert fields["customfield_10001"]["type"] == "doc"
    assert fields["customfield_10001"]["content"][0]["content"][0]["text"] == "SSH,22"
    assert fields["customfield_10002"] == {"value": "3"}
    assert fields["customfield_10003"] == "Low"
    assert fields["description"]["type"] == "doc"
    assert fields["customfield_10004"]["type"] == "doc"
    assert fields["customfield_10004"]["content"][0]["content"][0]["text"].startswith("Tester")


def test_cvss_select_buckets_to_1_10():
    assert _cvss_select_value("7.5") == "8"
    assert _cvss_select_value("0") == "N/A"
    assert _cvss_select_value("") == "N/A"
    assert _cvss_select_value("10.2") == "10"


def test_textarea_fields_use_adf_on_v3():
    jira = _FakeJira({
        "impact_type": "customfield_10053",
        "affected_system": "customfield_10051",
        "otherinformation": "customfield_10057",
    })
    fields = build_intake_issue_fields(
        jira,
        {"Vulnerability_Title": "Test", "Impact_Type": "Internal operations impact", "Affected_System": "Linux"},
        {"test_type": "IPT", "customer": "Acme"},
        project_key="AXG",
        client_label="Client",
        tag_client_label=True,
        is_v3=True,
    )
    for fid in ("customfield_10051", "customfield_10053", "customfield_10057"):
        assert fields[fid]["type"] == "doc"
        assert fields[fid]["version"] == 1


def test_other_information_block():
    block = _other_information_block({
        "tester": "a@b.com",
        "date_started": "01/01/2026",
        "customer": "Client Co",
    })
    assert "Tester" in block
    assert "a@b.com" in block
    assert "Client Co" in block
