import pytest
from unittest.mock import Mock, patch

from src.jira_client import JiraClient
from src.jira_client_v2 import JiraClientV2
from src.config import JiraConfig, JiraSecondaryConfig

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
    with patch("src.jira_client.JIRA"), patch("src.jira_client.requests"):
        with patch.object(JiraClient, "_load_fields"):
            client = JiraClient(make_jira_cfg())
    client._fields = fields or {}
    client._fetch_fields = "*all"
    client._session = Mock()
    client._j = Mock()
    return client

def test_jira_client_v1_os_field():
    client = make_client({
        "os[short text]": "customfield_10116",
        "os": "customfield_10117"
    })
    
    # Simulated ticket
    ticket = {
        "key": "TST-123",
        "fields": {
            "customfield_10117": "Windows Server 2019"
        }
    }
    
    serialized = client._serialize(ticket)
    assert serialized["os"] == "Windows Server 2019"

def test_jira_client_v2_os_field():
    cfg = JiraSecondaryConfig(
        url="https://test.com",
        api_token="test"
    )
    with patch("src.jira_client_v2.requests"):
        with patch.object(JiraClientV2, "_load_fields"):
            client = JiraClientV2(cfg)
    
    # Mock the field ids
    client._fields = {
        "os[short text]": "customfield_10116",
        "os": "customfield_10117"
    }
    
    # Simulated ticket
    ticket = {
        "key": "TST-124",
        "fields": {
            "customfield_10117": "Linux"
        }
    }
    
    serialized = client._serialize(ticket)
    assert serialized["os"] == "Linux"
