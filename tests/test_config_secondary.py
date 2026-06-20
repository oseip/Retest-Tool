"""
Tests for secondary-session additions to src/config.py

Covers:
- JiraSecondaryConfig construction and defaults
- Config with optional secondary fields
- Config.clients_secondary defaults to empty list
- load_config parses YAML with no secondary gracefully
- load_config parses YAML with jira_secondary and clients_secondary correctly
"""

import pytest
import textwrap
import tempfile
import os

from src.config import (
    Config, JiraConfig, JiraSecondaryConfig, JumpServerConfig,
    ClientConfig, AppConfig,
)
# Use the real load_config captured before the global mock patch is applied.
from tests.conftest import _real_load_config as load_config


# ---------------------------------------------------------------------------
# JiraSecondaryConfig
# ---------------------------------------------------------------------------

class TestJiraSecondaryConfig:
    def test_required_fields(self):
        cfg = JiraSecondaryConfig(url="https://tickets.test.com", api_token="my-pat")
        assert cfg.url == "https://tickets.test.com"
        assert cfg.api_token == "my-pat"

    def test_default_retest_status(self):
        cfg = JiraSecondaryConfig(url="https://x.com", api_token="tok")
        assert cfg.retest_status == "Remediated"

    def test_default_poll_interval(self):
        cfg = JiraSecondaryConfig(url="https://x.com", api_token="tok")
        assert cfg.poll_interval == 300

    def test_custom_retest_status(self):
        cfg = JiraSecondaryConfig(url="https://x.com", api_token="tok",
                                  retest_status="Ready for Retest")
        assert cfg.retest_status == "Ready for Retest"

    def test_custom_poll_interval(self):
        cfg = JiraSecondaryConfig(url="https://x.com", api_token="tok", poll_interval=60)
        assert cfg.poll_interval == 60


# ---------------------------------------------------------------------------
# Config — secondary fields
# ---------------------------------------------------------------------------

def _base_config(**kwargs) -> Config:
    defaults = dict(
        jira=JiraConfig(
            url="https://test.atlassian.net",
            username="u@t.com", api_token="tok", project="TEST",
        ),
        jump_server=JumpServerConfig(host="jump.example.com", port=22,
                                     user="admin", password="pass"),
        clients=[ClientConfig(label="C1", name="Client 1", kali_port=22,
                              kali_user="kali", kali_password="kp")],
    )
    defaults.update(kwargs)
    return Config(**defaults)


class TestConfigSecondaryFields:
    def test_jira_secondary_defaults_to_none(self):
        cfg = _base_config()
        assert cfg.jira_secondary is None

    def test_clients_secondary_defaults_to_empty_list(self):
        cfg = _base_config()
        assert cfg.clients_secondary == []

    def test_jira_secondary_can_be_set(self):
        j2 = JiraSecondaryConfig(url="https://tickets.test.com", api_token="pat")
        cfg = _base_config(jira_secondary=j2)
        assert cfg.jira_secondary is j2
        assert cfg.jira_secondary.url == "https://tickets.test.com"

    def test_clients_secondary_can_be_set(self):
        clients2 = [
            ClientConfig(label="CPEL", name="CPEL Client", kali_port=22,
                         kali_user="kali", kali_password="kp"),
        ]
        cfg = _base_config(clients_secondary=clients2)
        assert len(cfg.clients_secondary) == 1
        assert cfg.clients_secondary[0].label == "CPEL"

    def test_bool_of_secondary_false_when_none(self):
        cfg = _base_config()
        assert not bool(cfg.jira_secondary)

    def test_bool_of_secondary_true_when_set(self):
        cfg = _base_config(
            jira_secondary=JiraSecondaryConfig(url="https://x.com", api_token="t")
        )
        assert bool(cfg.jira_secondary)


# ---------------------------------------------------------------------------
# load_config — YAML parsing
# ---------------------------------------------------------------------------

def _write_yaml(content: str) -> str:
    """Write content to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))
    return path


_BASE_YAML = """
jira:
  url: https://test.atlassian.net
  username: u@t.com
  api_token: fake-token
  project: TEST
  retest_status: Remediated
  poll_interval: 60
jump_server:
  host: jump.example.com
  port: 22
  user: admin
  password: jumppass
clients:
  - label: TestClient
    name: Test Client
    kali_port: 22
    kali_user: kali
    kali_password: kp
"""


class TestLoadConfigSecondary:
    def test_no_secondary_fields_loads_cleanly(self):
        path = _write_yaml(_BASE_YAML)
        try:
            cfg = load_config(path)
            assert cfg.jira_secondary is None
            assert cfg.clients_secondary == []
        finally:
            os.unlink(path)

    def test_parses_jira_secondary_block(self):
        yaml = _BASE_YAML + textwrap.dedent("""
        jira_secondary:
          url: https://tickets.munit.ai
          api_token: my-pat-token
          retest_status: Remediated
          poll_interval: 120
        """)
        path = _write_yaml(yaml)
        try:
            cfg = load_config(path)
            assert cfg.jira_secondary is not None
            assert cfg.jira_secondary.url == "https://tickets.munit.ai"
            assert cfg.jira_secondary.api_token == "my-pat-token"
            assert cfg.jira_secondary.poll_interval == 120
        finally:
            os.unlink(path)

    def test_parses_clients_secondary_list(self):
        yaml = _BASE_YAML + textwrap.dedent("""
        jira_secondary:
          url: https://tickets.munit.ai
          api_token: my-pat-token
        clients_secondary:
          - label: CPEL
            name: CPEL Client
            kali_port: 2222
            kali_user: kali
            kali_password: kalipass
          - label: MTN
            name: MTN Client
            kali_port: 2223
            kali_user: kali
            kali_password: mtnpass
        """)
        path = _write_yaml(yaml)
        try:
            cfg = load_config(path)
            assert len(cfg.clients_secondary) == 2
            assert cfg.clients_secondary[0].label == "CPEL"
            assert cfg.clients_secondary[1].label == "MTN"
        finally:
            os.unlink(path)

    def test_missing_clients_secondary_key_gives_empty_list(self):
        yaml = _BASE_YAML + textwrap.dedent("""
        jira_secondary:
          url: https://tickets.munit.ai
          api_token: my-pat-token
        """)
        path = _write_yaml(yaml)
        try:
            cfg = load_config(path)
            assert cfg.clients_secondary == []
        finally:
            os.unlink(path)

    def test_empty_jira_secondary_block_gives_none(self):
        """A null/empty jira_secondary key should not crash."""
        yaml = _BASE_YAML + "jira_secondary:\n"
        path = _write_yaml(yaml)
        try:
            cfg = load_config(path)
            assert cfg.jira_secondary is None
        finally:
            os.unlink(path)

    def test_primary_clients_unaffected_by_secondary(self):
        yaml = _BASE_YAML + textwrap.dedent("""
        clients_secondary:
          - label: CPEL
            name: CPEL Client
            kali_port: 22
            kali_user: kali
            kali_password: kp
        """)
        path = _write_yaml(yaml)
        try:
            cfg = load_config(path)
            # Primary clients unchanged
            assert len(cfg.clients) == 1
            assert cfg.clients[0].label == "TestClient"
        finally:
            os.unlink(path)
