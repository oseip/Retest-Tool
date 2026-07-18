"""Tests for src/intake.py — duplicate matching, merge logic, and caching."""

import time

import src.intake as intake
from src.intake import (
    _merge_dedup,
    _match_finding_to_index,
    _normalize_title,
    _parse_cve_list,
    _index_from_tickets,
    _index_is_stale,
)


class TestNormalizeTitle:
    def test_openssl_version_family(self):
        raw = "OpenSSL 1.1.1k Multiple Vulnerabilities (CVE-2021-3449)"
        assert _normalize_title(raw) == "OpenSSL Multiple Vulnerabilities"

    def test_unchanged_when_no_pattern(self):
        title = "SSL Certificate Cannot Be Trusted"
        assert _normalize_title(title) == title

    def test_strips_whitespace(self):
        assert _normalize_title("  foo  ") == "foo"


class TestParseCveList:
    def test_comma_separated(self):
        assert _parse_cve_list("CVE-2021-3449, CVE-2020-1234") == [
            "CVE-2021-3449",
            "CVE-2020-1234",
        ]

    def test_empty(self):
        assert _parse_cve_list("") == []
        assert _parse_cve_list(None) == []


class TestMergeDedup:
    def _row(self, title, ip, port, cve="", cvss="5.0", rating="Medium"):
        return {
            "Vulnerability_Title": title,
            "_ip": ip,
            "_port": port,
            "CVE": cve,
            "CVSS": cvss,
            "Vulnerability_Rating": rating,
            "Technology": f"SSL,{port}" if port else "SSL",
        }

    def test_merges_same_title_ip_different_ports(self):
        rows = [
            self._row("SSL Certificate Cannot Be Trusted", "10.0.0.1", "443"),
            self._row("SSL Certificate Cannot Be Trusted", "10.0.0.1", "8443"),
        ]
        out = _merge_dedup(rows)
        assert len(out) == 1
        assert "443" in out[0]["Technology"]
        assert "8443" in out[0]["Technology"]

    def test_normalizes_title_before_dedup(self):
        rows = [
            self._row("OpenSSL 1.1.1k Multiple Vulnerabilities", "10.0.0.2", "443"),
            self._row("OpenSSL 1.0.2u Multiple Vulnerabilities", "10.0.0.2", "443"),
        ]
        out = _merge_dedup(rows)
        assert len(out) == 1
        assert out[0]["Vulnerability_Title"] == "OpenSSL Multiple Vulnerabilities"

    def test_keeps_highest_cvss_and_rating(self):
        rows = [
            self._row("Weak Cipher", "10.0.0.3", "443", cvss="5.0", rating="Medium"),
            self._row("Weak Cipher", "10.0.0.3", "8443", cvss="9.8", rating="Critical"),
        ]
        out = _merge_dedup(rows)
        assert len(out) == 1
        assert out[0]["CVSS"] == "9.8"
        assert out[0]["Vulnerability_Rating"] == "Critical"

    def test_merges_cve_lists(self):
        rows = [
            self._row("Foo", "10.0.0.4", "443", cve="CVE-2021-1111"),
            self._row("Foo", "10.0.0.4", "8443", cve="CVE-2021-2222"),
        ]
        out = _merge_dedup(rows)
        assert "CVE-2021-1111" in out[0]["CVE"]
        assert "CVE-2021-2222" in out[0]["CVE"]


class TestMatchFindingToIndex:
    def test_title_ip_port_match(self):
        title_index = {
            ("ssl certificate cannot be trusted", "10.1.1.1", "443"): "PROJ-1",
        }
        finding = {
            "Vulnerability_Title": "SSL Certificate Cannot Be Trusted",
            "System_IP": "10.1.1.1",
            "_ip": "10.1.1.1",
            "_port": "443",
        }
        key, kind = _match_finding_to_index(finding, title_index, {})
        assert key == "PROJ-1"
        assert kind == "title"

    def test_title_ip_without_port_fallback(self):
        title_index = {
            ("weak cipher suites", "10.1.1.2", ""): "PROJ-2",
        }
        finding = {
            "Vulnerability_Title": "Weak Cipher Suites",
            "System_IP": "10.1.1.2",
            "_ip": "10.1.1.2",
            "_port": "443",
        }
        key, kind = _match_finding_to_index(finding, title_index, {})
        assert key == "PROJ-2"
        assert kind == "title"

    def test_cve_fallback_when_title_differs(self):
        title_index = {}
        cve_index = {("CVE-2021-3449", "10.1.1.3"): "PROJ-3"}
        finding = {
            "Vulnerability_Title": "Some New Nessus Plugin Name",
            "System_IP": "10.1.1.3",
            "_ip": "10.1.1.3",
            "_port": "443",
            "CVE": "CVE-2021-3449",
        }
        key, kind = _match_finding_to_index(finding, title_index, cve_index)
        assert key == "PROJ-3"
        assert kind == "cve"

    def test_no_match(self):
        finding = {
            "Vulnerability_Title": "Brand New Finding",
            "System_IP": "10.1.1.4",
            "_ip": "10.1.1.4",
            "_port": "80",
        }
        key, kind = _match_finding_to_index(finding, {}, {})
        assert key is None
        assert kind is None

    def test_normalized_title_matches_jira_index(self):
        """Index stores normalised titles — finding with raw OpenSSL version must match."""
        title_index = {
            ("openssl multiple vulnerabilities", "10.1.1.5", "443"): "PROJ-4",
        }
        finding = {
            "Vulnerability_Title": "OpenSSL 1.1.1k Multiple Vulnerabilities",
            "System_IP": "10.1.1.5",
            "_ip": "10.1.1.5",
            "_port": "443",
        }
        key, kind = _match_finding_to_index(finding, title_index, {})
        assert key == "PROJ-4"
        assert kind == "title"


class TestIndexFromTickets:
    def test_builds_title_and_cve_indexes(self):
        tickets = [
            {
                "key": "PROJ-1",
                "summary": "SSL Certificate Cannot Be Trusted",
                "ips": ["10.0.0.1"],
                "ports": ["443"],
                "cves": ["CVE-2021-0001"],
            },
        ]
        title_index, cve_index = _index_from_tickets(tickets)
        assert title_index[("ssl certificate cannot be trusted", "10.0.0.1", "443")] == "PROJ-1"
        assert title_index[("ssl certificate cannot be trusted", "10.0.0.1", "")] == "PROJ-1"
        assert cve_index[("CVE-2021-0001", "10.0.0.1")] == "PROJ-1"

    def test_normalizes_versioned_titles(self):
        tickets = [{
            "key": "PROJ-2",
            "summary": "OpenSSL 1.1.1k Multiple Vulnerabilities",
            "ips": ["10.0.0.2"], "ports": ["443"], "cves": [],
        }]
        title_index, _ = _index_from_tickets(tickets)
        assert title_index[("openssl multiple vulnerabilities", "10.0.0.2", "443")] == "PROJ-2"

    def test_ticket_without_ip_indexed_with_blanks(self):
        tickets = [{"key": "PROJ-3", "summary": "Some Finding", "ips": [], "ports": [], "cves": []}]
        title_index, _ = _index_from_tickets(tickets)
        assert title_index[("some finding", "", "")] == "PROJ-3"


class TestIndexStaleness:
    def test_missing_fetched_at_is_stale(self):
        assert _index_is_stale({}) is True

    def test_recent_is_fresh(self):
        assert _index_is_stale({"fetched_at": time.time()}) is False

    def test_old_is_stale(self):
        old = time.time() - (intake._JIRA_CACHE_TTL + 60)
        assert _index_is_stale({"fetched_at": old}) is True


class TestJiraCacheRoundTrip:
    def test_save_and_load_rebuilds_index(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intake, "_JIRA_CACHE_DIR", str(tmp_path / "jira"))
        monkeypatch.setattr(intake, "_NESSUS_CACHE_DIR", str(tmp_path / "nessus"))
        with intake._INDEX_LOCK:
            intake._JIRA_INDEXES.pop("ACME", None)

        tickets = [
            {"key": "ACME-1", "summary": "Weak Cipher Suites",
             "ips": ["10.1.1.1"], "ports": ["443"], "cves": ["CVE-2020-1"]},
        ]
        intake._save_jira_cache("ACME", tickets, "https://jira.example.com", time.time())

        assert intake._load_jira_cache_into_memory("ACME") is True
        with intake._INDEX_LOCK:
            info = intake._JIRA_INDEXES["ACME"]
        assert info["status"] == "ready"
        assert info["from_cache"] is True
        assert info["count"] == 1
        assert info["index"][("weak cipher suites", "10.1.1.1", "443")] == "ACME-1"
        assert info["cve_index"][("CVE-2020-1", "10.1.1.1")] == "ACME-1"

    def test_load_missing_cache_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intake, "_JIRA_CACHE_DIR", str(tmp_path / "jira"))
        assert intake._load_jira_cache_into_memory("NOPE") is False


class TestNessusCacheRoundTrip:
    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intake, "_NESSUS_CACHE_DIR", str(tmp_path / "nessus"))
        rows = [{"Vulnerability_Title": "X", "_ip": "10.0.0.1", "_port": "443"}]
        intake._save_nessus_cache("ACME", 42, "Internal network", "Unauthenticated user",
                                  "My Scan", rows)
        cached = intake._load_nessus_cache("ACME", 42, "Internal network", "Unauthenticated user")
        assert cached is not None
        assert cached["scan_name"] == "My Scan"
        assert cached["findings"] == rows

    def test_cache_key_includes_vector_actor(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intake, "_NESSUS_CACHE_DIR", str(tmp_path / "nessus"))
        rows = [{"Vulnerability_Title": "X"}]
        intake._save_nessus_cache("ACME", 42, "Internal network", "Unauthenticated user",
                                  "S", rows)
        # Different vector → cache miss (risk values differ)
        assert intake._load_nessus_cache("ACME", 42, "External network",
                                         "Unauthenticated user") is None

    def test_missing_cache_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intake, "_NESSUS_CACHE_DIR", str(tmp_path / "nessus"))
        assert intake._load_nessus_cache("ACME", 999, "Internal network", "x") is None
