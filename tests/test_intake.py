"""Tests for src/intake.py — duplicate matching, merge logic, and caching."""

import time

import src.intake as intake
from src.intake import (
    _merge_dedup,
    _match_finding_to_index,
    _normalize_title,
    _family_key,
    _product_slug,
    _parse_cve_list,
    _index_from_tickets,
    _index_is_stale,
    _is_irrelevant,
    _index_hit,
    _classify_against_jira,
    _is_fixed_jira_status,
    _intake_exportable,
    _intake_pick_for_create,
)


class TestNormalizeTitle:
    def test_openssl_version_family(self):
        raw = "OpenSSL 1.1.1k Multiple Vulnerabilities (CVE-2021-3449)"
        assert _normalize_title(raw) == "OpenSSL Multiple Vulnerabilities"

    def test_openssh_version_family(self):
        assert _normalize_title("OpenSSH < 10.3 Multiple Vulnerabilities") == (
            "OpenSSH Multiple Vulnerabilities"
        )
        assert _normalize_title("OpenSSH < 9.8 RCE Multiple Vulnerabilities") == (
            "OpenSSH Multiple Vulnerabilities"
        )
        assert _product_slug("OpenSSH < 10.1 Multiple Vulnerabilities") == "openssh"
        # Config-style SSH findings must not collapse into the OpenSSH product family.
        assert _product_slug("SSH Weak Key Exchange Algorithms Enabled") is None

    def test_apache_version_family(self):
        assert _normalize_title("Apache HTTP Server 2.4.51 Multiple Vulnerabilities") == (
            "Apache HTTP Server Multiple Vulnerabilities"
        )

    def test_kibana_8x_nessus_title(self):
        raw = "Kibana 8.x < 8.19.16 / 9.0.x < 9.3.5 Multiple Vulnerabilities"
        assert _normalize_title(raw) == "Kibana Multiple Vulnerabilities"
        assert _product_slug(raw) == "kibana"

    def test_kibana_dos_title(self):
        raw = "Kibana 8.x < 8.19.16 DoS (ESA-2026-39)"
        assert _normalize_title(raw) == "Kibana Multiple Vulnerabilities"

    def test_grafana_labs_title(self):
        raw = "Grafana Labs < 11.6.2 Improper Input Validation"
        assert _normalize_title(raw) == "Grafana Multiple Vulnerabilities"
        assert _product_slug(raw) == "grafana"

    def test_grafana_labs_auth_title(self):
        raw = "Grafana Labs Incorrect Authorization"
        assert _product_slug(raw) == "grafana"

    def test_gitlab_version_family(self):
        assert _normalize_title("GitLab 16.7.2 Multiple Vulnerabilities") == (
            "GitLab Multiple Vulnerabilities"
        )

    def test_jira_summary_with_suffix(self):
        """Jira summaries often include IP/context after the title."""
        raw = "Apache HTTP Server 2.4.49 Multiple Vulnerabilities on 10.0.0.1"
        assert _normalize_title(raw) == "Apache HTTP Server Multiple Vulnerabilities"

    def test_unchanged_when_no_pattern(self):
        title = "SSL Certificate Cannot Be Trusted"
        assert _normalize_title(title) == title

    def test_strips_whitespace(self):
        assert _normalize_title("  foo  ") == "foo"


class TestFamilyKey:
    def test_returns_family_for_versioned_title(self):
        assert _family_key("Apache HTTP Server 2.4.51 Multiple Vulnerabilities") == (
            "apache http server multiple vulnerabilities"
        )

    def test_none_for_non_version_title(self):
        assert _family_key("Weak Cipher Suites Supported") is None


class TestIrrelevantFilter:
    def test_default_ssl_entries_excluded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intake, "_INTAKE_DATA_DIR", str(tmp_path))
        monkeypatch.setattr(intake, "_IRRELEVANT_PATH", str(tmp_path / "irrelevant.txt"))
        monkeypatch.setattr(intake, "_IRRELEVANT_LOADED", False)
        monkeypatch.setattr(intake, "_IRRELEVANT_SET", set())
        (tmp_path / "irrelevant.txt").write_text(
            "SSL Certificate Cannot Be Trusted\n", encoding="utf-8",
        )
        assert _is_irrelevant("SSL Certificate Cannot Be Trusted") is True
        assert _is_irrelevant("Apache HTTP Server 2.4.51 Multiple Vulnerabilities") is False


class TestTechnologyLabel:
    def test_ipmi_from_title(self):
        from src.intake import _technology, _technology_label, _rebuild_technology
        title = "IPMI v2.0 Password Hash Disclosure"
        assert _technology_label(title) == "IPMI"
        assert _technology(title, "623", "udp") == "IPMI,623"
        row = {"Vulnerability_Title": title, "Technology": "UDP,623,664", "_port": "623"}
        _rebuild_technology(row)
        assert row["Technology"] == "IPMI,623,664"

    def test_ssl_cipher_suite(self):
        from src.intake import _technology_label, _technology
        title = "SSL Medium Strength Cipher Suites Supported (SWEET32)"
        assert _technology_label(title) == "SSL"
        assert _technology(title, "443", "tcp") == "SSL,443"

    def test_openssh_version(self):
        from src.intake import _technology_label
        assert _technology_label("OpenSSH < 10.3 Multiple Vulnerabilities") == "OpenSSH"

    def test_tls_deprecated(self):
        from src.intake import _technology_label
        assert _technology_label("TLS Version 1.0 Protocol Detection") == "TLS"

    def test_never_uses_udp_as_label(self):
        from src.intake import _technology
        assert not _technology("IPMI v2.0 Password Hash Disclosure", "623", "udp").startswith("UDP")


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

    def test_merges_openssh_same_ip_different_versions(self):
        rows = [
            self._row("OpenSSH < 10.1 Multiple Vulnerabilities", "10.58.203.13", "22",
                       cve="CVE-2025-1111", cvss="7.0", rating="High"),
            self._row("OpenSSH < 10.3 Multiple Vulnerabilities", "10.58.203.13", "22",
                       cve="CVE-2025-2222", cvss="6.5", rating="Medium"),
            self._row("OpenSSH < 10.4 Multiple Vulnerabilities", "10.58.203.13", "22",
                       cve="CVE-2025-3333", cvss="5.0", rating="Low"),
            self._row("OpenSSH < 10.1 Multiple Vulnerabilities", "10.58.203.14", "22",
                       cve="CVE-2025-4444"),
        ]
        out = _merge_dedup(rows)
        assert len(out) == 2
        by_ip = {r["_ip"]: r for r in out}
        assert by_ip["10.58.203.13"]["Vulnerability_Title"] == "OpenSSH Multiple Vulnerabilities"
        assert by_ip["10.58.203.13"]["Vulnerability_Rating"] == "High"
        assert by_ip["10.58.203.13"]["_merged_count"] == 3
        assert "CVE-2025-1111" in by_ip["10.58.203.13"]["CVE"]
        assert "CVE-2025-3333" in by_ip["10.58.203.13"]["CVE"]
        assert by_ip["10.58.203.14"]["_merged_count"] == 1

    def test_merges_many_kibana_same_ip_port(self):
        rows = [
            self._row("Kibana 8.x < 8.19.16 / 9.0.x < 9.3.5 Multiple Vuln", "10.228.13.22", "5601",
                       cve="CVE-2026-56151", cvss="8.5", rating="High"),
            self._row("Kibana 8.x < 8.19.16 DoS (ESA-2026-39)", "10.228.13.22", "5601",
                       cve="CVE-2026-49094", cvss="6.8", rating="Medium"),
            self._row("Kibana Multiple Vulnerabilities", "10.228.13.22", "5601",
                       cve="CVE-2026-0532", cvss="7.7", rating="Medium"),
        ]
        out = _merge_dedup(rows)
        assert len(out) == 1
        assert out[0]["Vulnerability_Title"] == "Kibana Multiple Vulnerabilities"
        assert out[0]["Vulnerability_Rating"] == "High"
        assert "CVE-2026-56151" in out[0]["CVE"]
        assert "CVE-2026-49094" in out[0]["CVE"]
        assert out[0]["_merged_count"] == 3

    def test_merges_nginx_same_ip_different_ports(self):
        rows = [
            self._row("nginx Multiple Vulnerabilities", "10.228.27.220", "80", cve="CVE-2026-1642"),
            self._row("nginx Multiple Vulnerabilities", "10.228.27.220", "443", cve="CVE-2026-1642"),
        ]
        out = _merge_dedup(rows)
        assert len(out) == 1
        assert "80" in out[0]["Technology"]
        assert "443" in out[0]["Technology"]
        assert out[0]["Technology"].startswith("nginx,")

    def test_tls_versions_merge_and_normalize(self):
        from src.intake import _normalize_title, _product_slug
        assert _normalize_title("TLS Version 1.0 Protocol Detection") == "TLS Deprecated Protocol"
        assert _normalize_title("TLS Version 1.1 Deprecated Protocol") == "TLS Deprecated Protocol"
        assert _product_slug("TLS Version 1.0 Protocol Detection") == "tls"
        rows = [
            self._row("TLS Version 1.0 Protocol Detection", "10.228.10.47", "8443"),
            self._row("TLS Version 1.1 Deprecated Protocol", "10.228.10.47", "8443"),
        ]
        out = _merge_dedup(rows)
        assert len(out) == 1
        assert out[0]["Vulnerability_Title"] == "TLS Deprecated Protocol"
        assert out[0]["Technology"].startswith("TLS,")

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


class TestClassifyAgainstJira:
    def test_no_match_is_new(self):
        row = _classify_against_jira(None, "", None)
        assert row["status"] == "new"
        assert row["recurrence_of"] is None

    def test_open_ticket_is_duplicate(self):
        row = _classify_against_jira("AXG-100", "Open", "product")
        assert row["status"] == "duplicate"
        assert row["duplicate_of"] == "AXG-100"
        assert row["recurrence_of"] is None

    def test_fixed_ticket_is_recurrence(self):
        row = _classify_against_jira("AXG-49159", "Fixed", "product")
        assert row["status"] == "recurrence"
        assert row["recurrence_of"] == "AXG-49159"
        assert row["previous_jira_status"] == "Fixed"
        assert row["duplicate_of"] is None

    def test_remediated_open_ticket_stays_duplicate(self):
        row = _classify_against_jira("AXG-200", "Remediated", "product")
        assert row["status"] == "duplicate"

    def test_is_fixed_jira_status(self):
        assert _is_fixed_jira_status("Fixed") is True
        assert _is_fixed_jira_status("closed") is True
        assert _is_fixed_jira_status("Open") is False
        assert _is_fixed_jira_status("Remediated") is False


class TestMatchFindingToIndex:
    def _empty_indexes(self):
        return {}, {}, {}, {}

    def test_title_ip_port_match(self):
        hit = _index_hit("PROJ-1", "Open")
        title_index = {("ssl certificate cannot be trusted", "10.1.1.1", "443"): hit}
        finding = {
            "Vulnerability_Title": "SSL Certificate Cannot Be Trusted",
            "System_IP": "10.1.1.1",
            "_ip": "10.1.1.1",
            "_port": "443",
        }
        key, kind, status = _match_finding_to_index(finding, title_index, {}, {}, {})
        assert key == "PROJ-1"
        assert kind == "title"
        assert status == "Open"

    def test_title_ip_without_port_fallback(self):
        hit = _index_hit("PROJ-2", "Remediated")
        title_index = {("weak cipher suites", "10.1.1.2", ""): hit}
        finding = {
            "Vulnerability_Title": "Weak Cipher Suites",
            "System_IP": "10.1.1.2",
            "_ip": "10.1.1.2",
            "_port": "443",
        }
        key, kind, status = _match_finding_to_index(finding, title_index, {}, {}, {})
        assert key == "PROJ-2"
        assert kind == "title"
        assert status == "Remediated"

    def test_cve_fallback_when_title_differs(self):
        hit = _index_hit("PROJ-3", "Open")
        cve_index = {("CVE-2021-3449", "10.1.1.3"): hit}
        finding = {
            "Vulnerability_Title": "Some New Nessus Plugin Name",
            "System_IP": "10.1.1.3",
            "_ip": "10.1.1.3",
            "_port": "443",
            "CVE": "CVE-2021-3449",
        }
        key, kind, status = _match_finding_to_index(finding, {}, cve_index, {}, {})
        assert key == "PROJ-3"
        assert kind == "cve"
        assert status == "Open"

    def test_no_match(self):
        finding = {
            "Vulnerability_Title": "Brand New Finding",
            "System_IP": "10.1.1.4",
            "_ip": "10.1.1.4",
            "_port": "80",
        }
        key, kind, status = _match_finding_to_index(finding, *self._empty_indexes())
        assert key is None
        assert kind is None
        assert status == ""

    def test_normalized_title_matches_jira_index(self):
        hit = _index_hit("PROJ-4", "Open")
        title_index = {("openssl multiple vulnerabilities", "10.1.1.5", "443"): hit}
        finding = {
            "Vulnerability_Title": "OpenSSL 1.1.1k Multiple Vulnerabilities",
            "System_IP": "10.1.1.5",
            "_ip": "10.1.1.5",
            "_port": "443",
        }
        key, kind, _ = _match_finding_to_index(finding, title_index, {}, {}, {})
        assert key == "PROJ-4"
        assert kind == "title"

    def test_family_match_across_apache_versions(self):
        """New scan Apache 2.4.51 matches Jira ticket for Apache 2.4.49 via family index."""
        hit = _index_hit("PROJ-5", "Open")
        family_index = {
            ("apache http server multiple vulnerabilities", "10.1.1.6", "443"): hit,
        }
        finding = {
            "Vulnerability_Title": "Apache HTTP Server 2.4.51 Multiple Vulnerabilities",
            "System_IP": "10.1.1.6",
            "_ip": "10.1.1.6",
            "_port": "443",
        }
        key, kind, status = _match_finding_to_index(finding, {}, {}, family_index, {})
        assert key == "PROJ-5"
        assert kind == "family"
        assert status == "Open"

    def test_tls_product_dup_same_ip_port(self):
        hit = _index_hit("AXG-31644", "Fixed")
        product_index = {("tls", "10.228.10.47", "8443"): hit}
        finding = {
            "Vulnerability_Title": "TLS Version 1.1 Deprecated Protocol",
            "System_IP": "10.228.10.47",
            "_ip": "10.228.10.47",
            "_port": "8443",
            "_product": "tls",
        }
        key, kind, status = _match_finding_to_index(finding, {}, {}, {}, product_index)
        assert key == "AXG-31644"
        assert kind == "product"
        assert status == "Fixed"

    def test_grafana_product_match_same_ip_port(self):
        """Any Grafana on IP:port dupes when one Grafana ticket exists in Jira."""
        hit = _index_hit("AXG-40951", "Open")
        product_index = {("grafana", "10.228.27.19", "3000"): hit}
        finding = {
            "Vulnerability_Title": "Grafana Labs < 11.6.2 Improper Input Validation",
            "System_IP": "10.228.27.19",
            "_ip": "10.228.27.19",
            "_port": "3000",
        }
        key, kind, status = _match_finding_to_index(finding, {}, {}, {}, product_index)
        assert key == "AXG-40951"
        assert kind == "product"
        assert status == "Open"


class TestIndexFromTickets:
    def test_builds_title_and_cve_indexes(self):
        tickets = [
            {
                "key": "PROJ-1",
                "summary": "SSL Certificate Cannot Be Trusted",
                "status": "Open",
                "ips": ["10.0.0.1"],
                "ports": ["443"],
                "cves": ["CVE-2021-0001"],
            },
        ]
        title_index, cve_index, family_index, product_index = _index_from_tickets(tickets)
        hit = title_index[("ssl certificate cannot be trusted", "10.0.0.1", "443")]
        assert hit["key"] == "PROJ-1"
        assert hit["status"] == "Open"
        cve_hit = cve_index[("CVE-2021-0001", "10.0.0.1")]
        assert cve_hit["key"] == "PROJ-1"

    def test_normalizes_versioned_titles(self):
        tickets = [{
            "key": "PROJ-2",
            "summary": "OpenSSL 1.1.1k Multiple Vulnerabilities",
            "status": "Open",
            "ips": ["10.0.0.2"], "ports": ["443"], "cves": [],
        }]
        title_index, _, family_index, _ = _index_from_tickets(tickets)
        assert title_index[("openssl multiple vulnerabilities", "10.0.0.2", "443")]["key"] == "PROJ-2"
        assert family_index[("openssl multiple vulnerabilities", "10.0.0.2", "443")]["key"] == "PROJ-2"

    def test_indexes_apache_family_for_versioned_jira_summary(self):
        tickets = [{
            "key": "PROJ-3",
            "summary": "Apache HTTP Server 2.4.49 Multiple Vulnerabilities",
            "status": "Remediated",
            "ips": ["10.0.0.3"], "ports": ["443"], "cves": [],
        }]
        _, _, family_index, product_index = _index_from_tickets(tickets)
        fam = "apache http server multiple vulnerabilities"
        assert family_index[(fam, "10.0.0.3", "443")]["key"] == "PROJ-3"
        assert product_index[("apache", "10.0.0.3", "443")]["key"] == "PROJ-3"

    def test_indexes_grafana_by_product_slug(self):
        tickets = [{
            "key": "AXG-1",
            "summary": "Grafana Labs Incorrect Authorization",
            "status": "Open",
            "ips": ["10.228.27.19"], "ports": ["3000"], "cves": [],
        }]
        _, _, _, product_index = _index_from_tickets(tickets)
        assert product_index[("grafana", "10.228.27.19", "3000")]["key"] == "AXG-1"

    def test_ticket_without_ip_indexed_with_blanks(self):
        tickets = [{"key": "PROJ-4", "summary": "Some Finding", "status": "Open",
                    "ips": [], "ports": [], "cves": []}]
        title_index, _, _, _ = _index_from_tickets(tickets)
        assert title_index[("some finding", "", "")]["key"] == "PROJ-4"


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
            {"key": "ACME-1", "summary": "Weak Cipher Suites", "status": "Open",
             "ips": ["10.1.1.1"], "ports": ["443"], "cves": ["CVE-2020-1"]},
        ]
        intake._save_jira_cache("ACME", tickets, "https://jira.example.com", time.time())

        assert intake._load_jira_cache_into_memory("ACME") is True
        with intake._INDEX_LOCK:
            info = intake._JIRA_INDEXES["ACME"]
        assert info["status"] == "ready"
        assert info["from_cache"] is True
        assert info["count"] == 1
        hit = info["index"][("weak cipher suites", "10.1.1.1", "443")]
        assert hit["key"] == "ACME-1"
        assert info["cve_index"][("CVE-2020-1", "10.1.1.1")]["key"] == "ACME-1"
        assert info["key_index"]["ACME-1"] == "Open"

    def test_outdated_cache_without_status_is_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intake, "_JIRA_CACHE_DIR", str(tmp_path / "jira"))
        intake._ensure_cache_dirs()
        path = intake._jira_cache_path("OLD")
        intake._atomic_write_json(path, {
            "cache_version": 1,
            "label": "OLD",
            "jira_url": "https://jira.example.com",
            "fetched_at": time.time(),
            "count": 1,
            "tickets": [{"key": "OLD-1", "summary": "x", "status": "", "ips": [], "ports": [], "cves": []}],
        })
        assert intake._load_jira_cache_into_memory("OLD") is False

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
        assert intake._load_nessus_cache("ACME", 42, "External network",
                                         "Unauthenticated user") is None

    def test_missing_cache_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(intake, "_NESSUS_CACHE_DIR", str(tmp_path / "nessus"))
        assert intake._load_nessus_cache("ACME", 999, "Internal network", "x") is None


class TestIntakeCreateSelection:
    def test_exportable_excludes_duplicate_and_created(self):
        rows = [
            {"_id": 0, "_status": "new"},
            {"_id": 1, "_status": "recurrence"},
            {"_id": 2, "_status": "duplicate"},
            {"_id": 3, "_status": "new", "_jira_key": "AXG-1"},
        ]
        assert _intake_exportable(rows[0]) is True
        assert _intake_exportable(rows[1]) is True
        assert _intake_exportable(rows[2]) is False
        assert _intake_exportable(rows[3]) is False
        picked = _intake_pick_for_create(rows, "new")
        assert [r["_id"] for r in picked] == [0, 1]
