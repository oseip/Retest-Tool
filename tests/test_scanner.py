"""
Tests for src/scanner.py

Covers:
- _queue_ticket()    — correct job structure, source field, nmap command
- Nmap command       — ###XML### sentinel is embedded, not a standalone line
- Poll cleanup logic — only removes "poll"-sourced jobs, not sweep/manual
- stop_scan()        — returns True when event found, False otherwise
- XML sentinel       — emit() must match sentinel exactly (not as substring)
- run_triage()       — fast reachability check used to flag likely-fixed tickets
"""

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import src.scanner as scanner
from tests.conftest import make_ticket, _poll_patch


# ---------------------------------------------------------------------------
# _queue_ticket — job structure
# ---------------------------------------------------------------------------

class TestQueueTicket:
    def test_returns_job_id_and_adds_to_jobs(self):
        ticket = make_ticket()
        job_id = scanner._queue_ticket(ticket, "TestClient")
        assert job_id in scanner.JOBS

    def test_job_fields_are_set_correctly(self):
        ticket = make_ticket(key="TEST-99", summary="SSL Certificate Expiry on 10.0.0.1")
        job_id = scanner._queue_ticket(ticket, "TestClient", source="manual")
        job = scanner.JOBS[job_id]

        assert job["ticket_key"] == "TEST-99"
        assert job["ticket_summary"] == "SSL Certificate Expiry on 10.0.0.1"
        assert job["client_label"] == "TestClient"
        assert job["ip"] == "10.0.0.1"
        assert job["status"] == "queued"
        assert job["verdict"] is None
        assert job["output_lines"] == []
        assert job["jira_updated"] is False
        assert job["source"] == "manual"

    def test_default_source_is_poll(self):
        ticket = make_ticket()
        job_id = scanner._queue_ticket(ticket, "TestClient")
        assert scanner.JOBS[job_id]["source"] == "poll"

    def test_sweep_source_stored(self):
        ticket = make_ticket()
        job_id = scanner._queue_ticket(ticket, "TestClient", source="sweep")
        assert scanner.JOBS[job_id]["source"] == "sweep"

    def test_ip_extracted_from_ticket(self):
        ticket = make_ticket(ips=["192.168.1.50"])
        job_id = scanner._queue_ticket(ticket, "TestClient")
        assert scanner.JOBS[job_id]["ip"] == "192.168.1.50"

    def test_no_ip_in_ticket(self):
        ticket = make_ticket(ips=[])
        job_id = scanner._queue_ticket(ticket, "TestClient")
        assert scanner.JOBS[job_id]["ip"] is None

    def test_port_from_ticket_labels(self):
        ticket = make_ticket(ports=["8443"])
        job_id = scanner._queue_ticket(ticket, "TestClient")
        assert scanner.JOBS[job_id]["port"] == 8443

    def test_rule_matched_for_ssl_expiry(self):
        ticket = make_ticket(summary="SSL Certificate Expiry on 10.0.0.1")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        job = scanner.JOBS[job_id]
        assert job["rule_name"] is not None

    def test_no_rule_for_unknown_summary(self):
        ticket = make_ticket(summary="Unknown vulnerability type XYZ-9999")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        job = scanner.JOBS[job_id]
        assert job["rule_name"] is None
        assert job["nmap_command"] is None

    def test_nmap_command_built_for_ssl_expiry(self):
        ticket = make_ticket(
            summary="SSL Certificate Expiry on 10.0.0.1",
            ips=["10.0.0.1"],
            ports=["443"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert cmd is not None
        assert "nmap" in cmd
        assert "10.0.0.1" in cmd
        assert "443" in cmd

    def test_non_root_rule_does_not_use_sudo(self):
        ticket = make_ticket(
            summary="SSL Certificate Expiry on 10.0.0.1",
            ips=["10.0.0.1"],
            ports=["443"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert cmd.startswith("nmap ")
        assert "sudo" not in cmd

    def test_udp_rule_uses_sudo(self):
        ticket = make_ticket(
            summary="Portable SDK for UPnP Devices (libupnp)",
            ips=["10.0.0.1"],
            ports=["1900"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert cmd.startswith("sudo nmap ")

    def test_nmap_command_contains_xml_sentinel(self):
        # The sentinel must be embedded so the emit() function collects XML inline
        ticket = make_ticket(
            summary="SSL Certificate Expiry on 10.0.0.1",
            ips=["10.0.0.1"],
            ports=["443"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "###XML###" in cmd

    def test_smb_null_command_includes_smbclient(self):
        ticket = make_ticket(
            summary="SMB NULL Session Authentication",
            ips=["10.135.159.39"],
            ports=["445"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "smb-enum-shares" in cmd
        assert "###SMBCLIENT###" in cmd
        assert 'smbclient -L //10.135.159.39 -U "" -N' in cmd

    def test_mongodb_command_includes_mongosh_when_available(self):
        ticket = make_ticket(
            summary="MongoDB Unauthenticated Access",
            ips=["10.0.0.1"],
            ports=["27017"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "mongodb-info" in cmd
        assert "###MONGOSH###" in cmd
        assert "command -v mongosh" in cmd
        assert 'mongosh "mongodb://10.0.0.1:27017/"' in cmd
        assert "listDatabases" in cmd

    def test_nfs_shares_command_includes_showmount(self):
        ticket = make_ticket(
            summary="NFS Shares Accessible",
            ips=["10.0.0.1"],
            ports=["2049"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "nfs-showmount" in cmd
        assert "###SHOWMOUNT###" in cmd
        assert "command -v showmount" in cmd
        assert "showmount -e 10.0.0.1" in cmd

    def test_ftp_anonymous_command_includes_ftp_login(self):
        ticket = make_ticket(
            summary="FTP Anonymous Access",
            ips=["10.0.0.1"],
            ports=["21"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "ftp-anon" in cmd
        assert "###FTP###" in cmd
        assert "command -v ftp" in cmd
        assert "user anonymous anonymous@" in cmd
        assert "ftp -nv 10.0.0.1 21" in cmd

    def test_idrac_command_includes_redfish_curl(self):
        ticket = make_ticket(
            summary="Dell EMC iDRAC Multiple Vulnerabilities",
            ips=["10.0.0.1"],
            ports=["443"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "http-server-header" in cmd
        assert "###CURL###" in cmd
        assert "command -v curl" in cmd
        assert "redfish/v1/Managers/iDRAC.Embedded.1" in cmd
        assert "https://10.0.0.1:443" in cmd

    def test_activemq_command_includes_web_console_curl(self):
        ticket = make_ticket(
            summary="ActiveMQ RCE CVE-2023-46604",
            ips=["10.0.0.1"],
            ports=["61616"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "banner" in cmd
        assert "###CURL###" in cmd
        assert "8161/admin/" in cmd
        assert "http://10.0.0.1:8161" in cmd

    def test_activemq_multiple_vulns_command_includes_web_console(self):
        ticket = make_ticket(
            summary="Apache ActiveMQ 5.17 Multiple Vulnerabilities",
            ips=["10.0.0.1"],
            ports=["61616"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "banner" in cmd
        assert "###CURL###" in cmd
        assert "8161/admin/" in cmd

    def test_tomcat_version_command_includes_curl(self):
        ticket = make_ticket(
            summary="Apache Tomcat 9.0.35 Multiple Vulnerabilities",
            ips=["10.0.0.1"],
            ports=["8080"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "http-server-header" in cmd
        assert "###CURL###" in cmd
        assert "curl -sk -I" in cmd
        assert "VERSION.txt" in cmd
        assert "http://10.0.0.1:8080" in cmd

    def test_http_trace_command_uses_http_trace_and_track_curl(self):
        ticket = make_ticket(
            summary="HTTP TRACE Method Enabled",
            ips=["10.0.0.1"],
            ports=["80"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "http-trace" in cmd
        assert "http-methods" not in cmd
        assert "###CURL###" in cmd
        assert "-X TRACK" in cmd
        assert "http://10.0.0.1:80" in cmd

    def test_nmap_command_contains_job_id_in_tmp_path(self):
        ticket = make_ticket(summary="SSL Certificate Expiry on 10.0.0.1")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert job_id in cmd

    def test_curl_command_for_curl_tool(self, sample_ticket):
        # Find a rule that uses curl (e.g. HTTP redirect / missing security header)
        # If no curl rule exists this test is skipped
        from src.vuln_rules import match_rule
        curl_summaries = [
            "Missing HTTP Security Headers",
            "HTTP to HTTPS Redirect Missing",
            "Insecure HTTP Methods Enabled",
        ]
        curl_ticket = None
        for summary in curl_summaries:
            rule = match_rule(summary)
            if rule and rule.tool == "curl":
                curl_ticket = make_ticket(summary=summary, ips=["10.0.0.1"], ports=["80"])
                break
        if curl_ticket is None:
            pytest.skip("No curl-based rule found in vuln_rules")

        job_id = scanner._queue_ticket(curl_ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert "curl" in cmd
        # curl jobs must NOT contain the ###XML### sentinel
        assert "###XML###" not in cmd


# ---------------------------------------------------------------------------
# Poll cleanup logic
# ---------------------------------------------------------------------------

class TestPollJiraStop:
    """
    poll_jira() must exit its loop as soon as _poll_stop is set, so that
    reload_runtime_config() (src/main.py) can retire one poller thread and
    start a fresh one against a newly-saved config without orphaning threads.

    conftest.py replaces scanner.poll_jira with a session-wide MagicMock (so
    other tests don't spin up a real background thread), so these tests
    briefly restore the real function to exercise its actual loop logic.
    """

    def _call_real_poll_jira(self, cfg):
        _poll_patch.stop()
        try:
            scanner.poll_jira(cfg)
        finally:
            _poll_patch.start()

    def test_exits_immediately_when_poll_stop_already_set(self):
        with patch("src.scanner.JiraClient"), patch("src.scanner.run_poll_cycle") as mock_run:
            scanner._poll_stop.set()
            try:
                self._call_real_poll_jira(SimpleNamespace(jira=SimpleNamespace(poll_interval=60)))
            finally:
                scanner._poll_stop.clear()
            mock_run.assert_not_called()

    def test_runs_one_cycle_then_stops_when_signaled_mid_loop(self):
        def _stop(*a, **kw):
            # Mirrors reload_runtime_config(): set _poll_stop AND wake the
            # event being waited on, so the loop doesn't sit out the full
            # poll_interval before noticing the stop signal.
            scanner._poll_stop.set()
            scanner._wake_poll.set()

        with patch("src.scanner.JiraClient"), patch("src.scanner.run_poll_cycle") as mock_run:
            mock_run.side_effect = _stop
            try:
                self._call_real_poll_jira(SimpleNamespace(jira=SimpleNamespace(poll_interval=60)))
            finally:
                scanner._poll_stop.clear()
            mock_run.assert_called_once()


class TestPollCleanup:
    """
    Directly exercise the cleanup logic from poll_jira to verify it only
    removes 'poll'-sourced jobs and ignores sweep/manual/scanning jobs.
    """

    def _run_cleanup(self, client_label, current_keys):
        """Mirror the cleanup block from scanner.poll_jira."""
        with scanner._lock:
            for job_id, job in list(scanner.JOBS.items()):
                if (job["client_label"] == client_label
                        and job.get("source", "poll") == "poll"
                        and job["ticket_key"] not in current_keys
                        and job["status"] != "scanning"):
                    del scanner.JOBS[job_id]
                    scanner.SEEN_KEYS.discard(job["ticket_key"])

    def _add_job(self, job_id, ticket_key, source, status="queued"):
        scanner.JOBS[job_id] = {
            "id": job_id,
            "ticket_key": ticket_key,
            "client_label": "TestClient",
            "source": source,
            "status": status,
            "output_lines": [],
        }
        scanner.SEEN_KEYS.add(ticket_key)

    def test_poll_job_removed_when_not_in_current_keys(self):
        self._add_job("job-1", "TEST-100", "poll")
        self._run_cleanup("TestClient", current_keys=set())
        assert "job-1" not in scanner.JOBS
        assert "TEST-100" not in scanner.SEEN_KEYS

    def test_sweep_job_preserved_even_when_not_in_current_keys(self):
        self._add_job("job-2", "TEST-200", "sweep")
        self._run_cleanup("TestClient", current_keys=set())
        assert "job-2" in scanner.JOBS
        assert "TEST-200" in scanner.SEEN_KEYS

    def test_manual_job_preserved_even_when_not_in_current_keys(self):
        self._add_job("job-3", "TEST-300", "manual")
        self._run_cleanup("TestClient", current_keys=set())
        assert "job-3" in scanner.JOBS
        assert "TEST-300" in scanner.SEEN_KEYS

    def test_scanning_poll_job_not_removed(self):
        # A poll job that is currently scanning must never be removed mid-scan
        self._add_job("job-4", "TEST-400", "poll", status="scanning")
        self._run_cleanup("TestClient", current_keys=set())
        assert "job-4" in scanner.JOBS

    def test_poll_job_in_current_keys_not_removed(self):
        self._add_job("job-5", "TEST-500", "poll")
        self._run_cleanup("TestClient", current_keys={"TEST-500"})
        assert "job-5" in scanner.JOBS

    def test_only_target_client_jobs_removed(self):
        self._add_job("job-6", "TEST-600", "poll")
        scanner.JOBS["job-6"]["client_label"] = "OtherClient"
        self._run_cleanup("TestClient", current_keys=set())
        assert "job-6" in scanner.JOBS  # wrong client — should NOT be removed

    def test_mixed_sources_only_poll_removed(self):
        self._add_job("job-poll",   "TEST-101", "poll")
        self._add_job("job-sweep",  "TEST-102", "sweep")
        self._add_job("job-manual", "TEST-103", "manual")
        self._run_cleanup("TestClient", current_keys=set())
        assert "job-poll"   not in scanner.JOBS
        assert "job-sweep"  in scanner.JOBS
        assert "job-manual" in scanner.JOBS

    def test_implicit_poll_source_removed(self):
        # Jobs without 'source' field default to 'poll' (legacy compatibility)
        scanner.JOBS["job-legacy"] = {
            "id": "job-legacy",
            "ticket_key": "TEST-999",
            "client_label": "TestClient",
            # no 'source' key
            "status": "queued",
            "output_lines": [],
        }
        scanner.SEEN_KEYS.add("TEST-999")
        self._run_cleanup("TestClient", current_keys=set())
        assert "job-legacy" not in scanner.JOBS


# ---------------------------------------------------------------------------
# XML sentinel matching in emit()
# ---------------------------------------------------------------------------

class TestEmitSentinel:
    """
    Verify the critical fix: the sentinel '###XML###' must be matched with
    line.strip() == '###XML###' (exact), not as a substring.

    The nmap command includes  echo "###XML###"  embedded as part of the
    [INFO] Command display line.  Substring matching would trigger on that
    display line, silencing all subsequent nmap output.
    """

    def _run_emit_sequence(self, lines):
        """
        Simulate the emit() closure used inside run_scan.
        Returns (output_lines, xml_chunks).
        """
        output_lines = []
        xml_chunks = []
        collecting_xml = [False]

        def emit(line):
            if line.strip() == "###XML###":
                collecting_xml[0] = True
                return
            if collecting_xml[0]:
                xml_chunks.append(line)
                return
            output_lines.append(line)

        for line in lines:
            emit(line)

        return output_lines, xml_chunks

    def test_exact_sentinel_starts_xml_collection(self):
        lines = ["nmap output", "###XML###", "<?xml version", "</nmaprun>"]
        out, xml = self._run_emit_sequence(lines)
        assert "nmap output" in out
        assert "###XML###" not in out
        assert "<?xml version" in xml
        assert "</nmaprun>" in xml

    def test_sentinel_with_whitespace_still_triggers(self):
        # PTY output may include trailing carriage returns
        lines = ["before", "###XML###\r", "xml content"]
        out, xml = self._run_emit_sequence(lines)
        assert "before" in out
        assert "xml content" in xml

    def test_info_command_line_does_not_trigger_sentinel(self):
        # This is the exact line that caused the original bug
        info_line = '[INFO] Command : nmap --script ssl-cert -p 443 10.0.0.1 -oX /tmp/retest_abc.xml -v; echo "###XML###"; cat /tmp/retest_abc.xml'
        lines = [info_line, "normal nmap output", "Nmap done"]
        out, xml = self._run_emit_sequence(lines)

        # The [INFO] line must appear in output, NOT trigger XML collection
        assert info_line in out
        assert "normal nmap output" in out
        assert "Nmap done" in out
        assert xml == []

    def test_output_before_sentinel_is_visible(self):
        lines = [
            "[INFO] Ticket  : TEST-1",
            "[INFO] Target  : 10.0.0.1:443",
            "[NMAP] Starting scan...",
            "Starting Nmap 7.94",
            "443/tcp open  https",
            "###XML###",
            "<xml/>",
        ]
        out, xml = self._run_emit_sequence(lines)
        assert "[INFO] Ticket  : TEST-1" in out
        assert "Starting Nmap 7.94" in out
        assert "443/tcp open  https" in out
        assert "<xml/>" in xml
        assert len(xml) == 1

    def test_lines_after_sentinel_go_to_xml_only(self):
        lines = ["output", "###XML###", "xml-line-1", "xml-line-2", "xml-line-3"]
        out, xml = self._run_emit_sequence(lines)
        assert xml == ["xml-line-1", "xml-line-2", "xml-line-3"]
        assert "xml-line-1" not in out


# ---------------------------------------------------------------------------
# stop_scan
# ---------------------------------------------------------------------------

class TestStopScan:
    def test_stop_scan_returns_true_when_event_exists(self):
        job_id = "test-job-stop"
        event = threading.Event()
        scanner._stop_events[job_id] = event

        result = scanner.stop_scan(job_id)
        assert result is True
        assert event.is_set()

    def test_stop_scan_returns_false_for_unknown_job(self):
        result = scanner.stop_scan("nonexistent-job-id")
        assert result is False

    def test_stop_scan_sets_event(self):
        job_id = "test-job-set"
        event = threading.Event()
        scanner._stop_events[job_id] = event
        assert not event.is_set()
        scanner.stop_scan(job_id)
        assert event.is_set()


# ---------------------------------------------------------------------------
# _app_log
# ---------------------------------------------------------------------------

class TestAppLog:
    def test_log_entry_appears_in_app_logs(self):
        scanner._app_log("test message hello")
        assert any("test message hello" in entry for entry in scanner.APP_LOGS)

    def test_log_has_timestamp_prefix(self):
        scanner._app_log("timestamped entry")
        last = scanner.APP_LOGS[-1]
        assert last.startswith("[20")  # [YYYY-...

    def test_log_capped_at_500_entries(self):
        for i in range(550):
            scanner._app_log(f"entry {i}")
        assert len(scanner.APP_LOGS) <= 500


# ---------------------------------------------------------------------------
# _build_triage_command / run_triage — fast pre-scan reachability check
# ---------------------------------------------------------------------------

class TestBuildTriageCommand:
    def test_curl_tool_has_no_triage_command(self, sample_ticket):
        # Find a rule that uses curl
        from src.vuln_rules import match_rule
        curl_summaries = [
            "Missing HTTP Security Headers",
            "Apache 2.4.x HTTP Server",
        ]
        for summary in curl_summaries:
            rule = match_rule(summary)
            if rule and rule.tool == "curl":
                cmd = scanner._build_triage_command(rule, "10.0.0.1", 443)
                assert cmd is None
                return
        pytest.skip("No curl-tool rule found to test against")

    def test_nmap_tool_has_triage_command(self):
        ticket = make_ticket(
            summary="SSL Certificate Expiry on 10.0.0.1",
            ips=["10.0.0.1"],
            ports=["443"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["triage_command"]
        assert cmd is not None
        assert "nmap" in cmd
        assert "-p 443" in cmd
        assert "10.0.0.1" in cmd
        assert "--script" not in cmd  # triage skips version-detection scripts

    def test_udp_rule_triage_uses_sudo_and_su(self):
        ticket = make_ticket(
            summary="Portable SDK for UPnP Devices (libupnp)",
            ips=["10.0.0.1"],
            ports=["1900"],
        )
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["triage_command"]
        assert cmd.startswith("sudo nmap ")
        assert "-sU" in cmd

    def test_no_rule_or_no_ip_returns_none(self):
        assert scanner._build_triage_command(None, "10.0.0.1", 443) is None


class TestRunTriage:
    def _make_job(self, triage_command="nmap -Pn -T4 --max-retries 1 --host-timeout 10s -p 443 --open 10.0.0.1"):
        ticket = make_ticket(ips=["10.0.0.1"], ports=["443"])
        job_id = scanner._queue_ticket(ticket, "TestClient")
        scanner.JOBS[job_id]["triage_command"] = triage_command
        return job_id

    def test_skipped_when_no_triage_command(self):
        job_id = self._make_job(triage_command=None)
        scanner.run_triage(job_id, cfg=None)
        assert scanner.JOBS[job_id]["triage"] == "skipped"

    def test_error_when_ssh_not_connected(self):
        job_id = self._make_job()
        with patch("src.scanner.connections.get_connection", return_value=None):
            scanner.run_triage(job_id, cfg=None)
        assert scanner.JOBS[job_id]["triage"] == "error"
        assert "SSH not connected" in scanner.JOBS[job_id]["triage_note"]

    def test_open_port_detected(self):
        job_id = self._make_job()
        fake_conn = MagicMock()
        fake_conn.exec.return_value = (
            "443/tcp open  https\n", "", 0
        )
        with patch("src.scanner.connections.get_connection", return_value=fake_conn):
            scanner.run_triage(job_id, cfg=None)
        assert scanner.JOBS[job_id]["triage"] == "open"

    def test_closed_port_flagged_as_likely_fixed(self):
        job_id = self._make_job()
        fake_conn = MagicMock()
        fake_conn.exec.return_value = (
            "Nmap done: 1 IP address (1 host up) scanned in 1.2 seconds\n", "", 0
        )
        with patch("src.scanner.connections.get_connection", return_value=fake_conn):
            scanner.run_triage(job_id, cfg=None)
        assert scanner.JOBS[job_id]["triage"] == "closed"
        assert "likely fixed" in scanner.JOBS[job_id]["triage_note"]

    def test_host_down_detected(self):
        job_id = self._make_job()
        fake_conn = MagicMock()
        fake_conn.exec.return_value = (
            "Note: Host seems down. If it is really up, try -Pn\n", "", 0
        )
        with patch("src.scanner.connections.get_connection", return_value=fake_conn):
            scanner.run_triage(job_id, cfg=None)
        assert scanner.JOBS[job_id]["triage"] == "host_down"

    def test_udp_proto_detected_from_command(self):
        job_id = self._make_job(
            triage_command="sudo nmap -Pn -T4 --max-retries 1 --host-timeout 10s -sU -p 161 --open 10.0.0.1"
        )
        fake_conn = MagicMock()
        fake_conn.exec.return_value = ("161/udp open  snmp\n", "", 0)
        with patch("src.scanner.connections.get_connection", return_value=fake_conn):
            scanner.run_triage(job_id, cfg=None)
        assert scanner.JOBS[job_id]["triage"] == "open"

    def test_exception_during_exec_marks_error(self):
        job_id = self._make_job()
        fake_conn = MagicMock()
        fake_conn.exec.side_effect = RuntimeError("connection reset")
        with patch("src.scanner.connections.get_connection", return_value=fake_conn):
            scanner.run_triage(job_id, cfg=None)
        assert scanner.JOBS[job_id]["triage"] == "error"
        assert "connection reset" in scanner.JOBS[job_id]["triage_note"]


class TestTriageWorkerDispatch:
    def test_trigger_triage_runs_on_worker_without_post_scan_sleep(self):
        """trigger_triage should invoke run_triage via the per-client worker
        and must NOT incur the 2s post-PTY-scan cooldown that trigger_scan does."""
        ticket = make_ticket(ips=["10.0.0.1"], ports=["443"])
        job_id = scanner._queue_ticket(ticket, "TestClient")

        fake_conn = MagicMock()
        fake_conn.exec.return_value = ("443/tcp open  https\n", "", 0)

        with patch("src.scanner.connections.get_connection", return_value=fake_conn), \
             patch("src.scanner.time.sleep") as mock_sleep:
            scanner.trigger_triage(job_id, cfg=None)
            scanner._triage_queues["TestClient"].join()

        assert scanner.JOBS[job_id]["triage"] == "open"
        mock_sleep.assert_not_called()

    def test_pending_triage_set_cleared_after_processing(self):
        ticket = make_ticket(ips=["10.0.0.1"], ports=["443"])
        job_id = scanner._queue_ticket(ticket, "TestClient")

        fake_conn = MagicMock()
        fake_conn.exec.return_value = ("443/tcp open  https\n", "", 0)

        with patch("src.scanner.connections.get_connection", return_value=fake_conn):
            scanner.trigger_triage(job_id, cfg=None)
            assert job_id in scanner._pending_triage_ids
            scanner._triage_queues["TestClient"].join()

        assert job_id not in scanner._pending_triage_ids

    def test_scan_jumps_ahead_of_pending_triage_backlog(self):
        """If a scan is triggered while several triage jobs are still queued
        behind the one currently in flight, the scan must run next — not
        after the rest of the triage backlog."""
        client = "TestClient"
        triage_job_ids = [
            scanner._queue_ticket(make_ticket(ips=[f"10.0.0.{i}"], ports=["443"]), client)
            for i in range(2, 5)
        ]
        scan_job_id = scanner._queue_ticket(
            make_ticket(summary="SSL Certificate Expiry on 10.0.0.9", ips=["10.0.0.9"], ports=["443"]),
            client,
        )
        fake_cfg = SimpleNamespace(clients=[SimpleNamespace(label=client)], clients_secondary=None)
        import sys
        print(f"DEBUG_JOB: {scanner.JOBS[scan_job_id]}", file=sys.stderr)

        order = []
        order_lock = threading.Lock()
        first_triage_started = threading.Event()
        release_first_triage = threading.Event()
        conn = MagicMock()

        def fake_exec(cmd, timeout=20, stop_event=None):
            with order_lock:
                is_first = not first_triage_started.is_set()
                if is_first:
                    first_triage_started.set()
            if is_first:
                # Block here so jobs 2 and 3 pile up in the triage queue
                # behind it, and so the scan gets enqueued while this one
                # is still "in flight" — exactly the "Triage All in
                # progress, then I start a scan" scenario being tested.
                release_first_triage.wait(timeout=10)
            with order_lock:
                order.append("triage")
            return ("443/tcp open  https\n", "", 0)

        def fake_exec_stream(cmd, on_line, timeout=600, stop_event=None):
            with order_lock:
                order.append("scan")
            return 0

        conn.exec.side_effect = fake_exec
        conn.exec_stream.side_effect = fake_exec_stream

        with patch("src.scanner.connections.get_connection", return_value=conn), \
             patch("src.scanner.time.sleep"):
            for jid in triage_job_ids:
                scanner.trigger_triage(jid, cfg=None)
            first_triage_started.wait(timeout=10)
            scanner.trigger_scan(scan_job_id, cfg=fake_cfg)
            release_first_triage.set()
            scanner._scan_queues[client].join()
            scanner._triage_queues[client].join()

        # First triage (already in flight when the scan arrived) runs to
        # completion, then the scan must come before the remaining backlog.
        assert order[0] == "triage"
        assert order[1] == "scan"
        assert order.count("triage") == 3


class TestCancelAllTriage:
    def test_cancels_only_pending_triage_not_scans(self):
        client = "CancelTriageClient"
        triage_job_id = scanner._queue_ticket(make_ticket(ips=["10.0.0.2"], ports=["443"]), client)
        scan_job_id = scanner._queue_ticket(make_ticket(ips=["10.0.0.3"], ports=["443"]), client)

        with scanner._lock:
            scanner._pending_triage_ids.add(triage_job_id)

        result = scanner.cancel_all_triage(client)

        assert result == {"cancelled_triage": 1}
        assert triage_job_id in scanner._cancelled_ids
        assert triage_job_id not in scanner._pending_triage_ids
        assert scan_job_id not in scanner._cancelled_ids

        scanner._cancelled_ids.discard(triage_job_id)

    def test_scoped_to_client_label(self):
        job_a = scanner._queue_ticket(make_ticket(ips=["10.0.0.4"], ports=["443"]), "ClientA")
        job_b = scanner._queue_ticket(make_ticket(ips=["10.0.0.5"], ports=["443"]), "ClientB")

        with scanner._lock:
            scanner._pending_triage_ids.add(job_a)
            scanner._pending_triage_ids.add(job_b)

        result = scanner.cancel_all_triage("ClientA")

        assert result == {"cancelled_triage": 1}
        assert job_a in scanner._cancelled_ids
        assert job_b not in scanner._cancelled_ids
        assert job_b in scanner._pending_triage_ids

        scanner._cancelled_ids.discard(job_a)
        scanner._pending_triage_ids.discard(job_b)


class TestSudoNmap:
    def test_sudo_prepended_when_client_requires_it(self):
        from tests.conftest import make_test_config
        cfg = make_test_config()
        cfg.clients[0].sudo_nmap = True
        ticket = make_ticket(summary="SSL Certificate Expiry on 10.0.0.1")
        job_id = scanner._queue_ticket(ticket, "TestClient", cfg=cfg)
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert cmd.startswith("sudo nmap")

    def test_no_sudo_by_default(self):
        ticket = make_ticket(summary="SSL Certificate Expiry on 10.0.0.1")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        cmd = scanner.JOBS[job_id]["nmap_command"]
        assert cmd.startswith("nmap ")
        assert not cmd.startswith("sudo nmap")
