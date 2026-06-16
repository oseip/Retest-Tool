"""
Tests for KaliConnection.exec() drain logic and Nessus client response handling.

The core scenario being tested: on a double-hop SSH connection (local → jump → Kali)
the remote exit_status can arrive at our Python side *before* all stdout bytes have
propagated through the jump-server hop.  If exec() exits the read loop the moment it
sees exit_status_ready() && not recv_ready(), it silently truncates the response —
which then fails json.loads() with "Non-JSON response".

_FakeChannel simulates exactly this: burst-1 is returned first, exit_status fires
immediately after, then burst-2 arrives after a configurable delay.
"""
import json
import threading
import time
from unittest.mock import MagicMock

import pytest

from src.ssh_exec import KaliConnection
from src.config import JumpServerConfig, ClientConfig
from src import nessus_client as nc


# ─── helpers ─────────────────────────────────────────────────────────────────

def _make_conn():
    j = JumpServerConfig(host="jump", port=22, user="u", password="p")
    c = ClientConfig(
        label="t", name="T", kali_port=22, kali_user="kali", kali_password="p",
        nessus_access_key="ak", nessus_secret_key="sk",
    )
    conn = KaliConnection(j, c)
    return conn


class _FakeChannel:
    """
    Paramiko Channel stand-in.

    Delivers data in two bursts:
      - burst1 is available immediately.
      - exit_status_ready() returns True once burst1 is fully consumed.
      - burst2 becomes readable only after `delay_s` seconds — simulating
        bytes still travelling through a jump-server channel.

    This is the exact race condition that causes truncation in production.
    """

    def __init__(self, burst1: bytes, burst2: bytes, delay_s: float = 0.15):
        self._b1 = burst1
        self._b2 = burst2
        self._delay = delay_s
        self._b1_done = False
        self._b2_ready = False

    # paramiko interface ---------------------------------------------------------

    def exec_command(self, _cmd):
        pass

    def recv_ready(self) -> bool:
        if not self._b1_done:
            return bool(self._b1)
        return self._b2_ready and bool(self._b2)

    def recv(self, n: int) -> bytes:
        if not self._b1_done:
            chunk, self._b1 = self._b1[:n], self._b1[n:]
            if not self._b1:
                self._b1_done = True
                # Schedule burst-2 to become available after the delay
                threading.Timer(self._delay, self._release_b2).start()
            return chunk
        if self._b2_ready:
            chunk, self._b2 = self._b2[:n], self._b2[n:]
            return chunk
        return b""

    def _release_b2(self):
        self._b2_ready = True

    def recv_stderr_ready(self) -> bool:
        return False

    def recv_stderr(self, _n: int) -> bytes:
        return b""

    def exit_status_ready(self) -> bool:
        # True once burst1 is consumed (before burst2 is ready)
        return self._b1_done

    def recv_exit_status(self) -> int:
        return 0

    def close(self):
        pass


def _wire(conn: KaliConnection, channel: _FakeChannel):
    """Inject a fake channel into a KaliConnection without touching real SSH."""
    transport = MagicMock()
    transport.open_session.return_value = channel
    conn._kali = MagicMock()
    conn._kali.get_transport.return_value = transport


# ─── exec() drain tests ──────────────────────────────────────────────────────

class TestExecDrain:
    """exec() must not truncate output when exit_status fires before last bytes arrive."""

    def test_two_burst_small(self):
        """Tiny two-burst response — drain catches burst-2 (150 ms delay)."""
        b1 = b'{"hosts": ['
        b2 = b'{"hostname": "10.0.0.1"}]}'
        conn = _make_conn()
        _wire(conn, _FakeChannel(b1, b2, delay_s=0.15))

        out, _, rc = conn.exec("cmd", timeout=5)

        assert rc == 0
        assert out == (b1 + b2).decode(), f"Truncated — got: {out!r}"

    def test_large_response_split_at_64k(self):
        """
        ~300 KB response split exactly at the 64 KB SSH window boundary.
        This mirrors the production failure: large Nessus scan detail payloads
        get chopped at the first recv() boundary.
        """
        hosts = [{"hostname": f"10.{i//65536 % 256}.{i//256 % 256}.{i % 256}"} for i in range(2000)]
        full = json.dumps({
            "info": {"name": "weekly scan", "targets": ("10.0.0.1," * 6000).rstrip(",")},
            "hosts": hosts,
        }).encode()

        split = 65536
        b1, b2 = full[:split], full[split:]
        assert b2, f"Payload too small ({len(full)} B) to split at {split}"

        conn = _make_conn()
        _wire(conn, _FakeChannel(b1, b2, delay_s=0.2))

        out, _, _ = conn.exec("cmd", timeout=10)

        assert out.encode() == full, (
            f"Truncated: received {len(out)} B, expected {len(full)} B. "
            f"Last 60 chars: {out[-60:]!r}"
        )
        parsed = json.loads(out)
        assert len(parsed["hosts"]) == 2000

    def test_exit_fires_immediately_no_burst2(self):
        """Normal case: single burst, exit fires right after — no drain needed."""
        data = b'{"ok": true}'
        conn = _make_conn()
        _wire(conn, _FakeChannel(data, b"", delay_s=0.0))

        out, _, rc = conn.exec("cmd", timeout=5)
        assert rc == 0
        assert out == data.decode()

    def test_drain_timeout_respected(self):
        """If burst-2 never arrives (e.g. connection drop), exec() still returns."""
        b1 = b'partial'
        b2 = b' data'
        conn = _make_conn()
        # delay longer than drain window (3 s) — burst-2 never arrives in time
        _wire(conn, _FakeChannel(b1, b2, delay_s=4.0))

        start = time.time()
        out, _, _ = conn.exec("cmd", timeout=10)
        elapsed = time.time() - start

        # Should return within ~3 s drain window, not hang for the full 10 s timeout
        assert elapsed < 7.0, f"exec() hung for {elapsed:.1f}s"
        # Only burst-1 arrives; that's OK (truncated, but didn't hang)
        assert out == b1.decode()


# ─── nessus_client tests ─────────────────────────────────────────────────────

class TestNessusGetScanHosts:
    """get_scan_hosts() must return hosts from a complete Nessus scan response."""

    def _conn_for(self, payload: dict, split: int = 0, delay_s: float = 0.0):
        raw = json.dumps(payload).encode()
        if split and split < len(raw):
            b1, b2 = raw[:split], raw[split:]
        else:
            b1, b2 = raw, b""
        conn = _make_conn()
        _wire(conn, _FakeChannel(b1, b2, delay_s=delay_s))
        return conn

    def test_extracts_ip_from_hostname(self):
        conn = self._conn_for({"hosts": [{"hostname": "10.0.0.1"}, {"hostname": "10.0.0.2"}]})
        hosts = nc.get_scan_hosts(conn, "ak", "sk", 1)
        assert [h["ip"] for h in hosts] == ["10.0.0.1", "10.0.0.2"]

    def test_empty_hosts_key(self):
        conn = self._conn_for({"hosts": []})
        assert nc.get_scan_hosts(conn, "ak", "sk", 1) == []

    def test_missing_hosts_key(self):
        conn = self._conn_for({"info": {"name": "scan"}, "vulnerabilities": []})
        assert nc.get_scan_hosts(conn, "ak", "sk", 1) == []

    def test_skips_entries_without_hostname(self):
        conn = self._conn_for({"hosts": [
            {"hostname": "10.0.0.1"},
            {"no_hostname_here": True},
            {"hostname": "10.0.0.2"},
        ]})
        hosts = nc.get_scan_hosts(conn, "ak", "sk", 1)
        assert len(hosts) == 2

    def test_large_response_split_at_65k_boundary(self):
        """
        Reproduces the production failure: large scan detail response (~300 KB),
        split at 65 536 B, burst-2 delayed 200 ms after exit_status fires.
        get_scan_hosts() must return all 200 hosts without raising ValueError.
        """
        payload = {
            "info": {
                "name": "weekly p0 march",
                # Long targets string to push total size well past 65 536 B
                "targets": ("10.228.12.51," * 5000).rstrip(","),
            },
            "hosts": [{"hostname": f"10.0.{i//256}.{i%256}"} for i in range(200)],
        }
        raw = json.dumps(payload).encode()
        assert len(raw) > 65536, (
            f"Test payload only {len(raw)} B — not large enough to reproduce the bug. "
            "Increase range() values."
        )

        conn = self._conn_for(payload, split=65536, delay_s=0.2)
        hosts = nc.get_scan_hosts(conn, "ak", "sk", 1779)

        assert len(hosts) == 200, (
            f"Only {len(hosts)}/200 hosts returned — response was truncated"
        )
