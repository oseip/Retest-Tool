"""
Tests for src/port_forward.py — the local port-forwarding (tunnel) feature.

KaliConnection.connect() is monkeypatched to skip the real double-hop SSH
handshake; the fake transport's open_channel() opens a plain local socket
to the target instead of a paramiko direct-tcpip channel. Since paramiko's
Channel exposes the same recv/sendall/close interface as a socket, this lets
us exercise the real accept-loop and byte-piping logic in port_forward.py
without any real SSH or network infrastructure.
"""
import socket
import threading
import time

import pytest

from src import port_forward
from tests.conftest import make_test_config


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except Exception:
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


class _FakeTransport:
    def open_channel(self, kind, dest_addr, src_addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(dest_addr)
        return sock


class _FakeKaliClient:
    def get_transport(self):
        return _FakeTransport()

    def close(self):
        pass


def _wait_for_status(tunnel_id, not_status, timeout=5):
    deadline = time.time() + timeout
    while port_forward.TUNNELS[tunnel_id]["status"] == not_status and time.time() < deadline:
        time.sleep(0.02)


@pytest.fixture(autouse=True)
def clean_tunnels():
    port_forward.TUNNELS.clear()
    port_forward._stop_events.clear()
    port_forward._server_sockets.clear()
    port_forward._connections.clear()
    port_forward._active_pairs.clear()
    yield
    for tid in list(port_forward.TUNNELS.keys()):
        port_forward.remove_tunnel(tid)


class TestStartTunnelValidation:
    def test_unknown_client_raises(self):
        cfg = make_test_config()
        with pytest.raises(ValueError):
            port_forward.start_tunnel(cfg, "NoSuchClient", "127.0.0.1", 80, _free_port())

    def test_port_already_in_use_raises(self):
        cfg = make_test_config()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        try:
            with pytest.raises(RuntimeError):
                port_forward.start_tunnel(cfg, "TestClient", "127.0.0.1", 80, port)
        finally:
            blocker.close()


class TestTunnelRoundtrip:
    def test_data_flows_through_tunnel(self, monkeypatch):
        cfg = make_test_config()
        echo_srv, echo_port = _make_echo_server()
        monkeypatch.setattr(
            port_forward.KaliConnection, "connect",
            lambda self: setattr(self, "_kali", _FakeKaliClient()),
        )

        local_port = _free_port()
        tunnel_id = port_forward.start_tunnel(cfg, "TestClient", "127.0.0.1", echo_port, local_port)
        _wait_for_status(tunnel_id, "connecting")
        assert port_forward.TUNNELS[tunnel_id]["status"] == "listening"

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", local_port))
        client_sock.sendall(b"hello tunnel")
        client_sock.settimeout(5)
        data = client_sock.recv(1024)
        client_sock.close()
        echo_srv.close()

        assert data == b"hello tunnel"

    def test_stop_tunnel_frees_local_port(self, monkeypatch):
        cfg = make_test_config()
        monkeypatch.setattr(
            port_forward.KaliConnection, "connect",
            lambda self: setattr(self, "_kali", _FakeKaliClient()),
        )
        local_port = _free_port()
        tunnel_id = port_forward.start_tunnel(cfg, "TestClient", "127.0.0.1", 9, local_port)
        _wait_for_status(tunnel_id, "connecting")

        assert port_forward.stop_tunnel(tunnel_id) is True
        _wait_for_status(tunnel_id, "listening")
        assert port_forward.TUNNELS[tunnel_id]["status"] == "stopped"

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", local_port))
            bound_ok = True
        except OSError:
            bound_ok = False
        finally:
            probe.close()
        assert bound_ok

    def test_connect_failure_marks_error_status(self, monkeypatch):
        cfg = make_test_config()

        def _boom(self):
            raise RuntimeError("jump server unreachable")

        monkeypatch.setattr(port_forward.KaliConnection, "connect", _boom)

        local_port = _free_port()
        tunnel_id = port_forward.start_tunnel(cfg, "TestClient", "127.0.0.1", 80, local_port)
        _wait_for_status(tunnel_id, "connecting")

        assert port_forward.TUNNELS[tunnel_id]["status"] == "error"
        assert "jump server unreachable" in port_forward.TUNNELS[tunnel_id]["error"]


class TestStopAndRemoveTunnel:
    def test_stop_unknown_returns_false(self):
        assert port_forward.stop_tunnel("nonexistent") is False

    def test_remove_unknown_returns_false(self):
        assert port_forward.remove_tunnel("nonexistent") is False

    def test_remove_drops_from_list(self, monkeypatch):
        cfg = make_test_config()
        monkeypatch.setattr(
            port_forward.KaliConnection, "connect",
            lambda self: setattr(self, "_kali", _FakeKaliClient()),
        )
        local_port = _free_port()
        tunnel_id = port_forward.start_tunnel(cfg, "TestClient", "127.0.0.1", 9, local_port)
        _wait_for_status(tunnel_id, "connecting")

        assert port_forward.remove_tunnel(tunnel_id) is True
        assert tunnel_id not in port_forward.TUNNELS
        assert port_forward.get_tunnel(tunnel_id) is None


class TestListTunnels:
    def test_empty_initially(self):
        assert port_forward.list_tunnels() == []
