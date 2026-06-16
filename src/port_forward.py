"""Local port forwarding through a client's double-hop SSH connection.

Lets the browser reach a web app that's only visible from a client's Kali
box (e.g. http://localhost:5001 -> jump server -> Kali -> target host:port),
the same thing you'd get from chaining two `ssh -L` commands by hand — but
implemented with paramiko `direct-tcpip` channels instead of a real listening
socket on the jump host, so there's no port on the jump server to collide
with anyone else's tunnel.

Each tunnel opens its own dedicated KaliConnection — independent of the
connections.py pool used by scans and of the interactive shell — so starting
or stopping a tunnel never affects a scan in progress or a shell session.
"""
import logging
import socket
import threading
import uuid
from datetime import datetime
from typing import Dict, Optional

from .config import Config
from .ssh_exec import KaliConnection

log = logging.getLogger(__name__)

# tunnel_id -> tunnel state dict (label, target, local_port, status, error, created_at)
TUNNELS: Dict[str, dict] = {}

_stop_events: Dict[str, threading.Event] = {}
_server_sockets: Dict[str, socket.socket] = {}
_connections: Dict[str, KaliConnection] = {}
_active_pairs: Dict[str, list] = {}
_lock = threading.Lock()


def _pipe(src, dst, client_sock, channel):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        try:
            channel.close()
        except Exception:
            pass


def _handle_connection(tunnel_id: str, client_sock: socket.socket, channel):
    with _lock:
        _active_pairs.setdefault(tunnel_id, []).append((client_sock, channel))
    threading.Thread(target=_pipe, args=(client_sock, channel, client_sock, channel), daemon=True).start()
    threading.Thread(target=_pipe, args=(channel, client_sock, client_sock, channel), daemon=True).start()


def _run_tunnel(tunnel_id: str, cfg: Config, client_cfg, target_host: str,
                 target_port: int, server_sock: socket.socket, stop_event: threading.Event):
    conn = KaliConnection(cfg.jump_server, client_cfg)
    try:
        conn.connect()
    except Exception as exc:
        if tunnel_id in TUNNELS:
            TUNNELS[tunnel_id]["status"] = "error"
            TUNNELS[tunnel_id]["error"] = str(exc)
        try:
            server_sock.close()
        except Exception:
            pass
        log.error("Tunnel %s: failed to connect to %s: %s", tunnel_id, client_cfg.label, exc)
        return

    _connections[tunnel_id] = conn
    transport = conn._kali.get_transport()
    local_port = TUNNELS[tunnel_id]["local_port"] if tunnel_id in TUNNELS else "?"
    if tunnel_id in TUNNELS:
        TUNNELS[tunnel_id]["status"] = "listening"
    log.info(
        "Tunnel %s: listening on 127.0.0.1:%d -> %s:%d via %s",
        tunnel_id, local_port, target_host, target_port, client_cfg.label,
    )

    try:
        server_sock.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                channel = transport.open_channel("direct-tcpip", (target_host, target_port), addr)
            except Exception as exc:
                log.error("Tunnel %s: could not open channel to %s:%d: %s", tunnel_id, target_host, target_port, exc)
                try:
                    client_sock.close()
                except Exception:
                    pass
                continue

            _handle_connection(tunnel_id, client_sock, channel)
    except OSError:
        # server_sock was closed by a concurrent stop_tunnel() before we got
        # here (e.g. settimeout() raced a close()) — treat as already-stopped.
        pass

    with _lock:
        pairs = _active_pairs.pop(tunnel_id, [])
    for sock, chan in pairs:
        try:
            sock.close()
        except Exception:
            pass
        try:
            chan.close()
        except Exception:
            pass

    try:
        server_sock.close()
    except Exception:
        pass
    conn.close()
    if tunnel_id in TUNNELS and TUNNELS[tunnel_id]["status"] != "error":
        TUNNELS[tunnel_id]["status"] = "stopped"
    log.info("Tunnel %s: stopped", tunnel_id)


def start_tunnel(cfg: Config, label: str, target_host: str, target_port: int, local_port: int) -> str:
    """local_port=0 means "pick any free port" — the actual bound port is
    read back from the socket and used as the tunnel's local_port."""
    client_cfg = next((c for c in cfg.clients if c.label == label), None)
    if not client_cfg:
        raise ValueError(f"Unknown client: {label}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(("127.0.0.1", local_port))
    except OSError as exc:
        server_sock.close()
        raise RuntimeError(f"Local port {local_port} is already in use: {exc}")
    server_sock.listen(5)
    local_port = server_sock.getsockname()[1]

    tunnel_id = uuid.uuid4().hex[:12]
    stop_event = threading.Event()

    TUNNELS[tunnel_id] = {
        "id": tunnel_id,
        "label": label,
        "target_host": target_host,
        "target_port": target_port,
        "local_port": local_port,
        "status": "connecting",
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
    }
    _stop_events[tunnel_id] = stop_event
    _server_sockets[tunnel_id] = server_sock

    thread = threading.Thread(
        target=_run_tunnel,
        args=(tunnel_id, cfg, client_cfg, target_host, target_port, server_sock, stop_event),
        daemon=True,
    )
    thread.start()
    return tunnel_id


def stop_tunnel(tunnel_id: str) -> bool:
    stop_event = _stop_events.get(tunnel_id)
    if not stop_event:
        return False
    stop_event.set()
    server_sock = _server_sockets.get(tunnel_id)
    if server_sock:
        try:
            server_sock.close()
        except Exception:
            pass
    return True


def remove_tunnel(tunnel_id: str) -> bool:
    """Stop the tunnel (if running) and drop it from the list immediately."""
    if tunnel_id not in TUNNELS:
        return False
    stop_tunnel(tunnel_id)
    TUNNELS.pop(tunnel_id, None)
    _stop_events.pop(tunnel_id, None)
    _server_sockets.pop(tunnel_id, None)
    _connections.pop(tunnel_id, None)
    _active_pairs.pop(tunnel_id, None)
    return True


def list_tunnels() -> list:
    return list(TUNNELS.values())


def get_tunnel(tunnel_id: str) -> Optional[dict]:
    return TUNNELS.get(tunnel_id)
