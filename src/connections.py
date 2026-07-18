"""Persistent SSH connection pool — one connection per client (opco)."""
import logging
import threading
from typing import Dict, Optional

from .config import Config
from .ssh_exec import KaliConnection

log = logging.getLogger(__name__)
_lock = threading.Lock()

# label → open KaliConnection
_pool: Dict[str, KaliConnection] = {}

# label → human-readable status string
_status: Dict[str, str] = {}


def get_status() -> Dict[str, str]:
    with _lock:
        return dict(_status)


def connect(cfg: Config, label: str) -> None:
    all_clients = list(cfg.clients) + list(cfg.clients_secondary or [])
    client_cfg = next((c for c in all_clients if c.label == label), None)
    if not client_cfg:
        raise ValueError(f"Unknown client: {label}")

    with _lock:
        _status[label] = "connecting"

    try:
        conn = KaliConnection(cfg.jump_server, client_cfg)
        conn.connect()
        out, _, _ = conn.exec("whoami", timeout=10)
        with _lock:
            # Close any stale connection we're about to replace so we don't leak
            # its two SSH transports / jump channel on repeated reconnects.
            old = _pool.get(label)
            _pool[label] = conn
            _status[label] = f"connected ({out.strip()}@kali)"
        if old is not None and old is not conn:
            try:
                old.close()
            except Exception:
                pass
        log.info("SSH pool: connected to %s", label)
    except Exception as exc:
        with _lock:
            _status[label] = f"error: {exc}"
        log.error("SSH pool: failed to connect to %s: %s", label, exc)
        raise


def disconnect(label: str) -> None:
    with _lock:
        conn = _pool.pop(label, None)
        _status[label] = "disconnected"
    if conn:
        try:
            conn.close()
        except Exception:
            pass
    log.info("SSH pool: disconnected from %s", label)


def get_connection(label: str) -> Optional[KaliConnection]:
    """Return the pooled connection only if its transport is still live.

    A double-hop SSH transport can drop silently (jump server idle-timeout,
    Kali reboot, network blip). Previously this returned whatever was in the
    pool, so callers would fail deep inside ``exec``/``exec_stream`` and the
    error got mislabeled as a generic scan failure. We now verify liveness and
    evict dead connections so the caller sees a clean "not connected" state.
    """
    with _lock:
        conn = _pool.get(label)
        if conn is None:
            return None
        if conn.is_alive():
            return conn
        # Dead transport — evict and report as disconnected.
        _pool.pop(label, None)
        _status[label] = "disconnected (connection lost)"
    try:
        conn.close()
    except Exception:
        pass
    return None
