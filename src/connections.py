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
            _pool[label] = conn
            _status[label] = f"connected ({out.strip()}@kali)"
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
    """Return pooled connection if live, otherwise None."""
    with _lock:
        return _pool.get(label)
