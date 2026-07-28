"""Persistent SSH connection pool — one connection per client (opco)."""
import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple, TypeVar

from .config import Config
from .ssh_exec import KaliConnection

log = logging.getLogger(__name__)
_lock = threading.Lock()

# Parallel Nessus/API work uses one SSH session per worker — never multiple
# channels on the same transport (that corrupts large responses).
NESSUS_PARALLEL_WORKERS = 3
_LARGE_SCAN_HOSTS = 500
_HUGE_SCAN_HOSTS = 2000


def nessus_parallel_workers(scan_ids: List[int],
                            host_counts: Optional[Dict[int, int]] = None) -> int:
    """Fewer parallel workers for large scans so Nessus/SSH aren't overloaded."""
    host_counts = host_counts or {}
    max_hosts = max((host_counts.get(s, 0) for s in scan_ids), default=0)
    if max_hosts >= _HUGE_SCAN_HOSTS:
        return 1
    if max_hosts >= _LARGE_SCAN_HOSTS:
        return 2
    return NESSUS_PARALLEL_WORKERS

T = TypeVar("T")
R = TypeVar("R")

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


def _client_cfg_for_label(cfg: Config, label: str):
    all_clients = list(cfg.clients) + list(cfg.clients_secondary or [])
    return next((c for c in all_clients if c.label == label), None)


def _open_extra_connection(cfg: Config, label: str) -> KaliConnection:
    client_cfg = _client_cfg_for_label(cfg, label)
    if not client_cfg:
        raise ValueError(f"Unknown client: {label}")
    conn = KaliConnection(cfg.jump_server, client_cfg)
    conn.connect()
    return conn


def parallel_nessus_map(
    cfg: Config,
    label: str,
    items: List[T],
    worker_fn: Callable[[KaliConnection, T], R],
    max_workers: int = NESSUS_PARALLEL_WORKERS,
) -> List[Tuple[T, Optional[R], Optional[str]]]:
    """Run *worker_fn(conn, item)* across *items* using dedicated SSH sessions.

    Each worker gets its own KaliConnection so large Nessus responses don't
    corrupt each other (unlike sharing one transport with parallel channels).
    Returns ``[(item, result, error_msg), ...]`` in the same order as *items*.
    """
    if not items:
        return []

    primary = get_connection(label)
    if primary is None:
        raise ValueError(f"SSH not connected for '{label}'")

    workers = min(max(1, max_workers), len(items))
    extra: List[KaliConnection] = []
    conns: List[KaliConnection] = [primary]

    try:
        for _ in range(workers - 1):
            try:
                extra.append(_open_extra_connection(cfg, label))
                conns.append(extra[-1])
            except Exception as exc:
                log.warning(
                    "Parallel Nessus: could not open extra SSH session for %s — %s",
                    label, exc,
                )
                break

        pool_size = len(conns)
        ordered: List[Optional[Tuple[Optional[R], Optional[str]]]] = [None] * len(items)

        # Lease a connection per task rather than assigning by item index: with
        # more items than workers, index-based assignment hands the same
        # connection to two concurrently running threads, which opens parallel
        # channels on one transport and corrupts large responses.
        available: "queue.Queue[KaliConnection]" = queue.Queue()
        for conn in conns:
            available.put(conn)

        def _run(item: T) -> R:
            conn = available.get()
            try:
                return worker_fn(conn, item)
            finally:
                available.put(conn)

        with ThreadPoolExecutor(max_workers=pool_size) as pool:
            futures = {
                pool.submit(_run, item): i
                for i, item in enumerate(items)
            }
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    ordered[idx] = (fut.result(), None)
                except Exception as exc:
                    log.warning(
                        "Parallel Nessus task failed for %s item %s: %s",
                        label, items[idx], exc,
                    )
                    ordered[idx] = (None, str(exc))

        return [
            (items[i], ordered[i][0], ordered[i][1])
            for i in range(len(items))
            if ordered[i] is not None
        ]
    finally:
        for conn in extra:
            try:
                conn.close()
            except Exception:
                pass
