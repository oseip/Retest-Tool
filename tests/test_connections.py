"""Tests for SSH connection pool parallel Nessus helper."""
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from src import connections


@pytest.fixture
def cfg():
    client = MagicMock()
    client.label = "ACME"
    cfg = MagicMock()
    cfg.clients = [client]
    cfg.clients_secondary = []
    cfg.jump_server = MagicMock()
    return cfg


class TestParallelNessusMap:
    def test_empty_items(self, cfg):
        assert connections.parallel_nessus_map(cfg, "ACME", [], lambda c, x: x) == []

    def test_requires_primary_connection(self, cfg):
        with patch.object(connections, "get_connection", return_value=None):
            with pytest.raises(ValueError, match="not connected"):
                connections.parallel_nessus_map(cfg, "ACME", [1], lambda c, x: x)

    def test_runs_workers_in_order(self, cfg):
        primary = MagicMock()
        calls = []

        def worker(conn, item):
            calls.append(item)
            return item * 10

        with patch.object(connections, "get_connection", return_value=primary):
            with patch.object(connections, "_open_extra_connection") as open_extra:
                open_extra.side_effect = AssertionError("should not need extra conn")
                results = connections.parallel_nessus_map(cfg, "ACME", [1, 2, 3], worker)

        assert results == [(1, 10, None), (2, 20, None), (3, 30, None)]
        assert calls == [1, 2, 3]

    def test_uses_multiple_connections_for_many_items(self, cfg):
        primary = MagicMock(name="primary")
        extra = MagicMock(name="extra")
        seen = []

        def worker(conn, item):
            seen.append(conn)
            return item

        with patch.object(connections, "get_connection", return_value=primary):
            with patch.object(connections, "_open_extra_connection", return_value=extra) as open_extra:
                results = connections.parallel_nessus_map(
                    cfg, "ACME", [1, 2, 3, 4], worker, max_workers=2,
                )

        assert open_extra.call_count == 1
        assert len(results) == 4
        assert primary in seen
        assert extra in seen
        extra.close.assert_called_once()

    def test_never_shares_a_connection_between_concurrent_workers(self, cfg):
        """More items than workers must not hand one transport to two threads."""
        primary = MagicMock(name="primary")
        extras = [MagicMock(name=f"extra{i}") for i in range(2)]
        in_use = set()
        guard = threading.Lock()
        overlaps = []

        def worker(conn, item):
            with guard:
                if id(conn) in in_use:
                    overlaps.append(item)
                in_use.add(id(conn))
            # Item 0 stays busy while later items are dispatched onto freed
            # threads, which is exactly when index-based assignment collides.
            time.sleep(0.5 if item == 0 else 0.01)
            with guard:
                in_use.discard(id(conn))
            return item

        with patch.object(connections, "get_connection", return_value=primary):
            with patch.object(connections, "_open_extra_connection", side_effect=extras):
                results = connections.parallel_nessus_map(
                    cfg, "ACME", list(range(12)), worker, max_workers=3,
                )

        assert overlaps == []
        assert [r[0] for r in results] == list(range(12))
        assert [r[1] for r in results] == list(range(12))

    def test_captures_worker_errors(self, cfg):
        primary = MagicMock()

        def worker(conn, item):
            if item == 2:
                raise RuntimeError("boom")
            return item

        with patch.object(connections, "get_connection", return_value=primary):
            results = connections.parallel_nessus_map(cfg, "ACME", [1, 2, 3], worker)

        assert results[0] == (1, 1, None)
        assert results[1][0] == 2 and results[1][1] is None and "boom" in results[1][2]
        assert results[2] == (3, 3, None)


class TestNessusParallelWorkers:
    def test_full_parallel_for_small_scans(self):
        assert connections.nessus_parallel_workers([1, 2], {1: 50, 2: 80}) == 3

    def test_reduced_for_large_scans(self):
        assert connections.nessus_parallel_workers([1, 2], {1: 600, 2: 50}) == 2

    def test_sequential_for_huge_scans(self):
        assert connections.nessus_parallel_workers([1], {1: 2500}) == 1
