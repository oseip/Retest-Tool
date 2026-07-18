"""
Tests for src/assets.py — client asset scope vs. Nessus scan cross-reference.

Focus areas:
- cross_reference bucket correctness (reachable / not_reachable / out_of_scope)
- non-IP scanned hosts land in `unresolved` (never silently dropped)
- count invariant: total_scanned == reachable + out_of_scope + unresolved
- numeric IP sorting
- scope de-duplication and coverage counting
- save_asset_list validation + de-duplication
"""

import json

from src import assets


def _hosts(*ips):
    return [{"ip": ip, "status": "up"} for ip in ips]


# ---------------------------------------------------------------------------
# cross_reference — buckets
# ---------------------------------------------------------------------------
class TestCrossReferenceBuckets:
    def test_single_ip_reachable(self):
        r = assets.cross_reference(["10.0.0.5"], _hosts("10.0.0.5"))
        assert r["reachable"] == ["10.0.0.5"]
        assert r["not_reachable"] == []
        assert r["out_of_scope"] == []

    def test_single_ip_not_reachable(self):
        r = assets.cross_reference(["10.0.0.5"], _hosts("10.0.0.9"))
        assert r["reachable"] == []
        assert r["not_reachable"] == ["10.0.0.5"]
        assert r["out_of_scope"] == ["10.0.0.9"]

    def test_subnet_reachable_when_any_host_inside(self):
        r = assets.cross_reference(["10.0.0.0/24"], _hosts("10.0.0.7", "10.0.0.200"))
        assert r["counts"]["reachable"] == 2
        assert r["not_reachable"] == []
        assert r["counts"]["reachable_scope"] == 1

    def test_subnet_not_reachable_when_empty(self):
        r = assets.cross_reference(["10.0.0.0/24"], _hosts("192.168.1.1"))
        assert r["not_reachable"] == ["10.0.0.0/24"]
        assert r["out_of_scope"] == ["192.168.1.1"]
        assert r["counts"]["reachable_scope"] == 0

    def test_out_of_scope_host(self):
        r = assets.cross_reference(["10.0.0.0/24"], _hosts("10.0.0.5", "8.8.8.8"))
        assert "10.0.0.5" in r["reachable"]
        assert r["out_of_scope"] == ["8.8.8.8"]


# ---------------------------------------------------------------------------
# cross_reference — unresolved (non-IP hostnames) must not be dropped
# ---------------------------------------------------------------------------
class TestUnresolvedHosts:
    def test_dns_name_goes_to_unresolved(self):
        r = assets.cross_reference(["10.0.0.0/24"], _hosts("web01.corp.local", "10.0.0.5"))
        assert r["unresolved"] == ["web01.corp.local"]
        assert r["reachable"] == ["10.0.0.5"]

    def test_count_invariant_holds(self):
        hosts = _hosts("10.0.0.5", "8.8.8.8", "server.local")
        r = assets.cross_reference(["10.0.0.0/24"], hosts)
        c = r["counts"]
        assert c["total_scanned"] == c["reachable"] + c["out_of_scope"] + c["unresolved"]

    def test_no_unresolved_key_empty_when_all_ips(self):
        r = assets.cross_reference(["10.0.0.0/24"], _hosts("10.0.0.5"))
        assert r["unresolved"] == []
        assert r["counts"]["unresolved"] == 0


# ---------------------------------------------------------------------------
# cross_reference — sorting, dedup, coverage
# ---------------------------------------------------------------------------
class TestCrossReferenceQuality:
    def test_ips_sorted_numerically_not_lexically(self):
        r = assets.cross_reference(
            ["10.0.0.0/24"], _hosts("10.0.0.11", "10.0.0.2", "10.0.0.100")
        )
        assert r["reachable"] == ["10.0.0.2", "10.0.0.11", "10.0.0.100"]

    def test_duplicate_scope_entries_counted_once(self):
        r = assets.cross_reference(["10.0.0.0/24", "10.0.0.0/24"], _hosts("192.168.1.1"))
        assert r["counts"]["total_scope"] == 1

    def test_duplicate_scanned_hosts_counted_once(self):
        r = assets.cross_reference(["10.0.0.0/24"], _hosts("10.0.0.5", "10.0.0.5"))
        assert r["reachable"] == ["10.0.0.5"]
        assert r["counts"]["total_scanned"] == 1

    def test_scope_coverage_invariant(self):
        r = assets.cross_reference(
            ["10.0.0.0/24", "192.168.1.0/24"], _hosts("10.0.0.5")
        )
        c = r["counts"]
        assert c["total_scope"] == c["reachable_scope"] + c["not_reachable"]

    def test_ipv6_supported(self):
        r = assets.cross_reference(["2001:db8::/64"], _hosts("2001:db8::1"))
        assert r["reachable"] == ["2001:db8::1"]
        assert r["not_reachable"] == []

    def test_empty_scope_all_out_of_scope(self):
        r = assets.cross_reference([], _hosts("10.0.0.5", "10.0.0.6"))
        assert r["out_of_scope"] == ["10.0.0.5", "10.0.0.6"]
        assert r["counts"]["total_scope"] == 0

    def test_empty_hosts(self):
        r = assets.cross_reference(["10.0.0.0/24"], [])
        assert r["not_reachable"] == ["10.0.0.0/24"]
        assert r["counts"]["total_scanned"] == 0


# ---------------------------------------------------------------------------
# save_asset_list — validation + de-duplication
# ---------------------------------------------------------------------------
class TestSaveAssetList:
    def test_dedup_and_skip_invalid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(assets, "ASSETS_DIR", str(tmp_path))
        count = assets.save_asset_list(
            "acme",
            ["10.0.0.1", "10.0.0.1", "not-an-ip", "  ", "# comment", "10.0.0.0/24"],
        )
        assert count == 2  # 10.0.0.1 (deduped) + 10.0.0.0/24
        saved = json.loads((tmp_path / "acme.json").read_text())
        assert saved["entries"] == ["10.0.0.1", "10.0.0.0/24"]
