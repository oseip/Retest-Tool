"""Asset list management and Nessus cross-reference."""
import ipaddress
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Union

log = logging.getLogger(__name__)

ASSETS_DIR = "data/assets"

# Subnets larger than this are not enumerated for the "missed" list — the
# number of individual IPs would be impractical to report.
_ENUM_LIMIT = 65536


def _path(label: str) -> str:
    return os.path.join(ASSETS_DIR, f"{label}.json")


def save_asset_list(label: str, raw_entries: List[str]) -> int:
    """Validate and persist a list of IPs/subnets for a client. Returns saved count.

    Duplicate entries are removed (first occurrence wins) so the scope count and
    the "not reachable" list are not inflated by accidental repeats.
    """
    os.makedirs(ASSETS_DIR, exist_ok=True)
    cleaned = []
    seen = set()
    for entry in raw_entries:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            log.warning("Invalid IP/subnet skipped: %s", entry)
            continue
        if entry in seen:
            continue
        seen.add(entry)
        cleaned.append(entry)
    data = {
        "label": label,
        "entries": cleaned,
        "updated_at": datetime.utcnow().isoformat(),
    }
    with open(_path(label), "w") as f:
        json.dump(data, f, indent=2)
    return len(cleaned)


def load_asset_list(label: str) -> Dict:
    p = _path(label)
    if not os.path.exists(p):
        return {"label": label, "entries": [], "updated_at": None}
    with open(p) as f:
        return json.load(f)


def _parse_scope(entries: List[str]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Parse asset entries into ip_network objects (any size, any version)."""
    nets = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warning("Could not parse scope entry: %s", entry)
    return nets


def _in_scope(ip_str: str, scope: list) -> bool:
    """Return True if ip_str falls within any network in scope."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in scope)
    except ValueError:
        return False


def _sort_ips(ips: List[str]) -> List[str]:
    """Sort IP strings numerically (so 10.0.0.2 < 10.0.0.11), non-IPs last."""
    def key(ip: str):
        try:
            addr = ipaddress.ip_address(ip)
            return (0, addr.version, int(addr))
        except ValueError:
            return (1, 0, ip.lower())
    return sorted(ips, key=key)


def cross_reference(asset_entries: List[str], scan_hosts: List[Dict]) -> Dict:
    """
    Cross-reference the client asset list (scope) against Nessus scan hosts.

    Buckets returned:
      reachable     — Nessus host IPs that fall inside a scope entry
      not_reachable — scope entries (IP/subnet) where Nessus found no host
      out_of_scope  — Nessus host IPs that are not in any scope entry
      unresolved    — scanned host identifiers that are NOT valid IPs (e.g. a
                      DNS/NetBIOS name Nessus reported instead of an address).
                      These cannot be matched to scope by IP, so they are
                      surfaced explicitly rather than silently dropped.

    Count invariant: total_scanned == reachable + out_of_scope + unresolved.
    Scope coverage:  total_scope   == reachable_scope + not_reachable.
    """
    # De-duplicate scanned host identifiers, then split into real IPs vs.
    # anything that can't be parsed as an IP (so nothing disappears silently).
    scanned_raw = sorted({
        (h.get("ip") or "").strip()
        for h in scan_hosts
        if (h.get("ip") or "").strip()
    })
    scanned_addrs: Dict[str, "ipaddress._BaseAddress"] = {}
    unresolved: List[str] = []
    for ip in scanned_raw:
        try:
            scanned_addrs[ip] = ipaddress.ip_address(ip)
        except ValueError:
            unresolved.append(ip)

    # Parse scope entries once, de-duplicating identical networks while keeping
    # a human-friendly display label for each.
    scope: List[tuple] = []          # (display_label, net)
    seen_nets = set()
    for entry in asset_entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            log.warning("Could not parse scope entry: %s", entry)
            continue
        if net in seen_nets:
            continue
        seen_nets.add(net)
        # Keep a bare single host exactly as typed; normalise real subnets.
        is_single_host = net.num_addresses == 1 and "/" not in entry
        label = entry if is_single_host else str(net)
        scope.append((label, net))

    # Single membership pass: O(hosts x scope) once, instead of three times.
    reachable: List[str] = []
    out_of_scope: List[str] = []
    entry_hit = [False] * len(scope)
    for ip, addr in scanned_addrs.items():
        matched = False
        for idx, (_, net) in enumerate(scope):
            if addr in net:
                entry_hit[idx] = True
                matched = True
        (reachable if matched else out_of_scope).append(ip)

    # Scope entries with no host found, sorted numerically by network address.
    not_reachable_pairs = [
        (label, net) for idx, (label, net) in enumerate(scope) if not entry_hit[idx]
    ]
    not_reachable_pairs.sort(
        key=lambda ln: (ln[1].version, int(ln[1].network_address), ln[1].prefixlen)
    )
    not_reachable = [label for label, _ in not_reachable_pairs]
    reachable_scope = sum(1 for hit in entry_hit if hit)

    reachable = _sort_ips(reachable)
    out_of_scope = _sort_ips(out_of_scope)
    unresolved = _sort_ips(unresolved)

    return {
        "reachable":     reachable,
        "not_reachable": not_reachable,
        "out_of_scope":  out_of_scope,
        "unresolved":    unresolved,
        "counts": {
            "reachable":       len(reachable),
            "not_reachable":   len(not_reachable),
            "out_of_scope":    len(out_of_scope),
            "unresolved":      len(unresolved),
            "total_scope":     len(scope),
            "reachable_scope": reachable_scope,
            "total_scanned":   len(scanned_raw),
        },
    }
