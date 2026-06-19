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
    """Validate and persist a list of IPs/subnets for a client. Returns saved count."""
    os.makedirs(ASSETS_DIR, exist_ok=True)
    cleaned = []
    for entry in raw_entries:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
            cleaned.append(entry)
        except ValueError:
            log.warning("Invalid IP/subnet skipped: %s", entry)
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


def cross_reference(asset_entries: List[str], scan_hosts: List[Dict]) -> Dict:
    """
    Cross-reference client asset list against Nessus scan hosts.

    Works with individual IPs, small subnets (/24, /16, etc.) and large
    subnets (/8 or wider) — uses containment checks instead of expanding
    every address, so memory usage stays flat regardless of subnet size.

    Returns three categories:
      in_scope_scanned  — fell within asset scope AND appeared in Nessus scan
      in_scope_missed   — fell within asset scope but NOT seen by Nessus
      out_of_scope      — Nessus found it but it is NOT in asset scope
    """
    scope = _parse_scope(asset_entries)
    scanned_ips = sorted({h["ip"] for h in scan_hosts if h.get("ip")})
    scanned_set = set(scanned_ips)

    # Partition every scanned IP into in-scope / out-of-scope
    in_scope_scanned = [ip for ip in scanned_ips if _in_scope(ip, scope)]
    out_of_scope     = [ip for ip in scanned_ips if not _in_scope(ip, scope)]

    # Build the missed list: asset addresses not seen by Nessus
    missed: List[str] = []
    for net in scope:
        if net.num_addresses == 1:
            # Single host (/32 or /128)
            ip = str(net.network_address)
            if ip not in scanned_set:
                missed.append(ip)
        elif net.num_addresses <= _ENUM_LIMIT:
            # Small subnet — enumerate individual host addresses
            for host in net.hosts():
                if str(host) not in scanned_set:
                    missed.append(str(host))
        else:
            # Large subnet — impractical to list every missing IP.
            # Report the subnet itself so the operator knows it wasn't
            # fully covered, without flooding the output.
            scanned_in_net = [ip for ip in scanned_set if _in_scope(ip, [net])]
            missed_count   = net.num_addresses - len(scanned_in_net)
            if missed_count > 0:
                missed.append(
                    f"{net}  "
                    f"[{scanned_in_net.__len__()} scanned / {net.num_addresses} total — "
                    f"{missed_count} not reached]"
                )

    # Count of distinct "scope positions" (hosts for small nets, addresses for large)
    total_asset = 0
    for net in scope:
        total_asset += net.num_addresses

    return {
        "in_scope_scanned": sorted(in_scope_scanned),
        "in_scope_missed":  sorted(missed),
        "out_of_scope":     sorted(out_of_scope),
        "counts": {
            "in_scope_scanned": len(in_scope_scanned),
            "in_scope_missed":  len(missed),
            "out_of_scope":     len(out_of_scope),
            "total_asset":      total_asset,
            "total_scanned":    len(scanned_ips),
        },
    }
