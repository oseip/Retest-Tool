"""Asset list management and Nessus cross-reference."""
import ipaddress
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Set

log = logging.getLogger(__name__)

ASSETS_DIR = "data/assets"


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


def _expand(entries: List[str]) -> Set[str]:
    """Expand CIDR notation to individual IP strings."""
    ips: Set[str] = set()
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if net.num_addresses == 1:
                ips.add(str(net.network_address))
            elif net.num_addresses > 65536:
                # Keep as network notation — too large to enumerate
                log.warning("Large subnet kept as-is: %s (%d addrs)", entry, net.num_addresses)
                ips.add(entry)
            else:
                for ip in net.hosts():
                    ips.add(str(ip))
        except ValueError:
            ips.add(entry)
    return ips


def cross_reference(asset_entries: List[str], scan_hosts: List[Dict]) -> Dict:
    """
    Cross-reference client asset list against Nessus scan hosts.

    Returns three categories:
      in_scope_scanned  — in asset list + appeared in Nessus scan (reachable)
      in_scope_missed   — in asset list + NOT in Nessus scan (unreachable or not targeted)
      out_of_scope      — in Nessus scan + NOT in asset list
    """
    asset_ips: Set[str] = _expand(asset_entries)
    scanned_ips: Set[str] = {h["ip"] for h in scan_hosts if h.get("ip")}

    in_scope_scanned = sorted(asset_ips & scanned_ips)
    in_scope_missed  = sorted(asset_ips - scanned_ips)
    out_of_scope     = sorted(scanned_ips - asset_ips)

    return {
        "in_scope_scanned": in_scope_scanned,
        "in_scope_missed":  in_scope_missed,
        "out_of_scope":     out_of_scope,
        "counts": {
            "in_scope_scanned": len(in_scope_scanned),
            "in_scope_missed":  len(in_scope_missed),
            "out_of_scope":     len(out_of_scope),
            "total_asset":      len(asset_ips),
            "total_scanned":    len(scanned_ips),
        },
    }
