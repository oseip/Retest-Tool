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

    Each scope entry (IP or subnet of any size) counts as exactly 1.
    A subnet is "reachable" if Nessus found at least one host inside it.
    A subnet is "not reachable" if Nessus found zero hosts inside it.

    Returns:
      reachable     — scope entries where Nessus found at least 1 host
      not_reachable — scope entries where Nessus found nothing
      out_of_scope  — IPs Nessus found that are NOT in any scope entry
    """
    scanned_ips = sorted({h["ip"] for h in scan_hosts if h.get("ip")})
    scanned_set = set(scanned_ips)

    # Pre-convert all scanned IPs to ip_address objects once — avoids
    # re-parsing the same string thousands of times across scope entries.
    scanned_addrs: Dict[str, ipaddress.IPv4Address] = {}
    for ip in scanned_ips:
        try:
            scanned_addrs[ip] = ipaddress.ip_address(ip)
        except ValueError:
            pass

    valid_nets = []
    not_reachable: List[str] = []

    for entry in asset_entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
            valid_nets.append(net)
            hits = [ip for ip, addr in scanned_addrs.items() if addr in net]
            if not hits:
                # Preserve original entry string (don't expand IP to /32)
                label = entry if '/' not in entry and net.prefixlen == 32 else str(net)
                not_reachable.append(label)
        except ValueError:
            log.warning("Could not parse scope entry: %s", entry)

    # Reachable = all Nessus hosts that fall within any scope entry
    reachable = sorted(
        ip for ip, addr in scanned_addrs.items()
        if any(addr in net for net in valid_nets)
    )

    # Out of scope = Nessus hosts not in any scope entry
    out_of_scope = sorted(
        ip for ip, addr in scanned_addrs.items()
        if not any(addr in net for net in valid_nets)
    )

    return {
        "reachable":     reachable,
        "not_reachable": sorted(not_reachable),
        "out_of_scope":  out_of_scope,
        "counts": {
            "reachable":     len(reachable),
            "not_reachable": len(not_reachable),
            "out_of_scope":  len(out_of_scope),
            "total_scope":   len(valid_nets),
            "total_scanned": len(scanned_ips),
        },
    }
