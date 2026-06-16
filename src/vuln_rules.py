"""
Vulnerability → nmap mapping table.
Each rule matches against the Jira ticket summary and provides:
  - nmap script and arguments to run
  - a parser that reads nmap output and returns (verdict, reason)

Verdicts: "fixed" | "not_fixed" | "inconclusive"
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional, Tuple

Verdict = str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _host_down(text: str) -> bool:
    t = text.lower()
    return any(p in t for p in [
        "host seems down", "0 hosts up", "host is down",
        "curl: (6)", "curl: (7)", "curl: (28)",
        "could not resolve host", "connection timed out after",
    ])


def _port_closed(text: str, port: int) -> bool:
    t = text.lower()
    return (f"{port}/tcp closed" in t or f"{port}/tcp filtered" in t
            or f"{port}/udp closed" in t or f"{port}/udp filtered" in t)


def _xml_elem(xml: str, key: str) -> Optional[str]:
    try:
        root = ET.fromstring(xml)
        for elem in root.iter("elem"):
            if elem.get("key") == key and elem.text:
                return elem.text.strip()
    except Exception:
        pass
    return None


# Patterns to extract the originally-vulnerable version from the Jira description.
# Tried in order; first match wins.
_VER_EXTRACT_PATTERNS = [
    r'(?:installed|detected|affected|current|running|vulnerable|found)\s+version[:\s]+v?([\d]+[\d.p\-]+)',
    r'version[:\s]+v?([\d]+[\d.p\-]+)',
    r'(?:apache|nginx|openssh|openssl|jenkins|kibana|grafana|tomcat|iis|php|'
    r'mysql|mariadb|redis|mongodb|elasticsearch|node\.?js|python|ruby|'
    r'wordpress|joomla|drupal|proftpd|vsftpd|postfix|exim)[/ ]+v?([\d]+[\d.p\-]+)',
    r'/([\d]+\.\d+[\d.p\-]*)',
    r'v?([\d]+\.\d+\.\d+[\d.p\-]*)\s+(?:was|is|has been|are)\s+(?:detected|found|installed|running|vulnerable)',
]


def _extract_version_from_description(description: str) -> Optional[str]:
    """Return the first version string found in the Jira ticket description."""
    if not description:
        return None
    for pattern in _VER_EXTRACT_PATTERNS:
        m = re.search(pattern, description, re.I)
        if m:
            return m.group(1).strip(".")
    return None


def _ver_tuple(v: str) -> tuple:
    """Convert a version string like '2.4.49' or '8.9p1' into a comparable tuple."""
    parts = re.split(r'[.\-p]', v.lower())
    result = []
    for p in parts:
        if p.isdigit():
            result.append(int(p))
    return tuple(result)


def _compare_versions(detected: str, vuln: str) -> Tuple[Verdict, str]:
    """Compare detected version against the originally-vulnerable version."""
    d = _ver_tuple(detected)
    v = _ver_tuple(vuln)
    if not d or not v:
        return "inconclusive", f"Detected {detected} (vulnerable was {vuln}) — could not compare numerically"
    if d == v:
        return "not_fixed", f"Version unchanged: still {detected} (vulnerable version was {vuln})"
    if d > v:
        return "fixed", f"Version updated from {vuln} to {detected}"
    return "not_fixed", f"Version {detected} is still at or below vulnerable version {vuln}"


# ---------------------------------------------------------------------------
# Parse functions
# ---------------------------------------------------------------------------

def _parse_ssl_expiry(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — could not verify certificate"
    not_after = _xml_elem(xml, "notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after[:10], "%Y-%m-%d")
            if expiry < datetime.utcnow():
                return "not_fixed", f"Certificate still expired (expired {expiry.date()})"
            return "fixed", f"Certificate is valid until {expiry.date()}"
        except ValueError:
            pass
    m = re.search(r"Not valid after\s*:\s*(\d{4}-\d{2}-\d{2})", text)
    if m:
        try:
            expiry = datetime.strptime(m.group(1), "%Y-%m-%d")
            if expiry < datetime.utcnow():
                return "not_fixed", f"Certificate still expired (expired {m.group(1)})"
            return "fixed", f"Certificate valid until {m.group(1)}"
        except ValueError:
            pass
    if "ssl-cert" not in text.lower():
        return "inconclusive", "Could not retrieve SSL certificate — port may be closed or filtered"
    return "inconclusive", "Could not parse certificate expiry date"


def _parse_ssl_trust(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "self-signed" in low or "self signed" in low:
        return "not_fixed", "Certificate is still self-signed"
    if "unable to get local issuer" in low or "certificate verify failed" in low:
        return "not_fixed", "Certificate still not trusted by a known CA"
    if "ssl-cert" in low and "self-signed" not in low and ("issuer" in low or _xml_elem(xml, "commonName")):
        return "fixed", "Certificate appears to have a valid issuer"
    if "ssl-cert" not in low:
        return "inconclusive", "Could not retrieve certificate"
    return "inconclusive", "Could not determine certificate trust status"


def _parse_ssl_weak_hash(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    for alg in ("md5", "sha-1", "sha1"):
        if alg in low and ("signature" in low or "digest" in low):
            return "not_fixed", f"Certificate still uses weak hash algorithm ({alg.upper()})"
    for alg in ("sha256", "sha384", "sha512", "sha-256", "sha-384", "sha-512"):
        if alg in low:
            return "fixed", "Certificate now uses strong hash algorithm"
    if "ssl-cert" not in low:
        return "inconclusive", "Could not retrieve certificate"
    return "inconclusive", "Could not determine certificate signature algorithm"


def _parse_ssl_wrong_hostname(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "subject alternative name" in low or "san" in low:
        return "fixed", "Certificate has Subject Alternative Name (SAN) entries"
    cn = _xml_elem(xml, "commonName")
    if cn:
        return "inconclusive", f"Certificate CN is '{cn}' — verify it matches the hostname"
    return "inconclusive", "Could not parse certificate hostname — verify manually"


def _parse_tls_versions(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()

    # Detect whether ssl-enum-ciphers actually produced cipher enumeration output
    script_ran = "ssl-enum-ciphers" in low or "tlsv" in low or "sslv" in low

    if not script_ran:
        if re.search(r'\d+/tcp open', low):
            return "inconclusive", "ssl-enum-ciphers produced no output — service may not speak TLS"
        return "inconclusive", "Port closed/filtered or TLS service not detected"

    problems = []
    if re.search(r'\btlsv1\.0\b|\btls ?1\.0\b', low):
        problems.append("TLS 1.0 still enabled")
    if re.search(r'\btlsv1\.1\b|\btls ?1\.1\b', low):
        problems.append("TLS 1.1 still enabled")
    if re.search(r'\bsslv2\b|\bssl ?v2\b', low):
        problems.append("SSL v2 still enabled")
    if re.search(r'\bsslv3\b|\bssl ?v3\b', low):
        problems.append("SSL v3 still enabled")
    for cipher in ("3des", "des-cbc", "rc4", "export", "_null_", "anon"):
        if cipher in low:
            problems.append(f"Weak cipher: {cipher.upper()}")

    if problems:
        return "not_fixed", "; ".join(problems)

    # Script ran and found no weak protocols or ciphers
    if re.search(r'\btlsv1\.[23]\b', low):
        return "fixed", "Only TLS 1.2/1.3 detected — no weak protocols or ciphers found"
    return "fixed", "No weak TLS protocols or ciphers detected in ssl-enum-ciphers output"


def _parse_dh_params(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    m = re.search(r'(\d+)\s*bits', text.lower())
    if m:
        bits = int(m.group(1))
        if bits <= 1024:
            return "not_fixed", f"DH modulus still {bits} bits (must be > 1024)"
        return "fixed", f"DH modulus is {bits} bits"
    low = text.lower()
    if "logjam" in low and "vulnerable" in low:
        return "not_fixed", "Logjam vulnerability still present"
    if "ssl-dh-params" not in low and "open" not in low:
        return "inconclusive", "Port closed/filtered"
    return "inconclusive", "Could not determine DH parameter size — check output"


def _parse_ssh_algos(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 22):
        return "inconclusive", "SSH port closed or filtered"

    problems = []

    # hmac-sha1 without -etm suffix is weak; hmac-sha1-etm@openssh.com is acceptable
    if re.search(r'hmac-sha1(?!-etm)', low):
        problems.append("Weak MAC: hmac-sha1")
    for mac in ("hmac-md5", "hmac-sha1-96", "hmac-md5-96", "umac-64@openssh.com"):
        if mac in low:
            problems.append(f"Weak MAC: {mac}")

    for cipher in ("arcfour", "blowfish-cbc", "cast128-cbc", "3des-cbc", "des-cbc"):
        if cipher in low:
            problems.append(f"Weak cipher: {cipher}")
    # CBC ciphers in the encryption_algorithms list = Terrapin risk
    if re.search(r'\S+-cbc', low) and "encryption_algorithms" in low:
        problems.append("CBC mode ciphers present (Terrapin vulnerability risk)")

    for kex in ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                 "diffie-hellman-group-exchange-sha1",
                 "gss-gex-sha1", "gss-group1-sha1", "gss-group14-sha1"):
        if kex in low:
            problems.append(f"Weak KEX: {kex}")

    if problems:
        return "not_fixed", "; ".join(problems[:5])

    if "ssh2-enum-algos" in low or "server_host_key_algorithms" in low or "encryption_algorithms" in low:
        return "fixed", "No weak SSH algorithms detected"
    return "inconclusive", "Could not retrieve SSH algorithm list — script may not have connected"


def _parse_ssh_proto_v1(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "protocol 1" in low or "sshv1" in low or "ssh protocol 1" in low:
        return "not_fixed", "SSH Protocol Version 1 still supported"
    if "protocol 2" in low or "ssh2" in low or "22/tcp open" in low:
        return "fixed", "SSH Protocol Version 1 is no longer offered"
    return "inconclusive", "Could not determine SSH protocol version — check output"


def _parse_openssh_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    m = re.search(r'openssh[_\s]+([\d.p]+)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected OpenSSH {detected} — vulnerable version not found in ticket description"
    if "22/tcp open" in text.lower():
        return "inconclusive", "SSH is open but version not parsed — check banner in output"
    return "inconclusive", "Could not detect SSH version"


def _parse_smb_signing(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 445):
        return "inconclusive", "SMB port closed or filtered"
    # nmap output variants: "enabled and required" = fixed; "disabled" or "enabled but not required" = not fixed
    if "enabled and required" in low or "message_signing: required" in low or "required: true" in low:
        return "fixed", "SMB message signing is required"
    if ("message_signing: disabled" in low or "enabled but not required" in low
            or "signing: not required" in low or "required: false" in low):
        return "not_fixed", "SMB message signing is not required"
    return "inconclusive", "Could not determine SMB signing status"


def _parse_smb_v1(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 445):
        return "inconclusive", "SMB port closed or filtered"
    # smb-protocols: NT LM 0.12 dialect = SMBv1
    if re.search(r'smbv1[:\s]*true|nt lm 0\.12|smb1.*enabled', low):
        return "not_fixed", "SMBv1 (NT LM 0.12) still supported"
    if "smb-protocols" in low or "dialects" in low:
        if "nt lm 0.12" not in low and "smbv1" not in low:
            return "fixed", "SMBv1 not listed in supported SMB protocols"
    return "inconclusive", "Could not determine SMBv1 status — check smb-protocols output"


def _parse_ms17010(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 445):
        return "inconclusive", "SMB port closed or filtered — patch may have removed the service"
    if "vulnerable" in low and ("ms17-010" in low or "eternalblue" in low):
        return "not_fixed", "MS17-010 (EternalBlue/WannaCry) vulnerability still present"
    if "not vulnerable" in low or "host does not appear vulnerable" in low:
        return "fixed", "Host is not vulnerable to MS17-010"
    return "inconclusive", "Could not confirm MS17-010 status — check output"


def _parse_rdp(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 3389):
        return "inconclusive", "RDP port closed or filtered"
    if "nla_supported: true" in low or "nla supported" in low or "credssp" in low:
        return "fixed", "Network Level Authentication (NLA) is enabled"
    if "nla_supported: false" in low or "security layer: rdp" in low:
        return "not_fixed", "NLA not enforced — RDP accepts connections without pre-authentication"
    if "encryption level: low" in low or "encryption level: medium" in low:
        return "not_fixed", "RDP encryption level is insufficient"
    if "encryption level: high" in low or "encryption level: fips" in low:
        return "fixed", "RDP encryption level is high/FIPS"
    return "inconclusive", "Could not determine RDP security configuration"


def _parse_bluekeep(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 3389):
        return "inconclusive", "RDP port closed or filtered"
    if "vulnerable" in low and ("cve-2019-0708" in low or "bluekeep" in low):
        return "not_fixed", "BlueKeep (CVE-2019-0708) vulnerability still present"
    if "not vulnerable" in low or "host does not appear" in low:
        return "fixed", "Host is not vulnerable to BlueKeep"
    return "inconclusive", "No standard nmap script for BlueKeep — verify manually via authenticated scan"


def _parse_http_methods(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    problems = []
    if re.search(r'\btrace\b', low) and "http-methods" in low:
        problems.append("TRACE method still enabled")
    if re.search(r'\btrack\b', low) and "http-methods" in low:
        problems.append("TRACK method still enabled")
    if problems:
        return "not_fixed", "; ".join(problems)
    if "http-methods" in low:
        return "fixed", "TRACE/TRACK methods not detected"
    return "inconclusive", "Could not determine HTTP methods — port may be closed"


def _parse_hsts(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "strict-transport-security" in low:
        return "fixed", "HSTS (Strict-Transport-Security) header is present"
    # Script ran but HSTS was not in response headers
    if "http-security-headers" in low or "http-headers" in low:
        return "not_fixed", "HSTS header not found in server response"
    # curl output: HTTP/1.1 or HTTP/2 response line, or [STATUS:...] sentinel
    if re.search(r'http/[12]|\[status:\d', low) or re.search(r'\d+/tcp open', low):
        return "not_fixed", "Got HTTP response but HSTS header not found"
    return "inconclusive", "Could not check HSTS — port may be closed or filtered"


def _parse_clickjacking(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "x-frame-options" in low:
        return "fixed", "X-Frame-Options header is present"
    if "content-security-policy" in low and "frame-ancestors" in low:
        return "fixed", "Content-Security-Policy with frame-ancestors protection is present"
    if "http-security-headers" in low or "http-headers" in low:
        return "not_fixed", "X-Frame-Options / CSP frame-ancestors header not found in response"
    if re.search(r'http/[12]|\[status:\d', low) or re.search(r'\d+/tcp open', low):
        return "not_fixed", "Got HTTP response but X-Frame-Options / CSP frame-ancestors not found"
    return "inconclusive", "Could not check clickjacking protection"


def _parse_service_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    versions = re.findall(r'(?:server|version)[:\s/]+(\d+[\d.]+)', text, re.I)
    if not versions:
        versions = re.findall(r'/([\d]+\.[\d]+\.[\d]+)', text)
    if versions:
        detected = sorted(set(versions))[-1]  # use highest detected version
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected version(s): {', '.join(sorted(set(versions)))} — vulnerable version not found in ticket description"
    if "open" in text.lower():
        return "inconclusive", "Service is open but version not detected — check banner in output"
    return "inconclusive", "Could not detect service version — port may be closed"


def _parse_jenkins_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — could not connect to Jenkins"
    low = text.lower()
    m = re.search(r'x-jenkins[:\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected Jenkins {detected} — vulnerable version not found in ticket description"
    if re.search(r'x-jenkins-session|x-hudson', text, re.I):
        return "inconclusive", "Jenkins detected but version header not returned — check version manually at /api/json"
    if "nginx" in low or "apache" in low:
        return "inconclusive", "Reverse proxy not forwarding X-Jenkins header — check version manually at <IP>/api/json"
    if re.search(r'\d+/tcp open', low):
        return "inconclusive", "Port is open but Jenkins version not detected in headers — may be behind a proxy"
    return "inconclusive", "Could not connect to Jenkins — port may be closed or filtered"


def _parse_kibana_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — could not connect to Kibana"
    m = re.search(r'"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"', text)
    detected = m.group(1) if m else None
    if not detected:
        m2 = re.search(r'kbn-version[:\s]+([0-9]+\.[0-9]+\.[0-9]+)', text, re.I)
        detected = m2.group(1) if m2 else None
    if detected:
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected Kibana {detected} — vulnerable version not found in ticket description"
    low = text.lower()
    if re.search(r'x-elastic-product', text, re.I):
        return "inconclusive", "Elastic product detected but version not returned — check /api/status"
    if re.search(r'http/[12]|\[status:\d|\d+/tcp open', low):
        return "inconclusive", "Service responding but Kibana version not detected — check /api/status manually"
    return "inconclusive", "Could not connect to Kibana — port may be closed or filtered"


def _parse_grafana_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — could not connect to Grafana"
    m = re.search(r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9.+\-]+)"', text)
    detected = m.group(1) if m else None
    if not detected:
        m2 = re.search(r'x-grafana-version[:\s]+([0-9]+\.[0-9]+\.[0-9]+)', text, re.I)
        detected = m2.group(1) if m2 else None
    if detected:
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected Grafana {detected} — vulnerable version not found in ticket description"
    low = text.lower()
    if re.search(r'http/[12]|\[status:\d|\d+/tcp open', low):
        return "inconclusive", "Service responding but Grafana version not detected — check /api/health manually"
    return "inconclusive", "Could not connect to Grafana — port may be closed or filtered"


def _parse_vnc(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 5900):
        return "inconclusive", "VNC port closed or filtered"
    if "authentication: none" in low or "no authentication" in low or "securitytype: none" in low:
        return "not_fixed", "VNC still accessible without authentication"
    if "vnc authentication" in low or "authentication: vnc" in low or "invalid security" in low:
        return "fixed", "VNC requires authentication"
    return "inconclusive", "Could not determine VNC authentication status"


def _parse_telnet(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "23/tcp open" in low or ("telnet" in low and "open" in low):
        return "not_fixed", "Telnet service still running and accessible"
    if _port_closed(low, 23):
        return "fixed", "Telnet port is closed/filtered"
    return "inconclusive", "Could not determine Telnet service status"


def _parse_snmp(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    # snmp-brute output: "public - Valid credentials" when default community accessible
    if re.search(r'public\s*[-–]\s*valid', low) or "community: public" in low or '"public"' in low:
        return "not_fixed", "Default SNMP community string 'public' still accessible"
    if "no valid accounts found" in low or "no accounts found" in low:
        return "fixed", "Default SNMP community string not accessible"
    if "161/udp open" in low or "snmp" in low:
        return "inconclusive", "SNMP port open — could not confirm community string status"
    return "inconclusive", "SNMP port closed/filtered or not detected"


def _parse_mongodb(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 27017):
        return "inconclusive", "MongoDB port closed or filtered"
    if ("databases" in low or "listdatabases" in low or "mongodb_version" in low
            or "totalsize" in low):
        return "not_fixed", "MongoDB still accessible without authentication"
    if "authentication required" in low or "not authorized" in low:
        return "fixed", "MongoDB now requires authentication"
    return "inconclusive", "Could not determine MongoDB authentication status"


def _parse_redis(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 6379):
        return "inconclusive", "Redis port closed or filtered"
    if "redis_version" in low or "connected_clients" in low or "used_memory" in low:
        return "not_fixed", "Redis still accessible without authentication"
    if "noauth" in text or "authentication required" in low or "requirepass" in low:
        return "fixed", "Redis now requires authentication"
    return "inconclusive", "Could not determine Redis authentication status"


def _parse_elasticsearch(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if ('"cluster_name"' in text or '"tagline"' in text
            or ('"version"' in text and "elasticsearch" in low and "200" in text)):
        return "not_fixed", "Elasticsearch still accessible without authentication"
    if "401" in text or "authentication required" in low or "security_exception" in low:
        return "fixed", "Elasticsearch now requires authentication"
    return "inconclusive", "Could not determine Elasticsearch access status"


def _parse_solr(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 8983):
        return "inconclusive", "Solr port closed or filtered"
    # Unauthenticated Solr admin API returns JSON with "status" and core names
    if ('"status"' in text and '"name"' in text) or "solr-spec-version" in low:
        return "not_fixed", "Solr admin API (/solr/admin/cores) accessible without authentication"
    if "401" in text or "403" in text or "authentication required" in low:
        return "fixed", "Solr admin API requires authentication"
    if "8983/tcp open" in low:
        return "inconclusive", "Solr port open but admin API status unclear — check /solr/admin/cores manually"
    return "inconclusive", "Could not determine Solr access status"


def _parse_nfs(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 2049):
        return "inconclusive", "NFS port closed or filtered"
    if "exports" in low and ("/" in text or "nfs-showmount" in low):
        return "not_fixed", "NFS shares still accessible"
    if "no exports" in low or "export list" not in low:
        return "fixed", "No NFS shares accessible"
    return "inconclusive", "Could not determine NFS share status"


def _parse_x11(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "access: open" in low or ("x11 access" in low and "open" in low):
        return "not_fixed", "X11 server still accessible without authentication"
    if _port_closed(low, 6000) or "access: closed" in low or "access: restricted" in low:
        return "fixed", "X11 port is closed/filtered or access is restricted"
    return "inconclusive", "Could not determine X11 access status"


def _parse_ftp_anon(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "anonymous ftp login allowed" in low or "ftp-anon: anonymous" in low:
        return "not_fixed", "Anonymous FTP login still allowed"
    if _port_closed(low, 21):
        return "inconclusive", "FTP port closed or filtered"
    if "ftp-anon" in low:
        return "fixed", "Anonymous FTP login not allowed"
    return "inconclusive", "Could not determine FTP anonymous access status"


def _parse_smb_null(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 445):
        return "inconclusive", "SMB port closed or filtered"
    if "null session" in low or "account: " in low:
        return "not_fixed", "SMB null session still allowed"
    if "access denied" in low or "nt_status_access_denied" in low:
        return "fixed", "SMB null session is blocked"
    return "inconclusive", "Could not determine SMB null session status"


def _parse_ipmiv2(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "ipmiv2" in low or "rakp" in low or "hash" in low:
        return "not_fixed", "IPMI v2 RAKP authentication hash still exposed"
    if _port_closed(low, 623):
        return "inconclusive", "IPMI port closed or filtered"
    return "inconclusive", "Could not determine IPMI vulnerability status"


def _parse_iscsi(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "target name" in low or "iqn." in low:
        return "not_fixed", "iSCSI target still accessible without authentication"
    if _port_closed(low, 3260):
        return "inconclusive", "iSCSI port closed or filtered"
    return "inconclusive", "Could not determine iSCSI access status"


def _parse_hadoop_yarn(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "cluster" in low or "resourcemanager" in low or ("yarn" in low and "200" in text):
        return "not_fixed", "Hadoop YARN ResourceManager still accessible unauthenticated"
    if _port_closed(low, 8088):
        return "inconclusive", "YARN port closed or filtered"
    return "inconclusive", "Could not determine Hadoop YARN status"


def _parse_activemq(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "cve-2023-46604" in low and "vulnerable" in low:
        return "not_fixed", "ActiveMQ RCE (CVE-2023-46604) still present"
    if "not vulnerable" in low:
        return "fixed", "ActiveMQ is not vulnerable to CVE-2023-46604"
    if _port_closed(low, 61616):
        return "inconclusive", "ActiveMQ port closed or filtered"
    return "inconclusive", "Could not determine ActiveMQ vulnerability status"


def _parse_openssl_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    m = re.search(r'openssl[/\s]+([\d.a-z]+)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected OpenSSL {detected} — vulnerable version not found in ticket description"
    if "open" in text.lower():
        return "inconclusive", "Service open but OpenSSL version not parsed — check banner"
    return "inconclusive", "Could not detect OpenSSL version"


def _parse_tomcat_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — could not connect to Tomcat"
    m = re.search(r'apache[- ]tomcat[/\s]+([0-9]+\.[0-9]+\.[0-9.]+)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected Apache Tomcat {detected} — vulnerable version not found in ticket description"
    low = text.lower()
    if "coyote" in low or "tomcat" in low:
        return "inconclusive", "Apache Tomcat detected but version not in headers — check /manager/text or /VERSION.txt manually"
    if re.search(r'\d+/tcp open', low):
        return "inconclusive", "Port open but Tomcat not identified — may be behind a reverse proxy"
    return "inconclusive", "Could not detect Apache Tomcat — port may be closed or filtered"


def _parse_ghostcat(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "8009/tcp open" in low or "ajp" in low:
        return "not_fixed", "AJP connector (port 8009) is open — Ghostcat risk present; disable AJP or restrict to localhost"
    if "8009/tcp closed" in low or "8009/tcp filtered" in low:
        return "fixed", "AJP port 8009 is closed/filtered — Ghostcat risk mitigated"
    return "inconclusive", "Could not determine AJP connector status — check port 8009 manually"


def _parse_jboss(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if ("jmx" in low or "jboss" in low or "mbean" in low) and ("200" in text or "jmx-console" in low):
        return "not_fixed", "JBoss JMX Console is still accessible without authentication — critical RCE risk"
    if "401" in text or "403" in text or "access denied" in low:
        return "fixed", "JBoss JMX Console requires authentication"
    if re.search(r'\d+/tcp open', low):
        return "inconclusive", "Port open — check /jmx-console/ and /web-console/ manually for unauthenticated access"
    return "inconclusive", "Could not reach JBoss — port may be closed or filtered"


def _parse_oracle_db(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    m = re.search(r'(?:oracle|version)[^0-9]*([0-9]+\.[0-9]+\.[0-9.]+)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected Oracle DB {detected} — vulnerable version not found in ticket description"
    low = text.lower()
    if "1521/tcp open" in low or "oracle" in low:
        return "inconclusive", "Oracle DB port open but version not parsed — check TNS banner manually"
    return "inconclusive", "Could not detect Oracle Database — port 1521 may be closed or filtered"


def _parse_oracle_tns(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "1521/tcp open" in low or "oracle-tns" in low or "tnscmd" in low:
        m = re.search(r'version.*?([0-9]+\.[0-9]+\.[0-9.]+)', text, re.I)
        ver = f" {m.group(1)}" if m else ""
        return "inconclusive", f"Oracle TNS Listener{ver} is accessible — verify authentication is enforced and listener is patched"
    if "1521/tcp closed" in low or "1521/tcp filtered" in low:
        return "inconclusive", "Oracle TNS port 1521 is closed or filtered"
    return "inconclusive", "Could not reach Oracle TNS Listener — port may be closed"


def _parse_oracle_weblogic(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "weblogic" in low:
        m = re.search(r'weblogic[/\s]+([0-9]+\.[0-9.]+)', text, re.I)
        if m:
            detected = m.group(1)
            vuln_ver = _extract_version_from_description(description)
            if vuln_ver:
                return _compare_versions(detected, vuln_ver)
            return "inconclusive", f"Detected WebLogic {detected} — vulnerable version not found in ticket description"
        return "inconclusive", "WebLogic detected — check version via admin console at :7001/console and compare with ticket"
    if "7001/tcp open" in low or "7002/tcp open" in low:
        return "inconclusive", "WebLogic port open but not identified — check admin console at :7001/console"
    return "inconclusive", "Could not detect Oracle WebLogic — port 7001/7002 may be closed"


def _parse_mssql_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    m = re.search(r'sql server[^0-9]*([0-9]+\.[0-9]+\.[0-9.]+)', text, re.I)
    if not m:
        m = re.search(r'microsoft sql server[^0-9]*([0-9]+\.[0-9]+\.[0-9.]+)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected MSSQL {detected} — vulnerable version not found in ticket description"
    low = text.lower()
    if "1433/tcp open" in low or "ms-sql" in low or "sql server" in low:
        return "inconclusive", "MSSQL port open but version not parsed — check ms-sql-info nmap output"
    return "inconclusive", "Could not detect MSSQL — port 1433 may be closed or filtered"


def _parse_cisco_iosxe(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — Cisco WebUI not reachable"
    low = text.lower()
    if "cisco" in low or "ios" in low or "iosxe" in low:
        return "inconclusive", "Cisco IOS XE web interface detected — cannot confirm patch status via nmap; verify via 'show version' on device or PSIRT advisory"
    if re.search(r'\d+/tcp open', low):
        return "inconclusive", "Web interface accessible — verify Cisco IOS XE patch level via authenticated device access"
    return "inconclusive", "Could not reach Cisco IOS XE web interface — may be restricted or patched"


def _parse_hp_ilo(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — could not connect to HP iLO"
    m = re.search(r'ilo[/\s-]+([0-9]+\.[0-9]+\.[0-9.]+)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected HP iLO firmware {detected} — vulnerable version not found in ticket description"
    low = text.lower()
    if "ilo" in low or "hp" in low and "443/tcp open" in low:
        return "inconclusive", "HP iLO interface detected but firmware version not returned — check iLO web interface directly"
    if re.search(r'\d+/tcp open', low):
        return "inconclusive", "Port open but HP iLO firmware version not detected — check iLO admin interface at https://<IP>"
    return "inconclusive", "Could not detect HP iLO — HTTPS port may be closed or filtered"


def _parse_vmware(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — could not connect to VMware service"
    m = re.search(r'(?:vmware|vsphere|esxi|vcenter)[^0-9]*([0-9]+\.[0-9]+\.[0-9.]+)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected VMware {detected} — vulnerable version not found in ticket description"
    low = text.lower()
    if any(k in low for k in ("vmware", "vsphere", "vcenter", "esxi")):
        return "inconclusive", "VMware service detected but version not parsed — check vSphere Client or VMSA advisory for patch status"
    if re.search(r'\d+/tcp open', low):
        return "inconclusive", "Port open but VMware service not identified — verify version via management interface"
    return "inconclusive", "Could not detect VMware service — management port may be closed or filtered"


def _parse_log4shell(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if re.search(r'\d+/tcp open', low):
        return "inconclusive", "Service is running — Log4Shell requires application-level verification; confirm Log4j version ≥ 2.17.1 via authenticated scan or package audit"
    return "inconclusive", "Port closed or unreachable — could not perform Log4Shell service check"


def _parse_msmq(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "1801/tcp open" in low or "msmq" in low or "message queuing" in low:
        return "not_fixed", "MSMQ port 1801 is open — apply Microsoft patch for CVE-2023-21554 (QueueJumper)"
    if "1801/tcp closed" in low or "1801/tcp filtered" in low:
        return "fixed", "MSMQ port 1801 is closed/filtered — QueueJumper risk mitigated"
    return "inconclusive", "Could not determine MSMQ port status — check port 1801 manually"


def _parse_minio(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "minio" in low or ("9000/tcp open" in low or "9001/tcp open" in low):
        if "401" in text or "403" in text:
            return "fixed", "MinIO requires authentication — verify default credentials are not in use"
        return "not_fixed", "MinIO admin interface accessible — verify default credentials (minioadmin/minioadmin) have been changed"
    if "9000/tcp closed" in low or "9001/tcp closed" in low:
        return "inconclusive", "MinIO port closed — service may have been removed or port changed"
    return "inconclusive", "Could not detect MinIO service — verify manually at https://<IP>:9001"


def _parse_dropbear_version(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    m = re.search(r'dropbear[_\s]+(?:ssh[_\s]+)?([0-9]+\.[0-9]+)', text, re.I)
    if m:
        detected = m.group(1)
        vuln_ver = _extract_version_from_description(description)
        if vuln_ver:
            return _compare_versions(detected, vuln_ver)
        return "inconclusive", f"Detected Dropbear SSH {detected} — vulnerable version not found in ticket description"
    low = text.lower()
    if "dropbear" in low:
        return "inconclusive", "Dropbear SSH detected but version not parsed — check SSH banner manually"
    if "22/tcp open" in low:
        return "inconclusive", "SSH port open but Dropbear not identified — may be OpenSSH (check banner)"
    return "inconclusive", "Could not detect Dropbear SSH — port may be closed"


def _parse_ollama(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _port_closed(low, 11434):
        return "inconclusive", "Ollama port closed or filtered"
    if '"models"' in text or '"version"' in text or "ollama" in low:
        if "401" in text or "403" in text:
            return "fixed", "Ollama API requires authentication"
        return "not_fixed", "Ollama API still accessible without authentication"
    if _got_response(low):
        return "inconclusive", "Port open but Ollama not confirmed — check /api/tags manually"
    return "inconclusive", "Could not detect Ollama — port 11434 may be closed"


def _parse_amqp(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "5672/tcp open" in low or "amqp" in low:
        return "not_fixed", "AMQP port 5672 is open and cleartext — enable TLS (AMQPS on 5671) or restrict network access"
    if "5672/tcp closed" in low or "5672/tcp filtered" in low:
        return "inconclusive", "AMQP port closed or filtered — service may have been secured"
    return "inconclusive", "Could not determine AMQP service status — check port 5672"


def _parse_dns_cache(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "dns-cache-snoop" in low:
        if "cached" in low or "resolved" in low:
            return "not_fixed", "DNS cache snooping is possible — configure to refuse recursive queries from external hosts"
        return "fixed", "DNS cache snooping appears mitigated"
    if "53/udp open" in low or "53/tcp open" in low:
        return "inconclusive", "DNS port open — run dns-cache-snoop nmap script to confirm exposure"
    return "inconclusive", "DNS port closed/filtered or not detected"


def _parse_ntp(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "ntp-info" in low or "mode 6" in low or "ntpq" in low:
        return "not_fixed", "NTP Mode 6 (control queries) enabled — disable with 'restrict default noquery'"
    if "123/udp open" in low or "ntp" in low:
        return "inconclusive", "NTP service detected — verify mode 6 is disabled via ntpq -c readvar"
    return "inconclusive", "NTP port 123/UDP not detected — may be filtered"


def _parse_web_basic_auth(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "www-authenticate" in low or ("basic" in low and "401" in text):
        # curl: final URL contains https if served over TLS; nmap: "ssl" or "443/tcp open"
        if "443/tcp open" in low or "ssl" in low or "[url:https://" in low:
            return "fixed", "Basic authentication is served over HTTPS"
        if re.search(r'(?:80|8080|8008)/tcp open', low) or "[url:http://" in low:
            return "not_fixed", "Basic authentication detected on plain HTTP — move to HTTPS"
    if _got_response(low):
        return "inconclusive", "Got response — verify Basic Auth is only served over HTTPS"
    return "inconclusive", "Could not determine HTTP authentication mechanism"


def _parse_cleartext_creds(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    # curl: [URL:http://...] means cleartext; nmap: explicit port strings
    if re.search(r'\b80/tcp open\b|\b8080/tcp open\b', low) or "[url:http://" in low:
        return "not_fixed", "Service is accessible over cleartext HTTP — enforce HTTPS redirection"
    if "443/tcp open" in low or "ssl" in low or "[url:https://" in low:
        return "fixed", "Service is accessible over HTTPS"
    if _got_response(low):
        return "inconclusive", "Got response — verify all credential-bearing endpoints are HTTPS only"
    return "inconclusive", "Could not determine credential transmission security"


def _parse_ip_disclosure(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "x-real-ip" in low or "x-original-ip" in low or re.search(r'x-forwarded-for.*\d{1,3}\.\d{1,3}', low):
        return "not_fixed", "Internal IP address still disclosed in HTTP response headers"
    # nmap script ran, or curl returned a response — no IP header found
    if "http-headers" in low or "http-security-headers" in low or _got_response(low):
        return "fixed", "No internal IP disclosure headers found in response"
    return "inconclusive", "Could not retrieve HTTP headers — port may be closed"


def _parse_smtp_info(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "smtp-commands" in low or "220" in text or "ehlo" in low:
        for sw in ("postfix", "sendmail", "exim", "microsoft esmtp", "exchange"):
            if sw in low:
                return "not_fixed", f"SMTP banner discloses server software ({sw}) — configure to suppress banner details"
        return "inconclusive", "SMTP accessible — verify banner does not reveal server version or internal hostnames"
    if "25/tcp closed" in low or "587/tcp closed" in low:
        return "inconclusive", "SMTP port closed or filtered"
    return "inconclusive", "Could not reach SMTP service — ports 25/587 may be closed"


def _parse_alfresco(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "alfresco" in low:
        if "200" in text and ("admin" in low or "dashboard" in low or "repository" in low):
            return "not_fixed", "Alfresco admin panel accessible — verify default credentials (admin/admin) are not in use"
        if "401" in text or "403" in text:
            return "inconclusive", "Alfresco requires authentication — verify default credentials have been changed"
    if _got_response(low):
        return "inconclusive", "Got response — check /alfresco/ and /share/ for default credential access"
    return "inconclusive", "Could not detect Alfresco — port may be closed"


def _parse_browsable_dirs(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "index of" in low or "directory listing" in low or "parent directory" in low:
        return "not_fixed", "Directory listing still enabled — disable Options Indexes (Apache) or autoindex (nginx)"
    if "403" in text or "forbidden" in low:
        return "fixed", "Directory listing returns 403 Forbidden — appears disabled"
    if _got_response(low):
        return "inconclusive", "Got response — check web root and sub-directories for enabled directory listings"
    return "inconclusive", "Could not check directory listing — port may be closed"


def _parse_cvs_web(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "entries" in low and ("cvs" in low or "viewcvs" in low or "viewvc" in low):
        return "not_fixed", "CVS Entries file still accessible via web — remove CVS/ directories from web root"
    if "403" in text or "404" in text:
        return "fixed", "CVS Entries file not accessible (403/404)"
    if _got_response(low):
        return "inconclusive", "Got response — check /CVS/Entries and /cgi-bin/cvsweb.cgi manually"
    return "inconclusive", "Could not check CVS web interface — port may be closed"


def _parse_cisco_tftp(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if "69/udp open" in low or ("tftp" in low and "open" in low):
        return "not_fixed", "TFTP accessible — Cisco config files may be downloadable; disable TFTP or restrict with ACL"
    if "69/udp closed" in low or "69/udp filtered" in low:
        return "fixed", "TFTP port is closed/filtered — file disclosure risk mitigated"
    return "inconclusive", "Could not determine TFTP status — check port 69/UDP manually"


def _parse_moodle(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable — could not connect to Moodle"
    m = re.search(r'moodle[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', text, re.I)
    if m:
        return "inconclusive", f"Detected Moodle {m.group(1)} — compare against the patched version in the Jira ticket"
    low = text.lower()
    if "moodle" in low:
        return "inconclusive", "Moodle detected but version not returned — check /admin/environment.php for installed version"
    if _got_response(low):
        return "inconclusive", "Got response — check /login/index.php for Moodle; version visible at /lib/upgrade.txt"
    return "inconclusive", "Could not detect Moodle — port may be closed"


_CURL_RESPONSE = re.compile(r'http/[12]|\[status:\d')


def _got_response(low: str) -> bool:
    """True if output contains a live HTTP response (curl) or open TCP port (nmap)."""
    return bool(_CURL_RESPONSE.search(low) or re.search(r'\d+/tcp open', low))


def _parse_react_rce(text: str, xml: str, description: str = "") -> Tuple[Verdict, str]:
    if _host_down(text):
        return "inconclusive", "Host unreachable"
    low = text.lower()
    if _got_response(low):
        extra = " (Next.js detected)" if "x-powered-by: next.js" in low else ""
        return "inconclusive", (
            f"Service is reachable{extra} — React2Shell requires application-level verification; "
            "confirm React Server Components version is outside the vulnerable range in the ticket"
        )
    return "inconclusive", "Could not reach service — port may be closed or filtered"


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------

@dataclass
class VulnRule:
    name: str
    patterns: List[str]
    nmap_script: str = ""
    extra_args: str = ""
    default_port: Optional[int] = None
    parse: Optional[Callable] = None
    tool: str = "nmap"      # "nmap" | "curl"
    curl_path: str = "/"    # URL path appended when tool="curl"
    requires_root: bool = False  # True for UDP scans (-sU) and other raw-socket ops


RULES: List[VulnRule] = [

    # --- SSL / Certificate ---
    VulnRule(
        name="SSL Certificate Expiry",
        patterns=[r"ssl certificate expir", r"ssl cert.*expir"],
        nmap_script="ssl-cert",
        parse=_parse_ssl_expiry,
    ),
    VulnRule(
        name="SSL Certificate Cannot Be Trusted / Self-Signed",
        patterns=[r"ssl certificate cannot be trusted", r"ssl self.signed", r"self.signed certificate"],
        nmap_script="ssl-cert",
        parse=_parse_ssl_trust,
    ),
    VulnRule(
        name="SSL Certificate Signed Using Weak Hashing Algorithm",
        patterns=[r"ssl certificate signed using weak hash", r"weak hashing algorithm"],
        nmap_script="ssl-cert",
        parse=_parse_ssl_weak_hash,
    ),
    VulnRule(
        name="SSL Certificate with Wrong Hostname",
        patterns=[r"ssl certificate with wrong hostname", r"wrong hostname"],
        nmap_script="ssl-cert",
        parse=_parse_ssl_wrong_hostname,
    ),

    # --- TLS / Weak Ciphers ---
    VulnRule(
        name="TLS Version 1.0 / 1.1 / SSL v2 v3 / Weak Ciphers",
        patterns=[
            r"tls version 1\.0", r"tls version 1\.1", r"ssl version 2", r"ssl version 3",
            r"ssl medium strength", r"sweet32", r"ssl rc4", r"bar mitzvah",
            r"ssl anonymous cipher", r"poodle", r"weak ssl", r"early tls",
            r"tls.*deprecated", r"tls.*protocol detection",
            r"crime vulnerability", r"openssl aes-ni padding",
            r"ssl.*weak cipher", r"tls.*weak cipher", r"deprecated tls",
            r"tls 1\.0 enabled", r"tls 1\.1 enabled",
            r"ssl version 2 and 3 protocol detection",
        ],
        nmap_script="ssl-enum-ciphers",
        parse=_parse_tls_versions,
    ),
    VulnRule(
        name="SSL/TLS Diffie-Hellman Weak Parameters (Logjam)",
        patterns=[r"logjam", r"diffie.hellman modulus.*1024", r"dh modulus", r"dh.*weak parameter"],
        nmap_script="ssl-dh-params",
        parse=_parse_dh_params,
    ),
    VulnRule(
        name="MS14-066 Schannel RCE",
        patterns=[r"ms14-066", r"schannel.*code execution", r"2992611"],
        nmap_script="ssl-cert",
        extra_args="-sV",
        default_port=443,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="HSTS Missing from HTTPS Server",
        patterns=[
            r"hsts missing", r"strict.transport.security.*missing", r"hsts not enabled",
            r"misconfigured hsts", r"hsts header.*not", r"missing hsts",
            r"strict transport security header missing",
        ],
        nmap_script="",
        default_port=443,
        parse=_parse_hsts,
        tool="curl",
        curl_path="/",
    ),
    VulnRule(
        name="Web Application Vulnerable to Clickjacking",
        patterns=[r"clickjacking", r"x-frame-options", r"browser cross-site", r"frame.*injection"],
        nmap_script="",
        default_port=443,
        parse=_parse_clickjacking,
        tool="curl",
        curl_path="/",
    ),

    # --- SSH ---
    VulnRule(
        name="SSH Weak Algorithms / MAC / CBC / Key Exchange / Terrapin",
        patterns=[
            r"ssh weak key exchange", r"ssh weak mac", r"ssh server cbc mode",
            r"ssh terrapin", r"ssh weak algorithm", r"ssh.*weak.*insecure mac",
            r"ssh.*cbc mode cipher", r"ssh diffie.hellman",
            r"cve-2023-48795",
            r"ssh.*weak.*cipher", r"ssh.*insecure algorithm",
            r"ssh.*hmac-md5", r"ssh.*hmac-sha1",
        ],
        nmap_script="ssh2-enum-algos",
        default_port=22,
        parse=_parse_ssh_algos,
    ),
    VulnRule(
        name="SSH Protocol Version 1 Supported",
        patterns=[
            r"ssh protocol version 1 supported", r"ssh protocol version 1$",
            r"ssh protocol version 1 session", r"ssh protocol version 1 key",
        ],
        nmap_script="sshv1",
        default_port=22,
        parse=_parse_ssh_proto_v1,
    ),
    VulnRule(
        name="Dropbear SSH Server Version Vulnerability",
        patterns=[r"dropbear ssh", r"dropbear.*vulnerabilit"],
        nmap_script="banner",
        extra_args="-sV",
        default_port=22,
        parse=_parse_dropbear_version,
    ),
    VulnRule(
        name="OpenSSH Version Vulnerability",
        patterns=[
            r"openssh\s*<", r"openssh.*multiple vulnerabilities", r"outdated openssh",
            r"openssh.*cve", r"openssh.*vulnerability", r"openssh.*trusted x11",
        ],
        nmap_script="banner",
        extra_args="-sV",
        default_port=22,
        parse=_parse_openssh_version,
    ),

    # --- SMB / Windows ---
    VulnRule(
        name="SMB Signing Not Required",
        patterns=[r"smb signing not required", r"smb.*signing.*disabled", r"smb.*signing.*not required"],
        nmap_script="smb-security-mode",
        default_port=445,
        parse=_parse_smb_signing,
    ),
    VulnRule(
        name="MS17-010 EternalBlue / WannaCry / EternalRocks",
        patterns=[
            r"ms17-010", r"eternalblue", r"eternalchampion", r"eternalromance",
            r"wannacry", r"eternalrocks", r"petya", r"doublepulsar", r"eternalsynergy",
        ],
        nmap_script="smb-vuln-ms17-010,smb-double-pulsar-backdoor",
        default_port=445,
        parse=_parse_ms17010,
    ),
    VulnRule(
        name="MS09-050 Microsoft Windows SMB2 Vulnerability",
        patterns=[r"ms09-050", r"educatedscholar", r"smb2.*validat"],
        nmap_script="smb-vuln-ms17-010",
        default_port=445,
        parse=_parse_ms17010,
    ),
    VulnRule(
        name="SMB NULL Session / Shares Unprivileged Access",
        patterns=[
            r"smb null session", r"smb.*null.*auth",
            r"microsoft windows smb shares", r"smb.*shares.*unprivileged",
            r"smb.*shares.*unprivileged access",
        ],
        nmap_script="smb-enum-shares",
        default_port=445,
        parse=_parse_smb_null,
    ),
    VulnRule(
        name="Microsoft Windows SMBv1 Multiple Vulnerabilities",
        patterns=[r"smbv1", r"smb.*smbv?1", r"smb.*version 1", r"smb1.*enabled", r"smb.*enable.*version 1"],
        nmap_script="smb-protocols",
        default_port=445,
        parse=_parse_smb_v1,
    ),
    VulnRule(
        name="MS16-047 Badlock / Samba Badlock",
        patterns=[r"ms16-047", r"badlock"],
        nmap_script="smb-vuln-ms17-010",
        default_port=445,
        parse=_parse_ms17010,
    ),
    VulnRule(
        name="Microsoft MSMQ RCE QueueJumper (CVE-2023-21554)",
        patterns=[r"microsoft message queuing", r"queuejumper", r"cve-2023-21554", r"msmq"],
        nmap_script="banner",
        extra_args="-sV",
        default_port=1801,
        parse=_parse_msmq,
    ),

    # --- RDP ---
    VulnRule(
        name="Terminal Services / RDP NLA / Encryption",
        patterns=[
            r"terminal services.*nla", r"terminal services.*network level auth",
            r"terminal services.*encryption", r"remote desktop.*man.in.the.middle",
            r"ms12-020", r"rdp.*encryption", r"rdp.*nla", r"rdp.*without.*nla",
        ],
        nmap_script="rdp-enum-encryption",
        default_port=3389,
        parse=_parse_rdp,
    ),
    VulnRule(
        name="BlueKeep CVE-2019-0708",
        patterns=[r"bluekeep", r"cve-2019-0708"],
        nmap_script="rdp-vuln-ms12-020",
        extra_args="--script-args=unsafe=1",
        default_port=3389,
        parse=_parse_bluekeep,
    ),

    # --- HTTP / Web (most specific first to avoid generic rule swallowing them) ---
    VulnRule(
        name="Apache Log4Shell RCE (CVE-2021-44228)",
        patterns=[r"log4shell", r"log4j.*rce", r"cve-2021-44228", r"log4.*jndi"],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=8080,
        parse=_parse_log4shell,
    ),
    VulnRule(
        name="Apache Tomcat AJP Connector / Ghostcat",
        patterns=[r"ghostcat", r"ajp connector", r"tomcat.*ajp", r"apache tomcat ajp"],
        nmap_script="banner",
        extra_args="-sV",
        default_port=8009,
        parse=_parse_ghostcat,
    ),
    VulnRule(
        name="JBoss JMX Console / Deserialization RCE",
        patterns=[
            r"jboss jmx console", r"jboss.*deserialization", r"jboss.*rce",
            r"jboss java object", r"jboss enterprise application platform",
            r"ejbinvokerservlet", r"jmxinvokerservlet", r"jboss.*unrestricted",
        ],
        nmap_script="http-get",
        extra_args="--script-args=http-get.path=/jmx-console/",
        default_port=8080,
        parse=_parse_jboss,
    ),
    VulnRule(
        name="Apache Tomcat Version Vulnerability",
        patterns=[
            r"apache tomcat\s+[0-9]", r"apache tomcat.*multiple vulnerabilities",
            r"outdated apache tomcat", r"apache tomcat.*security constraint",
            r"apache tomcat.*poodle", r"apache tomcat.*ghostcat",
            r"apache tomcat default", r"apache tomcat.*ajp",
        ],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=8080,
        parse=_parse_tomcat_version,
    ),
    VulnRule(
        name="Oracle WebLogic Version / RCE",
        patterns=[
            r"oracle weblogic", r"weblogic.*rce", r"weblogic.*cve",
            r"weblogic unsupported", r"cve-2020-14882",
        ],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=7001,
        parse=_parse_oracle_weblogic,
    ),
    VulnRule(
        name="HTTP TRACE / TRACK Methods Allowed",
        patterns=[r"http trace", r"http track", r"options method allowed", r"http.*dangerous method"],
        nmap_script="http-methods",
        default_port=80,
        parse=_parse_http_methods,
    ),
    VulnRule(
        name="Apache / Nginx / Web Server Version",
        patterns=[
            r"apache 2\.4", r"apache 2\.2", r"apache http server",
            r"nginx\s*<", r"apache activemq web console",
            r"unsupported web server", r"unsupported web server detection",
            r"apache.*multiple vulnerabilities", r"apache.*cve",
            r"nginx.*multiple vulnerabilities",
            r"apache.*seol", r"apache http server seol",
        ],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=80,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="Apache Solr Unauthenticated Access / RCE",
        patterns=[r"apache solr", r"solr.*unauthenticated", r"solr.*without auth", r"solr.*rce"],
        nmap_script="http-get",
        extra_args="--script-args=http-get.path=/solr/admin/cores",
        default_port=8983,
        parse=_parse_solr,
    ),
    VulnRule(
        name="Jenkins Version Vulnerability",
        patterns=[
            r"jenkins lts\s*<", r"jenkins weekly\s*<",
            r"jenkins.*multiple vulnerabilities", r"jenkins.*cve",
            r"jenkins\s+[12]\.", r"jenkins.*outdated", r"jenkins.*update.*required",
        ],
        nmap_script="",
        default_port=8080,
        parse=_parse_jenkins_version,
        tool="curl",
        curl_path="/",
    ),
    VulnRule(
        name="Grafana Version Vulnerability",
        patterns=[
            r"grafana labs", r"grafana.*xss", r"grafana.*cve",
            r"grafana\s+[0-9]", r"grafana.*multiple vulnerabilities",
            r"grafana.*security bypass",
        ],
        nmap_script="",
        default_port=3000,
        parse=_parse_grafana_version,
        tool="curl",
        curl_path="/api/health",
    ),
    VulnRule(
        name="Kibana Version Vulnerability",
        patterns=[
            r"kibana\s*[0-9]", r"kibana\s*<", r"kibana.*esa-",
            r"elastic kibana", r"kibana.*multiple vulnerabilities",
            r"kibana.*cve", r"kibana.*vulnerability",
        ],
        nmap_script="",
        default_port=5601,
        parse=_parse_kibana_version,
        tool="curl",
        curl_path="/api/status",
    ),
    VulnRule(
        name="GitLab Version Vulnerability",
        patterns=[r"gitlab\s+\d", r"gitlab.*multiple vulnerabilities", r"gitlab.*cve"],
        nmap_script="http-headers",
        extra_args="-sV",
        default_port=443,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="WordPress Outdated Version",
        patterns=[r"outdated wordpress", r"wordpress.*outdated", r"wordpress.*multiple vulnerabilities"],
        nmap_script="http-wordpress-enum",
        extra_args="--script-args=http-wordpress-enum.root=/",
        default_port=80,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="MinIO Admin Default Credentials",
        patterns=[r"minio.*default credentials", r"minio admin.*client", r"minio.*admin.*web"],
        nmap_script="http-get",
        extra_args="--script-args=http-get.path=/",
        default_port=9001,
        parse=_parse_minio,
    ),

    # --- Database ---
    VulnRule(
        name="MongoDB Unauthenticated Access",
        patterns=[
            r"mongodb.*unauthenticated", r"mongodb.*without authentication",
            r"mongodb service without", r"mongodb.*no auth",
        ],
        nmap_script="mongodb-info",
        default_port=27017,
        parse=_parse_mongodb,
    ),
    VulnRule(
        name="Redis Unprotected by Password",
        patterns=[
            r"redis.*unprotected", r"redis.*without password",
            r"redis server unprotected", r"redis server unprotected by password",
        ],
        nmap_script="redis-info",
        default_port=6379,
        parse=_parse_redis,
    ),
    VulnRule(
        name="Elasticsearch Unrestricted Access",
        patterns=[
            r"elasticsearch unrestricted", r"elasticsearch.*unauthenticated",
            r"elasticsearch.*information disclosure",
        ],
        nmap_script="http-get",
        extra_args="-p 9200",
        default_port=9200,
        parse=_parse_elasticsearch,
    ),
    VulnRule(
        name="Oracle Database Version / Unsupported",
        patterns=[
            r"oracle database unsupported", r"oracle database.*version",
            r"oracle db.*cve", r"oracle database.*detection",
        ],
        nmap_script="oracle-tns-version",
        extra_args="-sV",
        default_port=1521,
        parse=_parse_oracle_db,
    ),
    VulnRule(
        name="Oracle TNS Listener Remote Poisoning",
        patterns=[r"oracle tns listener", r"tns listener.*poisoning", r"oracle tns.*remote"],
        nmap_script="oracle-tns-version",
        extra_args="-sV",
        default_port=1521,
        parse=_parse_oracle_tns,
    ),
    VulnRule(
        name="Microsoft SQL Server Version / Unsupported",
        patterns=[
            r"microsoft sql server unsupported", r"microsoft sql server.*version",
            r"microsoft sql server.*detection", r"mssql.*cve",
        ],
        nmap_script="ms-sql-info",
        extra_args="-sV",
        default_port=1433,
        parse=_parse_mssql_version,
    ),
    VulnRule(
        name="PostgreSQL Default Unpassworded Account",
        patterns=[r"postgresql default", r"postgresql.*unpassworded"],
        nmap_script="pgsql-brute",
        extra_args="--script-args=brute.firstonly=true,pgsql-brute.db=postgres",
        default_port=5432,
        parse=_parse_service_version,
    ),

    # --- Network Services ---
    VulnRule(
        name="SNMP Default Community Name (public)",
        patterns=[r"snmp.*default community", r"snmp agent default community", r"snmp.*getbulk", r"clear.text snmp"],
        nmap_script="snmp-brute",
        extra_args="-sU",
        default_port=161,
        parse=_parse_snmp,
        requires_root=True,
    ),
    VulnRule(
        name="Telnet Service / Telnetd RCE",
        patterns=[
            r"unencrypted telnet", r"telnet.*clear", r"clear text telnet",
            r"telnet.*service detected", r"telnetd.*remote code execution",
            r"cve-2020-10188", r"solaris.*telnet", r"forced login telnet",
            r"telnet vulnerability affecting cisco", r"cisco.*telnet",
        ],
        nmap_script="banner",
        default_port=23,
        parse=_parse_telnet,
    ),
    VulnRule(
        name="VNC Server Unauthenticated Access",
        patterns=[r"vnc.*unauthenticated", r"vnc server unauthenticated", r"vnc.*no auth"],
        nmap_script="vnc-info,vnc-brute",
        extra_args="--script-args=brute.firstonly=true",
        default_port=5900,
        parse=_parse_vnc,
    ),
    VulnRule(
        name="X11 Server Unauthenticated Access",
        patterns=[r"x11.*unauthenticated", r"x server detection"],
        nmap_script="x11-access",
        default_port=6000,
        parse=_parse_x11,
    ),
    VulnRule(
        name="NFS Shares Accessible",
        patterns=[
            r"nfs share.*mountable", r"nfs shares world readable", r"nfs exported share",
            r"nfs.*unauthenticated", r"nfs.*accessible", r"nfs exported share.*disclosure",
        ],
        nmap_script="nfs-ls,nfs-showmount",
        default_port=2049,
        parse=_parse_nfs,
    ),
    VulnRule(
        name="rsh / rexec / rlogin Service",
        patterns=[r"rsh service", r"rexecd service", r"rlogin service"],
        nmap_script="banner",
        default_port=514,
        parse=_parse_telnet,
    ),
    VulnRule(
        name="iSCSI Unauthenticated Target",
        patterns=[r"iscsi unauthenticated", r"iscsi.*target"],
        nmap_script="iscsi-info",
        default_port=3260,
        parse=_parse_iscsi,
    ),
    VulnRule(
        name="IPMI v2 Password Hash Disclosure",
        patterns=[r"ipmi.*password hash", r"ipmi v2"],
        nmap_script="ipmi-cipher-zero,ipmi-brute",
        extra_args="-sU",
        default_port=623,
        parse=_parse_ipmiv2,
        requires_root=True,
    ),
    VulnRule(
        name="FTP Anonymous Access",
        patterns=[r"ftp.*anonymous", r"ftp.*anon"],
        nmap_script="ftp-anon",
        default_port=21,
        parse=_parse_ftp_anon,
    ),

    # --- Application / Platform ---
    VulnRule(
        name="Cisco IOS XE Web UI Vulnerabilities",
        patterns=[
            r"cisco ios xe.*command execution", r"cisco ios xe.*rce",
            r"cisco ios xe.*privilege escalation", r"cisco ios xe.*web ui",
            r"cisco ios xe.*authentication bypass", r"cisco ios xe.*command injection",
            r"cisco ios xe.*netconf", r"cisco ios xe.*iox", r"cisco ios xe.*bgp",
            r"cisco ios xe.*firewall", r"cisco ios xe.*dns",
            r"cisco-sa-iosxe", r"cve-2023-20198",
        ],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=443,
        parse=_parse_cisco_iosxe,
    ),
    VulnRule(
        name="Cisco Prime Infrastructure Vulnerabilities",
        patterns=[r"cisco prime infrastructure", r"cisco prime.*tftp", r"cisco prime.*command"],
        nmap_script="banner",
        extra_args="-sV",
        default_port=443,
        parse=_parse_cisco_iosxe,
    ),
    VulnRule(
        name="HP iLO / Ripple20 Vulnerabilities",
        patterns=[
            r"hp ilo [345]", r"hpe ilo", r"ilo [0-9]",
            r"hp ilo.*ripple20", r"hp ilo.*rce",
            r"hp ilo.*multiple vulnerabilities", r"ilo.*ripple20",
            r"ilo.*xss", r"ilo.*vulnerabilit",
        ],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=443,
        parse=_parse_hp_ilo,
    ),
    VulnRule(
        name="HPE OneView / HP System Management Vulnerabilities",
        patterns=[
            r"hpe oneview", r"hp oneview", r"cve-2023-30908",
            r"hp system management homepage", r"hp smh", r"hpsbmu",
        ],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=443,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="Dell EMC iDRAC Vulnerabilities",
        patterns=[r"dell.*idrac", r"idrac.*cve", r"idrac.*vulnerabilit", r"dell emc idrac"],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=443,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="VMware ESXi / vCenter / Aria / Workspace ONE Vulnerabilities",
        patterns=[
            r"vmware esxi", r"vmware vcenter", r"vmware aria", r"vmware workspace",
            r"vsphere.*cve", r"esxi\s+[0-9]", r"vcenter.*cve", r"vmsa-",
            r"esxi.*xss", r"esxi.*vulnerabilit",
        ],
        nmap_script="http-server-header",
        extra_args="-sV",
        default_port=443,
        parse=_parse_vmware,
    ),
    VulnRule(
        name="ActiveMQ RCE CVE-2023-46604",
        patterns=[r"activemq.*rce", r"cve-2023-46604", r"activemq.*5\."],
        nmap_script="banner",
        extra_args="-sV",
        default_port=61616,
        parse=_parse_activemq,
    ),
    VulnRule(
        name="Apache ActiveMQ Multiple Vulnerabilities",
        patterns=[r"apache activemq\s+5\."],
        nmap_script="banner",
        extra_args="-sV",
        default_port=61616,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="Hadoop YARN Unauthenticated RCE",
        patterns=[r"hadoop yarn", r"resourcemanager.*unauthenticated"],
        nmap_script="http-get",
        extra_args="-p 8088",
        default_port=8088,
        parse=_parse_hadoop_yarn,
    ),
    VulnRule(
        name="HP Data Protector Remote Command Execution",
        patterns=[r"hp data protector", r"data protector.*command execution"],
        nmap_script="banner",
        extra_args="-sV",
        default_port=5555,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="Flexera FlexNet Publisher Vulnerabilities",
        patterns=[r"flexera flexnet", r"flexnet publisher"],
        nmap_script="banner",
        extra_args="-sV",
        default_port=27000,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="Portable SDK for UPnP Devices (libupnp)",
        patterns=[r"portable sdk for upnp", r"libupnp.*stack.based buffer"],
        nmap_script="banner",
        extra_args="-sU",
        default_port=1900,
        parse=_parse_service_version,
        requires_root=True,
    ),
    VulnRule(
        name="OpenSSL Version Vulnerability",
        patterns=[
            r"openssl\s+[0-9]", r"openssl.*multiple vulnerabilities", r"openssl.*vulnerability",
            r"openssl.*drown", r"openssl.*changecipherspec", r"openssl.*mitm",
        ],
        nmap_script="ssl-cert",
        extra_args="-sV",
        default_port=443,
        parse=_parse_openssl_version,
    ),
    VulnRule(
        name="PHP Version Vulnerability",
        patterns=[
            r"php\s+[5-9]\.", r"php unsupported", r"php expose_php", r"php prior to",
            r"php.*multiple vulnerabilities", r"php.*unsupported version",
            r"php-cgi", r"php.*cgi.*injection", r"php.*argument injection",
        ],
        nmap_script="http-php-version",
        default_port=80,
        parse=_parse_service_version,
    ),
    VulnRule(
        name="Python Unsupported Version Detection",
        patterns=[r"python unsupported", r"python.*end.of.life", r"python.*eol"],
        nmap_script="banner",
        extra_args="-sV",
        default_port=22,
        parse=_parse_service_version,
    ),

    # --- MongoDB version (distinct from auth bypass) ---
    VulnRule(
        name="MongoDB Version Vulnerability",
        patterns=[
            r"mongodb\s+[0-9]", r"mongodb.*incorrect enforcement",
            r"mongodb.*server-[0-9]", r"mongodb.*index constraint",
        ],
        nmap_script="mongodb-info",
        extra_args="-sV",
        default_port=27017,
        parse=_parse_service_version,
    ),

    # --- Web application / framework ---
    VulnRule(
        name="React Server Components RCE (React2Shell)",
        patterns=[r"react.*react2shell", r"react2shell", r"react server components.*rce",
                  r"react server components.*remote code"],
        nmap_script="",
        default_port=443,
        parse=_parse_react_rce,
        tool="curl",
        curl_path="/",
    ),
    VulnRule(
        name="Moodle Outdated Version",
        patterns=[r"moodle.*version", r"outdated moodle", r"moodle\s+[0-9]"],
        nmap_script="",
        default_port=80,
        parse=_parse_moodle,
        tool="curl",
        curl_path="/lib/upgrade.txt",
    ),
    VulnRule(
        name="Alfresco Default Credentials",
        patterns=[r"alfresco.*guest", r"alfresco.*default", r"alfresco.*credentials", r"alfresco.*admin"],
        nmap_script="",
        default_port=8080,
        parse=_parse_alfresco,
        tool="curl",
        curl_path="/alfresco/",
    ),
    VulnRule(
        name="Browsable Web Directories / Apache Multiviews",
        patterns=[
            r"browsable web director", r"apache multiviews.*director",
            r"arbitrary directory listing", r"directory listing.*enabled",
            r"web.*directory.*browsable",
        ],
        nmap_script="",
        default_port=80,
        parse=_parse_browsable_dirs,
        tool="curl",
        curl_path="/",
    ),
    VulnRule(
        name="CVS Web-Based Entries File Information Disclosure",
        patterns=[r"cvs.*web.*entries", r"cvs.*entries.*information disclosure",
                  r"cvswebentries", r"web-based.*cvs.*entries"],
        nmap_script="",
        default_port=80,
        parse=_parse_cvs_web,
        tool="curl",
        curl_path="/CVS/Entries",
    ),
    VulnRule(
        name="Ollama Unauthenticated Access",
        patterns=[r"ollama.*unauthenticated", r"ollama.*access", r"ollama.*unprotected"],
        nmap_script="",
        default_port=11434,
        parse=_parse_ollama,
        tool="curl",
        curl_path="/api/tags",
    ),

    # --- Web server headers ---
    VulnRule(
        name="Web Server Transmits Cleartext Credentials",
        patterns=[r"web server transmits cleartext", r"transmits cleartext credentials",
                  r"cleartext credential", r"credentials.*cleartext"],
        nmap_script="",
        default_port=80,
        parse=_parse_cleartext_creds,
        tool="curl",
        curl_path="/",
    ),
    VulnRule(
        name="Web Server Uses Basic Authentication Without HTTPS",
        patterns=[r"basic authentication without https", r"basic auth.*without https",
                  r"web server uses basic authentication"],
        nmap_script="",
        default_port=80,
        parse=_parse_web_basic_auth,
        tool="curl",
        curl_path="/",
    ),
    VulnRule(
        name="Web Server HTTP Header Internal IP Disclosure",
        patterns=[r"http header internal ip", r"internal ip disclosure",
                  r"http.*header.*ip disclosure", r"web server http header internal"],
        nmap_script="",
        default_port=80,
        parse=_parse_ip_disclosure,
        tool="curl",
        curl_path="/",
    ),

    # --- Network protocols ---
    VulnRule(
        name="AMQP Cleartext Authentication",
        patterns=[r"amqp cleartext", r"amqp.*authentication", r"amqp.*clear.text"],
        nmap_script="banner",
        extra_args="-sV",
        default_port=5672,
        parse=_parse_amqp,
    ),
    VulnRule(
        name="DNS Server Cache Snooping",
        patterns=[r"dns.*cache snooping", r"dns server cache snoop",
                  r"dns.*remote information disclosure"],
        nmap_script="dns-cache-snoop",
        extra_args="-sU",
        default_port=53,
        parse=_parse_dns_cache,
        requires_root=True,
    ),
    VulnRule(
        name="NTP Mode 6 Scanner",
        patterns=[r"ntp.*mode 6", r"network time protocol.*mode 6",
                  r"ntp mode 6 scanner", r"ntp.*scanner"],
        nmap_script="ntp-info",
        extra_args="-sU",
        default_port=123,
        parse=_parse_ntp,
        requires_root=True,
    ),
    VulnRule(
        name="Cisco IOS TFTP File Disclosure",
        patterns=[r"cisco.*tftp", r"cisco ios.*tftp", r"cisco.*tftp.*disclosure"],
        nmap_script="tftp-enum",
        extra_args="-sU",
        default_port=69,
        parse=_parse_cisco_tftp,
        requires_root=True,
    ),
    VulnRule(
        name="SMTP Configuration Information Disclosure",
        patterns=[r"smtp.*configuration.*information", r"smtp.*disclosure",
                  r"smtp.*information disclosure"],
        nmap_script="smtp-commands",
        default_port=25,
        parse=_parse_smtp_info,
    ),
]


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def match_rule(summary: str) -> Optional[VulnRule]:
    """Return the first matching VulnRule for a given ticket summary."""
    low = summary.lower()
    for rule in RULES:
        for pattern in rule.patterns:
            if re.search(pattern, low):
                return rule
    return None
