"""
Tests for src/vuln_rules.py

Covers:
- match_rule()  — pattern matching against ticket summaries
- Helper functions — _host_down, _port_closed, _xml_elem, _got_response
- Key parsers — ssl_expiry, tls_versions, ssh_algos, smb_signing, smb_v1
"""

import pytest
from src.vuln_rules import (
    match_rule,
    _host_down,
    _port_closed,
    _xml_elem,
)


# ---------------------------------------------------------------------------
# _host_down
# ---------------------------------------------------------------------------

class TestHostDown:
    def test_nmap_host_down(self):
        assert _host_down("Note: Host seems down.") is True

    def test_nmap_zero_hosts_up(self):
        assert _host_down("0 hosts up") is True

    def test_curl_connection_refused(self):
        assert _host_down("curl: (7) Failed to connect") is True

    def test_curl_timeout(self):
        assert _host_down("curl: (28) Connection timed out after 15000 milliseconds") is True

    def test_curl_dns_failure(self):
        assert _host_down("curl: (6) Could not resolve host: example.com") is True

    def test_host_up_returns_false(self):
        assert _host_down("443/tcp open  https") is False

    def test_empty_string(self):
        assert _host_down("") is False

    def test_case_insensitive(self):
        assert _host_down("HOST SEEMS DOWN") is True


# ---------------------------------------------------------------------------
# _port_closed
# ---------------------------------------------------------------------------

class TestPortClosed:
    def test_tcp_closed(self):
        assert _port_closed("443/tcp closed", 443) is True

    def test_tcp_filtered(self):
        assert _port_closed("443/tcp filtered", 443) is True

    def test_udp_closed(self):
        assert _port_closed("53/udp closed", 53) is True

    def test_udp_filtered(self):
        assert _port_closed("53/udp filtered", 53) is True

    def test_open_port_returns_false(self):
        assert _port_closed("443/tcp open  https", 443) is False

    def test_wrong_port_returns_false(self):
        # Port 80 closed should not trigger a check for port 443
        assert _port_closed("80/tcp closed", 443) is False

    def test_case_insensitive(self):
        assert _port_closed("443/TCP CLOSED", 443) is True


# ---------------------------------------------------------------------------
# _xml_elem
# ---------------------------------------------------------------------------

class TestXmlElem:
    VALID_XML = """<?xml version="1.0"?>
<nmaprun>
  <host><script id="ssl-cert">
    <table key="subject">
      <elem key="commonName">example.com</elem>
    </table>
    <elem key="notAfter">2030-01-01T00:00:00</elem>
  </script></host>
</nmaprun>"""

    def test_finds_existing_key(self):
        result = _xml_elem(self.VALID_XML, "notAfter")
        assert result == "2030-01-01T00:00:00"

    def test_finds_nested_elem(self):
        result = _xml_elem(self.VALID_XML, "commonName")
        assert result == "example.com"

    def test_missing_key_returns_none(self):
        assert _xml_elem(self.VALID_XML, "notBefore") is None

    def test_invalid_xml_returns_none(self):
        assert _xml_elem("not xml at all", "notAfter") is None

    def test_empty_string_returns_none(self):
        assert _xml_elem("", "notAfter") is None


# ---------------------------------------------------------------------------
# match_rule
# ---------------------------------------------------------------------------

class TestMatchRule:
    # SSL / TLS
    def test_ssl_expiry_match(self):
        rule = match_rule("SSL Certificate Expiry")
        assert rule is not None
        assert "expir" in rule.name.lower() or "ssl" in rule.name.lower()

    def test_tls_weak_protocol_match(self):
        rule = match_rule("TLS 1.0 Enabled")
        assert rule is not None

    def test_self_signed_cert_match(self):
        rule = match_rule("SSL Self-Signed Certificate")
        assert rule is not None

    # SSH
    def test_ssh_weak_algos_match(self):
        rule = match_rule("SSH Weak MAC Algorithms Supported")
        assert rule is not None

    def test_ssh_proto_v1_match(self):
        rule = match_rule("SSH Protocol Version 1 Supported")
        assert rule is not None

    # SMB
    def test_smb_signing_match(self):
        rule = match_rule("SMB Signing Not Required")
        assert rule is not None

    def test_smb_v1_match(self):
        rule = match_rule("SMBv1 Server Detected")
        assert rule is not None

    def test_unrecognised_summary_returns_none(self):
        assert match_rule("Random unrelated vulnerability XYZ 12345") is None

    def test_empty_summary_returns_none(self):
        assert match_rule("") is None

    def test_manual_only_rules(self):
        manual_summaries = [
            "VMware ESXi Version Vulnerability",
            "Terminal Services Encryption Level is Medium or Low",
            "IPMI v2.0 Password Hash Disclosure",
            "SNMP Agent Default Community Name (public)",
            "NTP Mode 6 Scanner",
            "Apache Struts Remote Code Execution",
            "Spring4Shell Spring Framework RCE",
            "Exposed phpinfo.php page"
        ]
        for summary in manual_summaries:
            rule = match_rule(summary)
            assert rule is None, f"Expected '{summary}' to bypass automated scan, but matched {rule}"

    # Rule structure
    def test_matched_rule_has_nmap_script_or_curl_path(self):
        rule = match_rule("SSL Certificate Expiry")
        assert rule is not None
        assert rule.tool in ("nmap", "curl")
        if rule.tool == "nmap":
            assert rule.nmap_script or rule.extra_args or rule.default_port
        else:
            assert rule.curl_path is not None

    def test_rule_has_parse_function(self):
        rule = match_rule("SSL Certificate Expiry")
        assert rule is not None
        assert callable(rule.parse)

    def test_case_insensitive_match(self):
        rule_lower = match_rule("ssl certificate expiry")
        rule_upper = match_rule("SSL CERTIFICATE EXPIRY")
        # At least one should match; both should match the same rule or both be None
        assert (rule_lower is None) == (rule_upper is None)
        if rule_lower and rule_upper:
            assert rule_lower.name == rule_upper.name


# ---------------------------------------------------------------------------
# _parse_ssl_expiry
# ---------------------------------------------------------------------------

class TestParseSslExpiry:
    def setup_method(self):
        rule = match_rule("SSL Certificate Expiry")
        assert rule is not None, "SSL Certificate Expiry rule must exist"
        self.parse = rule.parse

    EXPIRED_XML = """<?xml version="1.0"?>
<nmaprun><host><script id="ssl-cert">
  <elem key="notAfter">2020-01-01T00:00:00</elem>
</script></host></nmaprun>"""

    VALID_XML = """<?xml version="1.0"?>
<nmaprun><host><script id="ssl-cert">
  <elem key="notAfter">2099-12-31T00:00:00</elem>
</script></host></nmaprun>"""

    def test_expired_cert_is_not_fixed(self):
        verdict, reason = self.parse("ssl-cert output", self.EXPIRED_XML)
        assert verdict == "not_fixed"
        assert "expired" in reason.lower()

    def test_valid_cert_is_fixed(self):
        verdict, reason = self.parse("ssl-cert output", self.VALID_XML)
        assert verdict == "fixed"
        assert "valid" in reason.lower() or "2099" in reason

    def test_host_down_is_inconclusive(self):
        verdict, reason = self.parse("Host seems down.", "")
        assert verdict == "inconclusive"

    def test_no_ssl_cert_in_output_is_inconclusive(self):
        verdict, reason = self.parse("443/tcp open https", "")
        assert verdict == "inconclusive"

    def test_text_fallback_expired(self):
        text = "ssl-cert:\n  Not valid after : 2020-06-01"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"

    def test_text_fallback_valid(self):
        text = "ssl-cert:\n  Not valid after : 2099-06-01"
        verdict, reason = self.parse(text, "")
        assert verdict == "fixed"


# ---------------------------------------------------------------------------
# _parse_tls_versions
# ---------------------------------------------------------------------------

class TestParseTlsVersions:
    def setup_method(self):
        rule = match_rule("TLS 1.0 Enabled")
        assert rule is not None, "TLS versions rule must exist"
        self.parse = rule.parse

    def test_tls10_is_not_fixed(self):
        text = "ssl-enum-ciphers:\n  TLSv1.0:\n    ciphers:"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"
        assert "TLS 1.0" in reason

    def test_tls11_is_not_fixed(self):
        text = "ssl-enum-ciphers:\n  TLSv1.1:\n    ciphers:"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"
        assert "TLS 1.1" in reason

    def test_sslv3_is_not_fixed(self):
        text = "ssl-enum-ciphers:\n  SSLv3:\n    ciphers:"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"
        assert "SSL" in reason.upper()

    def test_tls12_only_is_fixed(self):
        text = "ssl-enum-ciphers:\n  TLSv1.2:\n    ciphers:\n      AES256"
        verdict, reason = self.parse(text, "")
        assert verdict == "fixed"

    def test_tls13_only_is_fixed(self):
        text = "ssl-enum-ciphers:\n  TLSv1.3:\n    ciphers:\n      AES256"
        verdict, reason = self.parse(text, "")
        assert verdict == "fixed"

    def test_host_down_is_inconclusive(self):
        verdict, reason = self.parse("0 hosts up", "")
        assert verdict == "inconclusive"

    def test_script_not_run_is_inconclusive(self):
        verdict, reason = self.parse("443/tcp open https", "")
        assert verdict == "inconclusive"

    def test_weak_cipher_3des_is_not_fixed(self):
        text = "ssl-enum-ciphers:\n  TLSv1.2:\n    ciphers:\n      3DES-CBC"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"


# ---------------------------------------------------------------------------
# _parse_ssh_algos
# ---------------------------------------------------------------------------

class TestParseSshAlgos:
    def setup_method(self):
        rule = match_rule("SSH Weak MAC Algorithms Supported")
        assert rule is not None, "SSH weak algos rule must exist"
        self.parse = rule.parse

    CLEAN_OUTPUT = (
        "22/tcp open  ssh\n"
        "ssh2-enum-algos:\n"
        "  encryption_algorithms: aes256-ctr,aes128-ctr\n"
        "  mac_algorithms: hmac-sha2-256,hmac-sha2-512\n"
        "  server_host_key_algorithms: rsa-sha2-256"
    )

    def test_weak_mac_hmac_sha1_is_not_fixed(self):
        text = self.CLEAN_OUTPUT + "\n  mac_algorithms: hmac-sha1,hmac-sha2-256"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"
        assert "hmac-sha1" in reason.lower()

    def test_weak_mac_hmac_md5_is_not_fixed(self):
        text = self.CLEAN_OUTPUT + "\n  mac_algorithms: hmac-md5"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"

    def test_weak_kex_dh_group1_is_not_fixed(self):
        text = self.CLEAN_OUTPUT + "\n  kex: diffie-hellman-group1-sha1"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"

    def test_weak_cipher_arcfour_is_not_fixed(self):
        text = self.CLEAN_OUTPUT + "\n  encryption_algorithms: arcfour"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"

    def test_clean_output_is_fixed(self):
        verdict, reason = self.parse(self.CLEAN_OUTPUT, "")
        assert verdict == "fixed"

    def test_host_down_is_inconclusive(self):
        verdict, reason = self.parse("Host seems down.", "")
        assert verdict == "inconclusive"

    def test_port_closed_is_inconclusive(self):
        verdict, reason = self.parse("22/tcp closed", "")
        assert verdict == "inconclusive"

    def test_hmac_sha1_etm_is_acceptable(self):
        # hmac-sha1-etm@openssh.com is NOT weak; only bare hmac-sha1 is
        text = (
            "22/tcp open  ssh\n"
            "ssh2-enum-algos:\n"
            "  encryption_algorithms: aes256-ctr\n"
            "  mac_algorithms: hmac-sha1-etm@openssh.com\n"
            "  server_host_key_algorithms: rsa-sha2-256"
        )
        verdict, reason = self.parse(text, "")
        assert verdict == "fixed"


# ---------------------------------------------------------------------------
# _parse_smb_signing
# ---------------------------------------------------------------------------

class TestParseSmbSigning:
    def setup_method(self):
        rule = match_rule("SMB Signing Not Required")
        assert rule is not None, "SMB signing rule must exist"
        self.parse = rule.parse

    def test_signing_required_is_fixed(self):
        text = "445/tcp open  microsoft-ds\nsmb2-security-mode:\n  Message signing enabled and required"
        verdict, reason = self.parse(text, "")
        assert verdict == "fixed"

    def test_signing_not_required_is_not_fixed(self):
        text = "445/tcp open  microsoft-ds\nsmb2-security-mode:\n  Message signing enabled but not required"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"

    def test_signing_disabled_is_not_fixed(self):
        text = "445/tcp open  microsoft-ds\nmessage_signing: disabled"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"

    def test_host_down_is_inconclusive(self):
        verdict, reason = self.parse("0 hosts up", "")
        assert verdict == "inconclusive"

    def test_port_closed_is_inconclusive(self):
        verdict, reason = self.parse("445/tcp closed", "")
        assert verdict == "inconclusive"


# ---------------------------------------------------------------------------
# _parse_smb_v1
# ---------------------------------------------------------------------------

class TestParseSmbV1:
    def setup_method(self):
        rule = match_rule("SMBv1 Server Detected")
        assert rule is not None, "SMBv1 rule must exist"
        self.parse = rule.parse

    def test_smbv1_present_is_not_fixed(self):
        text = "445/tcp open\nsmb-protocols:\n  dialects:\n    NT LM 0.12\n    2.02"
        verdict, reason = self.parse(text, "")
        assert verdict == "not_fixed"

    def test_no_smbv1_is_fixed(self):
        text = "445/tcp open\nsmb-protocols:\n  dialects:\n    2.02\n    3.00\n    3.02"
        verdict, reason = self.parse(text, "")
        assert verdict == "fixed"

    def test_host_down_is_inconclusive(self):
        verdict, reason = self.parse("Host seems down.", "")
        assert verdict == "inconclusive"

    def test_port_closed_is_inconclusive(self):
        verdict, reason = self.parse("445/tcp filtered", "")
        assert verdict == "inconclusive"
