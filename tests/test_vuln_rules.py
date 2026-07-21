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
    RULES,
    _host_down,
    _port_closed,
    _xml_elem,
    _parse_tls_versions,
    _parse_ssl_wrong_hostname,
    _parse_ssl_weak_hash,
    _parse_ssh_proto_v1,
)


# ---------------------------------------------------------------------------
# Scan-command accuracy — every nmap script referenced by a rule must be a real
# bundled NSE script, and rules that can only be checked with a DoS exploit or a
# non-nmap/curl protocol must route to manual review. Locks in the pentest-rule
# audit so a regression can't reintroduce a broken/dangerous scan command.
# ---------------------------------------------------------------------------

class TestScanCommandAccuracy:
    # Scripts that were previously referenced but do NOT exist in the standard
    # nmap distribution (or are unsafe to auto-run).
    INVALID_SCRIPTS = {
        "http-get",              # third-party gist, not bundled
        "zookeeper-info",        # no such NSE
        "smb-vuln-ms09-050",     # real script is smb-vuln-cve2009-3103 (a DoS)
        "rdp-vuln-ms19-0708",    # no bundled BlueKeep NSE
    }

    def test_no_rule_uses_invalid_nmap_script(self):
        for rule in RULES:
            if not rule.nmap_script:
                continue
            for script in rule.nmap_script.split(","):
                assert script.strip() not in self.INVALID_SCRIPTS, (
                    f"Rule '{rule.name}' references non-existent/unsafe nmap "
                    f"script '{script.strip()}'"
                )

    @pytest.mark.parametrize("summary", [
        "JBoss JMX Console Unrestricted Access",
        "Apache Solr Unauthenticated Access",
        "MinIO Admin Default Credentials",
        "Elasticsearch Unrestricted Access",
        "Hadoop YARN ResourceManager Unauthenticated",
    ])
    def test_http_get_rules_now_use_curl(self, summary):
        rule = match_rule(summary)
        assert rule is not None, f"'{summary}' should still match a rule"
        assert rule.tool == "curl", f"'{summary}' should be a curl check, got {rule.tool}"
        assert rule.curl_path, f"'{summary}' curl rule must define a path"

    @pytest.mark.parametrize("summary", [
        "MS09-050 Microsoft Windows SMB2 Vulnerability",
        "Apache ZooKeeper Accessible Without Authentication",
    ])
    def test_unsafe_checks_route_to_manual(self, summary):
        assert match_rule(summary) is None, (
            f"'{summary}' must fall back to manual review, not auto-scan"
        )

    def test_smb_signing_runs_both_dialect_scripts(self):
        rule = match_rule("SMB Signing Not Required")
        assert rule is not None
        scripts = {s.strip() for s in rule.nmap_script.split(",")}
        assert scripts == {"smb-security-mode", "smb2-security-mode"}


# ---------------------------------------------------------------------------
# False-positive hardening — verdicts must never say "fixed" on weak evidence.
# These lock in the accuracy fixes so a regression can't reintroduce a false
# "fixed" (the class of bug where colleagues found issues reported fixed that
# were still present).
# ---------------------------------------------------------------------------

class TestTlsFalsePositives:
    def test_least_strength_grade_c_is_not_fixed(self):
        text = ("ssl-enum-ciphers:\n  TLSv1.2:\n    ciphers:\n"
                "      TLS_RSA_WITH_AES_128_CBC_SHA - C\n"
                "  least strength: C")
        verdict, _ = _parse_tls_versions(text, "")
        assert verdict == "not_fixed"

    def test_per_cipher_grade_c_is_not_fixed(self):
        text = ("ssl-enum-ciphers:\n  TLSv1.2:\n    ciphers:\n"
                "      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - C")
        verdict, _ = _parse_tls_versions(text, "")
        assert verdict == "not_fixed"

    def test_sweet32_is_not_fixed(self):
        text = ("ssl-enum-ciphers:\n  TLSv1.2:\n    ciphers:\n"
                "      TLS_RSA_WITH_3DES_EDE_CBC_SHA - D\n"
                "    warnings:\n      64-bit block cipher 3DES vulnerable to SWEET32")
        verdict, _ = _parse_tls_versions(text, "")
        assert verdict == "not_fixed"

    def test_clean_strong_ciphers_still_fixed(self):
        text = ("ssl-enum-ciphers:\n  TLSv1.3:\n    ciphers:\n"
                "      TLS_AES_256_GCM_SHA384 - A\n  least strength: A")
        verdict, _ = _parse_tls_versions(text, "")
        assert verdict == "fixed"


class TestSslWrongHostname:
    def test_san_present_is_not_auto_fixed(self):
        # A SAN entry does NOT prove the cert matches the intended hostname.
        text = "ssl-cert: Subject Alternative Name: DNS:example.com"
        verdict, _ = _parse_ssl_wrong_hostname(text, "")
        assert verdict == "inconclusive"


class TestSslWeakHash:
    def test_strong_hash_without_signature_context_is_inconclusive(self):
        # "sha256" appearing only in a cipher suite must not read as a fixed
        # certificate signature.
        text = "ssl-cert stuff TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        verdict, _ = _parse_ssl_weak_hash(text, "")
        assert verdict == "inconclusive"

    def test_sha1_signature_is_not_fixed(self):
        text = "ssl-cert:\n  Signature Algorithm: sha1WithRSAEncryption"
        verdict, _ = _parse_ssl_weak_hash(text, "")
        assert verdict == "not_fixed"

    def test_sha256_signature_is_fixed(self):
        text = "ssl-cert:\n  Signature Algorithm: sha256WithRSAEncryption"
        verdict, _ = _parse_ssl_weak_hash(text, "")
        assert verdict == "fixed"


class TestSshProtoV1FalsePositive:
    def test_open_port_alone_is_not_fixed(self):
        # An open SSH port proves nothing about which protocol versions run.
        verdict, _ = _parse_ssh_proto_v1("22/tcp open ssh", "")
        assert verdict == "inconclusive"

    def test_ssh_199_banner_is_not_fixed(self):
        verdict, _ = _parse_ssh_proto_v1("SSH-1.99-OpenSSH_5.3", "")
        assert verdict == "not_fixed"

    def test_ssh_20_banner_is_fixed(self):
        verdict, _ = _parse_ssh_proto_v1("SSH-2.0-OpenSSH_8.9", "")
        assert verdict == "fixed"


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


# ---------------------------------------------------------------------------
# Nginx SSL Upstream Injection
# ---------------------------------------------------------------------------

class TestNginxSslUpstream:
    SUMMARY = "nginx 1.3.0 < 1.28.2 / 1.29.x < 1.29.5 SSL Upstream Injection"
    DESCRIPTION = (
        "URL               : http://10.222.243.181:8081/\n"
        "  Installed version : 1.24.0\n"
        "  Fixed version     : 1.28.2\n"
        " Recommendation \n"
        "Upgrade to nginx 1.28.2 / 1.29.5 or later."
    )
    CURL_OUT = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.24.0\r\n"
        "Date: Tue, 21 Jul 2026 06:20:39 GMT\r\n"
    )

    def setup_method(self):
        rule = match_rule(self.SUMMARY)
        assert rule is not None, "Nginx SSL upstream rule must match Nessus title"
        assert rule.tool == "curl"
        assert rule.extra_args == "-I"
        self.parse = rule.parse

    def test_still_vulnerable_version(self):
        verdict, _ = self.parse(self.CURL_OUT, "", self.DESCRIPTION)
        assert verdict == "not_fixed"

    def test_fixed_on_main_branch(self):
        out = self.CURL_OUT.replace("1.24.0", "1.28.2")
        verdict, _ = self.parse(out, "", self.DESCRIPTION)
        assert verdict == "fixed"

    def test_vulnerable_on_129_branch(self):
        out = self.CURL_OUT.replace("1.24.0", "1.29.3")
        verdict, _ = self.parse(out, "", self.DESCRIPTION)
        assert verdict == "not_fixed"

    def test_fixed_on_129_branch(self):
        out = self.CURL_OUT.replace("1.24.0", "1.29.5")
        verdict, _ = self.parse(out, "", self.DESCRIPTION)
        assert verdict == "fixed"


# ---------------------------------------------------------------------------
# Apache Tomcat Default Files
# ---------------------------------------------------------------------------

class TestTomcatDefaultFiles:
    SUMMARY = "Apache Tomcat Default Files"
    FIXED = """
[STATUS:404][URL:http://10.0.0.1:8080/examples/]
[STATUS:404][URL:http://10.0.0.1:8080/manager/]
[STATUS:404][URL:http://10.0.0.1:8080/host-manager/]
[STATUS:404][URL:http://10.0.0.1:8080/docs/]
"""
    OPEN = """
[STATUS:404][URL:http://10.0.0.1:8080/examples/]
[STATUS:200][URL:http://10.0.0.1:8080/manager/]
[STATUS:404][URL:http://10.0.0.1:8080/host-manager/]
[STATUS:404][URL:http://10.0.0.1:8080/docs/]
"""

    def setup_method(self):
        rule = match_rule(self.SUMMARY)
        assert rule is not None
        assert rule.tool == "curl"
        assert len(rule.curl_paths) == 4
        self.parse = rule.parse

    def test_all_404_is_fixed(self):
        verdict, _ = self.parse(self.FIXED, "")
        assert verdict == "fixed"

    def test_accessible_path_is_not_fixed(self):
        verdict, reason = self.parse(self.OPEN, "")
        assert verdict == "not_fixed"
        assert "manager" in reason.lower()


# ---------------------------------------------------------------------------
# Kibana version (/login)
# ---------------------------------------------------------------------------

class TestKibanaVersion:
    SUMMARY = "Kibana 8.x < 8.19.10 / 9.1.x < 9.1.10 / 9.2.x < 9.2.4 (ESA_2026_05)"
    LOGIN_HTML = '<script>{"version&quot;:&quot;8.19.18&quot;}</script>'

    def setup_method(self):
        rule = match_rule(self.SUMMARY)
        assert rule is not None
        assert rule.curl_path == "/login"
        self.parse = rule.parse

    def test_fixed_on_8x_branch(self):
        verdict, _ = self.parse(self.LOGIN_HTML, "", self.SUMMARY)
        assert verdict == "fixed"

    def test_not_fixed_on_8x_branch(self):
        html = self.LOGIN_HTML.replace("8.19.18", "8.19.5")
        verdict, _ = self.parse(html, "", self.SUMMARY)
        assert verdict == "not_fixed"

    def test_not_fixed_on_91_branch(self):
        html = self.LOGIN_HTML.replace("8.19.18", "9.1.5")
        verdict, _ = self.parse(html, "", self.SUMMARY)
        assert verdict == "not_fixed"


# ---------------------------------------------------------------------------
# RDP MITM / NLA / encryption
# ---------------------------------------------------------------------------

class TestRdpMitm:
    SUMMARY = "Remote Desktop Protocol Server Man-in-the-Middle Weakness"
    VULN_OUT = """
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|   Security layer
|     Native RDP: SUCCESS
|   RDP Encryption level: Client Compatible
|     40-bit RC4: SUCCESS
|     56-bit RC4: SUCCESS
|     128-bit RC4: SUCCESS
|     FIPS 140-1: SUCCESS
|_  RDP Protocol Version: Unknown
"""
    FIXED_OUT = """
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|   Security layer
|     CredSSP: SUCCESS
|   RDP Encryption level: High
|     128-bit RC4: SUCCESS
|_  RDP Protocol Version: 10.0
"""

    def setup_method(self):
        rule = match_rule(self.SUMMARY)
        assert rule is not None
        assert rule.nmap_script == "rdp-enum-encryption"
        self.parse = rule.parse

    def test_vulnerable_rdp_config(self):
        verdict, reason = self.parse(self.VULN_OUT, "")
        assert verdict == "not_fixed"
        assert "native rdp" in reason.lower() or "40-bit" in reason.lower()

    def test_nla_high_encryption_fixed(self):
        verdict, _ = self.parse(self.FIXED_OUT, "")
        assert verdict == "fixed"


class TestBlueKeep:
    SUMMARY = "Microsoft RDP RCE (CVE-2019-0708) (BlueKeep) (uncredentialed check)"

    FIXED_OUT = """
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|   RDP Encryption level: High
|_  RDP Protocol Version: 10.0
"""

    VULN_OUT = """
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|   Security layer
|     Native RDP: SUCCESS
|   RDP Encryption level: Client Compatible
|_  RDP Protocol Version: Unknown
"""

    def setup_method(self):
        rule = match_rule(self.SUMMARY)
        assert rule is not None
        assert rule.nmap_script == "rdp-enum-encryption"
        self.parse = rule.parse

    def test_nla_enabled_not_vulnerable(self):
        verdict, reason = self.parse(self.FIXED_OUT, "")
        assert verdict == "fixed"
        assert "nla" in reason.lower() or "credssp" in reason.lower()
        assert "bluekeep" in reason.lower()

    def test_native_rdp_without_nla_vulnerable(self):
        verdict, reason = self.parse(self.VULN_OUT, "")
        assert verdict == "not_fixed"
        assert "native rdp" in reason.lower()


class TestElasticsearchUnrestrictedAccess:
    SUMMARY = "Elasticsearch Unrestricted Access Information Disclosure"

    SECURED_OUT = """
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="security" charset="UTF-8"
Content-Type: application/json

{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication credentials for REST request [/]"}],"type":"security_exception","reason":"missing authentication credentials for REST request [/]","status":401}}
[STATUS:401][URL:https://10.222.130.53:9200/]
"""

    VULN_OUT = """
HTTP/1.1 200 OK
Content-Type: application/json

{"name":"node-1","cluster_name":"elasticsearch","cluster_uuid":"abc","version":{"number":"7.17.0"}}
[STATUS:200][URL:https://10.222.130.53:9200/]
"""

    def setup_method(self):
        rule = match_rule(self.SUMMARY)
        assert rule is not None
        assert rule.tool == "curl"
        assert rule.curl_scheme == "https"
        assert rule.default_port == 9200
        self.parse = rule.parse

    def test_secured_401_security_exception(self):
        verdict, reason = self.parse(self.SECURED_OUT, "")
        assert verdict == "fixed"
        assert "401" in reason

    def test_unauthenticated_cluster_info(self):
        verdict, reason = self.parse(self.VULN_OUT, "")
        assert verdict == "not_fixed"
        assert "without authentication" in reason.lower()


class TestUnsupportedWindowsOS:
    SUMMARY = "Unsupported Windows OS (remote)"

    SUPPORTED_OUT = """
445/tcp open  microsoft-ds
| smb-os-discovery:
|   OS: Windows Server 2022 Standard 20348 (Windows Server 2022 Standard 6.3)
|   Computer name: SHAREPOINTT
|   FQDN: SHAREPOINTT.tigo.co.tz
"""

    EOL_OUT = """
445/tcp open  microsoft-ds
| smb-os-discovery:
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   Computer name: OLDSERVER
"""

    def setup_method(self):
        rule = match_rule(self.SUMMARY)
        assert rule is not None
        assert rule.nmap_script == "smb-os-discovery"
        assert rule.default_port == 445
        self.parse = rule.parse

    def test_supported_server_2022(self):
        verdict, reason = self.parse(self.SUPPORTED_OUT, "")
        assert verdict == "fixed"
        assert "2022" in reason
        assert "supported" in reason.lower()

    def test_eol_server_2012_r2(self):
        verdict, reason = self.parse(self.EOL_OUT, "")
        assert verdict == "not_fixed"
        assert "2012" in reason
        assert "past end of support" in reason.lower()


class TestEsxiVmsa20250013:
    SUMMARY = (
        "VMware ESXi 7.x < 7.0 Update 3w / 8.x < 8.0 Update 2e / "
        "8.0 Update 3 < 8.0 Update 3f (VMSA-2025-0013)"
    )

    VULN_OUT = """
<fullName>VMware ESXi 7.0.2 build-17867351</fullName>
<version>7.0.2</version>
"""

    FIXED_7_OUT = """
<fullName>VMware ESXi 7.0 Update 3 build-24784741</fullName>
<version>7.0.3</version>
"""

    FIXED_8U3_OUT = """
<fullName>VMware ESXi 8.0.3 build-24784735</fullName>
<version>8.0.3</version>
"""

    FIXED_8U2_OUT = """
<fullName>VMware ESXi 8.0.2 build-24789317</fullName>
<version>8.0.2</version>
"""

    def setup_method(self):
        rule = match_rule(self.SUMMARY)
        assert rule is not None
        assert rule.tool == "curl"
        assert rule.curl_method == "POST"
        assert rule.curl_path == "/sdk"
        self.parse = rule.parse

    def test_vulnerable_702(self):
        verdict, reason = self.parse(self.VULN_OUT, "")
        assert verdict == "not_fixed"
        assert "17867351" in reason
        assert "24784741" in reason

    def test_fixed_70u3w(self):
        verdict, reason = self.parse(self.FIXED_7_OUT, "")
        assert verdict == "fixed"
        assert "7.0 Update 3w" in reason

    def test_fixed_80u3f(self):
        verdict, _ = self.parse(self.FIXED_8U3_OUT, "")
        assert verdict == "fixed"

    def test_fixed_80u2e(self):
        verdict, _ = self.parse(self.FIXED_8U2_OUT, "")
        assert verdict == "fixed"
