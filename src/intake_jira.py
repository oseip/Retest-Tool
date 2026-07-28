"""Map Intake findings to Jira create-issue payloads (Axian v3 + Non-Axian v2)."""
import re
from typing import Any, Dict, List, Optional, Protocol

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_PORT_RE = re.compile(r"^\d{2,5}$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
# Strip control chars that break Jira ADF text nodes (keep tab/newline for splitting).
_ADF_BAD_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\uFFFE\uFFFF]")

# Jira Cloud v3 write API expects ADF for paragraph/textarea custom fields even though
# createmeta reports schema type "string".
_V3_ADF_FIELD_NAMES = frozenset({
    "affected_system[paragraph]", "affected_system", "affected system",
    "impact_type",
    "otherinformation[paragraph]", "otherinformation", "other information",
    "technology",
})


class _FieldLookup(Protocol):
    def _fid(self, name: str) -> Optional[str]: ...


def _sanitize_adf_text(text: str) -> str:
    if not text:
        return ""
    return _ADF_BAD_CHARS.sub("", str(text)).strip()


def _adf_paragraph(text: str) -> dict:
    """Minimal valid ADF document for Jira Cloud paragraph / textarea fields."""
    content = []
    for block in (text or "").replace("\r\n", "\n").split("\n"):
        clean = _sanitize_adf_text(block)
        if clean:
            content.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": clean}],
            })
    if not content:
        content = [{"type": "paragraph", "content": [{"type": "text", "text": " "}]}]
    return {"type": "doc", "version": 1, "content": content}


def _field_uses_adf(names: List[str], *, is_v3: bool) -> bool:
    if not is_v3:
        return False
    return any(n.lower() in _V3_ADF_FIELD_NAMES for n in names)


def _set_custom(
    out: dict,
    jira: _FieldLookup,
    names: List[str],
    value: Any,
    *,
    is_v3: bool = False,
    as_adf: bool = False,
    as_select: bool = False,
) -> None:
    if value is None or value == "":
        return
    fid = None
    for name in names:
        fid = jira._fid(name)
        if fid:
            break
    if not fid:
        return
    use_adf = as_adf or _field_uses_adf(names, is_v3=is_v3)
    if use_adf:
        out[fid] = _adf_paragraph(str(value))
    elif as_select:
        out[fid] = {"value": str(value)}
    else:
        out[fid] = str(value) if not isinstance(value, (int, float)) else value


def _cvss_select_value(raw: Any) -> Optional[str]:
    """Axian CVSS is a single-select of N/A or integers 1–10 (not decimals)."""
    if raw is None or raw == "":
        return "N/A"
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return "N/A"
    if score <= 0:
        return "N/A"
    return str(max(1, min(10, round(score))))


def _parse_cves(raw: str) -> List[str]:
    if not raw:
        return []
    seen: set = set()
    out: List[str] = []
    for m in _CVE_RE.finditer(str(raw)):
        cve = m.group(0).upper()
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def _issue_labels(finding: dict, client_label: str, *, tag_client: bool) -> List[str]:
    labels: List[str] = []
    if tag_client and client_label:
        labels.append(client_label)

    ip = (finding.get("System_IP") or finding.get("_ip") or "").strip()
    if ip:
        labels.append(ip)

    tech = (finding.get("Technology") or "").strip()
    extra_ports: List[str] = []
    if tech:
        parts = [p.strip() for p in tech.split(",") if p.strip()]
        if parts:
            product = parts[0]
            if product.upper() not in ("TCP", "UDP"):
                labels.append(product)
            for part in parts[1:]:
                if _PORT_RE.match(part):
                    extra_ports.append(part)

    port = str(finding.get("_port") or "").strip()
    for p in ([port] if port else []) + extra_ports:
        if p and p not in labels:
            labels.append(p)

    for cve in _parse_cves(finding.get("CVE") or ""):
        labels.append(cve)

    seen: set = set()
    ordered: List[str] = []
    for lbl in labels:
        if lbl and lbl not in seen:
            seen.add(lbl)
            ordered.append(lbl)
    return ordered


def _other_information_block(engagement: dict) -> str:
    """Mirror the legacy CSV / Jira OtherInformation block."""
    blocks = [
        ("Tester", engagement.get("tester") or ""),
        ("Date Started", engagement.get("date_started") or ""),
        ("Purchaser", engagement.get("purchaser") or ""),
        ("Duration", engagement.get("duration") or ""),
        ("Customer", engagement.get("customer") or ""),
        ("Contact Person", engagement.get("contact_person") or ""),
        ("Technical Contact", engagement.get("technical_contact") or ""),
    ]
    parts: List[str] = []
    for title, value in blocks:
        if value:
            parts.append(f"{title}\n\n{value}")
    if engagement.get("munit_id"):
        parts.append(f"mUnit_ID\n\n{engagement['munit_id']}")
    return "\n\n".join(parts)


def _description_text(finding: dict) -> str:
    desc = (finding.get("Vulnerability_Description") or "").strip()
    rec = (finding.get("Recommendation") or "").strip()
    if rec:
        desc = f"{desc}\n Recommendation \n{rec}" if desc else f" Recommendation \n{rec}"

    prev = finding.get("_recurrence_of")
    if prev:
        prev_st = finding.get("_previous_jira_status") or "Fixed"
        note = (
            f"\n\n---\nRecurrence: previously reported as {prev} ({prev_st}). "
            "This is a new ticket created via Nemesis Intake."
        )
        desc = (desc or finding.get("Vulnerability_Title") or "Vulnerability") + note
    return desc.strip()


def build_intake_issue_fields(
    jira: _FieldLookup,
    finding: dict,
    engagement: dict,
    *,
    project_key: str,
    client_label: str,
    tag_client_label: bool,
    is_v3: bool,
    issue_type: str = "Bug",
) -> dict:
    """Build the ``fields`` object for Jira REST create-issue."""
    summary = (finding.get("Vulnerability_Title") or "Untitled vulnerability").strip()
    description = _description_text(finding)
    labels = _issue_labels(finding, client_label, tag_client=tag_client_label)

    fields: dict = {
        "project": {"key": project_key},
        "issuetype": {"name": issue_type},
        "summary": summary[:255],
        "labels": labels,
    }

    if is_v3:
        fields["description"] = _adf_paragraph(description)
    else:
        fields["description"] = description

    affected = finding.get("Affected_System") or finding.get("OS") or ""
    _set_custom(
        fields, jira,
        ["affected_system[paragraph]", "affected_system", "affected system"],
        affected, is_v3=is_v3,
    )
    _set_custom(fields, jira, ["os[short text]", "os"], finding.get("OS"), is_v3=is_v3)
    cvss_val = _cvss_select_value(finding.get("CVSS"))
    if cvss_val:
        _set_custom(fields, jira, ["cvss"], cvss_val, is_v3=is_v3, as_select=True)
    _set_custom(fields, jira, ["technology"], finding.get("Technology"), is_v3=is_v3)
    _set_custom(fields, jira, ["testtype[short text]", "testtype"], engagement.get("test_type"), is_v3=is_v3)
    _set_custom(fields, jira, ["impact_type"], finding.get("Impact_Type"), is_v3=is_v3)
    _set_custom(fields, jira, ["vector"], finding.get("Vector"), is_v3=is_v3)
    _set_custom(fields, jira, ["actor"], finding.get("Actor"), is_v3=is_v3)
    _set_custom(fields, jira, ["cia_damage", "cia damage"], finding.get("CIA_Damage"), is_v3=is_v3)
    _set_custom(fields, jira, ["risk value", "risk_value"], finding.get("Risk_Value"), is_v3=is_v3)
    rating = finding.get("Vulnerability_Rating")
    _set_custom(fields, jira, ["vulnerability_rating", "severity"], rating, is_v3=is_v3)

    other_info = _other_information_block(engagement)
    _set_custom(
        fields, jira,
        ["otherinformation[paragraph]", "otherinformation", "other information"],
        other_info,
        is_v3=is_v3,
    )

    return fields
