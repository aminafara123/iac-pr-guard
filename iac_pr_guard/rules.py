"""Deterministic rule engine.

Every check is pure Python over parsed resources: no network, no API key, no provider schema.
Rules cover common AWS misconfigurations. The set is representative, not exhaustive.

ponytail: representative rule/resource coverage, not a full policy library (that is Checkov/tfsec's
job). Add rules by extending RULES + a `_check_*` function; the engine, report and SARIF pick them up.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from .parser import Resource

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEV_DISPLAY = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# rule_id -> (severity, why/title, remediation)
RULES: dict[str, tuple[str, str, str]] = {
    "S3_PUBLIC_ACL": (
        "HIGH",
        "S3 bucket grants public access via its ACL.",
        'Set acl = "private" and add an aws_s3_bucket_public_access_block with all four flags = true.',
    ),
    "S3_NO_ENCRYPTION": (
        "MEDIUM",
        "S3 bucket has no server-side encryption configured.",
        "Add a server_side_encryption_configuration block (SSE-S3 aes256, or SSE-KMS).",
    ),
    "S3_NO_VERSIONING": (
        "LOW",
        "S3 bucket has versioning disabled (no protection against overwrite/delete).",
        'Add a versioning block with enabled = true.',
    ),
    "SG_OPEN_INGRESS": (
        "HIGH",
        "Security group allows ingress from 0.0.0.0/0 to a sensitive port.",
        "Restrict cidr_blocks to known admin ranges or front the service with a bastion/VPN.",
    ),
    "SG_OPEN_EGRESS": (
        "LOW",
        "Security group allows unrestricted egress to 0.0.0.0/0 on all ports.",
        "Scope egress to the destinations and ports the workload actually needs.",
    ),
    "IAM_WILDCARD_ACTION": (
        "HIGH",
        'IAM policy allows Action "*" (full administrative privilege).',
        "Replace the wildcard with the specific actions the principal needs (least privilege).",
    ),
    "IAM_WILDCARD_RESOURCE": (
        "MEDIUM",
        'IAM policy allows Resource "*" (applies to every resource).',
        "Scope Resource to specific ARNs.",
    ),
    "EBS_UNENCRYPTED": (
        "MEDIUM",
        "EBS volume is not encrypted at rest.",
        "Set encrypted = true (optionally with a kms_key_id).",
    ),
    "RDS_UNENCRYPTED": (
        "MEDIUM",
        "RDS instance storage is not encrypted at rest.",
        "Set storage_encrypted = true (requires a KMS key or the default aws/rds key).",
    ),
    "RDS_PUBLIC": (
        "HIGH",
        "RDS instance is publicly accessible from the internet.",
        "Set publicly_accessible = false and place the instance in private subnets.",
    ),
    "CLOUDTRAIL_MISSING": (
        "MEDIUM",
        "No CloudTrail is defined in this stack (no account-wide audit trail).",
        "Add an aws_cloudtrail resource writing to a dedicated, access-logged S3 bucket.",
    ),
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
IAM_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
TRUTHY = (True, "true")


@dataclass
class Finding:
    rule_id: str
    severity: str
    resource: str
    file: str | None
    line: int | None
    message: str
    remediation: str
    ai_explanation: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _mk(rule_id: str, res: Resource, line: int | None = None, why: str | None = None) -> Finding:
    sev, title, rem = RULES[rule_id]
    return Finding(rule_id, sev, res.address, res.file, line if line is not None else res.line,
                   why or title, rem)


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _is_open(cidrs: Any) -> bool:
    return any(c in OPEN_CIDRS for c in _as_list(cidrs))


def _covers_sensitive(from_port: Any, to_port: Any) -> list[tuple[int, str]]:
    try:
        lo, hi = int(from_port), int(to_port)
    except (TypeError, ValueError):
        return []
    return [(p, n) for p, n in SENSITIVE_PORTS.items() if lo <= p <= hi]


def _has_wildcard(v: Any) -> bool:
    return any(item == "*" for item in _as_list(v))


def _load_policy(pol: Any) -> dict | None:
    if isinstance(pol, dict):
        return pol
    if isinstance(pol, str):
        try:
            return json.loads(pol)
        except ValueError:
            return None  # ponytail: jsonencode()/var-based policies are not evaluated
    return None


def _check_s3(r: Resource) -> list[Finding]:
    if r.type != "aws_s3_bucket":
        return []
    out = []
    acl = r.get("acl")
    if acl in ("public-read", "public-read-write", "authenticated-read"):
        out.append(_mk("S3_PUBLIC_ACL", r, why=f'S3 bucket ACL is "{acl}".'))
    if not r.get("server_side_encryption_configuration"):
        out.append(_mk("S3_NO_ENCRYPTION", r))
    versioning = _as_list(r.get("versioning"))
    if not any(isinstance(v, dict) and v.get("enabled") in TRUTHY for v in versioning):
        out.append(_mk("S3_NO_VERSIONING", r))
    return out


def _check_sg(r: Resource) -> list[Finding]:
    out = []
    if r.type == "aws_security_group":
        for ing in _as_list(r.get("ingress")):
            if not isinstance(ing, dict) or not _is_open(ing.get("cidr_blocks")):
                continue
            hits = _covers_sensitive(ing.get("from_port"), ing.get("to_port"))
            if not hits and str(ing.get("protocol", "")).lower() in ("-1", "all"):
                hits = [(0, "all ports")]
            for port, name in hits:
                out.append(_mk("SG_OPEN_INGRESS", r, ing.get("_line"),
                               f"Ingress open to 0.0.0.0/0 on port {port} ({name})."))
        for eg in _as_list(r.get("egress")):
            if isinstance(eg, dict) and _is_open(eg.get("cidr_blocks")) \
                    and str(eg.get("protocol", "")).lower() in ("-1", "all"):
                out.append(_mk("SG_OPEN_EGRESS", r, eg.get("_line")))
    elif r.type == "aws_security_group_rule" and r.get("type") == "ingress" \
            and _is_open(r.get("cidr_blocks")):
        for port, name in _covers_sensitive(r.get("from_port"), r.get("to_port")):
            out.append(_mk("SG_OPEN_INGRESS", r,
                           why=f"Ingress open to 0.0.0.0/0 on port {port} ({name})."))
    return out


def _check_iam(r: Resource) -> list[Finding]:
    if r.type not in IAM_TYPES:
        return []
    pol = _load_policy(r.get("policy"))
    if pol is None:
        return []
    stmts = pol.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    action, resource = False, False
    for s in stmts:
        if not isinstance(s, dict) or s.get("Effect") != "Allow":
            continue
        action = action or _has_wildcard(s.get("Action"))
        resource = resource or _has_wildcard(s.get("Resource"))
    out = []
    if action:
        out.append(_mk("IAM_WILDCARD_ACTION", r))
    if resource:
        out.append(_mk("IAM_WILDCARD_RESOURCE", r))
    return out


def _check_ebs(r: Resource) -> list[Finding]:
    if r.type == "aws_ebs_volume" and r.get("encrypted") not in TRUTHY:
        return [_mk("EBS_UNENCRYPTED", r)]
    return []


def _check_rds(r: Resource) -> list[Finding]:
    if r.type != "aws_db_instance":
        return []
    out = []
    if r.get("storage_encrypted") not in TRUTHY:
        out.append(_mk("RDS_UNENCRYPTED", r))
    if r.get("publicly_accessible") in TRUTHY:
        out.append(_mk("RDS_PUBLIC", r))
    return out


_PER_RESOURCE = (_check_s3, _check_sg, _check_iam, _check_ebs, _check_rds)


def run_rules(resources: list[Resource]) -> list[Finding]:
    findings: list[Finding] = []
    for r in resources:
        for check in _PER_RESOURCE:
            findings.extend(check(r))
    if resources and not any(r.type == "aws_cloudtrail" for r in resources):
        sev, title, rem = RULES["CLOUDTRAIL_MISSING"]
        findings.append(Finding("CLOUDTRAIL_MISSING", sev, "(stack)", resources[0].file, None, title, rem))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.resource))
    return findings


def compute_gate(findings: list[Finding], fail_severity: str) -> bool:
    """Return True if the CI gate should FAIL (a finding at/above fail_severity exists)."""
    threshold = SEVERITY_ORDER.get(fail_severity.upper(), 3)
    return any(SEVERITY_ORDER[f.severity] >= threshold for f in findings)
