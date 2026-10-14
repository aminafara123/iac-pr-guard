"""Render findings as a markdown PR review, JSON, or SARIF."""

from __future__ import annotations

from . import __version__
from .rules import RULES, SEV_DISPLAY, Finding, compute_gate


def _counts(findings: list[Finding]) -> dict[str, int]:
    by: dict[str, int] = {}
    for f in findings:
        by[f.severity] = by.get(f.severity, 0) + 1
    return by


def to_markdown(findings: list[Finding], fail_severity: str, ai: bool = False) -> str:
    tripped = compute_gate(findings, fail_severity)
    by = _counts(findings)
    L = ["# IAC PR Guard - security review", ""]
    L.append("> Automated Terraform scan from a deterministic rule engine. Not a compliance attestation; a human must review before merge.")
    if ai:
        L.append("> AI notes below are AI-generated advisory drafts and require human review.")
    L.append("")
    L.append(f"**Gate:** {'FAIL' if tripped else 'PASS'} (fail-severity = {fail_severity.upper()})  |  **Findings:** {len(findings)}")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for sev in SEV_DISPLAY:
        if by.get(sev):
            L.append(f"| {sev} | {by[sev]} |")
    L.append(f"| **Total** | **{len(findings)}** |")
    L.append("")

    if not findings:
        L.append("No issues found. The stack passes all checks in this rule set.")
        return "\n".join(L)

    for sev in SEV_DISPLAY:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        L.append(f"## {sev} ({len(group)})")
        L.append("")
        for f in group:
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "n/a")
            L.append(f"### `{f.rule_id}` - `{f.resource}`")
            L.append(f"- Location: `{loc}`")
            L.append(f"- Why: {f.message}")
            L.append(f"- Remediation: {f.remediation}")
            if f.ai_explanation:
                L.append(f"- AI note (AI-generated, advisory, review required): {f.ai_explanation}")
            L.append("")
    return "\n".join(L)


def to_json(findings: list[Finding], fail_severity: str) -> dict:
    return {
        "tool": "iac-pr-guard",
        "version": __version__,
        "summary": {
            "total": len(findings),
            "by_severity": _counts(findings),
            "gate": {
                "fail_severity": fail_severity.upper(),
                "passed": not compute_gate(findings, fail_severity),
            },
        },
        "findings": [f.as_dict() for f in findings],
    }


def to_sarif(findings: list[Finding]) -> dict:
    """Minimal SARIF 2.1.0 so findings can be uploaded to GitHub code scanning."""
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    seen = {f.rule_id for f in findings}
    rules = [
        {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": RULES[rid][1]},
            "properties": {"severity": RULES[rid][0]},
        }
        for rid in sorted(seen)
    ]
    results = [
        {
            "ruleId": f.rule_id,
            "level": level.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file or "unknown"},
                        "region": {"startLine": f.line or 1},
                    }
                }
            ],
        }
        for f in findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "iac-pr-guard", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
