from iac_pr_guard.cli import _demo_path, load_resources
from iac_pr_guard.report import to_json, to_markdown, to_sarif
from iac_pr_guard.rules import run_rules

_FINDINGS = run_rules(load_resources(_demo_path("bad-stack")))


def test_json_schema():
    j = to_json(_FINDINGS, "HIGH")
    assert j["tool"] == "iac-pr-guard"
    assert j["summary"]["total"] == len(_FINDINGS)
    assert j["summary"]["gate"]["passed"] is False
    for item in j["findings"]:
        for key in ("rule_id", "severity", "resource", "message", "remediation"):
            assert key in item


def test_markdown_groups_and_gate():
    md = to_markdown(_FINDINGS, "HIGH")
    assert "## HIGH" in md
    assert "**Gate:** FAIL" in md
    assert "| Severity | Count |" in md


def test_markdown_clean_stack_passes():
    md = to_markdown([], "HIGH")
    assert "**Gate:** PASS" in md
    assert "No issues found" in md


def test_sarif_shape():
    s = to_sarif(_FINDINGS)
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["results"]
    assert s["runs"][0]["tool"]["driver"]["name"] == "iac-pr-guard"
