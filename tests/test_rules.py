from iac_pr_guard.cli import _demo_path, load_resources
from iac_pr_guard.rules import RULES, run_rules


def _ids(findings):
    return {f.rule_id for f in findings}


def test_bad_stack_triggers_every_rule():
    got = _ids(run_rules(load_resources(_demo_path("bad-stack"))))
    missing = set(RULES) - got
    assert not missing, f"rules not triggered by bad stack: {missing}"


def test_clean_stack_has_no_findings():
    findings = run_rules(load_resources(_demo_path("clean-stack")))
    assert findings == [], [f.rule_id for f in findings]


def test_compliant_s3_not_flagged_public():
    got = _ids(run_rules(load_resources(_demo_path("clean-stack"))))
    assert "S3_PUBLIC_ACL" not in got


def test_sg_open_ingress_names_the_port():
    findings = run_rules(load_resources(_demo_path("bad-stack")))
    ssh = [f for f in findings if f.rule_id == "SG_OPEN_INGRESS"]
    assert ssh and "22" in ssh[0].message


def test_findings_sorted_by_severity():
    sev = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    findings = run_rules(load_resources(_demo_path("bad-stack")))
    order = [sev[f.severity] for f in findings]
    assert order == sorted(order, reverse=True)
