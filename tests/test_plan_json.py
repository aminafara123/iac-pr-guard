from iac_pr_guard.cli import _demo_path, load_resources
from iac_pr_guard.rules import run_rules


def test_plan_json_parses_and_flags():
    got = {f.rule_id for f in run_rules(load_resources(_demo_path("plan.json")))}
    assert "S3_PUBLIC_ACL" in got
    assert "RDS_PUBLIC" in got
    assert "RDS_UNENCRYPTED" in got
    assert "CLOUDTRAIL_MISSING" in got  # no cloudtrail in the plan
