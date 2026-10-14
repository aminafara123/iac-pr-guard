from iac_pr_guard.cli import main


def test_clean_stack_exits_zero(capsys):
    assert main(["--demo", "clean", "--format", "json"]) == 0


def test_bad_stack_exits_nonzero(capsys):
    assert main(["--demo", "bad", "--format", "json"]) == 1


def test_fail_severity_can_be_raised_above_findings():
    # Bad stack's highest finding is HIGH; gating only on CRITICAL should pass.
    assert main(["--demo", "bad", "--format", "json", "--fail-severity", "CRITICAL"]) == 0


def test_fail_severity_low_still_fails():
    assert main(["--demo", "bad", "--format", "json", "--fail-severity", "LOW"]) == 1
