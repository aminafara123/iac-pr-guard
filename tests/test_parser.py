from iac_pr_guard.cli import _demo_path, load_resources
from iac_pr_guard.parser import resources_from_hcl_text


def test_resources_and_scalar_attrs():
    by = {r.address: r for r in load_resources(_demo_path("bad-stack"))}
    assert "aws_s3_bucket.data" in by
    assert by["aws_s3_bucket.data"].get("acl") == "public-read"
    assert by["aws_ebs_volume.vol"].get("encrypted") is False  # bool parsed, not "false"
    assert by["aws_ebs_volume.vol"].get("size") == 20  # int parsed


def test_nested_blocks_and_lists():
    sg = {r.address: r for r in load_resources(_demo_path("bad-stack"))}["aws_security_group.web"]
    ingress = sg.get("ingress")
    assert isinstance(ingress, list) and ingress[0]["from_port"] == 22
    assert ingress[0]["cidr_blocks"] == ["0.0.0.0/0"]  # single-line list


def test_heredoc_policy_captured():
    pol = [r for r in load_resources(_demo_path("bad-stack")) if r.type == "aws_iam_policy"][0]
    assert '"Action": "*"' in pol.get("policy")


def test_line_numbers_tracked():
    data = {r.address: r for r in load_resources(_demo_path("bad-stack"))}["aws_s3_bucket.data"]
    assert data.line and data.file and data.file.endswith("main.tf")


def test_comment_stripping_keeps_quoted_hash():
    res = resources_from_hcl_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "a#b"  # trailing comment\n}\n', "x.tf"
    )
    assert res[0].get("bucket") == "a#b"
