import iac_pr_guard.llm as llm
from iac_pr_guard.rules import Finding


def test_explain_degrades_when_offline(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("no network in tests")

    monkeypatch.setattr(llm.urllib.request, "urlopen", boom)
    f = Finding("S3_PUBLIC_ACL", "HIGH", "aws_s3_bucket.data", "x.tf", 1, "why", "fix")
    assert llm.explain_finding(f) is None  # returns None, never raises


def test_chat_returns_content(monkeypatch):
    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"choices":[{"message":{"content":"  hello  "}}]}'

    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda *a, **k: FakeResp())
    assert llm.chat([{"role": "user", "content": "hi"}]) == "hello"
