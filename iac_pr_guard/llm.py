"""Thin, optional LLM client (OpenAI-compatible chat endpoint).

Defaults to the user's local ollama. The scanner is fully deterministic and runs offline;
this module only drafts friendlier remediation prose when asked via `--explain`. If the
endpoint is unreachable it degrades gracefully (returns None) and never crashes the tool.
Stdlib only, no API key required for ollama.
"""

from __future__ import annotations

import json
import os
import urllib.request

DEFAULTS = {
    "base_url": "http://127.0.0.1:11434/v1",
    "model": "qwen3:30b-a3b-instruct-2507-q4_K_M",
    "api_key": "ollama",
}


def _cfg() -> tuple[str, str, str]:
    return (
        os.getenv("LLM_BASE_URL", DEFAULTS["base_url"]),
        os.getenv("LLM_MODEL", DEFAULTS["model"]),
        os.getenv("LLM_API_KEY", DEFAULTS["api_key"]),
    )


def chat(messages: list[dict], timeout: float = 20.0) -> str | None:
    """Call the chat endpoint. Returns the assistant text, or None on any failure."""
    base, model, key = _cfg()
    url = base.rstrip("/") + "/chat/completions"
    payload = json.dumps({"model": model, "messages": messages, "temperature": 0.2}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (configured endpoint)
            body = json.load(resp)
        return body["choices"][0]["message"]["content"].strip()
    except Exception:
        return None  # offline / no model / bad response: caller falls back to deterministic text


def explain_finding(finding) -> str | None:
    """Draft a 2-3 sentence plain-language note for one finding. Advisory only."""
    messages = [
        {
            "role": "system",
            "content": "You are a cloud security assistant. In 2-3 plain sentences, explain the "
            "risk and how to fix it. No preamble, no markdown headers.",
        },
        {
            "role": "user",
            "content": f"Rule {finding.rule_id} ({finding.severity}) on {finding.resource}: "
            f"{finding.message} Suggested remediation: {finding.remediation}",
        },
    ]
    return chat(messages)
