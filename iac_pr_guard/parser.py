"""Terraform input parsing.

Two inputs are supported:

1) A small, focused *subset* of HCL, parsed by a hand-rolled line scanner. We hand-roll
   on purpose: it keeps runtime dependencies at zero and the parser deterministic and
   unit-testable (no network, no provider schema). The trade-off is a known ceiling,
   see the `ponytail:` notes below.

2) Terraform plan JSON (`terraform show -json`), which is what real CI pipelines produce.
   Its `values` blocks already have the same shape our rules expect, so both inputs
   normalise to the same `Resource` objects.

ponytail: HCL subset only. Supported: resource/nested blocks, scalar attributes
(string/bool/number), single-line lists, and heredocs. NOT supported: single-line blocks
(`x { a = 1 }`), multi-line lists/maps, `jsonencode(...)`, and variable/module resolution.
Use the plan-JSON input when you need full fidelity.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

_HEREDOC = re.compile(r"^([\w-]+)\s*=\s*<<-?\s*(\w+)\s*$")
_LABELED_BLOCK = re.compile(r'^([A-Za-z_][\w-]*)\s+((?:"[^"]*"\s*)+)\{\s*$')
_BLOCK = re.compile(r"^([A-Za-z_][\w-]*)\s*=?\s*\{\s*$")
_ATTR = re.compile(r"^([\w-]+)\s*=\s*(.+)$")


@dataclass
class Resource:
    """A normalised Terraform resource that rules run against."""

    type: str
    name: str
    values: dict[str, Any]
    file: str | None = None
    line: int | None = None

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


def _strip_comment(line: str) -> str:
    """Drop a trailing `#` or `//` comment that is not inside a double-quoted string."""
    out = []
    in_str = False
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str:
            if c == "#":
                break
            if c == "/" and i + 1 < n and line[i + 1] == "/":
                break
        out.append(c)
        i += 1
    return "".join(out)


def _split_list(inner: str) -> list[str]:
    """Split a single-line list body on top-level commas (ignores commas inside quotes)."""
    parts, buf, in_str = [], [], False
    for c in inner:
        if c == '"':
            in_str = not in_str
        if c == "," and not in_str:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
    if buf:
        parts.append("".join(buf))
    return [p for p in (p.strip() for p in parts) if p]


def _parse_value(s: str) -> Any:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    if s == "true":
        return True
    if s == "false":
        return False
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    if s.startswith("[") and s.endswith("]"):
        return [_parse_value(p) for p in _split_list(s[1:-1])]
    return s  # reference, function call, or unquoted token: kept raw


@dataclass
class _Block:
    type: str
    labels: list[str]
    attrs: dict[str, tuple[Any, int]] = field(default_factory=dict)
    children: list["_Block"] = field(default_factory=list)
    line: int = 0


def _parse_body(lines: list[str], i: int) -> tuple[dict, list, int]:
    attrs: dict[str, tuple[Any, int]] = {}
    children: list[_Block] = []
    while i < len(lines):
        lineno = i + 1
        line = _strip_comment(lines[i]).strip()
        if not line:
            i += 1
            continue
        if line == "}":
            return attrs, children, i + 1

        m = _HEREDOC.match(line)
        if m:
            name, term = m.group(1), m.group(2)
            i += 1
            buf = []
            while i < len(lines) and lines[i].strip() != term:
                buf.append(lines[i])
                i += 1
            i += 1  # consume terminator
            attrs[name] = ("\n".join(buf), lineno)
            continue

        m = _LABELED_BLOCK.match(line)
        if m:
            labels = re.findall(r'"([^"]*)"', m.group(2))
            cattrs, cchildren, i = _parse_body(lines, i + 1)
            children.append(_Block(m.group(1), labels, cattrs, cchildren, lineno))
            continue

        m = _BLOCK.match(line)
        if m:
            cattrs, cchildren, i = _parse_body(lines, i + 1)
            children.append(_Block(m.group(1), [], cattrs, cchildren, lineno))
            continue

        m = _ATTR.match(line)
        if m:
            attrs[m.group(1)] = (_parse_value(m.group(2)), lineno)
            i += 1
            continue

        i += 1  # ponytail: silently skip syntax outside the supported subset
    return attrs, children, i


def parse_hcl(text: str) -> list[_Block]:
    """Parse HCL text into top-level blocks."""
    _, children, _ = _parse_body(text.splitlines(), 0)
    return children


def _block_to_dict(block: _Block) -> dict[str, Any]:
    """Flatten a block into {attr: value, nested_block_type: [ {...}, ... ]}.

    This matches the shape of Terraform plan JSON `values`, so rules work on both inputs.
    """
    d: dict[str, Any] = {}
    for k, (v, _ln) in block.attrs.items():
        d[k] = v
    for ch in block.children:
        sub = _block_to_dict(ch)
        sub["_line"] = ch.line
        d.setdefault(ch.type, []).append(sub)
    return d


def resources_from_hcl_text(text: str, filename: str | None = None) -> list[Resource]:
    out = []
    for b in parse_hcl(text):
        if b.type == "resource" and len(b.labels) >= 2:
            out.append(Resource(b.labels[0], b.labels[1], _block_to_dict(b), filename, b.line))
    return out


def _collect_plan_resources(module: dict) -> list[dict]:
    out = list(module.get("resources", []) or [])
    for child in module.get("child_modules", []) or []:
        out.extend(_collect_plan_resources(child))
    return out


def resources_from_plan_json(data: dict, filename: str | None = None) -> list[Resource]:
    """Parse `terraform show -json` output into Resource objects."""
    root = data.get("planned_values", {}).get("root_module", {})
    out = []
    for r in _collect_plan_resources(root):
        out.append(
            Resource(r.get("type", ""), r.get("name", ""), r.get("values", {}) or {}, filename, None)
        )
    return out


def resources_from_plan_text(text: str, filename: str | None = None) -> list[Resource]:
    return resources_from_plan_json(json.loads(text), filename)
