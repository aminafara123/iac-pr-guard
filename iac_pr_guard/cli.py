"""Command line entry point: scan Terraform, render a review, gate CI on severity."""

from __future__ import annotations

import argparse
import importlib.resources as ir
import json
import sys
from pathlib import Path

from . import __version__
from . import llm as _llm
from .parser import (
    Resource,
    resources_from_hcl_text,
    resources_from_plan_text,
)
from .report import to_json, to_markdown, to_sarif
from .rules import compute_gate, run_rules

_DEMO = {"bad": "bad-stack", "clean": "clean-stack"}


def _demo_path(name: str) -> str:
    """Absolute path to a bundled sample (e.g. 'bad-stack', 'clean-stack', 'plan.json')."""
    return str(ir.files("iac_pr_guard") / "samples" / name)


def load_resources(path: str) -> list[Resource]:
    """Load resources from a .tf file, a plan .json file, or a directory of .tf files."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    if p.is_file():
        text = p.read_text()
        if p.suffix == ".json":
            return resources_from_plan_text(text, str(p))
        return resources_from_hcl_text(text, str(p))
    out: list[Resource] = []
    for tf in sorted(p.rglob("*.tf")):
        out.extend(resources_from_hcl_text(tf.read_text(), str(tf)))
    for pj in sorted(p.glob("*.plan.json")):
        out.extend(resources_from_plan_text(pj.read_text(), str(pj)))
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iac-pr-guard",
        description="Scan Terraform for security misconfigurations and gate CI on severity.",
    )
    p.add_argument("path", nargs="?", help="Terraform dir, .tf file, or plan .json file.")
    p.add_argument("--demo", nargs="?", const="bad", choices=["bad", "clean"],
                   help="Scan a bundled sample stack instead of PATH (default: bad).")
    p.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown")
    p.add_argument("--fail-severity", default="HIGH",
                   choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Exit non-zero when a finding at or above this severity exists.")
    p.add_argument("--explain", action="store_true",
                   help="Add an AI-drafted note per finding (local ollama; advisory only).")
    p.add_argument("-o", "--output", help="Write the report to a file instead of stdout.")
    p.add_argument("--version", action="version", version=f"iac-pr-guard {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.demo is not None:
        path = _demo_path(_DEMO[args.demo])
    elif args.path:
        path = args.path
    else:
        build_parser().error("provide a PATH or use --demo")
        return 2  # unreachable; argparse exits

    try:
        resources = load_resources(path)
    except FileNotFoundError as e:
        print(f"error: path not found: {e}", file=sys.stderr)
        return 2

    findings = run_rules(resources)

    if args.explain and findings:
        for f in findings:
            note = _llm.explain_finding(f)
            if note:
                f.ai_explanation = note

    if args.format == "markdown":
        out = to_markdown(findings, args.fail_severity, ai=args.explain)
    elif args.format == "sarif":
        out = json.dumps(to_sarif(findings), indent=2)
    else:
        out = json.dumps(to_json(findings, args.fail_severity), indent=2)

    if args.output:
        Path(args.output).write_text(out + "\n")
    else:
        print(out)

    return 1 if compute_gate(findings, args.fail_severity) else 0


if __name__ == "__main__":
    sys.exit(main())
