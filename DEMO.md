# 60-second demo script

Goal: show that iac-pr-guard finds real misconfigurations, gates CI on severity, and runs offline. Record a terminal to `docs/demo.gif`.

## Setup (before recording)

```bash
make install
clear
```

## Recording (about 60 seconds)

1) Say the pitch (5s): "iac-pr-guard scans Terraform for cloud misconfigurations and fails the build on high-severity findings."

2) Scan the insecure stack (15s):

```bash
iac-pr-guard --demo
echo "exit code: $?"
```

Point at the FAIL gate, the severity summary table, and one finding (for example `SG_OPEN_INGRESS` on port 22). Note the exit code is `1`.

3) Show the CI gate is configurable (10s):

```bash
iac-pr-guard --demo --fail-severity CRITICAL ; echo "exit: $?"
```

Same findings, but the gate passes because nothing is CRITICAL. This is the knob CI tunes.

4) Show the clean stack passes (10s):

```bash
iac-pr-guard --demo clean ; echo "exit: $?"
```

Zero findings, exit `0`.

5) Show machine-readable output for tooling (10s):

```bash
iac-pr-guard --demo --format sarif | head -20
```

Mention it uploads to GitHub code scanning. Optionally show `--format json`.

6) Close (10s): "Deterministic, zero runtime dependencies, runs fully offline, and drops into any CI pipeline as a merge gate."

## Optional: the AI assist

If a local ollama is running, show the advisory notes (clearly labelled AI-generated):

```bash
iac-pr-guard --demo --explain | head -30
```
