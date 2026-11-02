# Renders docs/demo.gif with charmbracelet/vhs (needs vhs, ttyd and ffmpeg on PATH).
# Run from the repo root, with the deps installed in .venv:  vhs docs/demo.tape
# Follows DEMO.md: scan the insecure stack (FAIL, exit 1) -> CRITICAL gate passes -> clean stack -> SARIF. Step 1 passes the sample path so the report shows relative paths.
Output docs/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 40ms

Hide
Type "VIRTUAL_ENV_DISABLE_PROMPT=1 source .venv/bin/activate"
Enter
Wait@120s
Type "set -o pipefail"
Enter
Wait@120s
Type "clear"
Enter
Wait@120s
Show
Sleep 500ms

Type 'iac-pr-guard iac_pr_guard/samples/bad-stack | head -21; echo "exit code: $?"'
Sleep 400ms
Enter
Wait@120s
Sleep 4.5s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type 'iac-pr-guard --demo --fail-severity CRITICAL | grep Gate; echo "exit: $?"'
Sleep 400ms
Enter
Wait@120s
Sleep 2.5s

Type `iac-pr-guard --demo clean | grep -E 'Gate|No issues'; echo "exit: $?"`
Sleep 400ms
Enter
Wait@120s
Sleep 2.5s

Type "iac-pr-guard --demo --format sarif | head -18"
Sleep 400ms
Enter
Wait@120s
Sleep 3s

Sleep 1s
