# SysKnife demo — VHS tape file (https://github.com/charmbracelet/vhs)
#
# Regenerate: `vhs assets/demo/demo.tape` (writes assets/demo/demo.gif)
#
# This tape calls assets/demo/demo-mock.sh, a deterministic offline replay of a
# real planning + execution flow. We do not invoke the live `sysknife` CLI
# because that would require a daemon, an LLM key, and a network round-trip,
# and would produce a different recording every time. The mock matches the
# render styling of apps/sysknife-cli/src/render.rs.

Output "assets/demo/demo.gif"

Set Theme         "Catppuccin Mocha"
Set FontSize      24
Set Width         1200
Set Height        720
Set Padding       20
Set BorderRadius  10
Set TypingSpeed   55ms

# Drive the recording through the mock script — it prints its own fake prompt.
Sleep 400ms
Type "bash assets/demo/demo-mock.sh"
Enter

# Prompt render + spinner (~2s) + plan card render.
Sleep 3500ms

# Hold on the plan card so the reader can read risk pills (6s).
Sleep 6000ms

# Mock streams steps 1, 2, 3 — runtime ≈17s (slower per-line + 1.5s holds).
Sleep 18s

# Hold on the final ✓ + audit-hash line (3s).
Sleep 3000ms
