# SysKnife MCP flow demo — VHS tape file (https://github.com/charmbracelet/vhs)
#
# Regenerate: `vhs assets/demo/mcp-flow.tape` (writes assets/demo/mcp-flow.gif)
#
# This tape calls assets/demo/mcp-flow-mock.sh, a deterministic offline replay
# of a Claude Code session using the sysknife_plan + sysknife_execute MCP tools.
# No live LLM calls, daemon, or network access required — every render is
# identical.

Output "assets/demo/mcp-flow.gif"

Set Theme         "Catppuccin Mocha"
Set FontSize      18
Set Width         1200
Set Height        720
Set Padding       20
Set BorderRadius  10
Set TypingSpeed   55ms

# Drive the recording through the mock script — invocation hidden so the
# recording opens straight onto the Claude Code header bar (no shell prompt
# leak).
Hide
Type "bash assets/demo/mcp-flow-mock.sh"
Enter
Sleep 400ms
Show

# Header bar + first user turn render (≈1.6s).
Sleep 1800ms

# Hold on the assistant acknowledgement + sysknife_plan spinner (~2s spinner).
Sleep 2800ms

# Hold on the tool-result plan card so viewer can read risk pills (6s).
Sleep 6000ms

# Assistant plan summary + approval prompt + "y" typed.
Sleep 3000ms

# sysknife_execute spinner (~2s) + step 1 streaming (≈4.5s).
Sleep 7000ms

# Step 2 + step 3 streaming (≈5s each with 1.5s post-step hold).
Sleep 7000ms

# Hold on the final summary + audit hash (3s).
Sleep 3000ms
