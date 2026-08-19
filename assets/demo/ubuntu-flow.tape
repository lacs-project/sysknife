# SysKnife Ubuntu MCP flow demo — VHS tape file (https://github.com/charmbracelet/vhs)
#
# Regenerate: `vhs assets/demo/ubuntu-flow.tape` (writes assets/demo/ubuntu-flow.gif)
#
# Ubuntu counterpart to mcp-flow.tape. Drives assets/demo/ubuntu-flow-mock.sh,
# a deterministic offline replay of a Claude Code session on Ubuntu 24.04:
# UfwAllow, AptInstall and UfwStatus through terminal-issued receipts.
# No live LLM calls, daemon, or network access required — every render is
# identical.
#
# Kept under 400 frames on purpose: that is the ceiling above which LinkedIn
# freezes an uploaded GIF on its first frame instead of animating it.

Output "assets/demo/ubuntu-flow.gif"

Set Theme         "Catppuccin Mocha"
Set FontSize      18
Set Width         1000
Set Height        600
Set Framerate     12
Set Padding       20
Set BorderRadius  10
Set TypingSpeed   55ms

# Invocation hidden so the recording opens on the Claude Code header bar
# rather than a shell prompt.
Hide
Type "bash assets/demo/ubuntu-flow-mock.sh"
Enter
Sleep 400ms
Show

# Header bar, user turn, plan spinner (~2.2s).
Sleep 2400ms

# Hold on the plan card so the risk pills are readable (~2.6s).
Sleep 3000ms

# Terminal approvals and the three receipts (~3.2s).
Sleep 3400ms

# Execute spinner plus the three streaming steps (~5.5s).
Sleep 6000ms

# Final hold on the consumed-receipt note and the audit hash.
Sleep 2600ms
