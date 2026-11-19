# SysKnife audit-tamper demo, a VHS tape (https://github.com/charmbracelet/vhs)
#
# Regenerate (needs podman or docker and a debug build, see audit-tamper.sh):
#   SYSKNIFE_LLM_PROVIDER=groq SYSKNIFE_LLM_MODEL=openai/gpt-oss-120b GROQ_API_KEY=... \
#     assets/demo/audit-tamper.sh seed        # once: a real agent session, planned by a real LLM
#   vhs assets/demo/audit-tamper.tape         # any number of times: replays the saved seed
#
# Unlike the three mock-driven recordings in this folder, every line on screen here
# is produced by the real sysknife binary against a real daemon in a container.
# The tape needs no provider key.

Output "assets/demo/audit-tamper.gif"

Set Shell         "bash"
Set Theme         "Catppuccin Mocha"
Set FontSize      19
Set Width         1240
Set Height        640
Set Padding       20
Set BorderRadius  10
Set TypingSpeed   22ms

# Open the container and clear the bootstrap lines so the recording starts on the prompt.
Hide
Type "bash assets/demo/audit-tamper.sh shell"
Enter
Sleep 7s
Type "clear"
Enter
Sleep 500ms
Show

Type "# an agent worked overnight. what ran?"
Enter
Sleep 600ms
Type "sysknife history"
Enter
Sleep 3500ms

Type "# reads ran, changes did not. is the log intact?"
Enter
Sleep 500ms
Type "sysknife audit verify | cut -c1-96"
Enter
Sleep 4s

Type "clear"
Enter
Type "# now someone edits the log: the ssh change becomes a harmless read"
Enter
Sleep 500ms
Type `sqlite3 daemon.sqlite "UPDATE transactions SET action_name='GetHostState', summary='GetHostState preview (low-risk)' WHERE seq=5"`
Enter
Sleep 800ms
Type "# history reads that same file, so it repeats the edit"
Enter
Sleep 500ms
Type "sysknife history"
Enter
Sleep 3500ms

Type "clear"
Enter
Type "# verify checks the signatures, not the table"
Enter
Sleep 500ms
Type "sysknife audit verify | cut -c1-96"
Enter
Sleep 5s

Type "# an auditor needs only the public key"
Enter
Sleep 500ms
Type "sysknife audit verify --pubkey audit-key.pub | head -1"
Enter
Sleep 4s
