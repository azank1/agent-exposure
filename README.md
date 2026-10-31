# agent-exposure

What can the AI coding agents on this machine reach?

A read-only check for one user and, optionally, one project:

- **agents and configs:** Claude Code (user and project settings, plugins), MCP servers (`~/.claude.json`, `.mcp.json`, Cursor, Windsurf, Gemini CLI, Codex), Continue, Aider;
- **risky settings:** `bypassPermissions`, broad shell allow rules, Codex `danger-full-access` / `approval_policy = never`, settings files with no hooks;
- **MCP servers** started from an unpinned package (every start runs the latest release), or with secret-named env vars or credential headers in plain config;
- **credential and wallet stores** an agent running shell commands as this user can read: cloud CLIs, GitHub/npm/PyPI tokens, SSH keys, Solana/Ethereum/Foundry/Bitcoin wallets, browser profiles, `.env` files.

It reports presence only. Secret values are never printed or stored (there is a test for that).

```
python3 agent_exposure.py --project ~/my-repo          # markdown report
python3 agent_exposure.py --project ~/my-repo --json   # machine-readable
python3 test_agent_exposure.py                         # tests (stdlib only, Python 3.11+)
```
