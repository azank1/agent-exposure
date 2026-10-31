# agent-exposure

What can your AI coding agents reach, and who can tell them what to do?

Two read-only checks in Python, no telemetry: the machine check is stdlib only, and the repo check needs PyYAML for workflows (the Action installs it). Neither ever prints a secret value (there are tests for that).

| check | runs on | answers |
|---|---|---|
| `agent_exposure.py` | one developer machine | which agents and MCP servers are configured, and which credential and wallet stores an agent with shell access could read |
| `repo_check.py` (agent-check) | a repository, locally or as a GitHub Action | what risky agent setup the repo ships to everyone who clones it, which CI agents outside issue or PR text can drive, and which Supabase tables its migrations leave open to the API |

## agent-check: in CI

```yaml
# .github/workflows/agent-check.yml
on: [pull_request]
permissions:
  contents: read
jobs:
  agent-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azank1/agent-exposure@v1
        with:
          fail-on: high   # low | medium | high | critical | none
```

Findings appear as annotations on the pull request and as a table in the job summary. Locally:

```
python3 repo_check.py ~/my-repo            # markdown report, exit 1 on high or critical
python3 repo_check.py ~/my-repo --json
```

What it flags:

- **committed Claude Code settings** that apply to every clone: `bypassPermissions`, `Bash(*)`-style allow rules, the dangerous-mode prompt switched off, `enableAllProjectMcpServers` (any server added to `.mcp.json` in a pull request starts without a prompt), a committed `settings.local.json`;
- **MCP configs** (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`): unpinned `npx`/`uvx` packages, and credentials written into the file instead of referenced as `${VAR}`;
- **agent workflows** (`anthropics/claude-code-action`, `openai/codex-action`, `google-github-actions/run-gemini-cli`): anyone allowed to trigger the agent (`'*'`), sandbox or approval checks turned off, unrestricted shell tools, issue or PR text pasted into the prompt, write permissions on events that carry outside text, no `permissions:` block. An agent step given an empty `GITHUB_TOKEN` is not charged with the job's write scopes, unless `actions/checkout` left credentials in `.git/config`;
- **agent CLIs started from `run:` steps** (`claude -p`, `codex exec`, `gemini`, `aider` and others) on events that carry outside text, graded higher when approvals are skipped (`--yolo`, `--dangerously-skip-permissions`);
- **the two classic workflow holes** on the same channel: checking out pull request code in a job that holds the base repository's token (`pull_request_target`, or a comment trigger such as `issue_comment`, including `gh pr checkout`), and `${{ github.event.issue.title }}`-style text inside `run:`;
- **Supabase migrations** (`supabase/migrations/*.sql`, `supabase/schemas/*.sql`), often written by an AI app builder: tables in an exposed schema with row-level security off (critical when the migrations grant them to `anon`), default privileges that grant every new table to `anon`, which undoes Supabase's 30 October 2026 change, and views that skip row-level security because they lack `security_invoker`. The migrations are replayed in order, so a later `enable row level security`, rename, revoke or RLS-enabling event trigger counts.

Severity follows what the job can actually do: checked-out pull request code that is never executed, or a job limited to trusted authors, grades lower. A workflow file that does not parse is reported, not skipped.

How to fix each finding, with the safe setting: [`docs/fixes.md`](docs/fixes.md).

For full GitHub Actions linting, run [zizmor](https://github.com/zizmorcore/zizmor) too; agent-check covers the agent layer.

## agent-exposure: on a developer machine

- **agents and configs:** Claude Code (user and project settings, plugins), MCP servers (`~/.claude.json`, `.mcp.json`, Cursor, Windsurf, Gemini CLI, Codex), Continue, Aider;
- **risky settings:** `bypassPermissions`, broad shell allow rules, Codex `danger-full-access` / `approval_policy = never`, settings files with no hooks;
- **MCP servers** started from an unpinned package (every start runs the latest release), or with secret-named env vars or credential headers in plain config;
- **credential and wallet stores** an agent running shell commands as this user can read: cloud CLIs, GitHub/npm/PyPI tokens, SSH keys, Solana/Ethereum/Foundry/Bitcoin wallets, browser profiles, `.env` files.

It reports presence only. Nothing leaves the machine.

```
python3 agent_exposure.py --project ~/my-repo          # markdown report
python3 agent_exposure.py --project ~/my-repo --json   # machine-readable
```

## Tests

```
python3 test_agent_exposure.py    # Python 3.11+
python3 test_repo_check.py        # Python 3.10+, needs PyYAML for the workflow checks
```

## Help with the findings

If agent-check finds something you would rather not fix yourself, I fix a repository's findings in one fixed-price pull request. I also review agent and CI exposure for teams and set up Claude Code with guardrails that fail closed: [what that covers](https://azank1.github.io/offer-site/). MIT licensed.
