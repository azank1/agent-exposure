import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECRET = "sk-ant-THIS_VALUE_MUST_NEVER_APPEAR_0123456789"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def run(repo, *args):
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
    return subprocess.run([sys.executable, str(HERE / "repo_check.py"), str(repo), *args], capture_output=True, text=True, env=env, timeout=30)


RISKY_CLAUDE_WF = """
on:
  issues: {types: [opened]}
  issue_comment: {types: [created]}
permissions:
  contents: write
  id-token: write
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.issue.title }}"
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          claude_args: --allowedTools "Bash,Read"
          prompt: |
            Triage this issue: ${{ github.event.issue.body }}
"""

RISKY_CODEX_WF = """
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
      - uses: openai/codex-action@v1
        with:
          safety-strategy: unsafe
          allow-users: "*"
          prompt: Review the diff.
"""

CLEAN_WF = """
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash(npm test),Read"
          prompt: Review this pull request for bugs.
"""


class RiskyRepo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        r = cls.repo = Path(cls.tmp.name) / "risky"
        write(r / ".claude/settings.json", json.dumps({
            "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)", "Bash(npm test)"]},
            "enableAllProjectMcpServers": True, "env": {"ANTHROPIC_API_KEY": SECRET}}))
        write(r / ".claude/settings.local.json", "{}")
        write(r / ".mcp.json", json.dumps({"mcpServers": {
            "gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": SECRET}},
            "ref": {"command": "npx", "args": ["-y", "pinned-server@1.2.3"], "env": {"API_KEY": "${API_KEY}",
                    "GOOGLE_APPLICATION_CREDENTIALS": "/home/dev/keys/service-account.json", "AUTH_URL": "https://auth.example.org/v1/token"}},
            "py": {"command": "uvx", "args": ["mcp-server-fetch"]},
            "remote": {"type": "http", "url": "https://mcp.example.com", "headers": {"Authorization": "Bearer " + SECRET}}}}))
        write(r / ".vscode/mcp.json", json.dumps({"servers": {"db": {"command": "node", "args": ["db.js"], "env": {"DB_PASSWORD": SECRET}}}}))
        write(r / ".github/workflows/claude.yml", RISKY_CLAUDE_WF)
        write(r / ".github/workflows/codex.yml", RISKY_CODEX_WF)
        cls.result = run(r, "--json", "--fail-on", "none")
        cls.findings = json.loads(cls.result.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def rules(self, level=None):
        return [f["rule"] for f in self.findings if level is None or f["level"] == level]

    def test_settings(self):
        self.assertIn("bypass-permissions", self.rules("critical"))
        self.assertIn("broad-shell-allow", self.rules("high"))
        self.assertIn("all-project-mcp-enabled", self.rules("high"))
        self.assertIn("local-settings-committed", self.rules("low"))
        self.assertEqual(sum("Bash(npm test)" in f["message"] for f in self.findings), 0)

    def test_mcp(self):
        unpinned = [f["message"] for f in self.findings if f["rule"] == "unpinned-mcp-package"]
        self.assertEqual(len(unpinned), 2)  # npx server-github and uvx mcp-server-fetch, not pinned-server@1.2.3
        secrets = [f["message"] for f in self.findings if f["rule"] == "plaintext-secret"]
        self.assertEqual(len(secrets), 4)  # settings env, .mcp.json env + header, .vscode env; never ${API_KEY}
        self.assertFalse(any("API_KEY holds" in m and "ref" in m for m in secrets))

    def test_workflows(self):
        self.assertIn("pwn-request", self.rules("critical"))
        self.assertIn("shell-injection", self.rules("high"))
        open_to_anyone = [f for f in self.findings if f["rule"] == "agent-open-to-anyone"]
        self.assertEqual({f["level"] for f in open_to_anyone}, {"critical"})
        self.assertEqual(len(open_to_anyone), 2)  # claude allowed_non_write_users and codex allow-users
        self.assertIn("agent-unrestricted", self.rules("high"))
        self.assertIn("untrusted-text-in-prompt", self.rules("high"))
        self.assertIn("agent-default-token", self.rules("low"))
        self.assertTrue(any(f["rule"] == "broad-shell-allow" and f["file"].endswith("claude.yml") for f in self.findings))
        self.assertTrue(all(f["line"] for f in self.findings if f["file"].endswith(".yml") and f["rule"] != "agent-default-token"))

    def test_secret_never_printed(self):
        for args in ([], ["--json"], ["--github"]):
            r = run(self.repo, *args, "--fail-on", "none")
            self.assertNotIn(SECRET, r.stdout + r.stderr)
            self.assertNotIn("THIS_VALUE", r.stdout + r.stderr)

    def test_exit_codes(self):
        self.assertEqual(run(self.repo).returncode, 1)
        self.assertEqual(run(self.repo, "--fail-on", "none").returncode, 0)
        self.assertEqual(run(self.repo, "--fail-on", "critical").returncode, 1)

    def test_github_annotations(self):
        out = run(self.repo, "--github", "--fail-on", "none").stdout
        self.assertIn("::error file=.claude/settings.json,line=", out)
        self.assertIn("::warning file=", out)


READ_ONLY_TRIAGE_WF = """
on:
  issues: {types: [opened]}
permissions: {}
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: openai/codex-action@v1
        with:
          allow-users: "*"
          sandbox: read-only
          prompt: Suggest labels for this issue.
"""

CLAUDE_NO_TOKEN_WF = """
on:
  issues: {types: [opened]}
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          prompt: Label this issue.
"""

CHECKOUT_ONLY_WF = """
on: pull_request_target
permissions:
  contents: read
jobs:
  look:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""


class Calibration(unittest.TestCase):
    def findings(self, wf):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d) / ".github/workflows/w.yml", wf)
            return json.loads(run(d, "--json", "--fail-on", "none").stdout)

    def test_read_only_triage_is_medium(self):
        f = [x for x in self.findings(READ_ONLY_TRIAGE_WF) if x["rule"] == "agent-open-to-anyone"]
        self.assertEqual([x["level"] for x in f], ["medium"])

    def test_claude_open_users_need_github_token(self):
        self.assertFalse([x for x in self.findings(CLAUDE_NO_TOKEN_WF) if x["rule"] == "agent-open-to-anyone"])

    def test_checkout_without_execution_is_medium(self):
        f = [x for x in self.findings(CHECKOUT_ONLY_WF) if x["rule"] == "pwn-request"]
        self.assertEqual([x["level"] for x in f], ["medium"])


AGENT_READS_PR_WF = """
on: pull_request_target
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - run: git fetch --no-tags origin main
      - uses: openai/codex-action@v1
        with:
          sandbox: read-only
"""

GATED_EXEC_WF = """
on: pull_request_target
permissions:
  contents: read
jobs:
  test:
    if: github.event.pull_request.author_association == 'MEMBER'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
"""


PR_IN_SUBDIR_WF = """
on: pull_request_target
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: pr
          persist-credentials: false
      - uses: ./.github/actions/setup
      - run: python3 .github/scripts/summarise.py
"""

PR_IN_SUBDIR_EXECUTED_WF = PR_IN_SUBDIR_WF.replace("python3 .github/scripts/summarise.py", "cd pr && npm ci && npm test")


class PrCheckoutGrading(unittest.TestCase):
    def level(self, wf):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d) / ".github/workflows/w.yml", wf)
            return [x["level"] for x in json.loads(run(d, "--json", "--fail-on", "none").stdout) if x["rule"] == "pwn-request"]

    def test_read_only_agent_over_pr_code_is_medium(self):
        self.assertEqual(self.level(AGENT_READS_PR_WF), ["medium"])

    def test_pr_code_in_subdirectory_only_counts_when_used(self):
        self.assertEqual(self.level(PR_IN_SUBDIR_WF), ["medium"])
        self.assertEqual(self.level(PR_IN_SUBDIR_EXECUTED_WF), ["critical"])

    def test_trusted_author_gate_lowers_one_level(self):
        self.assertEqual(self.level(GATED_EXEC_WF), ["high"])


CLI_AGENT_WF = """
on:
  issues: {types: [opened]}
permissions:
  contents: write
jobs:
  triage:
    runs-on: ubuntu-latest
    env:
      ISSUE_BODY: ${{ github.event.issue.body }}
    steps:
      - uses: actions/checkout@v4
      - run: |
          npx -y @google/gemini-cli --yolo -p "Triage this issue: $ISSUE_BODY"
"""

CLI_AGENT_SAFE_WF = """
on:
  issues: {types: [opened]}
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: npx -y @google/gemini-cli -p "Summarise the open issues"
"""


class CliAgent(unittest.TestCase):
    def levels(self, wf):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d) / ".github/workflows/w.yml", wf)
            return [x["level"] for x in json.loads(run(d, "--json", "--fail-on", "none").stdout) if x["rule"] == "cli-agent-on-untrusted"]

    def test_yolo_cli_with_issue_text_and_write_token_is_critical(self):
        self.assertEqual(self.levels(CLI_AGENT_WF), ["critical"])

    def test_unparseable_workflow_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d) / ".github/workflows/w.yml", "on: push\njobs:\n  x:\n    steps:\n      - run: echo a: b: c\n")
            rules = [x["rule"] for x in json.loads(run(d, "--json", "--fail-on", "none").stdout)]
            self.assertEqual(rules, ["unparsed-workflow"])

    def test_npx_y_is_not_yolo(self):
        self.assertEqual(self.levels(CLI_AGENT_SAFE_WF), ["medium"])


class CleanRepo(unittest.TestCase):
    def test_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d)
            write(r / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(npm test)"], "deny": ["Read(./.env)"]}}))
            write(r / ".mcp.json", json.dumps({"mcpServers": {"gh": {"command": "npx", "args": ["-y", "server-github@2.0.1"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}))
            write(r / ".github/CODEOWNERS", "/.claude/ @team\n/.mcp.json @team\n")
            write(r / ".github/workflows/review.yml", CLEAN_WF)
            result = run(r)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("No risky agent setup found", result.stdout)

    def test_empty_repo(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run(d).returncode, 0)


if __name__ == "__main__":
    unittest.main()
