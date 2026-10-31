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


COMMENT_EXEC_WF = """
on:
  issue_comment: {types: [created]}
permissions:
  contents: write
jobs:
  test:
    if: github.event.issue.pull_request && contains(github.event.comment.body, '/test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: npm ci && npm test
"""

COMMENT_GATED_WF = COMMENT_EXEC_WF.replace(
    "if: github.event.issue.pull_request && contains(github.event.comment.body, '/test')",
    "if: github.event.comment.author_association == 'MEMBER'")

COMMENT_GH_CHECKOUT_WF = """
on:
  issue_comment: {types: [created]}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          gh pr checkout ${{ github.event.issue.number }}
          make build
        env:
          GH_TOKEN: ${{ github.token }}
"""

COMMENT_STEP_OUTPUT_WF = """
on:
  issue_comment: {types: [created]}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: pr
        uses: xt0rted/pull-request-comment-branch@v2
      - uses: actions/checkout@v4
        with:
          ref: ${{ steps.pr.outputs.head_sha }}
      - run: ./scripts/test.sh
"""

COMMENT_DEFAULT_BRANCH_WF = """
on:
  issue_comment: {types: [created]}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
"""

PULL_REQUEST_GH_CHECKOUT_WF = """
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          gh pr checkout ${{ github.event.pull_request.number }}
          make build
"""


class CommentTriggeredCheckout(unittest.TestCase):
    def findings(self, wf):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d) / ".github/workflows/w.yml", wf)
            return [x for x in json.loads(run(d, "--json", "--fail-on", "none").stdout) if x["rule"] == "pwn-request"]

    def test_comment_job_running_pr_code_is_critical(self):
        f = self.findings(COMMENT_EXEC_WF)
        self.assertEqual([x["level"] for x in f], ["critical"])
        self.assertIn("issue_comment", f[0]["message"])

    def test_trusted_commenter_gate_lowers_one_level(self):
        self.assertEqual([x["level"] for x in self.findings(COMMENT_GATED_WF)], ["high"])

    def test_gh_pr_checkout_counts_as_checkout(self):
        self.assertEqual([x["level"] for x in self.findings(COMMENT_GH_CHECKOUT_WF)], ["critical"])

    def test_head_sha_from_a_step_output(self):
        self.assertEqual([x["level"] for x in self.findings(COMMENT_STEP_OUTPUT_WF)], ["critical"])

    def test_default_branch_checkout_is_not_flagged(self):
        self.assertEqual(self.findings(COMMENT_DEFAULT_BRANCH_WF), [])

    def test_unprivileged_pull_request_event_is_not_flagged(self):
        self.assertEqual(self.findings(PULL_REQUEST_GH_CHECKOUT_WF), [])


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


TOKEN_WITHHELD_WF = """
on:
  issues: {types: [opened]}
permissions:
  contents: read
  issues: write
  actions: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: google-github-actions/run-gemini-cli@v0
        env:
          GITHUB_TOKEN: ''
        with:
          prompt: Read issue_context.md and pick one label.
"""


class TokenWithheld(unittest.TestCase):
    def findings(self, wf):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d) / ".github/workflows/w.yml", wf)
            return [(x["rule"], x["level"]) for x in json.loads(run(d, "--json", "--fail-on", "none").stdout)]

    def test_agent_without_token_is_not_flagged(self):
        self.assertEqual(self.findings(TOKEN_WITHHELD_WF), [])

    def test_persisted_checkout_credentials_still_reported_low(self):
        wf = TOKEN_WITHHELD_WF.replace("        with:\n          persist-credentials: false\n", "")
        self.assertEqual(self.findings(wf), [("agent-write-on-untrusted", "low")])


class SupabaseMigrations(unittest.TestCase):
    def findings(self, *migrations, config=None):
        with tempfile.TemporaryDirectory() as d:
            for i, sql in enumerate(migrations):
                write(Path(d) / f"supabase/migrations/2026100{i}000000_m{i}.sql", sql)
            if config:
                write(Path(d) / "supabase/config.toml", config)
            found = json.loads(run(d, "--json", "--fail-on", "none").stdout)
            return [(x["rule"], x["level"], x["message"], x["line"]) for x in found]

    def test_rls_off_table_granted_to_anon_is_critical(self):
        f = self.findings("create table public.notes (id uuid primary key, body text);\n"
                          "grant select, insert, update, delete on table public.notes to anon, authenticated;\n")
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("rls-off-table", "critical")])
        self.assertIn("read and change every row", f[0][2])

    def test_rls_off_table_readable_by_anon_is_high(self):
        f = self.findings("create table public.holidays (day date);\ngrant select on public.holidays to anon;\n")
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("rls-off-table", "high")])
        self.assertIn("anyone with the app's public key can read every row", f[0][2])

    def test_rls_off_table_without_grants_is_high(self):
        f = self.findings("-- profiles\n\ncreate table profiles (id uuid primary key, email text);\n")
        self.assertEqual([(r, lv, line) for r, lv, _, line in f], [("rls-off-table", "high", 3)])
        self.assertIn("30 Oct 2026", f[0][2])

    def test_authenticated_only_grant_is_high(self):
        f = self.findings("create table public.posts (id int);\ngrant select on public.posts to authenticated;\n")
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("rls-off-table", "high")])
        self.assertIn("any signed-in user can read every row", f[0][2])

    def test_rls_enabled_in_a_later_migration(self):
        self.assertEqual(self.findings('create table "public"."Orders" (id int);',
                                       'alter table if exists only "public"."Orders" enable row level security;'), [])

    def test_do_block_enabling_rls_on_every_table(self):
        self.assertEqual(self.findings("""create table a (id int);
create table b (id int);
do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname = 'public' loop
    execute format('alter table public.%I enable row level security', r.tablename);
  end loop;
end $$;"""), [])

    def test_do_block_enabling_rls_on_listed_tables(self):
        f = self.findings("""create table if not exists people (id int);
create table if not exists notes (id int);
create table if not exists forgotten (id int);
do $$ declare t text; begin
  foreach t in array array['people',
                           'notes'] loop
    execute format('alter table %I enable row level security', t);
  end loop;
end $$;""")
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("rls-off-table", "high")])
        self.assertIn("public.forgotten", f[0][2])

    def test_catalog_loop_filtered_by_relation_kind_covers_every_table(self):
        self.assertEqual(self.findings("""create table a (id int);
create table b (id int);
do $m$ declare target text; begin
  for target in select format('%I.%I', n.nspname, c.relname) from pg_class c join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = 'public' and c.relkind in ('r', 'p') loop
    execute format('alter table %s enable row level security', target);
  end loop;
end $m$;"""), [])

    def test_catalog_loop_filtered_by_table_name_covers_only_those(self):
        f = self.findings("""create table a (id int);
create table b (id int);
do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname = 'public' and tablename in ('a') loop
    execute format('alter table public.%I enable row level security', r.tablename);
  end loop;
end $$;""")
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("rls-off-table", "high")])
        self.assertIn("public.b", f[0][2])

    def test_do_block_with_a_literal_statement(self):
        self.assertEqual(self.findings("create table public.audit (id int);\n"
                                       "do $$ begin execute 'alter table public.audit enable row level security'; end $$;"), [])

    def test_event_trigger_enabling_rls_on_new_tables(self):
        self.assertEqual(self.findings("""create or replace function rls_auto_enable() returns event_trigger language plpgsql as $fn$
declare cmd record;
begin
  for cmd in select * from pg_event_trigger_ddl_commands() where command_tag = 'CREATE TABLE' loop
    execute format('alter table %s enable row level security', cmd.object_identity);
  end loop;
end $fn$;
create event trigger ensure_rls on ddl_command_end when tag in ('CREATE TABLE') execute function rls_auto_enable();
create table public.auto (id int);"""), [])

    def test_grant_on_all_tables_reaches_existing_tables(self):
        f = self.findings("create table public.items (id int);", "grant all on all tables in schema public to anon;")
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("rls-off-table", "critical")])

    def test_default_privileges_to_anon(self):
        f = self.findings("alter default privileges for role postgres in schema public grant all on tables to anon, authenticated, service_role;\n"
                          "create table public.later (id int);\n"
                          "create table public.safe (id int);\nalter table public.safe enable row level security;\n")
        self.assertEqual(sorted((r, lv) for r, lv, _, _ in f), [("default-grant-to-anon", "high"), ("rls-off-table", "critical")])
        self.assertIn("public.later", [m for r, _, m, _ in f if r == "rls-off-table"][0])

    def test_views_without_security_invoker(self):
        f = self.findings("create view public.open_view as select 1;\n"
                          "create view public.safe_view with (security_invoker = true) as select 1;\n"
                          "create or replace view public.later_fixed as select 1;\n"
                          "alter view public.later_fixed set (security_invoker = on);\n")
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("view-bypasses-rls", "high")])
        self.assertIn("public.open_view", f[0][2])

    def test_schema_exposed_only_through_config(self):
        sql = "create schema private;\ncreate table private.secrets (id int);\n"
        self.assertEqual(self.findings(sql), [])
        f = self.findings(sql, config='[api]\nschemas = ["public", "private"]\n')
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("rls-off-table", "high")])

    def test_comments_strings_drops_temp_tables_and_renames(self):
        self.assertEqual(self.findings("""-- create table public.commented (id int);
/* create table public.block (id int); */
create table public.gone (id int);
drop table if exists public.gone cascade;
create temp table scratch (id int);
create table public.old_name (id int);
alter table public.old_name rename to new_name;
alter table public.new_name enable row level security;
insert into notes values ('create table public.instring (id int);');"""), [])

    def test_revoked_from_api_roles(self):
        self.assertEqual(self.findings("create table public.internal (id int);\n"
                                       "revoke all on table public.internal from anon, authenticated;\n"), [])

    def test_rls_disabled_again(self):
        f = self.findings("create table t (id int);\nalter table t enable row level security;\n", "alter table t disable row level security;")
        self.assertEqual([(r, lv) for r, lv, _, _ in f], [("rls-off-table", "high")])


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
