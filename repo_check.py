#!/usr/bin/env python3
"""agent-check: risky AI-agent setup committed to a repository.

Read-only. Checks the agent configuration a repository ships to everyone who
clones it (Claude Code settings, MCP server configs for Claude Code, Cursor,
VS Code, Gemini CLI and Codex), the GitHub Actions workflows that run AI
agents or handle text from issues and pull requests, and the Supabase
migrations that AI app builders write: tables and views the API can reach
without row-level security. Secret values are never printed.

Usage: python3 repo_check.py [REPO_DIR] [--json] [--github] [--fail-on LEVEL]
Exits 1 when a finding at or above --fail-on (default: high) is present.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

from agent_exposure import PINNED_NPX, SECRET_NAME, load_json, load_toml

try:
    import yaml
except ImportError:  # workflow checks need PyYAML; config checks do not
    yaml = None

LEVELS = ["low", "medium", "high", "critical"]
MARKS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
FIX_GUIDE = "https://github.com/azank1/agent-exposure/blob/main/docs/fixes.md"
FIX_FOR_YOU = "https://x.com/azankhyder"
UNTRUSTED_EVENTS = {"issues", "issue_comment", "pull_request_target", "pull_request_review",
                    "pull_request_review_comment", "discussion", "discussion_comment"}
UNTRUSTED_TEXT = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body"
    r"|pull_request\.(?:title|body|head\.ref|head\.label)|discussion\.(?:title|body)|head_commit\.message)"
    r"|head_ref)\b")
EXEC_PR_CODE = re.compile(r"\b(?:npm|yarn|pnpm|bun|npx|node|make|pip3?|poetry|uv|python3?|pytest|tox|cargo|go|mvn|gradle|bundle|rake|composer)\s+(?!--version)\S|(?:^|[\s;&|])\./[\w./-]+|\b(?:bash|sh)\s+[\w./-]+\.sh\b", re.M)
TRUSTED_GATE = re.compile(r"author_association|github\.actor\s*==|user\.login\s*==|head\.repo\.full_name\s*==\s*github\.repository|head\.repo\.fork\s*==\s*false|label\.name\s*==")
AGENT_CLI = re.compile(r"(?:^|[\s;&|(])(?:npx\s+)?(@anthropic-ai/claude-code|claude|@openai/codex|codex|@google/gemini-cli|gemini|aider|opencode|goose|cursor-agent|qwen|copilot)(?:@[\w.^~-]+)?\s+(?:-p\b|--print\b|exec\b|run\b|--prompt\b|--message\b|--yolo\b|-y\b|--approval-mode\b|--yes\b)", re.M)
DANGEROUS_CLI_FLAGS = re.compile(r"--yolo\b|(?:^|\s)-y(?=\s|$)|--approval-mode[= ]+yolo\b|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--full-auto\b|--allow-all-tools\b|--permission-mode[= ]+bypassPermissions|--yes-always\b", re.M)
STRONG_SCOPES = {"contents", "actions", "packages", "deployments", "pages"}
# The pull request head, however it is reached: event fields, github.head_ref, refs/pull/N/head, or a step output
# such as steps.pr.outputs.head_sha (comment-triggered jobs have no pull_request payload).
PR_HEAD_REF = re.compile(r"refs/pull/|head[._](?:sha|ref)\b")
GH_PR_CHECKOUT = re.compile(r"\bgh\s+pr\s+checkout\b")
# Events whose jobs hold the base repository's token and secrets even when a fork's pull request triggers them.
PRIVILEGED_PR_EVENTS = ("pull_request_target", "issue_comment")
AGENT_ACTIONS = {
    "anthropics/claude-code-action": "Claude Code",
    "anthropics/claude-code-base-action": "Claude Code",
    "openai/codex-action": "Codex",
    "google-github-actions/run-gemini-cli": "Gemini CLI",
}
MCP_FILES = [(".mcp.json", "mcpServers"), (".cursor/mcp.json", "mcpServers"), (".vscode/mcp.json", "servers"),
             (".gemini/settings.json", "mcpServers")]
PLACEHOLDER = re.compile(r"your|xxx|<|>|changeme|example|placeholder|replace|redacted|\.\.\.|^\*+$|todo", re.I)
BROAD_BASH = re.compile(r"(?<![\w(])Bash(?:\(\*(?::\*)?\))?(?![\w(])")

# Supabase migrations. Until 30 Oct 2026 Supabase granted every new public table to the anon and authenticated
# roles, so row-level security was the only thing between the app's public key and the data; since then a new
# table needs an explicit grant, and the quick fix for "permission denied" is often a grant to everyone.
SQL_IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)'
SQL_QNAME = rf"(?:({SQL_IDENT})\s*\.\s*)?({SQL_IDENT})"
CREATE_TABLE = re.compile(rf"create\s+(?:(?:global|local)\s+)?(temp\s+|temporary\s+)?(?:unlogged\s+)?table\s+(if\s+not\s+exists\s+)?{SQL_QNAME}", re.I)
CREATE_VIEW = re.compile(rf"create\s+(?:or\s+replace\s+)?(temp\s+|temporary\s+)?(?:recursive\s+)?view\s+{SQL_QNAME}(.*?)\bas\b", re.I | re.S)
ALTER_RELATION = re.compile(rf"alter\s+(table|view)\s+(?:if\s+exists\s+)?(?:only\s+)?{SQL_QNAME}(.*)", re.I | re.S)
DROP_RELATION = re.compile(r"drop\s+(?:table|view)\s+(?:if\s+exists\s+)?(.+)", re.I | re.S)
GRANT = re.compile(r"(grant|revoke)\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+(.+?)\s+(?:to|from)\s+(.+)", re.I | re.S)
DEFAULT_GRANT = re.compile(r"alter\s+default\s+privileges\b(.*?)\bgrant\s+(.+?)\s+on\s+tables\s+to\s+(.+)", re.I | re.S)
NOT_A_RELATION = re.compile(r"(?:all\s+)?(?:sequences?|functions?|procedures?|routines?|schema|database|type|domain|language|large\s+object|tablespace|foreign)\b", re.I)
SECURITY_INVOKER = re.compile(r"security_invoker\s*(?:=\s*(?:true|on|1|yes)\b|(?=[,)]))", re.I)
ENABLE_RLS = re.compile(r"enable\s+row\s+level\s+security", re.I)
EVERY_TABLE = re.compile(r"\bpg_tables\b|information_schema\.tables|\bpg_class\b", re.I)
DYNAMIC_RLS = re.compile(r"alter\s+table\s[^;]*?(?:%|\|\|)[^;]*?enable\s+row\s+level\s+security", re.I)
NAME_COLUMN = r"\b(?:tablename|table_name|relname)\b\s*"
NAME_FILTER = re.compile(NAME_COLUMN + r"(?:=|in\s*\()", re.I)
NAME_EQUALS = re.compile(NAME_COLUMN + r"=\s*('[^']*')", re.I)
NAME_SKIPPED = re.compile(NAME_COLUMN + r"(?:not\s+in\s*\(([^)]*)\)|(?:<>|!=)\s*('[^']*'))", re.I)
SCHEMA_EQUALS = re.compile(r"\b(?:schemaname|table_schema|nspname|relnamespace)\b\s*=\s*'([^']*)'", re.I)
LISTED = re.compile(r"(?:array\s*\[|(?<!\bnot\s)\bin\s*\()([^\])]*)[\])]", re.I)
SPELLED_RLS = re.compile(rf"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{SQL_QNAME}\s+enable\s+row\s+level\s+security", re.I)
CREATE_POLICY = re.compile(rf"create\s+policy\s+({SQL_IDENT})\s+on\s+(?:only\s+)?{SQL_QNAME}(.*)", re.I | re.S)
ALTER_POLICY = re.compile(rf"alter\s+policy\s+({SQL_IDENT})\s+on\s+{SQL_QNAME}(.*)", re.I | re.S)
DROP_POLICY = re.compile(rf"drop\s+policy\s+(?:if\s+exists\s+)?({SQL_IDENT})\s+on\s+{SQL_QNAME}", re.I)
POLICY_CLAUSE = re.compile(r"\b(using|with\s+check)\s*\(", re.I)
ALWAYS_TRUE = re.compile(r"[\s(]*(?:true|1\s*=\s*1)[\s)]*", re.I)
SIGNED_IN = re.compile(r"[\s(]*(?:select\s+)?auth\.(?:uid\(\)(?:\s+as\s+\w+)?[\s)]*is\s+not\s+null"
                       r"|role\(\)(?:\s+as\s+\w+)?[\s)]*=\s*'authenticated'(?:::text)?)[\s)]*", re.I)
ACTIONS = {"select": "read", "insert": "add", "update": "change", "delete": "delete"}
DML = ("select", "insert", "update", "delete")

FIXES = {
    "bypass-permissions": "Remove defaultMode bypassPermissions from committed settings; keep it, if at all, in an uncommitted local file.",
    "broad-shell-allow": "Replace the wildcard with the few commands the team runs (for example Bash(npm test)) and add hooks that block destructive commands.",
    "dangerous-prompt-skipped": "Remove skipDangerousModePermissionPrompt from committed settings.",
    "all-project-mcp-enabled": "Set enableAllProjectMcpServers to false so each new server in .mcp.json needs a person to approve it.",
    "local-settings-committed": "Remove .claude/settings.local.json from git and add it to .gitignore.",
    "plaintext-secret": "Rotate the credential now, then reference an environment variable instead (${VAR}).",
    "unpinned-mcp-package": "Pin an exact version (package@1.2.3) and review upgrades like any other dependency.",
    "no-codeowners": "Add CODEOWNERS entries for .claude/, .mcp.json and .github/workflows/ so changes need an owner's review.",
    "pwn-request": "Never check out pull request code in a pull_request_target or issue_comment job, and never start an agent inside it: an agent may load that code's own agent config. Build it in an unprivileged pull_request workflow, and limit comment commands to trusted authors.",
    "shell-injection": "Pass the value through env: and quote it in the script instead of using ${{ }} inside run:.",
    "agent-open-to-anyone": "Restrict who can trigger the agent: remove '*' and list specific trusted users, or drop the input.",
    "agent-unrestricted": "Remove the flag; give the agent a narrow tool list and a sandbox instead.",
    "untrusted-text-in-prompt": "Do not paste issue or PR text into the prompt; let the agent read it as data with read-only permissions.",
    "agent-write-on-untrusted": "Give the agent job read-only permissions, and do any writes in a separate job after review.",
    "agent-default-token": "Add an explicit permissions: block with the least the job needs.",
    "cli-agent-on-untrusted": "Run the agent CLI read-only with approvals on, pass outside text as a file it reads as data, and post results from a separate step that holds the token.",
    "rls-off-table": "Enable row-level security on the table and add a policy for each role, then grant each role only the actions the app uses. Never fix 'permission denied' by granting everything to anon.",
    "default-grant-to-anon": "Remove the default-privileges grant and grant each new table explicitly, after enabling row-level security on it.",
    "view-bypasses-rls": "Create the view with (security_invoker = true) so it applies the row-level security of the tables it reads, or revoke it from anon and authenticated.",
    "rls-policy-always-true": "Give the policy a condition on the row, such as user_id = (select auth.uid()), and a TO clause naming only the roles that need it. Keep using (true) for reading public data.",
}


def add(out, level, path, root, rule, message, needle=None):
    rel = os.path.relpath(path, root)
    out.append({"level": level, "file": rel, "line": line_of(path, needle) if needle else None, "rule": rule, "message": message})


def line_of(path, needle):
    try:
        for i, line in enumerate(Path(path).read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if needle in line:
                return i
    except OSError:
        pass
    return None


def literal_secret(value):
    """A credential written into the file: long, no spaces, letters and digits, not a reference, path, URL or placeholder."""
    v = str(value).strip()
    if v.lower().startswith("bearer "):
        v = v[7:].strip()
    if len(v) < 16 or "$" in v or " " in v or "://" in v or v.startswith(("/", "~", ".")) or PLACEHOLDER.search(v):
        return False
    if re.search(r"\.(json|pem|key|p12|txt|ya?ml|env)$", v, re.I):
        return False
    return bool(re.search(r"[A-Za-z]", v) and re.search(r"\d", v))


def check_claude_settings(root, out):
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        p = root / rel
        data = load_json(p)
        if not isinstance(data, dict):
            continue
        if rel.endswith("local.json"):
            add(out, "low", p, root, "local-settings-committed", "personal Claude Code settings are committed and apply to every clone")
        perms = data.get("permissions") or {}
        if perms.get("defaultMode") == "bypassPermissions":
            add(out, "critical", p, root, "bypass-permissions", "defaultMode is bypassPermissions: every clone runs the agent with no approval prompts", "bypassPermissions")
        for rule in perms.get("allow") or []:
            if isinstance(rule, str) and (rule in ("Bash", "Bash(*)", "Bash(*:*)") or rule.startswith("Bash(sudo")):
                add(out, "high", p, root, "broad-shell-allow", f"allow rule {rule} pre-approves shell commands for everyone who clones the repo", rule)
        if data.get("skipDangerousModePermissionPrompt"):
            add(out, "high", p, root, "dangerous-prompt-skipped", "the dangerous-mode warning is switched off for every clone", "skipDangerousModePermissionPrompt")
        if data.get("enableAllProjectMcpServers") is True:
            add(out, "high", p, root, "all-project-mcp-enabled", "any MCP server added to .mcp.json, for example in a pull request, starts on developers' machines without a prompt", "enableAllProjectMcpServers")
        for k, v in (data.get("env") or {}).items():
            if SECRET_NAME.search(k) and literal_secret(v):
                add(out, "high", p, root, "plaintext-secret", f"env {k} holds a literal credential in a committed file", k)


def check_mcp_servers(root, out):
    files = [(rel, key, load_json(root / rel)) for rel, key in MCP_FILES]
    codex = load_toml(root / ".codex/config.toml")
    files.append((".codex/config.toml", "mcp_servers", codex))
    for rel, key, data in files:
        if not isinstance(data, dict):
            continue
        p = root / rel
        for name, spec in (data.get(key) or {}).items():
            if not isinstance(spec, dict):
                continue
            cmd = os.path.basename(str(spec.get("command", "")))
            pkgs = [str(a) for a in spec.get("args", []) if not str(a).startswith("-")]
            if cmd in ("npx", "bunx", "pnpx") and pkgs and not PINNED_NPX.search(pkgs[0]):
                add(out, "medium", p, root, "unpinned-mcp-package", f"MCP server {name} starts {pkgs[0]} with no version: unless it is a locked project dependency, every start runs the latest release", pkgs[0])
            if cmd == "uvx" and pkgs and "==" not in pkgs[0] and "@" not in pkgs[0]:
                add(out, "medium", p, root, "unpinned-mcp-package", f"MCP server {name} runs the latest release of {pkgs[0]} on every start", pkgs[0])
            for field in ("env", "headers"):
                for k, v in (spec.get(field) or {}).items():
                    if (SECRET_NAME.search(k) or k.lower() == "authorization") and literal_secret(v):
                        add(out, "high", p, root, "plaintext-secret", f"MCP server {name}: {field} {k} holds a literal credential in a committed file", k)


def check_codeowners(root, out):
    agent_files = [rel for rel in (".claude", ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini") if (root / rel).exists()]
    if not agent_files:
        return
    owners = ""
    for rel in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        try:
            owners += (root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass
    covered = lambda f: re.search(r"(^|\s)(\*\s|/?" + re.escape(f.split("/")[0]) + r")", owners, re.M)
    missing = [f for f in agent_files if not covered(f)]
    if missing:
        add(out, "low", root / missing[0], root, "no-codeowners", "no CODEOWNERS rule covers " + ", ".join(missing) + ": agent config can change without an owner's review")


def triggers(doc):
    on = doc.get("on", doc.get(True))  # PyYAML reads a bare `on` key as True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(e) for e in on}
    if isinstance(on, dict):
        return {str(e) for e in on}
    return set()


def write_scopes(perms):
    if perms is None:
        return None
    if isinstance(perms, str):
        return ["write-all"] if perms == "write-all" else []
    if isinstance(perms, dict):
        return sorted(f"{k}: write" for k, v in perms.items() if v == "write" and k != "id-token")
    return []


def check_workflows(root, out):
    wf_dir = root / ".github/workflows"
    if not wf_dir.is_dir():
        return
    files = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")))
    if files and yaml is None:
        out.append({"level": "low", "file": ".github/workflows", "line": None, "rule": "skipped",
                    "message": "workflow checks skipped: PyYAML is not installed"})
        return
    for p in files:
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8", errors="ignore"))
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            out.append({"level": "low", "file": os.path.relpath(p, root), "line": mark.line + 1 if mark else None,
                        "rule": "unparsed-workflow", "message": "workflow could not be parsed, so it was not checked"})
            continue
        if not isinstance(doc, dict):
            continue
        events = triggers(doc)
        untrusted = sorted(events & UNTRUSTED_EVENTS)
        privileged = [e for e in PRIVILEGED_PR_EVENTS if e in events]
        jobs = doc.get("jobs")
        for job_id, job in (jobs.items() if isinstance(jobs, dict) else []):
            if not isinstance(job, dict):
                continue
            perms = job.get("permissions", doc.get("permissions"))
            steps = [s for s in job.get("steps") or [] if isinstance(s, dict)]
            # actions/checkout leaves the job token in .git/config unless persist-credentials is false
            persisted = any(str(s.get("uses", "")).startswith("actions/checkout")
                            and str((s.get("with") or {}).get("persist-credentials", "true")).lower() != "false" for s in steps)
            for i, step in enumerate(steps):
                uses = str(step.get("uses", ""))
                run = str(step.get("run", ""))
                with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
                gh_checkout = GH_PR_CHECKOUT.search(run) if privileged else None
                if privileged and uses.startswith("actions/checkout") and PR_HEAD_REF.search(str(with_.get("ref", ""))):
                    check_pr_checkout(root, out, p, job_id, job, steps[i + 1:], with_, perms, privileged)
                elif gh_checkout:
                    # the rest of this script runs on the pull request code too
                    later = [{"run": run[gh_checkout.end():]}] + steps[i + 1:]
                    check_pr_checkout(root, out, p, job_id, job, later, {"ref": "gh pr checkout"}, perms, privileged)
                m = UNTRUSTED_TEXT.search(run)
                if m:
                    add(out, "high", p, root, "shell-injection", f"job {job_id} pastes {m.group(0)} }}}} into a shell script: anyone who can set that text can run commands", m.group(0))
                agent = agent_of(uses)
                if agent:
                    check_agent_step(root, out, p, job_id, agent, with_, untrusted, perms, step.get("env"), persisted)
                if run and untrusted:
                    env_text = " ".join(str(v) for scope in (doc.get("env"), job.get("env"), step.get("env")) if isinstance(scope, dict) for v in scope.values())
                    check_cli_agent(root, out, p, job_id, run, env_text, untrusted, perms)


def check_pr_checkout(root, out, p, job_id, job, later, checkout, perms, privileged):
    """Pull request code checked out in a job that holds the base repo's token and secrets: grade by what runs on it."""
    pr_dir = str(checkout.get("path") or "").strip().strip("./")

    def on_pr_code(st):
        # PR code checked out into a subdirectory only runs if a later step points at that directory.
        if not pr_dir:
            return True
        wd = str(st.get("working-directory", "")).strip().strip("./")
        if wd == pr_dir or wd.startswith(pr_dir + "/"):
            return True
        text = str(st.get("run", "")) + " " + str(st.get("uses", ""))
        d = re.escape(pr_dir)
        return re.search(r"(?:^|[\s\"'=])(?:\./)?" + d + r"/|\bcd\s+(?:\./)?" + d + r"\b", text) is not None

    touched = [st for st in later if on_pr_code(st)]
    executes = (any(EXEC_PR_CODE.search(str(st.get("run", ""))) for st in touched)
                or any(str(st.get("uses", "")).startswith("./") for st in touched))
    agents = [st for st in later if agent_of(str(st.get("uses", "")))]
    gated = bool(TRUSTED_GATE.search(str(job.get("if", "")))) or "environment" in job
    scopes = write_scopes(perms)
    if executes:
        level, what = "critical", "then runs build, test or local-action code from it"
    elif agents:
        w = {k: str(v) for st in agents for k, v in (st.get("with") or {}).items()}
        env = {k for st in agents for k in (st.get("env") or {})}
        strong = (w.get("sandbox") == "danger-full-access" or w.get("safety-strategy") == "unsafe"
                  or env & {"GH_TOKEN", "GITHUB_TOKEN"} or scopes is None or bool(scopes))
        level = "high" if strong else "medium"
        what = "then has an agent read it" + (" with write access or no sandbox" if strong else " in a read-only job")
    else:
        level, what = "medium", "in a job that holds the base repo's token"
    if gated:
        level = LEVELS[max(0, LEVELS.index(level) - 1)]
        what += "; the job is limited to trusted authors or a protected environment"
    add(out, level, p, root, "pwn-request", f"job {job_id} checks out pull request code under {' and '.join(privileged)}, {what}", str(checkout.get("ref")))


def check_cli_agent(root, out, p, job_id, run, env_text, untrusted, perms):
    """An agent CLI started from a shell step on events whose text outsiders write."""
    cmd = re.sub(r"\bnpx\s+(?:--yes|-y)\b", "npx", run)
    m = AGENT_CLI.search(cmd)
    if not m:
        return
    name = m.group(1)
    dangerous = DANGEROUS_CLI_FLAGS.search(cmd)
    text_in = UNTRUSTED_TEXT.search(env_text)
    scopes = write_scopes(perms)
    strong = scopes is not None and any(sc == "write-all" or sc.split(":")[0] in STRONG_SCOPES for sc in scopes)
    if dangerous and text_in and (strong or scopes is None):
        level = "critical"
    elif dangerous or (text_in and (scopes is None or scopes)):
        level = "high"
    else:
        level = "medium"
    parts = [f"job {job_id} runs the {name} CLI on " + ", ".join(untrusted)]
    if text_in:
        parts.append(f"with {text_in.group(0)} }}}} in its environment")
    if dangerous:
        parts.append(f"with approvals off ({dangerous.group(0).strip()})")
    if scopes is None:
        parts.append("with the repository's default token")
    elif scopes:
        parts.append("with " + ", ".join(scopes))
    add(out, level, p, root, "cli-agent-on-untrusted", ", ".join(parts), m.group(0).strip())


def agent_of(uses):
    action = uses.split("@")[0]
    return next((label for prefix, label in AGENT_ACTIONS.items() if action == prefix or action.startswith(prefix + "/")), None)


def token_withheld(step_env, w):
    """The agent step is explicitly given no GitHub token."""
    env = {k: str(v).strip() for k, v in (step_env or {}).items()} if isinstance(step_env, dict) else {}
    named = [k for k in ("GITHUB_TOKEN", "GH_TOKEN") if k in env]
    return bool(named) and all(env[k] in ("", "''", '""') for k in named) \
        and not any(w.get(k, "").strip() for k in ("github_token", "github-token"))


def check_agent_step(root, out, p, job_id, agent, with_, untrusted, perms, step_env=None, persisted=False):
    w = {k: str(v) for k, v in with_.items()}
    where = f"job {job_id} ({agent})"
    if untrusted:
        where += " on " + ", ".join(untrusted)
    scopes = write_scopes(perms)
    withheld = token_withheld(step_env, w)
    if withheld and not persisted:
        scopes = []  # the job's write scopes belong to other steps; the agent gets no token
    strong = scopes is not None and any(sc == "write-all" or sc.split(":")[0] in STRONG_SCOPES for sc in scopes)
    unrestricted = []
    if w.get("safety-strategy") == "unsafe":
        unrestricted.append(("safety-strategy", "safety-strategy unsafe gives the agent the runner's sudo and its secrets"))
    if w.get("sandbox") == "danger-full-access":
        unrestricted.append(("danger-full-access", "sandbox danger-full-access turns the sandbox off"))
    args = " ".join(w.get(k, "") for k in ("claude_args", "codex-args", "settings"))
    for flag in ("--dangerously-skip-permissions", "--dangerously-bypass-approvals-and-sandbox", "--yolo", "bypassPermissions"):
        if flag in args:
            unrestricted.append((flag, f"{flag} removes every approval check"))
    m = re.search(r"--allowed-?tools[ =]+[\"']?([^\"'\n]*)", args, re.I)
    for needle, msg in unrestricted:
        add(out, "high", p, root, "agent-unrestricted", f"{where}: {msg}", needle)
    if m and BROAD_BASH.search(m.group(1)):
        add(out, "high", p, root, "broad-shell-allow", f"{where}: the agent may run any shell command (--allowedTools includes unrestricted Bash)", "allowedTools")
        unrestricted.append(("allowedTools", "unrestricted Bash"))

    # Claude Code's allowed_non_write_users only takes effect when github_token is passed.
    open_keys = [k for k in ("allowed_non_write_users", "allow-users") if w.get(k, "").strip() == "*"
                 and (k != "allowed_non_write_users" or "github_token" in w)]
    if w.get("allowed_bots", "").strip() == "*":
        open_keys.append("allowed_bots")
    for key in open_keys:
        who = "any GitHub App" if key == "allowed_bots" else "any GitHub user"
        if not untrusted:
            level, power = "low", "none of this workflow's triggers carry outside text yet"
        elif unrestricted or strong:
            level, power = "critical", "and the agent can " + ("act without limits" if unrestricted else "write with " + ", ".join(scopes))
        elif scopes is None or scopes:
            level, power = "high", ("and the job's token can write (" + ", ".join(scopes) + ")") if scopes else "and the job's token gets the repository default, which may include write access"
        else:
            level, power = "medium", "the job is read-only, so injected instructions can only change the agent's output: later jobs must treat it as untrusted"
        add(out, level, p, root, "agent-open-to-anyone", f"{where}: {key} '*' lets {who} drive the agent; {power}", key)

    t = UNTRUSTED_TEXT.search(w.get("prompt", ""))
    if t:
        risky = untrusted and (open_keys or unrestricted or scopes is None or scopes)
        add(out, "high" if risky else "medium", p, root, "untrusted-text-in-prompt", f"{where}: {t.group(0)} }}}} is pasted into the agent's prompt, so whoever writes that text can instruct the agent", t.group(0))
    if scopes is None:
        add(out, "low", p, root, "agent-default-token", f"{where}: no permissions block, so the token gets the repository default")
    elif scopes and untrusted and not open_keys:
        if withheld:
            add(out, "low", p, root, "agent-write-on-untrusted", f"{where}: the agent step gets no token, but a checkout in this job leaves the job token ({', '.join(scopes)}) in .git/config", "persist-credentials")
        else:
            add(out, "medium", p, root, "agent-write-on-untrusted", f"{where}: the agent reads text from outside contributors, with {', '.join(scopes)}", "permissions")


def sql_code(text):
    """The SQL with comments, string literals and dollar-quoted bodies blanked out (newlines kept, so offsets still
    match the file), plus each dollar-quoted body with its offset."""
    code, bodies, i, n = list(text), [], 0, len(text)
    while i < n:
        if text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
        elif text[i] == "'":
            j = i + 1
            while j < n and (text[j] != "'" or text.startswith("''", j)):
                j += 2 if text.startswith("''", j) else 1
            j = min(j + 1, n)
        elif text[i] == '"':  # quoted identifiers stay
            j = text.find('"', i + 1)
            i = n if j < 0 else j + 1
            continue
        elif m := re.match(r"\$(?:[A-Za-z_]\w*)?\$", text[i:i + 64]):
            j = text.find(m.group(0), i + len(m.group(0)))
            j = n if j < 0 else j + len(m.group(0))
            bodies.append((i, text[i:j]))
        else:
            i += 1
            continue
        for k in range(i, j):
            if code[k] != "\n":
                code[k] = " "
        i = j
    return "".join(code), bodies


def sql_ident(t):
    return t[1:-1] if t.startswith('"') else t.lower()


def sql_qualify(schema, name):
    return (sql_ident(schema) if schema else "public", sql_ident(name))


def sql_names(text):
    """Qualified names from a list such as 'table a, public."B" cascade'."""
    return [sql_qualify(m.group(1), m.group(2)) for part in text.split(",")
            if (m := re.match(rf"\s*(?:table\s+)?{SQL_QNAME}", part, re.I))]


def sql_privileges(text):
    text = text.lower()
    return set(DML) if re.search(r"\ball\b", text) else {p for p in DML if re.search(rf"\b{p}\b", text)}


def sql_roles(text):
    text = re.split(r"\bwith\s+grant\s+option\b|\bgranted\s+by\b|\bcascade\b|\brestrict\b", text, flags=re.I)[0]
    return {r.strip().strip('"').lower() for r in text.split(",") if r.strip()}


def rls_loop_targets(body):
    """The tables a DO block switches row-level security on for, as (every, names, schemas): the names it lists or
    spells out, or for a loop over the catalog, every table in the schemas it reads except the names it skips."""
    if not ENABLE_RLS.search(body):
        return False, set(), set()
    quoted = lambda groups: {n for g in groups for n in re.findall(r"'([A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?)'", g)}
    listed = quoted(LISTED.findall(body)) | quoted(NAME_EQUALS.findall(body))
    # a loop over the catalog builds its statement per table, and keeps every table unless it filters on listed names
    if EVERY_TABLE.search(body) and DYNAMIC_RLS.search(body) and not (NAME_FILTER.search(body) and listed):
        return True, quoted("".join(g) for g in NAME_SKIPPED.findall(body)), set(SCHEMA_EQUALS.findall(body))
    return False, listed | {f"{m.group(1) or 'public'}.{m.group(2)}" for m in SPELLED_RLS.finditer(body)}, set()


def sql_policy(code, raw):
    """A policy's clauses from the text after 'on <table>'. The clauses are found in the code, where comments and strings
    are blanked, and each expression is read from the raw text at the same place. None marks a clause that is absent."""
    exprs, pos, head = {}, 0, code
    while m := POLICY_CLAUSE.search(code, pos):
        head = code[:m.start()] if not exprs else head
        depth, i = 1, m.end()
        while i < len(code) and depth:
            depth += {"(": 1, ")": -1}.get(code[i], 0)
            i += 1
        exprs.setdefault("using" if m.group(1).lower() == "using" else "check", raw[m.end():i - 1].strip())
        pos = i
    cmd, to = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", head, re.I), re.search(r"\bto\s+(.+)", head, re.I | re.S)
    return {"restrictive": bool(re.search(r"\bas\s+restrictive\b", head, re.I)), "cmd": cmd and cmd.group(1).lower(),
            "roles": to and sql_roles(to.group(1)), "using": exprs.get("using"), "check": exprs.get("check")}


def policy_reach(p):
    """What a permissive policy lets through on every row, as (actions for anyone with the app's public key, actions for
    any signed-in user): its condition is always true, or only checks that the user is signed in."""
    roles, cmd = p["roles"] or {"public"}, p["cmd"] or "all"
    anyone, signed = set(), set()
    for action in (DML if cmd == "all" else (cmd,)) if not p["restrictive"] else ():
        expr = (p["check"] or (p["using"] if cmd == "all" else None)) if action == "insert" else p["using"]
        if expr is not None and ALWAYS_TRUE.fullmatch(expr):
            anyone |= {action} if roles & {"anon", "public"} else set()
            signed |= {action} if roles & {"public", "authenticated"} else set()
        elif expr is not None and SIGNED_IN.fullmatch(expr) and roles & {"public", "authenticated"}:
            signed.add(action)
    return anyone, signed


def say_actions(actions):
    rows = [ACTIONS[a] for a in DML if a in actions - {"insert"}]
    said = (", ".join(rows[:-1]) + " and " + rows[-1] if len(rows) > 1 else "".join(rows)) + " every row" if rows else ""
    return said + (", and add rows" if rows and "insert" in actions else "add rows" if "insert" in actions else "")


def found(out, level, where, rule, message):
    out.append({"level": level, "file": where[0], "line": where[1], "rule": rule, "message": message})


def supabase_schemas(path):
    """The schemas config.toml exposes to the API. Without tomllib (Python < 3.11) the [api] schemas line is read directly."""
    if (config := load_toml(path)) is not None:
        return (config.get("api") or {}).get("schemas")
    try:
        api = re.search(r"^\[api\][^\[]*?^\s*schemas\s*=\s*\[([^\]]*)\]", path.read_text(encoding="utf-8"), re.M | re.S)
    except OSError:
        return None
    return re.findall(r"""["']([^"']+)["']""", api.group(1)) if api else None


def check_supabase(root, out):
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
        if os.path.basename(dirpath) == "supabase" and {"migrations", "schemas"} & set(dirnames):
            base = Path(dirpath)
            files = sorted((base / "migrations").glob("*.sql")) + sorted((base / "schemas").glob("*.sql"))
            check_migrations(root, out, files, set(supabase_schemas(base / "config.toml") or ["public"]))


def check_migrations(root, out, files, exposed):
    """Replay the migrations in order, tracking row-level security, grants and renames, then report what the API can reach."""
    rels, defaults, auto_rls = {}, {}, False  # defaults: schema (None = every schema) -> role -> privileges
    pending = set()  # tables switched to RLS before they exist: Postgres refuses that, so the files ran in another order

    def initial_grants(schema):
        grants = {}
        for scope in (None, schema):
            for role, privs in defaults.get(scope, {}).items():
                grants.setdefault(role, set()).update(privs)
        return grants

    def replay_policy(stmt, raw, where):
        if c := DROP_POLICY.match(stmt):
            if (r := rels.get(sql_qualify(c.group(2), c.group(3)))) and r["kind"] == "table":
                r["policies"].pop(sql_ident(c.group(1)), None)
        elif (c := CREATE_POLICY.match(stmt) or ALTER_POLICY.match(stmt)) and \
                (r := rels.get(sql_qualify(c.group(2), c.group(3)))) and r["kind"] == "table":
            name, parsed = sql_ident(c.group(1)), sql_policy(c.group(4), raw[c.start(4):])
            if stmt[:6].lower() == "create":
                r["policies"][name] = dict(parsed, where=where)
            elif rn := re.match(rf"\s*rename\s+to\s+({SQL_IDENT})", c.group(4), re.I):
                if name in r["policies"]:
                    r["policies"][sql_ident(rn.group(1))] = r["policies"].pop(name)
            elif name in r["policies"]:
                r["policies"][name].update({k: v for k, v in parsed.items() if k in ("roles", "using", "check") and v is not None})

    for p in files:
        text = p.read_text(encoding="utf-8", errors="ignore")
        code, bodies = sql_code(text)
        for m in re.finditer(r"[^;]+", code):
            stmt = m.group(0).lstrip()
            if not stmt:
                continue
            at = m.end() - len(stmt)
            where = (os.path.relpath(p, root), text.count("\n", 0, at) + 1)
            inside = [(o, b) for o, b in bodies if m.start() <= o < m.end()]
            if any(ENABLE_RLS.search(b) and "pg_event_trigger_ddl_commands" in b for _, b in inside):
                auto_rls = True  # an event-trigger function that switches RLS on for each new table
            if re.match(r"do\b", stmt, re.I):
                for o, b in inside:
                    every, targets, schemas = rls_loop_targets(b)
                    if every:  # a loop over the catalog: every existing table in the schemas it reads, bar the skipped
                        targets = [f"{k[0]}.{k[1]}" for k, r in rels.items() if r["kind"] == "table"
                                   and (not schemas or k[0] in schemas) and not {k[1], f"{k[0]}.{k[1]}"} & targets]
                    for t in targets:
                        schema, _, name = t.rpartition(".")
                        for key in ((schema.strip('"') or "public", name.strip('"')), (schema.strip('"').lower() or "public", name.strip('"').lower())):
                            if key in rels and rels[key]["kind"] == "table":
                                rels[key]["rls"] = True
                                break
                    tag = re.match(r"\$\w*\$", b).group(0)  # every body starts with its tag
                    raw = b[len(tag):].removesuffix(tag)
                    inner = sql_code(raw)[0]
                    for d in re.finditer(r"\bdrop\s+(?:table|view)\s+(?:if\s+exists\s+)?([^;]+)", inner, re.I):
                        for key in sql_names(d.group(1)):  # a cleanup step inside the block
                            rels.pop(key, None)
                    for piece in re.finditer(r"[^;]+", inner):  # policies created only if missing, a common idiom
                        if s := re.search(r"\b(?:create|alter|drop)\s+policy\b", piece.group(0), re.I):
                            start = piece.start() + s.start()
                            replay_policy(inner[start:piece.end()], raw[start:piece.end()],
                                          (where[0], text.count("\n", 0, o + len(tag) + start) + 1))
            elif re.match(r"(?:create|alter|drop)\s+policy\b", stmt, re.I):
                replay_policy(stmt, text[at:m.end()], where)
            elif c := CREATE_TABLE.match(stmt):
                key = sql_qualify(c.group(3), c.group(4))
                if not c.group(1) and not (c.group(2) and key in rels):
                    rels[key] = {"kind": "table", "rls": auto_rls or key in pending, "invoker": False, "where": where,
                                 "grants": initial_grants(key[0]), "revoked": set(), "policies": {}}
            elif c := CREATE_VIEW.match(stmt):
                key = sql_qualify(c.group(2), c.group(3))
                old = rels.get(key)
                if not c.group(1):
                    keep = old is not None and old["invoker"] and "with" not in c.group(4).lower()
                    rels[key] = {"kind": "view", "rls": False, "invoker": bool(SECURITY_INVOKER.search(c.group(4))) or keep,
                                 "where": where, "grants": old["grants"] if old else initial_grants(key[0]),
                                 "revoked": old["revoked"] if old else set()}
            elif c := ALTER_RELATION.match(stmt):
                key, rest = sql_qualify(c.group(2), c.group(3)), c.group(4)
                r = rels.get(key)
                if r is None:  # two files sharing a version prefix can sort this way; IF EXISTS makes it a silent no-op
                    if ENABLE_RLS.search(rest) and not re.match(r"alter\s+table\s+if\s+exists\b", stmt, re.I):
                        pending.add(key)
                    continue
                if rn := re.search(rf"\brename\s+to\s+({SQL_IDENT})", rest, re.I):
                    rels[sql_qualify(f'"{key[0]}"', rn.group(1))] = rels.pop(key)
                if re.search(r"\bdisable\s+row\s+level\s+security", rest, re.I):
                    r["rls"] = False
                if ENABLE_RLS.search(rest):
                    r["rls"] = True
                if re.search(r"security_invoker\s*=\s*(?:false|off|0|no)\b", rest, re.I):
                    r["invoker"] = False
                elif re.search(r"\bset\s*\(", rest, re.I) and SECURITY_INVOKER.search(rest):
                    r["invoker"] = True
            elif c := DROP_RELATION.match(stmt):
                for key in sql_names(c.group(1)):
                    rels.pop(key, None)
            elif c := DEFAULT_GRANT.match(stmt):
                privs, roles = sql_privileges(c.group(2)), sql_roles(c.group(3))
                s = re.search(r"\bin\s+schema\s+(.+?)\s*$", c.group(1), re.I | re.S)
                schemas = [sql_qualify(None, x.strip())[1] for x in s.group(1).split(",")] if s else [None]
                for schema in schemas:
                    for role in roles:
                        defaults.setdefault(schema, {}).setdefault(role, set()).update(privs)
                api_roles, anyone = roles & {"anon", "public", "authenticated"}, roles & {"anon", "public"}
                if privs and api_roles and (schemas == [None] or set(schemas) & exposed):
                    who = "anyone with the app's public key" if anyone else "any signed-in user"
                    found(out, "high" if anyone else "medium", where, "default-grant-to-anon",
                          f"default privileges grant {', '.join(sorted(privs))} on every new table to {', '.join(sorted(api_roles))}: "
                          f"tables created later are reachable through the API as before Supabase's 30 Oct 2026 change, "
                          f"so any of them without row-level security is open to {who}")
            elif c := GRANT.match(stmt):
                verb, privs, target, roles = c.group(1).lower(), sql_privileges(c.group(2)), c.group(3).strip(), sql_roles(c.group(4))
                if s := re.match(r"all\s+tables\s+in\s+schema\s+(.+)", target, re.I | re.S):
                    schemas = {sql_qualify(None, x.strip())[1] for x in s.group(1).split(",")}
                    keys = [k for k in rels if k[0] in schemas]
                elif NOT_A_RELATION.match(target):
                    continue
                else:
                    keys = [k for k in sql_names(target) if k in rels]
                for k in keys:
                    for role in roles:
                        held = rels[k]["grants"].setdefault(role, set())
                        if verb == "grant":
                            held |= privs
                            rels[k]["revoked"].discard(role)
                        else:
                            held -= privs
                            if privs == set(DML):
                                rels[k]["revoked"].add(role)

    for (schema, name), r in rels.items():
        anon = r["grants"].get("anon", set()) | r["grants"].get("public", set())
        signed_in = r["grants"].get("authenticated", set())
        if schema not in exposed or ({"anon", "authenticated"} <= r["revoked"] and not anon and not signed_in):
            continue
        label = f"{schema}.{name}"
        if r["kind"] == "table" and not r["rls"]:
            if anon or signed_in:
                privs = anon or signed_in
                can = " and ".join(word for word, ok in (("read", "select" in privs), ("change", privs - {"select"})) if ok)
                who = "anyone with the app's public key" if anon else "any signed-in user"
                found(out, "critical" if anon and privs - {"select"} else "high", r["where"], "rls-off-table",
                      f"table {label} has row-level security off and is granted to {'anon' if anon else 'authenticated'}: {who} can {can} every row")
            else:
                found(out, "high", r["where"], "rls-off-table",
                      f"table {label} has row-level security off. Supabase granted new tables to anon and authenticated until "
                      "30 Oct 2026, so wherever it did, anyone with the app's public key can read and change every row")
        elif r["kind"] == "view" and not r["invoker"]:
            found(out, "high", r["where"], "view-bypasses-rls",
                  f"view {label} runs with its owner's rights and skips the row-level security of the tables it reads, "
                  "so API users see every row the owner can see")
        elif r["kind"] == "table":
            explicit = bool(anon or signed_in or {"anon", "authenticated"} & r["revoked"])
            for pname, pol in sorted(r["policies"].items()):
                anyone, signed = policy_reach(pol)
                if explicit:  # the grants bound what a policy can open; with none, the pre-30 Oct 2026 defaults applied
                    anyone, signed = anyone & anon, signed & (signed_in | r["grants"].get("public", set()))
                level, who, acts = (("critical", "anyone with the app's public key", anyone) if anyone & {"update", "delete"} else
                                    ("high", "any signed-in user", signed) if signed & {"update", "delete"} else
                                    ("low", "anyone with the app's public key", {"insert"}) if "insert" in anyone else (None, None, None))
                if level:
                    found(out, level, pol["where"], "rls-policy-always-true",
                          f'policy "{pname}" on table {label} lets {who} {say_actions(acts)}: row-level security is on, but '
                          + ("the policy never checks whose row it is" if level != "low" else "nothing limits who adds what"))


def check(root):
    root = Path(root)
    out = []
    check_claude_settings(root, out)
    check_mcp_servers(root, out)
    check_codeowners(root, out)
    check_workflows(root, out)
    check_supabase(root, out)
    out.sort(key=lambda f: (-LEVELS.index(f["level"]), f["file"], f["line"] or 0))
    return out


def report(name, findings):
    counts = {lv: sum(f["level"] == lv for f in findings) for lv in LEVELS}
    lines = [f"# agent-check: {name}", ""]
    if not findings:
        return "\n".join(lines + ["No risky agent setup found.", ""])
    summary = ", ".join(f"{counts[lv]} {lv}" for lv in reversed(LEVELS) if counts[lv])
    lines += [f"**{len(findings)} finding{'s' if len(findings) != 1 else ''}: {summary}.**", "", "| level | where | finding |", "|---|---|---|"]
    for f in findings:
        where = f["file"] + (f":{f['line']}" if f["line"] else "")
        lines.append(f"| {MARKS[f['level']]} {f['level']} | `{where}` | {f['message']} |")
    lines += ["", "## How to fix", ""]
    for rule in dict.fromkeys(f["rule"] for f in findings):
        if rule in FIXES:
            lines.append(f"- **{rule}**: {FIXES[rule]}")
    lines += ["", f"The safe setting for each rule, with examples: [docs/fixes.md]({FIX_GUIDE}). "
                  f"Rather have them fixed? One fixed-price pull request: message [@azankhyder on X]({FIX_FOR_YOU})."]
    return "\n".join(lines) + "\n"


def annotate(findings):
    kind = {"critical": "error", "high": "error", "medium": "warning", "low": "notice"}
    for f in findings:
        loc = f"file={f['file']}" + (f",line={f['line']}" if f["line"] else "")
        msg = f["message"].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{kind[f['level']]} {loc},title=agent-check {f['level']}::{msg}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--github", action="store_true", help="emit GitHub annotations and a job summary")
    ap.add_argument("--fail-on", default="high", choices=LEVELS + ["none"])
    a = ap.parse_args(argv)
    root = Path(a.repo).resolve()
    findings = check(root)
    if a.json:
        json.dump(findings, sys.stdout, indent=1)
        print()
    else:
        text = report(root.name, findings)
        sys.stdout.write(text)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if a.github and summary:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(text)
    if a.github:
        annotate(findings)
    if a.fail_on != "none" and any(LEVELS.index(f["level"]) >= LEVELS.index(a.fail_on) for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
