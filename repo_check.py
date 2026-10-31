#!/usr/bin/env python3
"""agent-check: risky AI-agent setup committed to a repository.

Read-only. Checks the agent configuration a repository ships to everyone who
clones it (Claude Code settings, MCP server configs for Claude Code, Cursor,
VS Code, Gemini CLI and Codex) and the GitHub Actions workflows that run AI
agents or handle text from issues and pull requests. Secret values are never
printed.

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
UNTRUSTED_EVENTS = {"issues", "issue_comment", "pull_request_target", "pull_request_review",
                    "pull_request_review_comment", "discussion", "discussion_comment"}
UNTRUSTED_TEXT = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body"
    r"|pull_request\.(?:title|body|head\.ref|head\.label)|discussion\.(?:title|body)|head_commit\.message)"
    r"|head_ref)\b")
EXEC_PR_CODE = re.compile(r"\b(?:npm|yarn|pnpm|bun|npx|node|make|pip3?|poetry|uv|python3?|pytest|tox|cargo|go|mvn|gradle|bundle|rake|composer)\s+(?!--version)\S|(?:^|[\s;&|])\./[\w./-]+|\b(?:bash|sh)\s+[\w./-]+\.sh\b", re.M)
TRUSTED_GATE = re.compile(r"author_association|github\.actor\s*==|user\.login\s*==|head\.repo\.full_name\s*==\s*github\.repository|head\.repo\.fork\s*==\s*false|label\.name\s*==")
STRONG_SCOPES = {"contents", "actions", "packages", "deployments", "pages"}
PR_HEAD_REF = re.compile(r"github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)|refs/pull/")
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

FIXES = {
    "bypass-permissions": "Remove defaultMode bypassPermissions from committed settings; keep it, if at all, in an uncommitted local file.",
    "broad-shell-allow": "Replace the wildcard with the few commands the team runs (for example Bash(npm test)) and add hooks that block destructive commands.",
    "dangerous-prompt-skipped": "Remove skipDangerousModePermissionPrompt from committed settings.",
    "all-project-mcp-enabled": "Set enableAllProjectMcpServers to false so each new server in .mcp.json needs a person to approve it.",
    "local-settings-committed": "Remove .claude/settings.local.json from git and add it to .gitignore.",
    "plaintext-secret": "Rotate the credential now, then reference an environment variable instead (${VAR}).",
    "unpinned-mcp-package": "Pin an exact version (package@1.2.3) and review upgrades like any other dependency.",
    "no-codeowners": "Add CODEOWNERS entries for .claude/, .mcp.json and .github/workflows/ so changes need an owner's review.",
    "pwn-request": "Never check out pull request code in a pull_request_target job; split it into an unprivileged pull_request build.",
    "shell-injection": "Pass the value through env: and quote it in the script instead of using ${{ }} inside run:.",
    "agent-open-to-anyone": "Restrict who can trigger the agent: remove '*' and list specific trusted users, or drop the input.",
    "agent-unrestricted": "Remove the flag; give the agent a narrow tool list and a sandbox instead.",
    "untrusted-text-in-prompt": "Do not paste issue or PR text into the prompt; let the agent read it as data with read-only permissions.",
    "agent-write-on-untrusted": "Give the agent job read-only permissions, and do any writes in a separate job after review.",
    "agent-default-token": "Add an explicit permissions: block with the least the job needs.",
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
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        events = triggers(doc)
        untrusted = sorted(events & UNTRUSTED_EVENTS)
        jobs = doc.get("jobs")
        for job_id, job in (jobs.items() if isinstance(jobs, dict) else []):
            if not isinstance(job, dict):
                continue
            perms = job.get("permissions", doc.get("permissions"))
            steps = [s for s in job.get("steps") or [] if isinstance(s, dict)]
            for i, step in enumerate(steps):
                uses = str(step.get("uses", ""))
                run = str(step.get("run", ""))
                with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
                if "pull_request_target" in events and uses.startswith("actions/checkout") and PR_HEAD_REF.search(str(with_.get("ref", ""))):
                    check_pr_checkout(root, out, p, job_id, job, steps[i + 1:], with_, perms)
                m = UNTRUSTED_TEXT.search(run)
                if m:
                    add(out, "high", p, root, "shell-injection", f"job {job_id} pastes {m.group(0)} }}}} into a shell script: anyone who can set that text can run commands", m.group(0))
                agent = agent_of(uses)
                if agent:
                    check_agent_step(root, out, p, job_id, agent, with_, untrusted, perms)


def check_pr_checkout(root, out, p, job_id, job, later, checkout, perms):
    """Pull request code checked out in a privileged pull_request_target job: grade by what runs on it."""
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
    add(out, level, p, root, "pwn-request", f"job {job_id} checks out pull request code under pull_request_target, {what}", str(checkout.get("ref")))


def agent_of(uses):
    action = uses.split("@")[0]
    return next((label for prefix, label in AGENT_ACTIONS.items() if action == prefix or action.startswith(prefix + "/")), None)


def check_agent_step(root, out, p, job_id, agent, with_, untrusted, perms):
    w = {k: str(v) for k, v in with_.items()}
    where = f"job {job_id} ({agent})"
    if untrusted:
        where += " on " + ", ".join(untrusted)
    scopes = write_scopes(perms)
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
        add(out, "medium", p, root, "agent-write-on-untrusted", f"{where}: the agent reads text from outside contributors, with {', '.join(scopes)}", "permissions")


def check(root):
    root = Path(root)
    out = []
    check_claude_settings(root, out)
    check_mcp_servers(root, out)
    check_codeowners(root, out)
    check_workflows(root, out)
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
        lines.append(f"| {f['level']} | `{where}` | {f['message']} |")
    lines += ["", "## How to fix", ""]
    for rule in dict.fromkeys(f["rule"] for f in findings):
        if rule in FIXES:
            lines.append(f"- **{rule}**: {FIXES[rule]}")
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
