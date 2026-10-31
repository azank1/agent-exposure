#!/usr/bin/env python3
"""agent-exposure: what can the AI coding agents on this machine reach?

Read-only. Lists the AI agents and MCP servers configured for a user and a
project, flags risky settings, and lists credential and wallet stores an agent
with shell access could read. It reports whether a file exists and, for a few
config files, whether a token-shaped key is present. It never prints or stores
secret values.

Usage: python3 agent_exposure.py [--home DIR] [--project DIR] [--json]
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11: Codex TOML configs are skipped
    tomllib = None

SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|AUTH|CREDENTIAL)", re.I)
PINNED_NPX = re.compile(r"@\d[\w.\-]*$|@[\^~]?\d")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_toml(path):
    if tomllib is None:
        return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def mcp_findings(source, servers):
    """Describe each MCP server: how it starts, and risky traits."""
    out = []
    for name, spec in (servers or {}).items():
        if not isinstance(spec, dict):
            continue
        cmd = spec.get("command", "")
        args = [str(a) for a in spec.get("args", [])]
        notes = []
        if spec.get("url") or spec.get("type") in ("http", "sse"):
            launch = f"remote {spec.get('url', '')}".strip()
        else:
            launch = " ".join([cmd] + args).strip()
            if os.path.basename(cmd) in ("npx", "bunx", "pnpx"):
                pkgs = [a for a in args if not a.startswith("-")]
                if pkgs and not PINNED_NPX.search(pkgs[0]):
                    notes.append("unpinned package: every start runs the latest release")
            if os.path.basename(cmd) == "uvx":
                pkgs = [a for a in args if not a.startswith("-")]
                if pkgs and "==" not in pkgs[0] and "@" not in pkgs[0]:
                    notes.append("unpinned package: every start runs the latest release")
        secret_env = sorted(k for k in (spec.get("env") or {}) if SECRET_NAME.search(k))
        if secret_env:
            notes.append("secret-named env passed in config: " + ", ".join(secret_env))
        secret_headers = sorted(k for k in (spec.get("headers") or {}) if SECRET_NAME.search(k) or k.lower() == "authorization")
        if secret_headers:
            notes.append("credential header in config: " + ", ".join(secret_headers))
        out.append({"source": source, "server": name, "launch": launch, "notes": notes})
    return out


def claude_settings_findings(path):
    data = load_json(path)
    if data is None:
        return []
    notes = []
    perms = data.get("permissions") or {}
    if perms.get("defaultMode") == "bypassPermissions":
        notes.append("defaultMode is bypassPermissions: no approval prompts at all")
    for rule in perms.get("allow") or []:
        if rule in ("Bash", "Bash(*)", "Bash(*:*)") or rule.startswith("Bash(sudo"):
            notes.append(f"broad shell allow rule: {rule}")
    if data.get("skipDangerousModePermissionPrompt"):
        notes.append("dangerous-mode prompt skipped")
    hooks = data.get("hooks") or {}
    events = sorted(hooks) if isinstance(hooks, dict) else []
    return [{"file": str(path), "hook_events": events, "deny_rules": len(perms.get("deny") or []), "notes": notes}]


def scan_agents(home, project):
    agents, mcp, settings = [], [], []

    def seen(label, path):
        if path.exists():
            agents.append({"agent": label, "config": str(path)})
            return True
        return False

    # Claude Code
    for p in (home / ".claude/settings.json", home / ".claude/settings.local.json"):
        if seen("Claude Code (user)", p):
            settings += claude_settings_findings(p)
    if project:
        for p in (project / ".claude/settings.json", project / ".claude/settings.local.json"):
            if seen("Claude Code (project)", p):
                settings += claude_settings_findings(p)
        pm = load_json(project / ".mcp.json")
        if pm:
            agents.append({"agent": "MCP (project .mcp.json)", "config": str(project / ".mcp.json")})
            mcp += mcp_findings(".mcp.json", pm.get("mcpServers"))
    cj = load_json(home / ".claude.json")
    if cj:
        agents.append({"agent": "Claude Code (state)", "config": str(home / ".claude.json")})
        mcp += mcp_findings("~/.claude.json (user)", cj.get("mcpServers"))
        for proj, pdata in (cj.get("projects") or {}).items():
            if isinstance(pdata, dict):
                mcp += mcp_findings(f"~/.claude.json project {proj}", pdata.get("mcpServers"))
    plugins = home / ".claude/plugins"
    if plugins.is_dir():
        agents.append({"agent": "Claude Code plugins", "config": str(plugins)})

    # Other agents
    for label, rel in (
        ("Cursor MCP", ".cursor/mcp.json"),
        ("Windsurf MCP", ".codeium/windsurf/mcp_config.json"),
        ("Gemini CLI", ".gemini/settings.json"),
    ):
        p = home / rel
        if seen(label, p):
            data = load_json(p) or {}
            mcp += mcp_findings(f"~/{rel}", data.get("mcpServers"))
    codex = home / ".codex/config.toml"
    if seen("Codex CLI", codex):
        data = load_toml(codex) or {}
        notes = []
        if data.get("sandbox_mode") == "danger-full-access":
            notes.append("sandbox_mode is danger-full-access")
        if data.get("approval_policy") == "never":
            notes.append("approval_policy is never")
        settings.append({"file": str(codex), "hook_events": [], "deny_rules": 0, "notes": notes})
        mcp += mcp_findings("~/.codex/config.toml", data.get("mcp_servers"))
    for label, rel in (("Continue", ".continue/config.json"), ("Continue", ".continue/config.yaml"), ("Aider", ".aider.conf.yml")):
        seen(label, home / rel)
    return agents, mcp, settings


def contains_token_key(path, pattern):
    try:
        return re.search(pattern, path.read_text(encoding="utf-8", errors="ignore")) is not None
    except OSError:
        return False


def scan_credentials(home, project):
    """Credential and wallet stores readable by the current user. Presence only."""
    checks = [
        ("cloud", "AWS credentials", ".aws/credentials", None),
        ("cloud", "Google Cloud config", ".config/gcloud", None),
        ("cloud", "Azure CLI", ".azure", None),
        ("cloud", "Kubernetes config", ".kube/config", None),
        ("cloud", "Docker registry auth", ".docker/config.json", r'"auths"\s*:\s*\{\s*"'),
        ("code", "GitHub CLI token", ".config/gh/hosts.yml", r"oauth_token"),
        ("code", "git credential store", ".git-credentials", None),
        ("code", "npm publish token", ".npmrc", r"_authToken"),
        ("code", "PyPI token", ".pypirc", r"password"),
        ("code", "Vercel CLI auth", ".local/share/com.vercel.cli/auth.json", None),
        ("wallet", "Solana keypair", ".config/solana/id.json", None),
        ("wallet", "Ethereum keystore", ".ethereum/keystore", None),
        ("wallet", "Foundry keystores", ".foundry/keystores", None),
        ("wallet", "Bitcoin Core wallets", ".bitcoin/wallets", None),
        ("wallet", "Electrum wallets", ".electrum/wallets", None),
        ("wallet", "Exodus wallet", ".config/Exodus", None),
        ("browser", "Chrome profile (cookies, sessions)", ".config/google-chrome", None),
        ("browser", "Firefox profile (cookies, sessions)", ".mozilla/firefox", None),
    ]
    found = []
    for kind, label, rel, pattern in checks:
        p = home / rel
        if not p.exists():
            continue
        if pattern and p.is_file() and not contains_token_key(p, pattern):
            continue
        found.append({"kind": kind, "store": label, "path": f"~/{rel}"})
    ssh = home / ".ssh"
    if ssh.is_dir():
        keys = [f.name for f in ssh.iterdir() if f.is_file() and f.name.startswith("id_") and not f.name.endswith(".pub")]
        if keys:
            found.append({"kind": "code", "store": f"SSH private keys ({len(keys)})", "path": "~/.ssh"})
    if project:
        envs = []
        for root, dirs, files in os.walk(project):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "dist", "build")]
            envs += [os.path.relpath(os.path.join(root, f), project) for f in files if f == ".env" or f.startswith(".env.")]
            if len(envs) > 200:
                break
        envs = [e for e in envs if not e.endswith((".example", ".sample", ".template"))]
        if envs:
            found.append({"kind": "project", "store": f".env files in project ({len(envs)})", "path": ", ".join(sorted(envs)[:5]) + (" …" if len(envs) > 5 else "")})
    return found


def report(agents, mcp, settings, creds):
    lines = ["# Agent exposure report", ""]
    lines.append(f"**{len(agents)} agent configs, {len(mcp)} MCP servers, {len(creds)} credential or wallet stores readable by this user.**")
    lines.append("Any agent allowed to run shell commands as this user can read every store listed below.")
    lines += ["", "## Agents and configs", ""]
    lines += [f"- {a['agent']}: `{a['config']}`" for a in agents] or ["- none found"]
    lines += ["", "## Risky settings", ""]
    risky = [(s["file"], n) for s in settings for n in s["notes"]]
    lines += [f"- `{f}`: {n}" for f, n in risky] or ["- none found"]
    no_hooks = [s["file"] for s in settings if not s["hook_events"] and s["file"].endswith("settings.json")]
    if no_hooks:
        lines.append(f"- no hooks configured in: {', '.join(f'`{f}`' for f in no_hooks)} (nothing can block a command before it runs)")
    lines += ["", "## MCP servers", ""]
    if mcp:
        lines += ["| source | server | launch | notes |", "|---|---|---|---|"]
        for m in mcp:
            lines.append(f"| {m['source']} | {m['server']} | `{m['launch'][:80]}` | {'; '.join(m['notes']) or '-'} |")
    else:
        lines.append("- none found")
    lines += ["", "## Credential and wallet stores (presence only, values never read out)", ""]
    if creds:
        lines += ["| kind | store | path |", "|---|---|---|"]
        lines += [f"| {c['kind']} | {c['store']} | `{c['path']}` |" for c in creds]
    else:
        lines.append("- none found")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--home", default=str(Path.home()))
    ap.add_argument("--project", default=None, help="project directory to include (.claude/, .mcp.json, .env files)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    home = Path(a.home).expanduser()
    project = Path(a.project).expanduser() if a.project else None
    agents, mcp, settings = scan_agents(home, project)
    creds = scan_credentials(home, project)
    if a.json:
        json.dump({"agents": agents, "mcp": mcp, "settings": settings, "credentials": creds}, sys.stdout, indent=1)
        print()
    else:
        sys.stdout.write(report(agents, mcp, settings, creds))


if __name__ == "__main__":
    main()
