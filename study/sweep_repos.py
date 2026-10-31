#!/usr/bin/env python3
"""Run agent-check across a list of repositories.

Each repository is fetched with a shallow, sparse git clone of only its agent
and CI configuration (no GitHub API quota is used), checked, and deleted.
Findings go to a JSON file; nothing else is kept.

Usage: python3 study/sweep_repos.py REPOS.txt OUT.json [--min-level medium]
REPOS.txt holds one owner/name per line; text after a space is kept as a label.
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repo_check  # noqa: E402

# Cone-mode directories; files at the repository root (.mcp.json, CODEOWNERS) always come along.
SPARSE = [".github", ".claude", ".gemini", ".vscode", ".cursor", ".codex", "supabase"]


def git(*args, cwd=None):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=300,
                       env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin"})
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[-200:])


def fetch(repo, dest):
    git("clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout", f"https://github.com/{repo}.git", dest)
    git("sparse-checkout", "set", "--cone", *SPARSE, cwd=dest)
    git("checkout", "--quiet", cwd=dest)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=dest, capture_output=True, text=True).stdout.strip()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("repos")
    ap.add_argument("out")
    ap.add_argument("--min-level", default="medium", choices=repo_check.LEVELS)
    ap.add_argument("--tmp", default="/dev/shm", help="directory for the temporary clones (RAM by default)")
    a = ap.parse_args(argv)
    floor = repo_check.LEVELS.index(a.min_level)
    entries = [line.split(None, 1) for line in Path(a.repos).read_text().splitlines() if line.strip() and not line.startswith("#")]
    results = []
    for parts in entries:
        repo, label = parts[0], (parts[1] if len(parts) > 1 else "")
        with tempfile.TemporaryDirectory(dir=a.tmp) as d:
            try:
                sha = fetch(repo, d + "/r")
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                results.append({"repo": repo, "label": label, "error": str(e)})
                print(f"{repo}: fetch failed", file=sys.stderr)
                continue
            findings = [f for f in repo_check.check(d + "/r") if repo_check.LEVELS.index(f["level"]) >= floor and f["rule"] != "skipped"]
        results.append({"repo": repo, "label": label, "commit": sha, "findings": findings})
        worst = max((f["level"] for f in findings), key=repo_check.LEVELS.index, default="-")
        print(f"{repo}: {len(findings)} findings, worst {worst}", file=sys.stderr)
    Path(a.out).write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
