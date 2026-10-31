#!/usr/bin/env python3
"""How common is risky agent setup in public repositories?

Samples public files through GitHub code search (gh CLI auth), runs the
agent-check rules on each file in a RAM-backed temp directory, deletes it, and
writes aggregate rates. File contents are never kept. Repositories with
critical or high CI findings are listed in out/triage.json for private
disclosure only; that directory is gitignored and never published.

Usage: python3 study/public_repos.py [--pages 3] [--out study/out]
"""
import argparse
import collections
import concurrent.futures
import datetime
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repo_check  # noqa: E402

CATEGORIES = {
    "claude-settings": "permissions filename:settings.json path:.claude",
    "mcp-json": "mcpServers filename:.mcp.json",
    "claude-action": "anthropics/claude-code-action path:.github/workflows",
    "codex-action": "openai/codex-action path:.github/workflows",
    "gemini-action": "run-gemini-cli path:.github/workflows",
}
IGNORED_RULES = {"no-codeowners", "skipped", "unparsed-workflow"}  # only single files are fetched, so these say nothing


def gh(args, accept=None):
    cmd = ["gh", "api", "-X", "GET"] + (["-H", f"Accept: {accept}"] if accept else []) + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:200])
    return r.stdout


def search(query, pages):
    hits, total = [], None
    for page in range(1, pages + 1):
        for attempt in range(3):
            try:
                data = json.loads(gh(["search/code", "-f", f"q={query}", "-f", "per_page=100", "-f", f"page={page}"]))
                break
            except RuntimeError as e:
                print(f"  search retry ({e})", file=sys.stderr)
                time.sleep(30)
        else:
            break
        total = data.get("total_count", total)
        items = data.get("items") or []
        hits += [(i["repository"]["full_name"], i["path"]) for i in items]
        time.sleep(7)  # code search allows 10 requests a minute
        if len(items) < 100:
            break
    return total, hits


def canonical(path):
    """Where the rules expect this file, or None when the hit is not a config or workflow."""
    name = path.rsplit("/", 1)[-1]
    if path.endswith((".claude/settings.json", ".claude/settings.local.json")):
        return ".claude/" + name
    if name == ".mcp.json":
        return ".mcp.json"
    if "/.github/workflows/" in "/" + path and name.endswith((".yml", ".yaml")):
        return ".github/workflows/" + name
    return None


def analyse(repo, path):
    try:
        text = gh([f"repos/{repo}/contents/{path}"], accept="application/vnd.github.raw")
    except (RuntimeError, subprocess.TimeoutExpired):
        return None
    with tempfile.TemporaryDirectory(dir="/dev/shm") as d:
        f = Path(d) / canonical(path)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        findings = repo_check.check(d)
    return [{"level": x["level"], "rule": x["rule"]} for x in findings if x["rule"] not in IGNORED_RULES]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=3)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "out"))
    ap.add_argument("--only", default="", help="comma-separated categories to re-sample; merged into the existing summary")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    only = [c for c in a.only.split(",") if c]
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=Path(__file__).resolve().parent, capture_output=True, text=True).stdout.strip()
    summary = {"date": datetime.date.today().isoformat(), "tool_commit": commit,
               "method": "GitHub code search sample, default branches, forks excluded", "categories": {}}
    triage = []
    if only:
        summary = json.loads((out / "summary.json").read_text())
        summary["tool_commit"] = commit
        triage = [t for t in json.loads((out / "triage.json").read_text()) if t["category"] not in only]
    for cat, query in CATEGORIES.items():
        if only and cat not in only:
            continue
        total, hits = search(query, a.pages)
        seen, unique = set(), []
        for repo, path in hits:
            if canonical(path) and (repo, path) not in seen:
                seen.add((repo, path))
                unique.append((repo, path))
        print(f"{cat}: {total} indexed, {len(unique)} sampled", file=sys.stderr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda rp: (rp, analyse(*rp)), unique))
        analysed = [(rp, f) for rp, f in results if f is not None]
        print(f"{cat}: {len(analysed)} of {len(unique)} fetched", file=sys.stderr)
        repos = {rp[0] for rp, _ in analysed}
        by_rule, by_level, rule_level = collections.Counter(), collections.Counter(), collections.Counter()
        for (repo, path), findings in analysed:
            for rule in {x["rule"] for x in findings}:
                by_rule[rule] += 1
            for rule, level in {(x["rule"], x["level"]) for x in findings}:
                rule_level[f"{rule}:{level}"] += 1
            worst = max((repo_check.LEVELS.index(x["level"]) for x in findings), default=-1)
            if worst >= 0:
                by_level[repo_check.LEVELS[worst]] += 1
            if cat.endswith("action") and worst >= repo_check.LEVELS.index("high"):
                triage.append({"category": cat, "repo": repo, "path": path, "findings": findings})
        summary["categories"][cat] = {
            "query": query, "indexed_total": total, "files_analysed": len(analysed), "repos": len(repos),
            "files_with_rule": dict(by_rule.most_common()), "files_with_rule_at_level": dict(sorted(rule_level.items())),
            "files_by_worst_level": dict(by_level),
        }
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    (out / "triage.json").write_text(json.dumps(triage, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
