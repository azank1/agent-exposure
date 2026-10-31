#!/usr/bin/env python3
"""Render study/out/summary.json as study/RESULTS.md: aggregate rates only, no repository names."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LABELS = {
    "claude-settings": "committed `.claude/settings.json`",
    "mcp-json": "committed `.mcp.json`",
    "claude-action": "workflows using `anthropics/claude-code-action`",
    "codex-action": "workflows using `openai/codex-action`",
    "gemini-action": "workflows using `google-github-actions/run-gemini-cli`",
}


def pct(n, d):
    return f"{100 * n / d:.1f}%" if d else "n/a"


def main(path=HERE / "out/summary.json"):
    s = json.loads(Path(path).read_text())
    lines = ["# What public repositories ship to their AI agents", "",
             f"Sample taken {s['date']} with [`public_repos.py`](public_repos.py): {s['method']}. "
             "Up to 300 code-search hits per category, each checked with the agent-check rules in [`repo_check.py`](../repo_check.py). "
             "Code search ranks by relevance, not at random, so read these as rates in a large sample, not as exact population figures. "
             "Only aggregate counts are published. Repositories with serious findings are contacted privately and are not named here.", ""]
    for cat, c in s["categories"].items():
        n = c["files_analysed"]
        lines += [f"## {LABELS.get(cat, cat)}", "",
                  f"{n} files from {c['repos']} repositories (GitHub indexes about {c['indexed_total']:,} matching files).", "",
                  "| finding | level | files | share |", "|---|---|---|---|"]
        for key, count in sorted(c["files_with_rule_at_level"].items(), key=lambda kv: -kv[1]):
            rule, level = key.rsplit(":", 1)
            lines.append(f"| {rule} | {level} | {count} | {pct(count, n)} |")
        lines.append("")
    out = HERE / "RESULTS.md"
    out.write_text("\n".join(lines))
    print(out)


if __name__ == "__main__":
    main(*sys.argv[1:])
