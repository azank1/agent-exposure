import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECRET = "ghp_THIS_VALUE_MUST_NEVER_APPEAR"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class FixtureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home, self.proj = root / "home", root / "proj"
        h, p = self.home, self.proj
        write(h / ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}}))
        write(h / ".claude.json", json.dumps({
            "mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": SECRET}}},
            "projects": {str(p): {"mcpServers": {"pinned": {"command": "npx", "args": ["-y", "some-server@1.2.3"]}}}},
        }))
        write(h / ".codex/config.toml", 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n')
        write(h / ".config/gh/hosts.yml", f"github.com:\n  oauth_token: {SECRET}\n")
        write(h / ".npmrc", "registry=https://registry.npmjs.org/\n")  # no token: must not be listed
        write(h / ".config/solana/id.json", "[1,2,3]")
        write(h / ".ssh/id_ed25519", "PRIVATE")
        write(h / ".ssh/id_ed25519.pub", "PUBLIC")
        write(p / ".env", f"STRIPE_KEY={SECRET}\n")
        write(p / ".env.example", "STRIPE_KEY=\n")
        write(p / ".claude/settings.json", json.dumps({"hooks": {"PreToolUse": []}}))

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, *extra):
        r = subprocess.run([sys.executable, "-I", str(HERE / "agent_exposure.py"), "--home", str(self.home), "--project", str(self.proj), *extra],
                           capture_output=True, text=True, check=True)
        return r.stdout

    def test_never_prints_secret_values(self):
        for out in (self.run_tool(), self.run_tool("--json")):
            self.assertNotIn(SECRET, out)

    def test_findings(self):
        d = json.loads(self.run_tool("--json"))
        notes = [n for s in d["settings"] for n in s["notes"]]
        self.assertTrue(any("bypassPermissions" in n for n in notes))
        self.assertTrue(any("Bash(*)" in n for n in notes))
        self.assertTrue(any("danger-full-access" in n for n in notes))
        gh = next(m for m in d["mcp"] if m["server"] == "gh")
        self.assertTrue(any("unpinned" in n for n in gh["notes"]))
        self.assertTrue(any("GITHUB_TOKEN" in n for n in gh["notes"]))
        pinned = next(m for m in d["mcp"] if m["server"] == "pinned")
        self.assertFalse(any("unpinned" in n for n in pinned["notes"]))
        stores = {c["store"] for c in d["credentials"]}
        self.assertIn("GitHub CLI token", stores)
        self.assertIn("Solana keypair", stores)
        self.assertIn("SSH private keys (1)", stores)
        self.assertNotIn("npm publish token", stores)
        env = next(c for c in d["credentials"] if c["kind"] == "project")
        self.assertEqual(env["store"], ".env files in project (1)")


if __name__ == "__main__":
    unittest.main()
