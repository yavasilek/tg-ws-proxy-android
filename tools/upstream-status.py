"""List upstream network changes which still need a Rust port review."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--check", action="store_true", help="Fail if upstream network changes are pending")
    args = parser.parse_args()
    pinned = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    if args.fetch:
        subprocess.run(["git", "fetch", "--no-tags", "upstream", "main"], cwd=ROOT, check=True)
    if git("merge-base", pinned["commit"], "upstream/main") != pinned["commit"]:
        raise SystemExit("Upstream history changed; manual comparison is required")
    commits = git("log", "--reverse", "--format=%h %s", pinned["commit"] + "..upstream/main", "--", "proxy", "tests")
    print(commits or f"No network changes after {pinned['version']} ({pinned['commit'][:7]})")
    if args.check and commits:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
