#!/usr/bin/env python3
"""
TracePatch — Changelog entry writer
Appends a single entry to CHANGELOG.json at the repo root. Non-interactive —
intended to be invoked with explicit flags (e.g. by Claude when it judges a
commit to be user-facing), not run by hand.

Usage: python3 tools/add_changelog_entry.py --type {add,fix,remove} --text "..." [--commit HASH] [--date YYYY-MM-DD]
If --commit/--date are omitted they default to the current HEAD's short hash and commit date.
"""
import argparse
import json
import subprocess
from pathlib import Path

CHANGELOG_PATH = Path(__file__).resolve().parent.parent / 'CHANGELOG.json'


def git(*args):
    return subprocess.run(['git', *args], capture_output=True, text=True, check=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--type', required=True, choices=['add', 'fix', 'remove'])
    parser.add_argument('--text', required=True)
    parser.add_argument('--commit', default=None, help="defaults to current HEAD's short hash")
    parser.add_argument('--date', default=None, help="defaults to current HEAD's commit date (YYYY-MM-DD)")
    args = parser.parse_args()

    commit = args.commit or git('rev-parse', '--short', 'HEAD')
    date = args.date or git('show', '-s', '--format=%cs', 'HEAD')

    entries = json.loads(CHANGELOG_PATH.read_text()) if CHANGELOG_PATH.exists() else []
    entries.append({
        'commit': commit,
        'date': date,
        'changes': [{'type': args.type, 'text': args.text}],
    })
    CHANGELOG_PATH.write_text(json.dumps(entries, indent=2) + '\n')
    print(f"Added {args.type} entry for {commit} ({date}) to {CHANGELOG_PATH}")


if __name__ == '__main__':
    main()
