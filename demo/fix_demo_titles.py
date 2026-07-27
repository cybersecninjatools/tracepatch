#!/usr/bin/env python3
"""One-time fix: correct titles on demo findings created via PDF upload."""
import sqlite3
import os

DB_PATH = os.environ.get('SECTRACK_DB', '/opt/sectrack/data/sectrack.db')

# Maps the CVE (unique per finding) to the correct title
TITLE_FIXES = {
    'CVE-2021-41773': 'Outdated Apache HTTP Server',
    'CVE-2022-0778': 'Unpatched OpenSSL Library',
    'CVE-2016-2183': 'Weak TLS Cipher Suites Enabled',
    'CVE-2023-27997': 'Default Credentials on Admin Panel',
}

conn = sqlite3.connect(DB_PATH)
rows = conn.execute("SELECT id, title, cves FROM findings").fetchall()
for fid, title, cves in rows:
    if cves:
        for cve, correct_title in TITLE_FIXES.items():
            if cve in cves:
                conn.execute("UPDATE findings SET title=? WHERE id=?", (correct_title, fid))
                print(f"Fixed {fid}: '{title}' -> '{correct_title}'")
    elif title == 'Risk: Low':
        conn.execute("UPDATE findings SET title=? WHERE id=?", ('Missing HTTP Security Headers', fid))
        print(f"Fixed {fid}: '{title}' -> 'Missing HTTP Security Headers'")

conn.commit()
conn.close()
