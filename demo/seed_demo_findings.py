#!/usr/bin/env python3
"""Save the 5 corrected demo findings, tied to engagement_id 1."""
import sqlite3
import os

DB_PATH = os.environ.get('SECTRACK_DB', '/opt/sectrack/data/sectrack.db')

FINDINGS = [
    {
        'title': 'Outdated Apache HTTP Server',
        'description': 'The web server at demo-web-01.example.local is running Apache 2.4.49, which is vulnerable to a path traversal and remote code execution flaw. An attacker could access files outside the intended document root.',
        'risk': 'Critical', 'status': 'Open',
        'affected_hosts': 'demo-web-01.example.local', 'cves': 'CVE-2021-41773',
        'owner': 'Alex Chen', 'remediation': 'Upgrade Apache to 2.4.51 or later.',
    },
    {
        'title': 'Unpatched OpenSSL Library',
        'description': 'demo-app-02.example.local uses a version of OpenSSL affected by an infinite loop denial-of-service vulnerability in BN_mod_sqrt().',
        'risk': 'High', 'status': 'In Progress',
        'affected_hosts': 'demo-app-02.example.local', 'cves': 'CVE-2022-0778',
        'owner': 'Jordan Reyes', 'remediation': 'Patch OpenSSL to version 1.0.2ze or 1.1.1n.',
    },
    {
        'title': 'Weak TLS Cipher Suites Enabled',
        'description': 'demo-lb-01.example.local supports 3DES cipher suites, which are vulnerable to the SWEET32 birthday attack against long-lived connections.',
        'risk': 'Medium', 'status': 'Open',
        'affected_hosts': 'demo-lb-01.example.local', 'cves': 'CVE-2016-2183',
        'owner': 'Unassigned', 'remediation': 'Disable 3DES cipher suites in load balancer TLS config.',
    },
    {
        'title': 'Default Credentials on Admin Panel',
        'description': 'The management interface at demo-fw-01.example.local was found accessible with default vendor credentials still in place.',
        'risk': 'Critical', 'status': 'Resolved',
        'affected_hosts': 'demo-fw-01.example.local', 'cves': 'CVE-2023-27997',
        'owner': 'Alex Chen', 'remediation': 'Default credentials changed; MFA enabled on management interface.',
    },
    {
        'title': 'Missing HTTP Security Headers',
        'description': 'demo-web-01.example.local does not set X-Frame-Options or Content-Security-Policy headers, increasing clickjacking risk.',
        'risk': 'Low', 'status': 'Open',
        'affected_hosts': 'demo-web-01.example.local', 'cves': '',
        'owner': 'Jordan Reyes', 'remediation': 'Add security headers via Nginx config.',
    },
]

def next_finding_id(conn, prefix='F'):
    row = conn.execute("SELECT id FROM findings ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return f"{prefix}-001"
    n = int(row[0].split('-')[1]) + 1
    return f"{prefix}-{n:03d}"

conn = sqlite3.connect(DB_PATH)
for f in FINDINGS:
    fid = next_finding_id(conn)
    conn.execute('''INSERT INTO findings
        (id,title,description,engagement_id,source_label,risk,status,is_new,owner,due_date,remediation,evidence,affected_hosts,cves,in_poam)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        fid, f['title'], f['description'], 1, 'demo_pentest_report',
        f['risk'], f['status'], 1, f['owner'], '', f['remediation'], '',
        f['affected_hosts'], f['cves'], 1
    ))
    print(f"Created {fid}: {f['title']}")
conn.commit()
conn.close()
