#!/usr/bin/env python3
"""Seeds remaining demo data: findings, engagement 2, vuln scan data, users, settings."""
import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get('SECTRACK_DB', '/opt/sectrack/data/sectrack.db')

conn = sqlite3.connect(DB_PATH)

# --- Second engagement ---
cur = conn.execute(
    "INSERT INTO engagements (name,type,vendor,eng_date,status) VALUES (?,?,?,?,?)",
    ('Q3 2026 Internal Network Assessment', 'Internal Assessment', 'In-house Security Team', '2026-07-15', 'active')
)
eng2_id = cur.lastrowid

# --- 5 more findings (tied to engagement 2) ---
MORE_FINDINGS = [
    {
        'title': 'SMB Signing Not Enforced', 'risk': 'High', 'status': 'Open',
        'affected_hosts': 'demo-dc-01.example.local', 'cves': 'CVE-2020-1472',
        'owner': 'Alex Chen',
        'description': 'SMB signing is not enforced on demo-dc-01.example.local, leaving it exposed to relay attacks including a known Zerologon-adjacent exploitation path.',
        'remediation': 'Enforce SMB signing via Group Policy on all domain controllers.',
    },
    {
        'title': 'Outdated Windows Server Build', 'risk': 'Medium', 'status': 'In Progress',
        'affected_hosts': 'demo-file-01.example.local', 'cves': 'CVE-2023-21554',
        'owner': 'Jordan Reyes',
        'description': 'demo-file-01.example.local is running an outdated Windows Server build missing several months of security patches, including a fix for a Message Queuing RCE.',
        'remediation': 'Apply latest cumulative update and enable automatic patching.',
    },
    {
        'title': 'Unencrypted Internal Traffic (Telnet)', 'risk': 'Medium', 'status': 'Open',
        'affected_hosts': 'demo-switch-02.example.local', 'cves': '',
        'owner': 'Unassigned',
        'description': 'Network switch management interface at demo-switch-02.example.local accepts Telnet connections, transmitting admin credentials in cleartext.',
        'remediation': 'Disable Telnet; enforce SSH-only management access.',
    },
    {
        'title': 'Excessive Local Admin Rights', 'risk': 'Medium', 'status': 'Resolved',
        'affected_hosts': 'demo-ws-fleet (23 hosts)', 'cves': '',
        'owner': 'Alex Chen',
        'description': 'Audit of workstation fleet found 23 standard user accounts with unnecessary local administrator privileges.',
        'remediation': 'Local admin rights removed from all 23 accounts; LAPS deployed for break-glass access.',
    },
    {
        'title': 'Guest Wireless Network Segmentation Gap', 'risk': 'Low', 'status': 'Open',
        'affected_hosts': 'demo-wifi-guest', 'cves': '',
        'owner': 'Jordan Reyes',
        'description': 'Guest wireless VLAN was found to have limited but non-zero routability to an internal printing subnet.',
        'remediation': 'Tighten ACLs on guest VLAN to fully isolate from internal subnets.',
    },
]

def next_finding_id(conn, prefix='F'):
    row = conn.execute("SELECT id FROM findings ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return f"{prefix}-001"
    n = int(row[0].split('-')[1]) + 1
    return f"{prefix}-{n:03d}"

for f in MORE_FINDINGS:
    fid = next_finding_id(conn)
    conn.execute('''INSERT INTO findings
        (id,title,description,engagement_id,source_label,risk,status,is_new,owner,due_date,remediation,evidence,affected_hosts,cves,in_poam)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        fid, f['title'], f['description'], eng2_id, 'Internal Assessment Q3',
        f['risk'], f['status'], 1, f['owner'], '', f['remediation'], '',
        f['affected_hosts'], f['cves'], 1
    ))
    print(f"Created {fid}: {f['title']}")

# --- Vuln scan data ---
cur = conn.execute(
    "INSERT INTO vuln_scans (filename,scan_date,uploaded_by,finding_count,new_count,updated_count,scope) VALUES (?,?,?,?,?,?,?)",
    ('demo_nessus_scan_q3.csv', '2026-07-20', 'Alex Chen', 3, 3, 0, 'Internal Network')
)
scan_id = cur.lastrowid

VULN_FINDINGS = [
    {
        'plugin_id': '104631', 'plugin_name': 'Apache HTTP Server 2.4.x < 2.4.51 Multiple Vulnerabilities',
        'severity': 'Critical', 'cves': 'CVE-2021-41773', 'host_count': 2,
        'description': 'The remote web server is affected by multiple vulnerabilities in Apache HTTP Server.',
        'solution': 'Upgrade to Apache 2.4.51 or later.',
    },
    {
        'plugin_id': '157462', 'plugin_name': 'OpenSSL 1.1.1 < 1.1.1n Multiple Vulnerabilities',
        'severity': 'High', 'cves': 'CVE-2022-0778', 'host_count': 4,
        'description': 'The remote host has an OpenSSL library that is affected by a denial of service vulnerability.',
        'solution': 'Upgrade to OpenSSL 1.1.1n or later.',
    },
    {
        'plugin_id': '42873', 'plugin_name': 'SSL Medium Strength Cipher Suites Supported (SWEET32)',
        'severity': 'Medium', 'cves': 'CVE-2016-2183', 'host_count': 6,
        'description': 'The remote host supports the use of SSL ciphers that offer medium strength encryption.',
        'solution': 'Reconfigure the service to disable support for 3DES/64-bit block ciphers.',
    },
]

for i, v in enumerate(VULN_FINDINGS, start=1):
    vid = f"V-{i:03d}"
    conn.execute('''INSERT INTO vuln_findings
        (id,plugin_id,plugin_name,severity,status,owner,description,solution,cves,host_count,last_scan_filename,last_scope)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''', (
        vid, v['plugin_id'], v['plugin_name'], v['severity'], 'Open', 'Unassigned',
        v['description'], v['solution'], v['cves'], v['host_count'],
        'demo_nessus_scan_q3.csv', 'Internal Network'
    ))
    print(f"Created {vid}: {v['plugin_name']}")

conn.execute(
    "INSERT INTO vuln_scopes (name) VALUES (?)",
    ('Internal Network',)
)

# --- Real user accounts ---
USERS = [
    ('achen', 'Alex Chen', 'analyst', 'Security Analyst'),
    ('jreyes', 'Jordan Reyes', 'analyst', 'IT Security Engineer'),
]
for username, display, role, title in USERS:
    existing = conn.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO users (username,password_hash,display,role,title) VALUES (?,?,?,?,?)",
            (username, generate_password_hash('DemoPass123!'), display, role, title)
        )
        print(f"Created user: {username} ({display})")

# --- app_settings ---
SETTINGS = [
    ('org_name', 'Demo Security Corp', 'Organization Name', 'Display name shown throughout the app', 'text'),
    ('max_evidence_file_mb', '20', 'Max Evidence File Size (MB)', 'Maximum upload size for evidence files', 'number'),
]
for key, value, label, desc, type_ in SETTINGS:
    existing = conn.execute("SELECT key FROM app_settings WHERE key=?", (key,)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO app_settings (key,value,label,description,type) VALUES (?,?,?,?,?)",
            (key, value, label, desc, type_)
        )
        print(f"Set app_setting: {key} = {value}")

# --- audit_notes ---
conn.execute(
    "INSERT INTO audit_notes (notes,updated_by) VALUES (?,?)",
    ('Demo instance — all findings, hosts, and vulnerability data shown here are synthetic and generated for demonstration purposes only. No real organizational data is represented.', 'System')
)

conn.commit()
conn.close()

print("\nSeed complete.")
