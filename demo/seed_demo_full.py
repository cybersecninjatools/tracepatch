#!/usr/bin/env python3
"""Seeds remaining demo data: findings, engagement 2, vuln scan data, users, settings."""
import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get('SECTRACK_DB', '/opt/sectrack/data/sectrack.db')

conn = sqlite3.connect(DB_PATH)

# --- Second engagement ---
cur = conn.execute(
    "INSERT INTO engagements (name,type,vendor,eng_date,status,is_demo) VALUES (?,?,?,?,?,1)",
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
        (id,title,description,engagement_id,source_label,risk,status,is_new,owner,due_date,remediation,evidence,affected_hosts,cves,in_poam,is_demo)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)''', (
        fid, f['title'], f['description'], eng2_id, 'Internal Assessment Q3',
        f['risk'], f['status'], 1, f['owner'], '', f['remediation'], '',
        f['affected_hosts'], f['cves'], 1
    ))
    conn.execute("INSERT INTO activity (finding_id,actor,action) VALUES (?,?,?)",
                 (fid, f['owner'] if f['owner'] != 'Unassigned' else 'System', 'Finding created'))
    if f['status'] != 'Open':
        conn.execute("INSERT INTO activity (finding_id,actor,action) VALUES (?,?,?)",
                     (fid, f['owner'] if f['owner'] != 'Unassigned' else 'System', f'Updated: status: "Open" → "{f["status"]}"'))
    print(f"Created {fid}: {f['title']}")

# --- Vuln scan data ---
cur = conn.execute(
    "INSERT INTO vuln_scans (filename,scan_date,uploaded_by,finding_count,new_count,updated_count,scope,is_demo) VALUES (?,?,?,?,?,?,?,1)",
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
        'severity': 'Medium', 'cves': 'CVE-2016-2183', 'host_count': 6, 'status': 'Patched',
        'description': 'The remote host supports the use of SSL ciphers that offer medium strength encryption.',
        'solution': 'Reconfigure the service to disable support for 3DES/64-bit block ciphers.',
    },
]
RESOLVED_STATUSES = ('Resolved', 'Patched', 'Likely Resolved', 'Risk Accepted', 'False Positive', 'Compensating Control')

for i, v in enumerate(VULN_FINDINGS, start=1):
    vid = f"V-{i:03d}"
    status = v.get('status', 'Open')
    conn.execute('''INSERT INTO vuln_findings
        (id,plugin_id,plugin_name,severity,status,owner,description,solution,cves,host_count,last_scan_filename,last_scope,is_demo)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)''', (
        vid, v['plugin_id'], v['plugin_name'], v['severity'], status, 'Unassigned',
        v['description'], v['solution'], v['cves'], v['host_count'],
        'demo_nessus_scan_q3.csv', 'Internal Network'
    ))
    for h in range(v['host_count']):
        conn.execute('''INSERT INTO vuln_hosts
            (plugin_id,host_ip,hostname,port,protocol,scan_id,scope)
            VALUES (?,?,?,?,?,?,?)''', (
            v['plugin_id'], f'10.60.{i}.{10+h}', f'demo-host-{i}-{h+1}.example.local',
            '443', 'tcp', scan_id, 'Internal Network'
        ))
    conn.execute("INSERT INTO vuln_activity (vuln_id,actor,action) VALUES (?,?,?)",
                 (vid, 'System', 'Detected in scan: demo_nessus_scan_q3.csv (scope: Internal Network)'))
    if status != 'Open':
        conn.execute("INSERT INTO vuln_activity (vuln_id,actor,action) VALUES (?,?,?)",
                     (vid, 'Alex Chen', f'Updated: status: "Open" → "{status}"'))
    print(f"Created {vid}: {v['plugin_name']}")

if not conn.execute("SELECT 1 FROM vuln_scopes WHERE name=?", ('Internal Network',)).fetchone():
    conn.execute("INSERT INTO vuln_scopes (name) VALUES (?)", ('Internal Network',))

# --- Vuln trend history ---
# Two earlier scans (snapshot points only, no re-detailed findings — this
# mirrors how the real /api/vuln/trend endpoint reads purely from
# vuln_snapshots) so the Vulnerabilities trend graph has enough history to
# render weekly/monthly on a fresh install instead of showing "not enough
# scan history yet".
TREND_SNAPSHOTS = [
    ('nessus_scan_2026_06a.csv', '2026-06-08', {
        'open_critical': 1, 'open_high': 1, 'open_medium': 1, 'open_low': 0,
        'resolved_total': 0, 'total_findings': 3, 'completion_pct': 0,
    }),
    ('nessus_scan_2026_06b.csv', '2026-06-29', {
        'open_critical': 1, 'open_high': 1, 'open_medium': 0, 'open_low': 0,
        'resolved_total': 1, 'total_findings': 3, 'completion_pct': 33,
    }),
]
for filename, scan_date, snap in TREND_SNAPSHOTS:
    hist_cur = conn.execute(
        "INSERT INTO vuln_scans (filename,scan_date,uploaded_by,finding_count,new_count,updated_count,scope,is_demo) VALUES (?,?,?,?,?,?,?,1)",
        (filename, scan_date, 'Alex Chen', snap['total_findings'], 0, snap['total_findings'], 'Internal Network')
    )
    conn.execute(
        "INSERT INTO vuln_snapshots (scan_id,snapshot_date,open_critical,open_high,open_medium,open_low,resolved_total,total_findings,completion_pct) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (hist_cur.lastrowid, scan_date, snap['open_critical'], snap['open_high'], snap['open_medium'], snap['open_low'],
         snap['resolved_total'], snap['total_findings'], snap['completion_pct'])
    )
    print(f"Created trend snapshot for {scan_date}")

# Snapshot for the current scan, computed from VULN_FINDINGS so it always
# matches the actually-seeded state above.
final_open_by_sev = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
final_resolved = 0
for v in VULN_FINDINGS:
    status = v.get('status', 'Open')
    if status in RESOLVED_STATUSES:
        final_resolved += 1
    elif v['severity'] in final_open_by_sev:
        final_open_by_sev[v['severity']] += 1
final_total = len(VULN_FINDINGS)
final_pct = round(final_resolved / final_total * 100) if final_total else 0
conn.execute(
    "INSERT INTO vuln_snapshots (scan_id,snapshot_date,open_critical,open_high,open_medium,open_low,resolved_total,total_findings,completion_pct) "
    "VALUES (?,?,?,?,?,?,?,?,?)",
    (scan_id, '2026-07-20', final_open_by_sev['Critical'], final_open_by_sev['High'],
     final_open_by_sev['Medium'], final_open_by_sev['Low'], final_resolved, final_total, final_pct)
)
print("Created trend snapshot for current scan")

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
    ('demo_data_visible', 'true', 'Show demo data',
     'When enabled, synthetic demo data is shown alongside real data. Turns off automatically the first '
     'time a real (non-demo) finding is created.', 'bool'),
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
