#!/usr/bin/env python3
"""
TracePatch — Database initializer
Creates an empty schema matching the production structure.
Safe to run on a fresh/empty database only — will not overwrite existing tables.
"""
import sqlite3
import os

DB_PATH = os.environ.get('SECTRACK_DB', '/opt/sectrack/data/sectrack.db')

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    vendor TEXT,
    eng_date TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    status TEXT NOT NULL DEFAULT 'active',
    is_demo INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    engagement_id INTEGER REFERENCES engagements(id),
    source_label TEXT,
    risk TEXT NOT NULL DEFAULT 'Medium',
    status TEXT NOT NULL DEFAULT 'Open',
    is_new INTEGER DEFAULT 1,
    owner TEXT DEFAULT 'Unassigned',
    due_date TEXT,
    remediation TEXT,
    evidence TEXT,
    in_poam INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    affected_hosts TEXT,
    cves TEXT,
    is_demo INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    ts TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    notes TEXT,
    updated_by TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS evidence_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    orig_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT DEFAULT (datetime('now')),
    page_count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    display TEXT,
    role TEXT NOT NULL DEFAULT 'analyst',
    title TEXT,
    email TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    display TEXT NOT NULL,
    email TEXT,
    requested_role TEXT NOT NULL DEFAULT 'analyst',
    justification TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    src_ip TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    reviewed_by TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS patch_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requested_by TEXT NOT NULL,
    requested_at TEXT DEFAULT (datetime('now')),
    package_count INTEGER,
    packages_json TEXT,
    reboot_required INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    command_shown TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    label TEXT,
    description TEXT,
    type TEXT DEFAULT 'text',
    min_role TEXT DEFAULT 'master_admin',
    updated_by TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vuln_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    uploaded_by TEXT,
    uploaded_at TEXT DEFAULT (datetime('now')),
    finding_count INTEGER DEFAULT 0,
    new_count INTEGER DEFAULT 0,
    updated_count INTEGER DEFAULT 0,
    scope TEXT DEFAULT 'Unspecified',
    is_demo INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vuln_findings (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL UNIQUE,
    plugin_name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Medium',
    status TEXT NOT NULL DEFAULT 'Open',
    owner TEXT DEFAULT 'Unassigned',
    due_date TEXT,
    description TEXT,
    solution TEXT,
    remediation TEXT,
    evidence_notes TEXT,
    cves TEXT,
    host_count INTEGER DEFAULT 0,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    scan_count INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    archived INTEGER DEFAULT 0,
    last_scan_filename TEXT,
    last_scope TEXT,
    is_demo INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vuln_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id TEXT REFERENCES vuln_findings(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    ts TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vuln_evidence_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id TEXT NOT NULL REFERENCES vuln_findings(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    orig_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT DEFAULT (datetime('now')),
    page_count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS vuln_scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vuln_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_id TEXT NOT NULL,
    host_ip TEXT,
    hostname TEXT,
    port TEXT,
    protocol TEXT,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    scan_id INTEGER REFERENCES vuln_scans(id),
    scope TEXT DEFAULT 'Unspecified',
    UNIQUE(plugin_id, host_ip, port, scope)
);

CREATE TABLE IF NOT EXISTS vuln_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES vuln_scans(id),
    snapshot_date TEXT NOT NULL,
    open_critical INTEGER DEFAULT 0,
    open_high INTEGER DEFAULT 0,
    open_medium INTEGER DEFAULT 0,
    open_low INTEGER DEFAULT 0,
    resolved_total INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    completion_pct INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
"""

def ensure_column(conn, table, column, decl):
    """Add a column to an existing table if it's not already there. Safe to
    call on every startup — CREATE TABLE IF NOT EXISTS only helps fresh
    databases, this is what lets existing ones pick up new columns too."""
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

DEFAULT_SETTINGS = [
    ('signer_title', 'IT Security Analyst', 'Signer Title',
     'Title shown next to the signature line on POA&M reports', 'text', 'admin'),
    ('report_classification', 'Sensitive / Internal Use Only', 'Report Classification',
     'Classification label shown on report headers', 'text', 'admin'),
    ('compliance_framework', 'NIST SP 800-53 Rev 5', 'Compliance Framework',
     'Framework reference shown on POA&M reports', 'text', 'admin'),
]

def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    ensure_column(conn, 'users', 'email', 'TEXT')
    for key, value, label, desc, type_, min_role in DEFAULT_SETTINGS:
        conn.execute(
            "INSERT OR IGNORE INTO app_settings (key, value, label, description, type, min_role) "
            "VALUES (?,?,?,?,?,?)",
            (key, value, label, desc, type_, min_role)
        )
    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")

if __name__ == '__main__':
    main()
