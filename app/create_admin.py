#!/usr/bin/env python3
"""
TracePatch — First admin user creator
Run once after init_db.py to create the initial login.
Usage: python3 create_admin.py <username> <password> [display_name]
"""
import sqlite3
import os
import sys
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get('SECTRACK_DB', '/opt/sectrack/data/sectrack.db')

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 create_admin.py <username> <password> [display_name]")
        sys.exit(1)

    username = sys.argv[1].strip().lower()
    password = sys.argv[2]
    display = sys.argv[3] if len(sys.argv) > 3 else username

    if len(password) < 8:
        print("Error: password must be at least 8 characters")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    existing = conn.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        print(f"Error: user '{username}' already exists")
        sys.exit(1)

    password_hash = generate_password_hash(password)
    conn.execute(
        "INSERT INTO users (username, password_hash, display, role, title) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, display, 'master_admin', 'Administrator')
    )
    conn.commit()
    conn.close()
    print(f"Admin user '{username}' created successfully.")

if __name__ == '__main__':
    main()
