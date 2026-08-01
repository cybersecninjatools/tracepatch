#!/usr/bin/env python3
"""
TracePatch — First admin user creator / break-glass password reset
Run once after init_db.py to create the initial login. Also doubles as the
recovery path when a master admin forgets their password and there's no
other admin left to reset it for them via the Users page — see SETUP.md.

Usage: python3 create_admin.py <username> <password> [display_name]
       python3 create_admin.py --reset <username> <new_password>
"""
import sqlite3
import os
import sys
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get('SECTRACK_DB', '/opt/sectrack/data/sectrack.db')

def main():
    args = sys.argv[1:]

    if args and args[0] == '--reset':
        if len(args) < 3:
            print("Usage: python3 create_admin.py --reset <username> <new_password>")
            sys.exit(1)
        username = args[1].strip().lower()
        password = args[2]
        if len(password) < 8:
            print("Error: password must be at least 8 characters")
            sys.exit(1)
        conn = sqlite3.connect(DB_PATH)
        existing = conn.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
        if not existing:
            print(f"Error: user '{username}' not found")
            sys.exit(1)
        conn.execute("UPDATE users SET password_hash=? WHERE username=?",
                     (generate_password_hash(password), username))
        conn.commit()
        conn.close()
        print(f"Password for '{username}' reset successfully.")
        return

    if len(args) < 2:
        print("Usage: python3 create_admin.py <username> <password> [display_name]")
        print("       python3 create_admin.py --reset <username> <new_password>")
        sys.exit(1)

    username = args[0].strip().lower()
    password = args[1]
    display = args[2] if len(args) > 2 else username

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
