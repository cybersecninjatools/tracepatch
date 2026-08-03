#!/usr/bin/env python3
"""
TracePatch - POA&M / Pen Test Remediation Tracker
Flask backend - no external API calls, all data local
"""

import sqlite3, os, json, csv, io, re, tempfile, uuid, math
from datetime import datetime, date, timedelta
from flask import Flask, request, jsonify, send_file, g, session, redirect

app = Flask(__name__, static_folder='/opt/sectrack/static', template_folder='/opt/sectrack/templates')

app.secret_key = os.environ.get('SECTRACK_SECRET')
if not app.secret_key:
    raise RuntimeError("SECTRACK_SECRET environment variable must be set — refusing to start with no secret key")

app.config['ORG_NAME'] = os.environ.get('SECTRACK_ORG_NAME', 'Your Organization')
app.config['ORG_ABBREV'] = os.environ.get('SECTRACK_ORG_ABBREV', 'ORG')



DB_PATH    = os.environ.get('SECTRACK_DB',    '/opt/sectrack/data/sectrack.db')
UPLOADS_PATH = os.environ.get('SECTRACK_UPLOADS', '/opt/sectrack/uploads')

RISK_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}

# ---------- User config helpers ----------

def get_db_user(username):
    """Look up a user from the SQLite users table. Returns dict or None."""
    db  = get_db()
    row = db.execute(
        "SELECT username, display, role, title, email FROM users WHERE username=?",
        (username,)
    ).fetchone()
    return dict(row) if row else None

def get_current_user():
    """
    Resolve the authenticated user. Priority:
      1. Flask session (new login system)
      2. X-Remote-User header from Nginx Basic Auth (legacy, during transition)
    Looks up full profile from the users table.
    """
    username = session.get('username')
    if not username:
        username = (
            request.headers.get('X-Remote-User') or
            request.headers.get('X-Forwarded-User')
        )
    if not username:
        return {'username': 'anonymous', 'display': 'Anonymous', 'role': 'none'}

    dbu = get_db_user(username)
    if dbu:
        dbu['username'] = username
        return dbu

    # Fallback: known to Nginx but not yet in users table
    return {'username': username, 'display': username, 'role': 'analyst', 'title': ''}

def require_admin(fn):
    """Decorator — returns 403 if current user is not admin or master_admin."""
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = get_current_user()
        if u.get('role') not in ('admin', 'master_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

def require_master_admin(fn):
    """Decorator — returns 403 if current user is not master_admin."""
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = get_current_user()
        if u.get('role') != 'master_admin':
            return jsonify({'error': 'Master admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

def require_login(fn):
    """Decorator — returns 401 if no authenticated session/header user."""
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = get_current_user()
        if u.get('role') == 'none':
            return jsonify({'error': 'Authentication required'}), 401
        return fn(*args, **kwargs)
    return wrapper

# ---------- DB helpers ----------

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

@app.after_request
def set_security_headers(resp):
    # Belt-and-suspenders against browsers reinterpreting an uploaded evidence
    # file's declared type (e.g. an HTML/script payload uploaded with a .png
    # extension) as something executable.
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp

def row_to_dict(row):
    return dict(row) if row else None

def next_finding_id(db):
    cur = db.execute("SELECT id FROM findings ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    if not row:
        return 'F-001'
    last = row[0]
    try:
        num = int(last.split('-')[1]) + 1
    except:
        num = 1
    return f'F-{num:03d}'

def _maybe_hide_demo_data(db):
    """If demo data is currently visible and a real (non-demo) record was just created, hide demo data automatically."""
    row = db.execute("SELECT value FROM app_settings WHERE key='demo_data_visible'").fetchone()
    if row and row['value'] == 'true':
        db.execute("UPDATE app_settings SET value='false' WHERE key='demo_data_visible'")
        db.commit()

def log_activity(db, finding_id, actor, action):
    db.execute("INSERT INTO activity (finding_id,actor,action) VALUES (?,?,?)",
               (finding_id, actor, action))

# ---------- Routes: static ----------

@app.route('/401')
def unauthorized():
    with open(os.path.join(app.template_folder, '401.html')) as f:
        return f.read().replace('{{ORG_NAME}}', app.config['ORG_NAME']), 401

@app.route('/landing')
def landing():
    with open(os.path.join(app.template_folder, 'landing.html')) as f:
        return f.read().replace('{{ORG_NAME}}', app.config['ORG_NAME'])

@app.route('/')
@app.route('/app')
def index():
    with open(os.path.join(app.template_folder, 'index.html')) as f:
        return f.read()

@app.route('/finding-report/<fid>')
def finding_report_page(fid):
    with open(os.path.join(app.template_folder, 'finding_report.html')) as f:
        return f.read().replace('{{ORG_NAME}}', app.config['ORG_NAME'])

# ---------- Routes: authentication ----------
@app.route('/login')
def login_page():
    with open(os.path.join(app.template_folder, 'login.html')) as f:
        return f.read().replace('{{ORG_NAME}}', app.config['ORG_NAME'])

def _parse_lockout_dt(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return None

def _lockout_message(seconds_remaining):
    minutes = max(1, math.ceil(seconds_remaining / 60))
    return f"Account locked due to too many failed login attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}."

def _client_ip():
    return request.headers.get('X-Real-IP') or request.remote_addr or 'unknown'

def _check_ip_lockout(db, ip):
    """Returns an error message if this IP is currently rate-limited, else None."""
    row = db.execute("SELECT lockout_until FROM login_ip_attempts WHERE ip_address=?", (ip,)).fetchone()
    if not row:
        return None
    lockout_until = _parse_lockout_dt(row['lockout_until'])
    if lockout_until and datetime.utcnow() < lockout_until:
        seconds = (lockout_until - datetime.utcnow()).total_seconds()
        minutes = max(1, math.ceil(seconds / 60))
        return f"Too many failed login attempts from this network. Try again in {minutes} minute{'s' if minutes != 1 else ''}."
    return None

def _record_ip_failure(db, ip):
    """Rolling-window failure counter per source IP, independent of username.
    Deliberately never reset by a successful login — only by the window
    expiring — so spraying many usernames from one IP can't be masked by
    slipping in one valid login. See feedback_tracepatch_ip_rate_limit memory."""
    max_attempts    = get_setting_int('ip_rate_limit_max_attempts', 20)
    window_minutes  = get_setting_int('ip_rate_limit_window_minutes', 15)
    lockout_minutes = get_setting_int('ip_rate_limit_lockout_minutes', 15)
    now = datetime.utcnow()
    row = db.execute("SELECT failed_attempts, window_start FROM login_ip_attempts WHERE ip_address=?", (ip,)).fetchone()
    window_start = _parse_lockout_dt(row['window_start']) if row else None
    if not row or not window_start or (now - window_start).total_seconds() > window_minutes * 60:
        attempts     = 1
        window_start = now
    else:
        attempts = (row['failed_attempts'] or 0) + 1
    lockout_val = (now + timedelta(minutes=lockout_minutes)).strftime('%Y-%m-%d %H:%M:%S') if attempts >= max_attempts else None
    db.execute(
        "INSERT INTO login_ip_attempts (ip_address, failed_attempts, window_start, lockout_until) VALUES (?,?,?,?) "
        "ON CONFLICT(ip_address) DO UPDATE SET failed_attempts=excluded.failed_attempts, window_start=excluded.window_start, lockout_until=excluded.lockout_until",
        (ip, attempts, window_start.strftime('%Y-%m-%d %H:%M:%S'), lockout_val)
    )
    db.commit()

@app.route('/api/login', methods=['POST'])
def api_login():
    from werkzeug.security import check_password_hash
    data     = request.json or {}
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    client_ip = _client_ip()
    db  = get_db()

    ip_block_msg = _check_ip_lockout(db, client_ip)
    if ip_block_msg:
        return jsonify({'error': ip_block_msg}), 429

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    row = db.execute(
        "SELECT username, password_hash, display, role, failed_login_attempts, lockout_until FROM users WHERE username=?",
        (username,)
    ).fetchone()
    if not row:
        _record_ip_failure(db, client_ip)
        return jsonify({'error': 'Invalid username or password'}), 401

    now = datetime.utcnow()
    lockout_until = _parse_lockout_dt(row['lockout_until'])
    if lockout_until and now < lockout_until:
        _record_ip_failure(db, client_ip)
        return jsonify({'error': _lockout_message((lockout_until - now).total_seconds())}), 403

    if not check_password_hash(row['password_hash'], password):
        max_attempts    = get_setting_int('max_login_attempts', 3)
        lockout_minutes = get_setting_int('lockout_duration_minutes', 5)
        attempts = (row['failed_login_attempts'] or 0) + 1
        if attempts >= max_attempts:
            new_lockout = now + timedelta(minutes=lockout_minutes)
            db.execute("UPDATE users SET failed_login_attempts=?, lockout_until=? WHERE username=?",
                       (attempts, new_lockout.strftime('%Y-%m-%d %H:%M:%S'), username))
            db.commit()
            _record_ip_failure(db, client_ip)
            return jsonify({'error': _lockout_message(lockout_minutes * 60)}), 403
        db.execute("UPDATE users SET failed_login_attempts=? WHERE username=?", (attempts, username))
        db.commit()
        _record_ip_failure(db, client_ip)
        return jsonify({'error': 'Invalid username or password'}), 401

    db.execute("UPDATE users SET failed_login_attempts=0, lockout_until=NULL WHERE username=?", (username,))
    db.commit()
    session.permanent = True
    session['username'] = username
    return jsonify({'ok': True, 'display': row['display'], 'role': row['role']})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/change_password', methods=['POST'])
@require_login
def api_change_password():
    from werkzeug.security import check_password_hash, generate_password_hash
    data    = request.json or {}
    current = data.get('current_password') or ''
    new_pw  = data.get('new_password') or ''
    if len(new_pw) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400
    u   = get_current_user()
    db  = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE username=?", (u['username'],)).fetchone()
    if not row or not check_password_hash(row['password_hash'], current):
        return jsonify({'error': 'Current password is incorrect'}), 401
    db.execute("UPDATE users SET password_hash=? WHERE username=?",
               (generate_password_hash(new_pw), u['username']))
    db.commit()
    return jsonify({'ok': True})

# ---------- Routes: current user ----------
@app.route('/api/me', methods=['GET'])
def me():
    return jsonify(get_current_user())

# ---------- App settings helper ----------
_settings_cache = {}
_settings_cache_time = 0

def get_setting(key, default=None):
    """Read a setting from the database with a 60-second in-memory cache."""
    import time
    global _settings_cache, _settings_cache_time
    now = time.time()
    if now - _settings_cache_time > 60:
        try:
            db = get_db()
            demo_visible = db.execute("SELECT value FROM app_settings WHERE key='demo_data_visible'").fetchone()
            demo_filter = "" if (demo_visible and demo_visible['value'] == 'true') else " AND is_demo=0"            
            rows = db.execute("SELECT key, value FROM app_settings").fetchall()
            _settings_cache = {r['key']: r['value'] for r in rows}
            _settings_cache_time = now
        except Exception:
            pass
    return _settings_cache.get(key, default)

def get_setting_int(key, default=0):
    try:
        return int(get_setting(key, default))
    except (ValueError, TypeError):
        return default

def get_setting_bool(key, default=False):
    val = get_setting(key, 'false')
    return str(val).lower() in ('true', '1', 'yes')

DUE_DATE_DAYS_SETTING = {
    'Critical': 'due_date_days_critical',
    'High':     'due_date_days_high',
    'Medium':   'due_date_days_medium',
    'Low':      'due_date_days_low',
}

def auto_due_date(risk):
    """Auto-calculate a due date from today based on risk, using the
    per-risk due_date_days_* settings. Informational (and unknown) risk
    levels are never auto-dated."""
    setting_key = DUE_DATE_DAYS_SETTING.get(risk)
    if not setting_key:
        return ''
    days = get_setting_int(setting_key, 0)
    if days <= 0:
        return ''
    return str(date.today() + timedelta(days=days))

# ---------- Routes: settings ----------
@app.route('/api/settings', methods=['GET'])
@require_admin
def get_settings():
    db   = get_db()
    rows = db.execute("SELECT * FROM app_settings ORDER BY min_role, key").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/settings/<key>', methods=['PUT'])
@require_admin
def update_setting(key):
    global _settings_cache_time
    actor = get_current_user()
    data  = request.json or {}
    value = str(data.get('value', '')).strip()
    db    = get_db()
    row   = db.execute("SELECT * FROM app_settings WHERE key=?", (key,)).fetchone()
    if not row:
        return jsonify({'error': 'Unknown setting'}), 404
    if row['min_role'] == 'master_admin' and actor.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can change this setting'}), 403
    db.execute(
        "UPDATE app_settings SET value=?, updated_by=?, updated_at=datetime('now') WHERE key=?",
        (value, actor.get('display', actor.get('username')), key)
    )
    db.commit()
    _settings_cache_time = 0  # Invalidate cache immediately
    return jsonify({'ok': True, 'key': key, 'value': value})

# ---------- Routes: patch management ----------
PATCH_STATUS_PATH = '/opt/sectrack/patch-mgmt/patch_status.json'

@app.route('/api/patch-status/refresh', methods=['POST'])
@require_admin
def refresh_patch_status():
    import subprocess
    try:
        result = subprocess.run(
            ['sudo', '-n', '/opt/sectrack/patch-mgmt/check_patches.sh'],
            capture_output=True, timeout=120, text=True
        )
        if result.returncode != 0:
            return jsonify({'error': f'Check failed: {result.stderr[:300]}'}), 500
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Patch check timed out after 120 seconds'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    if not os.path.exists(PATCH_STATUS_PATH):
        return jsonify({'error': 'Check completed but no status file was produced'}), 500
    with open(PATCH_STATUS_PATH) as f:
        return jsonify(json.load(f))


@app.route('/api/patch-status', methods=['GET'])
@require_admin
def get_patch_status():
    if not os.path.exists(PATCH_STATUS_PATH):
        return jsonify({'checked_at': None, 'package_count': 0, 'reboot_required': False, 'packages': []})
    try:
        with open(PATCH_STATUS_PATH) as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': f'Could not read patch status: {str(e)}'}), 500

@app.route('/api/patch-approvals', methods=['GET'])
@require_admin
def list_patch_approvals():
    db   = get_db()
    rows = db.execute(
        "SELECT * FROM patch_approvals ORDER BY requested_at DESC LIMIT 50"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/patch-approvals', methods=['POST'])
@require_admin
def create_patch_approval():
    actor = get_current_user()
    if actor.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can approve patches'}), 403

    if not os.path.exists(PATCH_STATUS_PATH):
        return jsonify({'error': 'No patch status data available yet'}), 400
    with open(PATCH_STATUS_PATH) as f:
        status = json.load(f)

    packages = status.get('packages', [])
    if not packages:
        return jsonify({'error': 'No pending packages to approve'}), 400

    reboot_required = status.get('reboot_required', False)
    latest_release  = status.get('latest_release', '')

    db = get_db()
    db.execute(
        "INSERT INTO patch_approvals (requested_by,package_count,packages_json,reboot_required,status) VALUES (?,?,?,?,?)",
        (actor.get('display', actor.get('username')), len(packages), json.dumps(packages),
         1 if reboot_required else 0, 'approved_dry_run')
    )
    db.commit()
    return jsonify({'ok': True, 'package_count': len(packages), 'reboot_required': reboot_required, 'latest_release': latest_release})

    return jsonify(get_current_user())

# ---------- Global auth guard ----------
PUBLIC_PATHS = {'/login', '/api/login', '/landing', '/401', '/logged-out', '/request-access', '/api/request-access'}

@app.before_request
def enforce_login():
    import time
    p = request.path
    if p in PUBLIC_PATHS:
        return None

    u = get_current_user()
    if u.get('role') == 'none':
        if p.startswith('/api/'):
            return jsonify({'error': 'Authentication required'}), 401
        return redirect('/login')

    # Idle session timeout enforcement
    timeout_mins = get_setting_int('session_timeout_minutes', 60)
    timeout_secs = timeout_mins * 60
    now = time.time()
    last_active = session.get('last_active', now)

    if now - last_active > timeout_secs:
        session.clear()
        if p.startswith('/api/'):
            return jsonify({'error': 'Session expired', 'expired': True}), 401
        return redirect('/login')

    # Reset idle timer on every request
    session['last_active'] = now
    session.modified = True
    return None


# ---------- Routes: user management (admin only) ----------
@app.route('/api/users', methods=['GET'])
@require_admin
def list_users():
    db   = get_db()
    rows = db.execute(
        "SELECT username, display, role, title, email FROM users ORDER BY username"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

USERNAME_PAT = re.compile(r'^[a-z0-9._-]{3,32}$')
ALL_ROLES    = ('master_admin', 'admin', 'analyst', 'auditor')
ELEVATED_ROLES = ('admin', 'master_admin')

@app.route('/api/users', methods=['POST'])
@require_admin
def create_user():
    from werkzeug.security import generate_password_hash
    actor    = get_current_user()
    data     = request.json or {}
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    display  = (data.get('display') or '').strip()[:80]
    title    = (data.get('title') or '').strip()[:80]
    role     = data.get('role', 'analyst')
    email    = (data.get('email') or '').strip()[:120]

    if not USERNAME_PAT.match(username):
        return jsonify({'error': 'Username must be 3-32 chars: lowercase letters, numbers, dots, dashes, underscores only'}), 400
    if not display:
        return jsonify({'error': 'Display name required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if role not in ALL_ROLES:
        return jsonify({'error': 'Invalid role'}), 400
    if role in ELEVATED_ROLES and actor.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can assign admin or master admin roles'}), 403
    if email and not EMAIL_PAT.match(email):
        return jsonify({'error': 'Invalid email format'}), 400

    db = get_db()
    exists = db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if exists:
        return jsonify({'error': 'User already exists'}), 409
    db.execute(
        "INSERT INTO users (username,password_hash,display,role,title,email) VALUES (?,?,?,?,?,?)",
        (username, generate_password_hash(password), display, role, title, email)
    )
    db.commit()
    return jsonify({'ok': True, 'username': username}), 201

@app.route('/api/users/<username>', methods=['PUT'])
@require_admin
def update_user(username):
    from werkzeug.security import generate_password_hash
    actor = get_current_user()
    data  = request.json or {}
    db    = get_db()
    row   = db.execute("SELECT username, role FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({'error': 'User not found'}), 404

    if 'role' in data:
        new_role = data['role']
        if new_role not in ALL_ROLES:
            return jsonify({'error': 'Invalid role'}), 400
        target_is_elevated = new_role in ELEVATED_ROLES or row['role'] in ELEVATED_ROLES
        if target_is_elevated and actor.get('role') != 'master_admin':
            return jsonify({'error': 'Only a master admin can assign or change admin/master admin roles'}), 403

    if 'email' in data:
        email = (data['email'] or '').strip()[:120]
        if email and not EMAIL_PAT.match(email):
            return jsonify({'error': 'Invalid email format'}), 400

    fields, vals = [], []
    if 'display' in data: fields.append('display=?'); vals.append((data['display'] or '').strip()[:80])
    if 'role'    in data: fields.append('role=?');    vals.append(data['role'])
    if 'title'   in data: fields.append('title=?');   vals.append((data['title'] or '').strip()[:80])
    if 'email'   in data: fields.append('email=?');   vals.append((data['email'] or '').strip()[:120])
    if data.get('password'):
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        fields.append('password_hash=?')
        vals.append(generate_password_hash(data['password']))
    if fields:
        vals.append(username)
        db.execute(f"UPDATE users SET {', '.join(fields)} WHERE username=?", vals)
        db.commit()
    return jsonify({'ok': True})
@app.route('/api/users/<username>', methods=['DELETE'])
@require_admin
def delete_user(username):
    me  = get_current_user()
    if me['username'] == username:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    db  = get_db()
    row = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({'error': 'User not found'}), 404
    if row['role'] in ELEVATED_ROLES and me.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can remove an admin or master admin account'}), 403
    db.execute("DELETE FROM users WHERE username=?", (username,))
    db.commit()
    return jsonify({'ok': True})

# ---------- Routes: access requests ----------
JUSTIFICATION_MAX = 500
EMAIL_PAT = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,24}$')

def _clean_text(s, maxlen):
    if not s:
        return ''
    s = str(s)[:maxlen]
    # Strip control characters (defense against injection/log-poisoning)
    s = ''.join(c for c in s if c.isprintable() or c in ('\n', '\t'))
    return s.strip()

@app.route('/request-access')
def request_access_page():
    with open(os.path.join(app.template_folder, 'request_access.html')) as f:
        return f.read().replace('{{ORG_NAME}}', app.config['ORG_NAME'])

@app.route('/api/request-access', methods=['POST'])
def submit_access_request():
    data = request.json or {}

    username = (data.get('username') or '').strip().lower()
    display  = _clean_text(data.get('display'), 80)
    email    = _clean_text(data.get('email'), 120)
    role     = data.get('requested_role', 'analyst')
    justification = _clean_text(data.get('justification'), JUSTIFICATION_MAX)
    src_ip   = request.headers.get('X-Real-IP') or request.remote_addr or 'unknown'

    if not USERNAME_PAT.match(username):
        return jsonify({'error': 'Username must be 3-32 chars: lowercase letters, numbers, dots, dashes, underscores only'}), 400
    if not display:
        return jsonify({'error': 'Display name required'}), 400
    if email and not EMAIL_PAT.match(email):
        return jsonify({'error': 'Invalid email format'}), 400
    if role not in ('analyst', 'auditor'):
        # Requesters can only self-select non-elevated roles; admin/master_admin must be granted, never requested
        role = 'analyst'

    db = get_db()

    # Reject if username already exists as an active user
    if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return jsonify({'error': 'That username is already taken'}), 409

    # Rate limit: cap pending requests per source IP
    pending_count = db.execute(
        "SELECT COUNT(*) FROM access_requests WHERE src_ip=? AND status='pending'", (src_ip,)
    ).fetchone()[0]
    if pending_count >= 5:
        return jsonify({'error': 'Too many pending requests from this network. Contact an administrator.'}), 429

    # Reject duplicate pending request for same username
    if db.execute("SELECT 1 FROM access_requests WHERE username=? AND status='pending'", (username,)).fetchone():
        return jsonify({'error': 'A pending request for that username already exists'}), 409

    db.execute(
        "INSERT INTO access_requests (username,display,email,requested_role,justification,src_ip) VALUES (?,?,?,?,?,?)",
        (username, display, email, role, justification, src_ip)
    )
    db.commit()
    return jsonify({'ok': True}), 201

@app.route('/api/access-requests', methods=['GET'])
@require_admin
def list_access_requests():
    db   = get_db()
    rows = db.execute(
        "SELECT * FROM access_requests WHERE status='pending' ORDER BY created_at ASC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/access-requests/<int:req_id>/approve', methods=['POST'])
@require_admin
def approve_access_request(req_id):
    from werkzeug.security import generate_password_hash
    actor = get_current_user()
    data  = request.json or {}
    db    = get_db()

    row = db.execute("SELECT * FROM access_requests WHERE id=? AND status='pending'", (req_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Request not found or already processed'}), 404

    final_role = data.get('role', row['requested_role'])
    if final_role not in ALL_ROLES:
        return jsonify({'error': 'Invalid role'}), 400
    if final_role in ELEVATED_ROLES and actor.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can approve elevated (admin/master admin) roles'}), 403

    password = data.get('password') or ''
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    if db.execute("SELECT 1 FROM users WHERE username=?", (row['username'],)).fetchone():
        return jsonify({'error': 'A user with that username already exists'}), 409

    db.execute(
        "INSERT INTO users (username,password_hash,display,role,title) VALUES (?,?,?,?,?)",
        (row['username'], generate_password_hash(password), row['display'], final_role,
         data.get('title', ''))
    )
    db.execute(
        "UPDATE access_requests SET status='approved', reviewed_by=?, reviewed_at=datetime('now') WHERE id=?",
        (actor.get('display', actor.get('username')), req_id)
    )
    db.commit()
    return jsonify({'ok': True, 'username': row['username']})

@app.route('/api/access-requests/<int:req_id>/deny', methods=['POST'])
@require_admin
def deny_access_request(req_id):
    actor = get_current_user()
    db    = get_db()
    row   = db.execute("SELECT id FROM access_requests WHERE id=? AND status='pending'", (req_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Request not found or already processed'}), 404
    db.execute(
        "UPDATE access_requests SET status='denied', reviewed_by=?, reviewed_at=datetime('now') WHERE id=?",
        (actor.get('display', actor.get('username')), req_id)
    )
    db.commit()
    return jsonify({'ok': True})


# ---------- Routes: engagements ----------

@app.route('/api/engagements', methods=['GET'])
def list_engagements():
    db     = get_db()
    status = request.args.get('status', 'active')
    demo_visible = db.execute("SELECT value FROM app_settings WHERE key='demo_data_visible'").fetchone()
    demo_join = "" if (demo_visible and demo_visible['value'] == 'true') else " AND f.is_demo=0"
    if status == 'all':
        q = f"SELECT e.*, COUNT(f.id) as finding_count FROM engagements e LEFT JOIN findings f ON f.engagement_id=e.id{demo_join} GROUP BY e.id ORDER BY e.eng_date DESC"
        rows = db.execute(q).fetchall()
    else:
        q = f"SELECT e.*, COUNT(f.id) as finding_count FROM engagements e LEFT JOIN findings f ON f.engagement_id=e.id{demo_join} WHERE e.status=? GROUP BY e.id ORDER BY e.eng_date DESC"
        rows = db.execute(q, (status,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/engagements/<int:eid>/archive', methods=['POST'])
@require_admin
def archive_engagement(eid):
    db  = get_db()
    row = db.execute("SELECT id FROM engagements WHERE id=?", (eid,)).fetchone()
    if not row:
        return jsonify({'error': 'Engagement not found'}), 404
    db.execute("UPDATE engagements SET status='archived' WHERE id=?", (eid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/engagements/<int:eid>/unarchive', methods=['POST'])
@require_admin
def unarchive_engagement(eid):
    db  = get_db()
    row = db.execute("SELECT id FROM engagements WHERE id=?", (eid,)).fetchone()
    if not row:
        return jsonify({'error': 'Engagement not found'}), 404
    db.execute("UPDATE engagements SET status='active' WHERE id=?", (eid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/engagements', methods=['POST'])

def create_engagement():
    u = get_current_user()
    if u.get('role') == 'auditor':
        return jsonify({'error': 'Auditors cannot create engagements'}), 403
    data = request.json
    db = get_db()
    cur = db.execute("INSERT INTO engagements (name,type,vendor,eng_date) VALUES (?,?,?,?)",
                     (data['name'], data['type'], data.get('vendor',''), data.get('eng_date', str(date.today()))))
    db.commit()
    return jsonify({'id': cur.lastrowid}), 201




# ---------- Routes: findings ----------

@app.route('/api/findings', methods=['GET'])
def list_findings():
    db = get_db()
    status = request.args.get('status')
    risk   = request.args.get('risk')
    poam   = request.args.get('poam')
    q = "SELECT f.*, e.name as engagement_name, e.type as engagement_type FROM findings f LEFT JOIN engagements e ON f.engagement_id=e.id WHERE 1=1"
    params = []
    demo_visible = db.execute("SELECT value FROM app_settings WHERE key='demo_data_visible'").fetchone()
    if not (demo_visible and demo_visible['value'] == 'true'):
        q += " AND f.is_demo=0"
    if status and status != 'All': q += " AND f.status=?"; params.append(status)
    if risk   and risk   != 'All': q += " AND f.risk=?";   params.append(risk)
    if poam == '1': q += " AND f.in_poam=1"
    rows = db.execute(q, params).fetchall()
    findings = [dict(r) for r in rows]
    findings.sort(key=lambda x: RISK_ORDER.get(x['risk'], 99))
    return jsonify(findings)

@app.route('/api/findings', methods=['POST'])
def create_finding():
    u = get_current_user()
    if u.get('role') == 'auditor':
        return jsonify({'error': 'Auditors cannot create findings'}), 403
    data  = request.json
    db    = get_db()
    risk     = data.get('risk','Medium')
    due_date = data.get('due_date','') or auto_due_date(risk)
    if risk in ('Critical', 'High') and not due_date and get_setting_bool('require_due_date_high_risk', False):
        return jsonify({'error': 'A due date is required for Critical and High risk findings.'}), 400
    fid   = next_finding_id(db)
    actor = get_current_user().get('display', data.get('actor', 'System'))
    db.execute('''INSERT INTO findings (id,title,description,engagement_id,source_label,risk,status,is_new,owner,due_date,remediation,evidence,affected_hosts,cves,in_poam)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        fid, data['title'], data.get('description',''),
        data.get('engagement_id'), data.get('source_label',''),
        risk, data.get('status','Open'),
        1 if data.get('is_new', True) else 0,
        data.get('owner') or get_setting('default_finding_owner', 'Unassigned'), due_date,
        data.get('remediation',''), data.get('evidence',''),
        data.get('affected_hosts',''), data.get('cves',''),
        1 if data.get('in_poam', False) else 0
    ))
    log_activity(db, fid, actor, 'Finding created')
    db.commit()
    _maybe_hide_demo_data(db)
    return jsonify({'id': fid}), 201


@app.route('/api/findings/<fid>', methods=['GET'])
def get_finding(fid):
    db  = get_db()
    row = db.execute("SELECT f.*, e.name as engagement_name FROM findings f LEFT JOIN engagements e ON f.engagement_id=e.id WHERE f.id=?", (fid,)).fetchone()
    if not row: return jsonify({'error': 'Not found'}), 404
    f    = dict(row)
    hist = db.execute("SELECT * FROM activity WHERE finding_id=? ORDER BY ts ASC", (fid,)).fetchall()
    f['history'] = [dict(h) for h in hist]
    return jsonify(f)

@app.route('/api/findings/<fid>', methods=['PUT'])
def update_finding(fid):
    u = get_current_user()
    if u.get('role') == 'auditor':
        return jsonify({'error': 'Auditors cannot edit findings'}), 403
    data  = request.json
    db    = get_db()
    row   = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row: return jsonify({'error': 'Not found'}), 404
    old   = dict(row)
    actor = get_current_user().get('display', data.pop('actor', 'System'))
    # Check require_evidence_resolved setting
    if data.get('status') == 'Resolved' and get_setting_bool('require_evidence_resolved', False):
        ev_count = db.execute("SELECT COUNT(*) FROM evidence_files WHERE finding_id=?", (fid,)).fetchone()[0]
        if ev_count == 0:
            return jsonify({'error': 'Evidence is required before marking a finding as Resolved. Please upload at least one evidence file first.'}), 400
    # Check require_due_date_high_risk setting against the resulting (merged) state
    effective_risk     = data.get('risk', old.get('risk'))
    effective_due_date = data.get('due_date', old.get('due_date'))
    if effective_risk in ('Critical', 'High') and not effective_due_date and get_setting_bool('require_due_date_high_risk', False):
        return jsonify({'error': 'A due date is required for Critical and High risk findings.'}), 400
    data.pop('actor', None)
    fields    = ['title','description','risk','status','is_new','owner','due_date','remediation','evidence','in_poam']
    long_fields = ('description', 'remediation', 'evidence', 'title')
    changes   = []
    for field in fields:
        if field in data:
            old_val = old.get(field)
            new_val = data[field]
            if str(old_val) != str(new_val):
                if field in long_fields:
                    old_len = len(str(old_val or ''))
                    new_len = len(str(new_val or ''))
                    changes.append(f'{field} edited ({old_len} → {new_len} characters)')
                else:
                    changes.append(f'{field}: "{old_val}" → "{new_val}"')
    if changes:
        set_clause = ', '.join([f'{f}=?' for f in fields if f in data])
        vals = [data[f] for f in fields if f in data]
        vals.append(str(datetime.now()))
        vals.append(fid)
        db.execute(f"UPDATE findings SET {set_clause}, updated_at=? WHERE id=?", vals)
        for c in changes:
            log_activity(db, fid, actor, f'Updated: {c}')
    db.commit()
    return jsonify({'ok': True})
@app.route('/api/findings/<fid>', methods=['DELETE'])
def delete_finding(fid):
    u    = get_current_user()
    role = u.get('role')
    allow_analyst = get_setting_bool('allow_analyst_delete', False)
    if role == 'auditor':
        return jsonify({'error': 'Auditors cannot delete findings'}), 403
    if role == 'analyst' and not allow_analyst:
        return jsonify({'error': 'Analysts are not permitted to delete findings'}), 403
    db = get_db()

    row = db.execute("SELECT id, is_demo FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        return jsonify({'error': 'Finding not found'}), 404
    if row['is_demo']:
        return jsonify({'error': 'This is demo data and cannot be deleted. Go to Settings and turn off "Show demo data" to hide it instead.'}), 403

    ev_rows = db.execute("SELECT filename, mime_type FROM evidence_files WHERE finding_id=?", (fid,)).fetchall()
    for ev in ev_rows:
        file_path = os.path.join(UPLOADS_PATH, fid, ev['filename'])
        try:
            os.unlink(file_path)
        except FileNotFoundError:
            pass
        if ev['mime_type'] == 'application/pdf':
            base_id  = os.path.splitext(ev['filename'])[0]
            dest_dir = os.path.join(UPLOADS_PATH, fid)
            try:
                for fn in os.listdir(dest_dir):
                    if fn.startswith(f"{base_id}-page"):
                        os.unlink(os.path.join(dest_dir, fn))
            except FileNotFoundError:
                pass
    try:
        os.rmdir(os.path.join(UPLOADS_PATH, fid))
    except (FileNotFoundError, OSError):
        pass

    db.execute("DELETE FROM evidence_files WHERE finding_id=?", (fid,))
    db.execute("DELETE FROM activity WHERE finding_id=?", (fid,))
    db.execute("DELETE FROM findings WHERE id=?", (fid,))
    db.commit()
    return jsonify({'ok': True})
    return jsonify({'ok': True})

# ---------- Routes: activity ----------

@app.route('/api/activity', methods=['GET'])
def recent_activity():
    db   = get_db()
    rows = db.execute("SELECT a.*, f.title as finding_title FROM activity a LEFT JOIN findings f ON a.finding_id=f.id ORDER BY a.ts DESC LIMIT 50").fetchall()
    return jsonify([dict(r) for r in rows])

# ---------- Routes: export ----------

@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    db        = get_db()
    poam_only = request.args.get('poam') == '1'
    q         = "SELECT f.*, e.name as engagement_name FROM findings f LEFT JOIN engagements e ON f.engagement_id=e.id"
    if poam_only: q += " WHERE f.in_poam=1"
    rows   = db.execute(q).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID','Title','Risk','Status','New/Existing','Owner','Due Date','Source','In POA&M','Evidence','Remediation','Description'])
    for r in rows:
        writer.writerow([
            r['id'], r['title'], r['risk'], r['status'],
            'New' if r['is_new'] else 'Existing',
            r['owner'], r['due_date'], r['engagement_name'] or r['source_label'],
            'Yes' if r['in_poam'] else 'No',
            r['evidence'] or '', r['remediation'] or '', r['description'] or ''
        ])
    output.seek(0)
    fname = f"{app.config['ORG_ABBREV']}_POAM_{'POAMOnly_' if poam_only else ''}{date.today()}.csv"
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv',
                     as_attachment=True, download_name=fname)

ALLOWED_EVIDENCE_TYPES = {
    'image/jpeg': '.jpg',
    'image/png':  '.png',
    'image/gif':  '.gif',
    'image/webp': '.webp',
    'application/pdf': '.pdf',
}
MAX_PDF_PAGES = 25
@app.route('/api/findings/<fid>/evidence_files', methods=['GET'])
def list_evidence_files(fid):
    db   = get_db()
    rows = db.execute(
        "SELECT * FROM evidence_files WHERE finding_id=? ORDER BY uploaded_at ASC", (fid,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])
@app.route('/api/findings/<fid>/evidence_files', methods=['POST'])
def upload_evidence_file(fid):
    import subprocess
    u = get_current_user()
    if u.get('role') == 'auditor':
        return jsonify({'error': 'Auditors cannot upload evidence'}), 403
    db  = get_db()
    row = db.execute("SELECT id FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        return jsonify({'error': 'Finding not found'}), 404
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f         = request.files['file']
    mime_type = f.content_type or 'application/octet-stream'
    if f.filename.lower().endswith(('.jpg', '.jpeg')):
        mime_type = 'image/jpeg'
    elif f.filename.lower().endswith('.png'):
        mime_type = 'image/png'
    elif f.filename.lower().endswith('.gif'):
        mime_type = 'image/gif'
    elif f.filename.lower().endswith('.webp'):
        mime_type = 'image/webp'
    elif f.filename.lower().endswith('.pdf'):
        mime_type = 'application/pdf'
    if mime_type not in ALLOWED_EVIDENCE_TYPES:
        return jsonify({'error': 'Only JPEG, PNG, GIF, WebP, or PDF files allowed'}), 400
    # Verify the file's actual content, not just its filename/declared type —
    # a renamed non-image (e.g. an HTML/script payload named "evidence.png")
    # must not be accepted just because the extension looks right.
    if mime_type != 'application/pdf':
        from PIL import Image
        try:
            f.seek(0)
            Image.open(f).verify()
        except Exception:
            return jsonify({'error': 'File content does not match a valid image'}), 400
        finally:
            f.seek(0)
    # Check file size against settings
    max_mb  = get_setting_int('max_evidence_file_mb', 20)
    f.seek(0, 2)  # seek to end
    file_size = f.tell()
    f.seek(0)     # reset
    if file_size > max_mb * 1024 * 1024:
        return jsonify({'error': f'File exceeds maximum size of {max_mb}MB'}), 400
    ext       = ALLOWED_EVIDENCE_TYPES[mime_type]
    base_id   = uuid.uuid4().hex
    safe_name = f"{base_id}{ext}"
    dest_dir  = os.path.join(UPLOADS_PATH, fid)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, safe_name)
    f.save(dest_path)
    page_count = 1
    if mime_type == 'application/pdf':
        page_prefix = os.path.join(dest_dir, f"{base_id}-page")
        try:
            result = subprocess.run(
                ['pdftoppm', '-png', '-r', '120', '-l', str(MAX_PDF_PAGES), dest_path, page_prefix],
                capture_output=True, timeout=60, text=True
            )
            if result.returncode != 0:
                return jsonify({'error': f'PDF conversion failed: {result.stderr[:200]}'}), 400
            # Poppler's zero-padding varies by page count (1 digit under 10, etc).
            # Normalize all generated pages to a consistent 2-digit pattern.
            raw_pages = sorted(
                [fn for fn in os.listdir(dest_dir) if fn.startswith(f"{base_id}-page")],
                key=lambda fn: int(re.search(r'-page-(\d+)\.png$', fn).group(1))
            )
            for idx, old_name in enumerate(raw_pages, start=1):
                new_name = f"{base_id}-page-{idx:02d}.png"
                if old_name != new_name:
                    os.rename(os.path.join(dest_dir, old_name), os.path.join(dest_dir, new_name))
            page_count = len(raw_pages)
            if page_count == 0:
                return jsonify({'error': 'PDF conversion produced no pages'}), 400
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'PDF conversion timed out'}), 400
        except FileNotFoundError:
            return jsonify({'error': 'pdftoppm not installed on server'}), 500

    db.execute(
        "INSERT INTO evidence_files (finding_id,filename,orig_name,mime_type,uploaded_by,page_count) VALUES (?,?,?,?,?,?)",
        (fid, safe_name, f.filename, mime_type, u.get('display', u.get('username', 'System')), page_count)
    )
    log_activity(db, fid, u.get('display', 'System'), f'Evidence uploaded: {f.filename}')
    # Auto-add to POA&M if finding is already Resolved
    finding_row = db.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
    if finding_row and finding_row['status'] == 'Resolved':
        db.execute("UPDATE findings SET in_poam=1 WHERE id=?", (fid,))
        log_activity(db, fid, 'System', 'Auto-added to POA&M (Resolved + evidence attached)')
    db.commit()
    return jsonify({'ok': True, 'filename': safe_name, 'orig_name': f.filename, 'page_count': page_count}), 201

@app.route('/api/findings/<fid>/evidence_files/<int:file_id>', methods=['DELETE'])
def delete_evidence_file(fid, file_id):
    u = get_current_user()
    if u.get('role') not in ('admin', 'master_admin'):
        return jsonify({'error': 'Only admins can delete evidence files'}), 403

    db  = get_db()
    row = db.execute(
        "SELECT * FROM evidence_files WHERE id=? AND finding_id=?", (file_id, fid)
    ).fetchone()
    if not row:
        return jsonify({'error': 'File not found'}), 404

    file_path = os.path.join(UPLOADS_PATH, fid, row['filename'])
    try:
        os.unlink(file_path)
    except FileNotFoundError:
        pass

    db.execute("DELETE FROM evidence_files WHERE id=?", (file_id,))
    log_activity(db, fid, u.get('display', 'System'), f'Evidence deleted: {row["orig_name"]}')
    # Auto-remove from POA&M if finding is Resolved and now has no evidence
    finding_row = db.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
    if finding_row and finding_row['status'] == 'Resolved':
        remaining = db.execute("SELECT COUNT(*) FROM evidence_files WHERE finding_id=?", (fid,)).fetchone()[0]
        if remaining == 0:
            db.execute("UPDATE findings SET in_poam=0 WHERE id=?", (fid,))
            log_activity(db, fid, 'System', 'Removed from POA&M (no evidence remaining)')
    db.commit()
    return jsonify({'ok': True})

@app.route('/uploads/<fid>/<filename>', methods=['GET'])
def serve_evidence_file(fid, filename):
    fid      = re.sub(r'[^A-Za-z0-9\-]', '', fid)
    filename = re.sub(r'[^A-Za-z0-9\-\.]', '', filename)
    if not fid or not filename or set(fid) == {'.'} or set(filename) == {'.'}:
        return jsonify({'error': 'Not found'}), 404
    file_path = os.path.join(UPLOADS_PATH, fid, filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'Not found'}), 404
    ext_map = {'.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png',
               '.gif':'image/gif','.webp':'image/webp','.pdf':'application/pdf'}
    ext  = os.path.splitext(filename)[1].lower()
    mime = ext_map.get(ext, 'application/octet-stream')
    return send_file(file_path, mimetype=mime)

@app.route('/api/stats', methods=['GET'])
def stats():
    db       = get_db()
    demo_visible = db.execute("SELECT value FROM app_settings WHERE key='demo_data_visible'").fetchone()
    demo_filter = "" if (demo_visible and demo_visible['value'] == 'true') else " AND is_demo=0"
    total    = db.execute(f"SELECT COUNT(*) FROM findings WHERE 1=1{demo_filter}").fetchone()[0]
    open_c   = db.execute(f"SELECT COUNT(*) FROM findings WHERE status='Open'{demo_filter}").fetchone()[0]
    inprog   = db.execute(f"SELECT COUNT(*) FROM findings WHERE status='In Progress'{demo_filter}").fetchone()[0]
    resolved = db.execute(f"SELECT COUNT(*) FROM findings WHERE status='Resolved'{demo_filter}").fetchone()[0]
    critical = db.execute(f"SELECT COUNT(*) FROM findings WHERE risk='Critical'{demo_filter}").fetchone()[0]
    poam_c   = db.execute(f"SELECT COUNT(*) FROM findings WHERE in_poam=1{demo_filter}").fetchone()[0]
    today    = str(date.today())
    COMPLETE_STATUSES = "('Resolved','Risk Accepted','False Positive')"
    overdue  = db.execute(f"SELECT COUNT(*) FROM findings WHERE status NOT IN {COMPLETE_STATUSES} AND due_date < ?{demo_filter}", (today,)).fetchone()[0]
    risk_accepted    = db.execute(f"SELECT COUNT(*) FROM findings WHERE status='Risk Accepted'{demo_filter}").fetchone()[0]
    critical_resolved = db.execute(f"SELECT COUNT(*) FROM findings WHERE risk='Critical' AND status IN {COMPLETE_STATUSES}{demo_filter}").fetchone()[0]
    high_resolved     = db.execute(f"SELECT COUNT(*) FROM findings WHERE risk='High' AND status IN {COMPLETE_STATUSES}{demo_filter}").fetchone()[0]
    actionable_total    = db.execute(f"SELECT COUNT(*) FROM findings WHERE risk!='Informational'{demo_filter}").fetchone()[0]
    actionable_resolved = db.execute(f"SELECT COUNT(*) FROM findings WHERE risk!='Informational' AND status IN {COMPLETE_STATUSES}{demo_filter}").fetchone()[0]
    completion_pct    = round(actionable_resolved / actionable_total * 100) if actionable_total else 0
    by_risk  = {}
    by_risk_resolved = {}
    for r in ['Critical','High','Medium','Low','Informational']:
        by_risk[r]         = db.execute(f"SELECT COUNT(*) FROM findings WHERE risk=?{demo_filter}", (r,)).fetchone()[0]
        by_risk_resolved[r]= db.execute(f"SELECT COUNT(*) FROM findings WHERE risk=? AND status IN {COMPLETE_STATUSES}{demo_filter}", (r,)).fetchone()[0]
    return jsonify({'total':total,'open':open_c,'in_progress':inprog,'resolved':resolved,
                    'risk_accepted':risk_accepted,'critical':critical,'critical_resolved':critical_resolved,
                    'high_resolved':high_resolved,'completion_pct':completion_pct,
                    'actionable_total':actionable_total,'actionable_resolved':actionable_resolved,
                    'poam':poam_c,'overdue':overdue,'by_risk':by_risk,'by_risk_resolved':by_risk_resolved})

@app.route('/api/audit_notes', methods=['GET'])
def get_audit_notes():
    db  = get_db()
    row = db.execute("SELECT * FROM audit_notes ORDER BY updated_at DESC LIMIT 1").fetchone()
    return jsonify(row_to_dict(row) or {'notes': ''})

@app.route('/api/audit_notes', methods=['POST'])
def save_audit_notes():
    data  = request.json
    db    = get_db()
    actor = get_current_user().get('display', 'System')
    db.execute("INSERT INTO audit_notes (notes, updated_by) VALUES (?,?)",
               (data.get('notes',''), actor))
    db.commit()
    return jsonify({'ok': True})

# ---------- Routes: PDF upload ----------



def _parse_securin_app(pdf_path):
    """
    Targeted parser for Securin application/web pen test report format.
    Findings use 2.X.X subsection headers e.g. "2.1.1 TLS Misconfigurations in ERB Main Site"
    Affected field is "Affected Endpoints:" not "Affected Host(s)"
    """
    try:
        import pdfplumber, warnings
        warnings.filterwarnings("ignore")
    except ImportError:
        return []

    import re

    severity_map = {
        "critical":"Critical","high":"High",
        "medium":"Medium","low":"Low","informational":"Informational"
    }

    section_pat  = re.compile(r"^2\.\d+\.\d+\s+(.+)$")
    severity_pat = re.compile(r"^Severity\s*[:\-]?\s*(Critical|High|Medium|Low|Informational)", re.I)
    cve_pat      = re.compile(r"CVE-\d{4}-\d+", re.I)
    url_pat      = re.compile(r"https?://[\S]+|(?:ERB|erb|MSS|mss|ESS|ess|V3|v3)[\w\-\.]*", re.I)
    skip_pat     = re.compile(
        r"^(Securin\s*\|\s*Confidential|Figure \d+|Table \d+|Section \d+|"
        r"CVSS|AV:|Evidence:|CWE:|OWASP|Appendix)",
        re.I
    )

    all_lines = []
    with pdfplumber.open(pdf_path) as pdf:
        for i, page in enumerate(pdf.pages[:100]):
            try:
                text = page.extract_text() or ""
                all_lines.extend(text.split("\n"))
            except Exception:
                continue

    findings = []
    seen     = set()
    current  = None
    state    = None

    for line in all_lines:
        line = line.strip()
        if not line:
            continue

        # Skip page footers and noise
        if skip_pat.match(line):
            continue

        # Detect finding header e.g. "2.1.1 TLS Misconfigurations in ERB Main Site"
        m = section_pat.match(line)
        if m:
            # Save previous
            if current and current.get("title") and current.get("risk") != "Unknown":
                key = current["title"].lower()[:50]
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title":          current["title"],
                        "risk":           current["risk"],
                        "description":    current["description"].strip(),
                        "remediation":    current["remediation"].strip(),
                        "cves":           ", ".join(sorted(current["cves"])),
                        "affected_hosts": ", ".join(sorted(current["affected_hosts"]))
                    })
            current = {
                "title":          m.group(1).strip()[:120],
                "risk":           "Unknown",
                "description":    "",
                "remediation":    "",
                "cves":           set(),
                "affected_hosts": set()
            }
            state = None
            continue

        if current is None:
            continue

        # Severity line
        sm = severity_pat.match(line)
        if sm:
            current["risk"] = severity_map.get(sm.group(1).lower(), "Medium")
            continue

        # Section transitions
        if re.match(r"^Affected Endpoints?\s*:", line, re.I):
            state = "hosts"
            # Grab inline endpoints on same line
            inline = re.sub(r"^Affected Endpoints?\s*:\s*", "", line, flags=re.I).strip()
            if inline and not re.match(r"^CVSS|^AV:", inline):
                current["affected_hosts"].add(inline[:80])
            continue

        if re.match(r"^Description\s*:", line, re.I):
            state = "desc"
            inline = re.sub(r"^Description\s*:\s*", "", line, flags=re.I).strip()
            if inline:
                current["description"] = inline
            continue

        if re.match(r"^(Solution|Remediation)\s*:", line, re.I):
            state = "solution"
            continue

        if re.match(r"^(Evidence|Reference|CWE|CVSS|Figure|Table)", line, re.I):
            state = None
            continue

        # Collect CVEs anywhere
        for cve in cve_pat.findall(line):
            current["cves"].add(cve.upper())

        if state == "hosts":
            # Stop at CVSS vector line
            if re.match(r"^(CVSS|AV:|\(AV:)", line, re.I):
                state = None
                continue
            # Collect endpoint paths (/, /wp-cron.php, /api/... etc)
            if re.match(r"^/", line) or re.match(r"^https?://", line, re.I):
                current["affected_hosts"].add(line.strip()[:100])
                continue
            # Also catch full URLs
            urls = url_pat.findall(line)
            for url in urls:
                current["affected_hosts"].add(url[:80])
            # Stop if line looks like description prose
            if len(line) > 80 and not line.startswith("/"):
                state = "desc"
                current["description"] += " " + line

        elif state == "desc":
            if len(current["description"]) < 600 and len(line) > 10:
                current["description"] += " " + line

        elif state == "solution":
            if len(current["remediation"]) < 600 and len(line) > 5:
                if not re.match(r"^(https?://|<https)", line, re.I):
                    current["remediation"] += " " + line

    # Catch last finding
    if current and current.get("title") and current.get("risk") != "Unknown":
        key = current["title"].lower()[:50]
        if key not in seen:
            seen.add(key)
            findings.append({
                "title":          current["title"],
                "risk":           current["risk"],
                "description":    current["description"].strip(),
                "remediation":    current["remediation"].strip(),
                "cves":           ", ".join(sorted(current["cves"])),
                "affected_hosts": ", ".join(sorted(current["affected_hosts"]))
            })

    order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Informational":4,"Unknown":5}
    findings.sort(key=lambda x: order.get(x["risk"], 5))
    return findings


def _parse_securin(pdf_path):
    """
    Targeted parser for Securin pen test report format.
    Detects numbered finding sections (2.1, 2.2 etc),
    extracts severity, affected hosts table, CVEs, description and solution.
    """
    try:
        import pdfplumber, re
    except ImportError:
        return []

    findings = []
    seen = set()

    # Securin finding header: "2.1 Full Domain Compromise..."
    section_pat = re.compile(r'^2\.\d+\s+(.+)$')
    severity_pat = re.compile(r'^Severity\s*[:\-]?\s*(Critical|High|Medium|Low|Informational)', re.I)
    cve_pat      = re.compile(r'CVE-\d{4}-\d+', re.I)
    ip_pat       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')
    host_pat     = re.compile(r'\b(?:ERB|erb)-[\w\-\.]+', re.I)

    # Skip these section headers — not actual findings
    skip_titles = re.compile(
        r'^(table of contents|introduction|objective|findings distribution|scope|'
        r'testing constraints|conclusion|attack sequence|appendix|methodology|'
        r'penetration testing|executive report|key contributors|securin triage)',
        re.I
    )

    with pdfplumber.open(pdf_path) as pdf:
        lines = []
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                lines.extend(text.split('\n'))

    current = None
    state   = None  # 'desc', 'hosts', 'solution'
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Detect new finding section header
        m = section_pat.match(line)
        if m:
            title = m.group(1).strip()
            # Skip non-finding sections
            if not skip_titles.match(title):
                # Save previous finding
                if current and current.get('title') and current.get('risk') != 'Unknown':
                    key = current['title'].lower()[:50]
                    if key not in seen:
                        seen.add(key)
                        findings.append(current)
                # Start new finding
                current = {
                    'title':          title[:120],
                    'risk':           'Unknown',
                    'description':    '',
                    'remediation':    '',
                    'cves':           set(),
                    'affected_hosts': set()
                }
                state = 'desc'
                # Extract CVEs from title
                for cve in cve_pat.findall(title):
                    current['cves'].add(cve.upper())
            i += 1
            continue

        if current is None:
            i += 1
            continue

        # Detect severity
        sm = severity_pat.match(line)
        if sm:
            current['risk'] = sm.group(1).capitalize()
            i += 1
            continue

        # Detect affected hosts section
        if re.match(r'^Affected Host', line, re.I):
            state = 'hosts'
            i += 1
            continue

        # Stop collecting at page footers and appendix markers
        if re.match(r'^(Securin\s*\|\s*Confidential|Section \d+\.0|Appendix)', line, re.I):
            i += 1
            continue

        # Detect solution/evidence sections
        if re.match(r'^(?:Solution|Remediation|Fix|Recommendation)', line, re.I):
            state = 'solution'
            i += 1
            continue

        # Description label — start collecting description
        if re.match(r'^Description\s*:', line, re.I):
            state = 'desc'
            # Grab inline text after "Description:" label if present
            inline = re.sub(r'^Description\s*:\s*', '', line, flags=re.I).strip()
            if inline and current:
                current['description'] = inline
            i += 1
            continue

        if re.match(r'^(?:Evidence|Figure \d+|Note:|CVSS)', line, re.I):
            state = 'skip'
            i += 1
            continue

        # Extract CVEs from any line
        for cve in cve_pat.findall(line):
            current['cves'].add(cve.upper())

        # Extract IPs
        ips   = ip_pat.findall(line)
        hosts = host_pat.findall(line)

        if state == 'hosts':
            for ip in ips:
                # Filter out CVSS vectors and version numbers
                parts = ip.split('.')
                if all(int(p) <= 255 for p in parts[:4] if p.isdigit()):
                    current['affected_hosts'].add(ip)
            for h in hosts:
                current['affected_hosts'].add(h)

        elif state == 'solution':
            # Stop at page footer, figure captions, or next section
            if re.match(r'^(Securin\s*\|\s*Confidential|Section \d+|Figure \d+|Appendix)', line, re.I):
                i += 1
                continue
            if len(current['remediation']) < 600 and len(line) > 10:
                current['remediation'] += (' ' + line).strip()

        elif state == 'desc':
            # Skip CVSS vectors, figure captions, page footers
            if re.match(r'^(AV:|CVSS|Figure \d+:|Securin\s*\|\s*Confidential|Section \d+\.0)', line, re.I):
                i += 1
                continue
            # Collect IPs found in description as potential hosts
            for ip in ips:
                parts = ip.split('.')
                if all(int(p) <= 255 for p in parts[:4] if p.isdigit()):
                    current['affected_hosts'].add(ip)
            for h in hosts:
                current['affected_hosts'].add(h)
            if len(current['description']) < 600 and len(line) > 15:
                current['description'] += (' ' + line).strip()

        i += 1

    # Catch last finding
    if current and current.get('title') and current.get('risk') != 'Unknown':
        key = current['title'].lower()[:50]
        if key not in seen:
            seen.add(key)
            findings.append(current)

    # Convert sets to strings
    for f in findings:
        f['cves']           = ', '.join(sorted(f['cves']))
        f['affected_hosts'] = ', '.join(sorted(f['affected_hosts']))

    # Sort by severity
    order = {'Critical':0,'High':1,'Medium':2,'Low':3,'Informational':4,'Unknown':5}
    findings.sort(key=lambda x: order.get(x['risk'], 5))

    return findings

def _parse_nodezero(pdf_path):
    """
    Targeted NodeZero / Horizon3.ai pen test report parser.
    Reads summary table for H3-YYYY-NNNN finding IDs, then collects
    affected hosts and mitigations from detail pages.
    Only reads first 20 pages to avoid font-error hangs on large PDFs.
    """
    try:
        import pdfplumber, warnings
        warnings.filterwarnings("ignore")
    except ImportError:
        return []

    import re

    severity_map = {
        "critical":"Critical","high":"High",
        "medium":"Medium","low":"Low","informational":"Informational"
    }

    h3_id_pat   = re.compile(r"H3-\d{4}-\d{4}", re.I)
    cve_pat     = re.compile(r"CVE-\d{4}-\d+", re.I)
    ip_pat      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
    host_pat    = re.compile(r"\(([^)]+\.(?:nmerb|local|aws|internal)[^)]*)\)", re.I)
    summary_pat = re.compile(
        r"^\d+\s+\d{2}/\d{2}/\d{4}.+?(H3-\d{4}-\d{4})\s+\S+\s+(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)",
        re.I
    )
    # Title extraction from summary line
    title_clean = re.compile(
        r"^\d+\s+\d{2}/\d{2}/\d{4},?\s+\d+:\d+\s+[AP]M\s+(.+?)\s+H3-\d{4}-\d{4}.+$",
        re.I
    )
    # Bullet reference uses \x00 as bullet char: "\x00. H3-2022-0015: description..."
    bullet_pat  = re.compile(
        r"^[\x00.\s]*?(H3-\d{4}-\d{4}):\s*(.+)$", re.I
    )

    all_lines = []
    with pdfplumber.open(pdf_path) as pdf:
        for i, page in enumerate(pdf.pages[:20]):
            try:
                text = page.extract_text() or ""
                all_lines.extend(text.split("\n"))
            except Exception:
                continue

    # Pass 1 — build finding map from summary table and bullet references
    finding_map = {}

    for line in all_lines:
        line = line.strip()

        # Summary table line
        m = summary_pat.match(line)
        if m:
            h3_id = m.group(1).upper()
            risk  = severity_map.get(m.group(2).lower(), "Medium")
            title = re.sub(r"^\d+\s+\d{2}/\d{2}/\d{4},?\s+\d+:\d+\s+[AP]M\s+", "", line)
            title = re.sub(r"\s+" + re.escape(h3_id) + r".+$", "", title).strip()
            # Clean title - remove leading count + date prefix
            title = re.sub(r"^\d+\s+\d{2}/\d{2}/\d{4},?\s+\d+:\d+\s+[AP]M\s+", "", title).strip()
            if h3_id not in finding_map:
                finding_map[h3_id] = {
                    "title":          title[:120] or h3_id,
                    "risk":           risk,
                    "description":    "",
                    "remediation":    "",
                    "cves":           set(),
                    "affected_hosts": set()
                }
            continue

        # Bullet reference line — fills in title if not already set
        b = bullet_pat.match(line)
        if b:
            h3_id = b.group(1).upper()
            if h3_id in finding_map and not finding_map[h3_id]["description"]:
                raw = b.group(2).strip()
                # Remove non-printable chars (\x00 bullet chars etc)
                raw = ''.join(c for c in raw if c.isprintable())
                # Stop at summary table line (date pattern)
                import re as _re
                raw = _re.sub(r'\s*\d+\s+\d{2}/\d{2}/\d{4}.+$', '', raw).strip()
                finding_map[h3_id]["description"] = raw[:400]

    # Pass 2 — collect hosts, remediation, CVEs from detail pages
    current_h3 = None
    state      = None

    for line in all_lines:
        line = line.strip()
        if not line:
            continue

        # Detect H3 section header
        h3_m = h3_id_pat.search(line)
        if h3_m:
            h3_id = h3_m.group(0).upper()
            if h3_id in finding_map:
                current_h3 = h3_id
                state      = "header"

        if current_h3 is None:
            continue

        f = finding_map[current_h3]

        # Section transitions
        if re.match(r"^Affected Assets", line, re.I):
            state = "hosts"
            continue
        if re.match(r"^(Mitigations?|Remediation|How to Fix)", line, re.I):
            state = "remediation"
            continue
        if re.match(r"^(References?|Proof|CWE|MITRE|https?://)", line, re.I):
            state = "refs"
            continue

        # CVEs anywhere
        for cve in cve_pat.findall(line):
            f["cves"].add(cve.upper())

        if state == "hosts":
            for ip in ip_pat.findall(line):
                parts = ip.split(":")[0].split(".")
                if all(p.isdigit() and int(p) <= 255 for p in parts):
                    f["affected_hosts"].add(ip)
            hm = host_pat.search(line)
            if hm:
                f["affected_hosts"].add(hm.group(1))

        elif state == "remediation":
            if len(f["remediation"]) < 600 and len(line) > 10:
                if not re.match(r"^(CWE|MITRE|https?://|Reference)", line, re.I):
                    f["remediation"] += (" " + line).strip()

        elif state == "header":
            if len(f["description"]) < 400 and len(line) > 15:
                if not re.match(r"^(H3-|Affected|Proof|Mitigat|Reference|CWE|MITRE)", line, re.I):
                    f["description"] += (" " + line).strip()

    # Build output list
    findings = []
    seen     = set()
    for h3_id, f in finding_map.items():
        key = f["title"].lower()[:50]
        if key not in seen:
            seen.add(key)
            findings.append({
                "title":          f["title"],
                "risk":           f["risk"],
                "description":    f["description"].strip(),
                "remediation":    f["remediation"].strip(),
                "cves":           ", ".join(sorted(f["cves"])),
                "affected_hosts": ", ".join(sorted(f["affected_hosts"]))
            })

    order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Informational":4}
    findings.sort(key=lambda x: order.get(x["risk"], 5))
    return findings


def _parse_nessus_csv(csv_content):
    """
    Parse Nessus CSV export.
    Nessus CSV columns: Plugin ID, CVE, CVSS v2.0 Base Score, Risk,
    Host, Protocol, Port, Name, Synopsis, Description, Solution, See Also, Plugin Output
    """
    import csv, io

    findings = []
    seen = set()

    severity_map = {
        'critical': 'Critical', 'high': 'High',
        'medium': 'Medium', 'low': 'Low', 'info': 'Informational', 'none': 'Informational'
    }

    reader = csv.DictReader(io.StringIO(csv_content))

    # Group by Plugin Name to deduplicate — collect all affected hosts per finding
    grouped = {}

    for row in reader:
        # Nessus CSV header names vary slightly — normalize
        name     = (row.get('Name') or row.get('Plugin Name') or '').strip()
        risk     = (row.get('Risk') or row.get('Severity') or 'Info').strip().lower()
        host     = (row.get('Host') or row.get('IP Address') or '').strip()
        port     = (row.get('Port') or '').strip()
        protocol = (row.get('Protocol') or '').strip()
        cve      = (row.get('CVE') or '').strip()
        desc     = (row.get('Synopsis') or row.get('Description') or '').strip()[:500]
        solution = (row.get('Solution') or '').strip()[:500]

        if not name or risk in ('none', ''):
            continue

        host_str = f"{host}:{port}" if port and port != '0' else host

        key = name.lower()[:60]
        if key not in grouped:
            grouped[key] = {
                'title':          name[:120],
                'risk':           severity_map.get(risk, 'Medium'),
                'description':    desc,
                'remediation':    solution,
                'cves':           set(),
                'affected_hosts': set()
            }

        if host_str:
            grouped[key]['affected_hosts'].add(host_str)
        if cve:
            for c in cve.split(','):
                c = c.strip()
                if c:
                    grouped[key]['cves'].add(c)

    for key, f in grouped.items():
        findings.append({
            'title':          f['title'],
            'risk':           f['risk'],
            'description':    f['description'],
            'remediation':    f['remediation'],
            'cves':           ', '.join(sorted(f['cves'])),
            'affected_hosts': ', '.join(sorted(f['affected_hosts']))
        })

    # Sort by severity
    risk_order = {'Critical':0,'High':1,'Medium':2,'Low':3,'Informational':4}
    findings.sort(key=lambda x: risk_order.get(x['risk'], 99))

    return findings[:200]

def _parse_nessus_csv_for_vuln_tracker(csv_content):
    """
    Parse Nessus CSV for the vulnerability tracker.
    Keys on Plugin ID (not name) so the same vuln across scans/hosts merges correctly.
    Returns a dict: {plugin_id: {plugin_name, severity, description, solution, cves:set, hosts:[{ip,hostname,port,protocol}]}}
    """
    import csv, io
    severity_map = {
        'critical': 'Critical', 'high': 'High',
        'medium': 'Medium', 'low': 'Low', 'info': 'Informational', 'none': 'Informational'
    }
    reader = csv.DictReader(io.StringIO(csv_content))
    grouped = {}
    for row in reader:
        plugin_id = (row.get('Plugin ID') or row.get('pluginID') or '').strip()
        name      = (row.get('Name') or row.get('Plugin Name') or '').strip()
        risk      = (row.get('Risk') or row.get('Severity') or 'Info').strip().lower()
        host      = (row.get('Host') or row.get('IP Address') or '').strip()
        hostname  = (row.get('DNS Name') or row.get('Hostname') or '').strip()
        port      = (row.get('Port') or '').strip()
        protocol  = (row.get('Protocol') or '').strip()
        cve       = (row.get('CVE') or '').strip()
        desc      = (row.get('Synopsis') or row.get('Description') or '').strip()[:1000]
        solution  = (row.get('Solution') or '').strip()[:1000]

        if not plugin_id or not name or risk == '':
            continue

        if plugin_id not in grouped:
            grouped[plugin_id] = {
                'plugin_name': name[:200],
                'severity':    severity_map.get(risk, 'Medium'),
                'description': desc,
                'solution':    solution,
                'cves':        set(),
                'hosts':       []
            }
        if cve:
            for c in cve.split(','):
                c = c.strip()
                if c:
                    grouped[plugin_id]['cves'].add(c)
        if host:
            grouped[plugin_id]['hosts'].append({
                'ip': host, 'hostname': hostname, 'port': port, 'protocol': protocol
            })

    return grouped
@app.route('/api/vuln/upload', methods=['POST'])
def upload_vuln_scan():
    u = get_current_user()
    if u.get('role') == 'auditor':
        return jsonify({'error': 'Auditors cannot upload scans'}), 403
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if not f.filename.lower().endswith('.csv'):
        return jsonify({'error': 'Only Nessus CSV exports are supported'}), 400

    scope = (request.form.get('scope') or 'Unspecified').strip()[:60]
    db = get_db()
    if not db.execute("SELECT id FROM vuln_scopes WHERE name=?", (scope,)).fetchone():
        db.execute("INSERT OR IGNORE INTO vuln_scopes (name) VALUES (?)", (scope,))

    csv_content = f.read().decode('utf-8', errors='replace')
    parsed = _parse_nessus_csv_for_vuln_tracker(csv_content)
    if not parsed:
        return jsonify({'error': 'No valid findings found in this CSV. Check the file format.'}), 400

    actor = u.get('display', u.get('username', 'System'))
    scan_date = request.form.get('scan_date', str(date.today()))
    scan_cur = db.execute(
        "INSERT INTO vuln_scans (filename, scan_date, uploaded_by, finding_count, scope) VALUES (?,?,?,?,?)",
        (f.filename, scan_date, actor, len(parsed), scope)
    )
    scan_id = scan_cur.lastrowid
    new_count = 0
    updated_count = 0
    resolved_count = 0

    for plugin_id, data in parsed.items():
        existing = db.execute("SELECT id, host_count, scan_count, status FROM vuln_findings WHERE plugin_id=?", (plugin_id,)).fetchone()
        cves_str = ', '.join(sorted(data['cves']))
        if existing:
            vuln_id = existing['id']
            update_status = ""
            prev_status = existing['status']
            # Persistent human-decision statuses are never overridden by re-detection
            PERSISTENT_STATUSES = ('Risk Accepted', 'False Positive', 'Compensating Control')
            if prev_status not in PERSISTENT_STATUSES and prev_status in ('Likely Resolved', 'Resolved', 'Patched'):
                update_status = ", status='Open'"
            db.execute(
                f"UPDATE vuln_findings SET last_seen=datetime('now'), scan_count=scan_count+1, "
                f"description=?, solution=?, cves=?, last_scan_filename=?, last_scope=?{update_status} WHERE id=?",
                (data['description'], data['solution'], cves_str, f.filename, scope, vuln_id)
            )
            if update_status:
                log_activity_vuln(db, vuln_id, 'System', f'Re-detected in scan: {f.filename} — was marked "{prev_status}" but scan shows it still exists, reverted to Open for review')
            updated_count += 1
        else:
            vuln_id = f"V-{plugin_id}"
            db.execute(
                "INSERT INTO vuln_findings (id, plugin_id, plugin_name, severity, description, solution, cves, last_scan_filename, last_scope) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (vuln_id, plugin_id, data['plugin_name'], data['severity'], data['description'], data['solution'], cves_str, f.filename, scope)
            )
            log_activity_vuln(db, vuln_id, 'System', f'Detected in scan: {f.filename} (scope: {scope})')
            new_count += 1

        # Scope-aware host reconciliation: only touch hosts previously seen in THIS scope
        # for this plugin. Hosts from other scopes are never affected by this upload.
        current_hosts = {(h['ip'], h['port']) for h in data['hosts']}
        existing_hosts_in_scope = db.execute(
            "SELECT id, host_ip, port FROM vuln_hosts WHERE plugin_id=? AND scope=?", (plugin_id, scope)
        ).fetchall()
        for eh in existing_hosts_in_scope:
            if (eh['host_ip'], eh['port']) not in current_hosts:
                db.execute("DELETE FROM vuln_hosts WHERE id=?", (eh['id'],))

        for h in data['hosts']:
            existing_host = db.execute(
                "SELECT id FROM vuln_hosts WHERE plugin_id=? AND host_ip=? AND port=? AND scope=?",
                (plugin_id, h['ip'], h['port'], scope)
            ).fetchone()
            if existing_host:
                db.execute("UPDATE vuln_hosts SET last_seen=datetime('now'), scan_id=? WHERE id=?", (scan_id, existing_host['id']))
            else:
                db.execute(
                    "INSERT INTO vuln_hosts (plugin_id, host_ip, hostname, port, protocol, scan_id, scope) VALUES (?,?,?,?,?,?,?)",
                    (plugin_id, h['ip'], h['hostname'], h['port'], h['protocol'], scan_id, scope)
                )

        # host_count reflects ALL scopes combined for this plugin
        host_count = db.execute("SELECT COUNT(*) FROM vuln_hosts WHERE plugin_id=?", (plugin_id,)).fetchone()[0]
        db.execute("UPDATE vuln_findings SET host_count=? WHERE id=?", (host_count, vuln_id))

    # Auto-resolve: only when host_count is zero across ALL scopes, not just this one
    zeroed = db.execute(
        "SELECT id, plugin_name, status FROM vuln_findings WHERE host_count=0 AND status NOT IN ('Likely Resolved','Resolved','Patched','Risk Accepted','False Positive','Compensating Control')"
    ).fetchall()
    for z in zeroed:
        db.execute("UPDATE vuln_findings SET status='Likely Resolved' WHERE id=?", (z['id'],))
        log_activity_vuln(db, z['id'], 'System', 'Auto-marked Likely Resolved — no longer detected on any host in any scope')
        resolved_count += 1


    # Capture a snapshot of current state for trend tracking
    snap_open_crit = db.execute("SELECT COUNT(*) FROM vuln_findings WHERE severity='Critical' AND status='Open' AND archived=0").fetchone()[0]
    snap_open_high = db.execute("SELECT COUNT(*) FROM vuln_findings WHERE severity='High' AND status='Open' AND archived=0").fetchone()[0]
    snap_open_med  = db.execute("SELECT COUNT(*) FROM vuln_findings WHERE severity='Medium' AND status='Open' AND archived=0").fetchone()[0]
    snap_open_low  = db.execute("SELECT COUNT(*) FROM vuln_findings WHERE severity='Low' AND status='Open' AND archived=0").fetchone()[0]
    snap_actionable_total = db.execute("SELECT COUNT(*) FROM vuln_findings WHERE severity!='Informational' AND archived=0").fetchone()[0]
    snap_actionable_resolved = db.execute(
        "SELECT COUNT(*) FROM vuln_findings WHERE severity!='Informational' AND status IN ('Resolved','Patched','Likely Resolved','Risk Accepted','False Positive','Compensating Control') AND archived=0"
    ).fetchone()[0]
    snap_completion = round(snap_actionable_resolved / snap_actionable_total * 100) if snap_actionable_total else 0
    db.execute(
        "INSERT INTO vuln_snapshots (scan_id, snapshot_date, open_critical, open_high, open_medium, open_low, resolved_total, total_findings, completion_pct) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (scan_id, scan_date, snap_open_crit, snap_open_high, snap_open_med, snap_open_low,
         snap_actionable_resolved, snap_actionable_total, snap_completion)
    )
    db.execute("UPDATE vuln_scans SET new_count=?, updated_count=? WHERE id=?", (new_count, updated_count, scan_id))
    db.commit()
    _maybe_hide_demo_data(db)
    return jsonify({
        'ok': True, 'scan_id': scan_id, 'total_plugins': len(parsed), 'scope': scope,
        'new': new_count, 'updated': updated_count, 'likely_resolved': resolved_count
    }), 201

def log_activity_vuln(db, vuln_id, actor, action):
    db.execute("INSERT INTO vuln_activity (vuln_id, actor, action) VALUES (?,?,?)", (vuln_id, actor, action))

@app.route('/api/vuln/scopes', methods=['GET'])
def list_vuln_scopes():
    db = get_db()
    rows = db.execute("SELECT * FROM vuln_scopes ORDER BY name").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/vuln/scopes', methods=['POST'])
def create_vuln_scope():
    u = get_current_user()
    if u.get('role') == 'auditor':
        return jsonify({'error': 'Auditors cannot create scopes'}), 403
    data = request.json or {}
    name = (data.get('name') or '').strip()[:60]
    if not name:
        return jsonify({'error': 'Scope name required'}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM vuln_scopes WHERE name=?", (name,)).fetchone()
    if existing:
        return jsonify({'ok': True, 'id': existing['id'], 'name': name})
    cur = db.execute("INSERT INTO vuln_scopes (name) VALUES (?)", (name,))
    db.commit()
    return jsonify({'ok': True, 'id': cur.lastrowid, 'name': name}), 201

@app.route('/api/vuln/scopes/<int:sid>', methods=['PUT'])
@require_admin
def rename_vuln_scope(sid):
    db = get_db()
    row = db.execute("SELECT name FROM vuln_scopes WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({'error': 'Scope not found'}), 404
    old_name = row['name']
    data = request.json or {}
    new_name = (data.get('name') or '').strip()[:60]
    if not new_name:
        return jsonify({'error': 'New name required'}), 400
    if new_name == old_name:
        return jsonify({'ok': True})
    conflict = db.execute("SELECT id FROM vuln_scopes WHERE name=? AND id!=?", (new_name, sid)).fetchone()
    if conflict:
        return jsonify({'error': f'A scope named "{new_name}" already exists. Use merge instead by deleting this scope and reassigning to it.'}), 409

    # Cascade the rename everywhere the old name is referenced as plain text
    db.execute("UPDATE vuln_scopes SET name=? WHERE id=?", (new_name, sid))
    db.execute("UPDATE vuln_scans SET scope=? WHERE scope=?", (new_name, old_name))
    db.execute("UPDATE vuln_hosts SET scope=? WHERE scope=?", (new_name, old_name))
    db.execute("UPDATE vuln_findings SET last_scope=? WHERE last_scope=?", (new_name, old_name))
    db.commit()
    return jsonify({'ok': True, 'old_name': old_name, 'new_name': new_name})

@app.route('/api/vuln/scopes/<int:sid>', methods=['DELETE'])
def delete_vuln_scope(sid):
    u = get_current_user()
    if u.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can delete a scope'}), 403
    db = get_db()
    row = db.execute("SELECT name FROM vuln_scopes WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({'error': 'Scope not found'}), 404
    name = row['name']
    data = request.json or {}
    reassign_to = (data.get('reassign_to') or '').strip()

    scan_count = db.execute("SELECT COUNT(*) FROM vuln_scans WHERE scope=?", (name,)).fetchone()[0]
    host_count = db.execute("SELECT COUNT(*) FROM vuln_hosts WHERE scope=?", (name,)).fetchone()[0]

    if scan_count or host_count:
        if not reassign_to:
            return jsonify({'error': f'"{name}" is used by {scan_count} scan(s) and {host_count} host record(s). Provide reassign_to to move this data to another scope before deleting, or rename instead.'}), 409
        target = db.execute("SELECT id FROM vuln_scopes WHERE name=?", (reassign_to,)).fetchone()
        if not target:
            return jsonify({'error': f'Target scope "{reassign_to}" does not exist'}), 400
        db.execute("UPDATE vuln_scans SET scope=? WHERE scope=?", (reassign_to, name))
        db.execute("UPDATE vuln_hosts SET scope=? WHERE scope=?", (reassign_to, name))
        db.execute("UPDATE vuln_findings SET last_scope=? WHERE last_scope=?", (reassign_to, name))

    db.execute("DELETE FROM vuln_scopes WHERE id=?", (sid,))
    db.commit()
    return jsonify({'ok': True, 'reassigned_to': reassign_to or None})



# ---------- Routes: vulnerability tracker ----------
@app.route('/api/vuln/findings', methods=['GET'])
def list_vuln_findings():
    db = get_db()
    show_archived = request.args.get('archived', 'false') == 'true'
    q = "SELECT * FROM vuln_findings WHERE archived=?"
    params = [1 if show_archived else 0]
    demo_visible = db.execute("SELECT value FROM app_settings WHERE key='demo_data_visible'").fetchone()
    if not (demo_visible and demo_visible['value'] == 'true'):
        q += " AND is_demo=0"
    sev = request.args.get('severity')
    status = request.args.get('status')
    if sev and sev != 'All':
        q += " AND severity=?"; params.append(sev)
    if status and status != 'All':
        q += " AND status=?"; params.append(status)
    q += " ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, host_count DESC"
    rows = db.execute(q, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/vuln/findings/<vid>', methods=['GET'])
def get_vuln_finding(vid):
    db = get_db()
    row = db.execute("SELECT * FROM vuln_findings WHERE id=?", (vid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    hosts = db.execute("SELECT * FROM vuln_hosts WHERE plugin_id=? ORDER BY host_ip", (row['plugin_id'],)).fetchall()
    activity = db.execute("SELECT * FROM vuln_activity WHERE vuln_id=? ORDER BY ts DESC", (vid,)).fetchall()
    result = dict(row)
    result['hosts'] = [dict(h) for h in hosts]
    result['activity'] = [dict(a) for a in activity]
    return jsonify(result)

@app.route('/api/vuln/findings/<vid>', methods=['PUT'])
def update_vuln_finding(vid):
    data = request.json or {}
    db = get_db()
    row = db.execute("SELECT * FROM vuln_findings WHERE id=?", (vid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    actor = get_current_user().get('display', 'System')
    fields = ['status', 'owner', 'due_date', 'remediation', 'evidence_notes']
    changes = []
    updates = []
    vals = []
    for field in fields:
        if field in data and str(data[field]) != str(row[field] or ''):
            changes.append(f"{field}: \"{row[field] or ''}\" -> \"{data[field]}\"")
            updates.append(f"{field}=?")
            vals.append(data[field])
    if updates:
        vals.append(vid)
        db.execute(f"UPDATE vuln_findings SET {', '.join(updates)}, updated_at=datetime('now') WHERE id=?", vals)
        for c in changes:
            log_activity_vuln(db, vid, actor, f'Updated: {c}')
        db.commit()
    return jsonify({'ok': True})

@app.route('/api/vuln/findings/<vid>/archive', methods=['POST'])
@require_admin
def archive_vuln_finding(vid):
    db = get_db()
    row = db.execute("SELECT id FROM vuln_findings WHERE id=?", (vid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    actor = get_current_user().get('display', 'System')
    db.execute("UPDATE vuln_findings SET archived=1 WHERE id=?", (vid,))
    log_activity_vuln(db, vid, actor, 'Archived')
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/vuln/findings/<vid>/unarchive', methods=['POST'])
@require_admin
def unarchive_vuln_finding(vid):
    db = get_db()
    row = db.execute("SELECT id FROM vuln_findings WHERE id=?", (vid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    actor = get_current_user().get('display', 'System')
    db.execute("UPDATE vuln_findings SET archived=0 WHERE id=?", (vid,))
    log_activity_vuln(db, vid, actor, 'Unarchived')
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/vuln/findings/<vid>', methods=['DELETE'])
def delete_vuln_finding(vid):
    u = get_current_user()
    if u.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can permanently delete a vulnerability. Use Archive instead.'}), 403
    data = request.json or {}
    db = get_db()
    row = db.execute("SELECT plugin_name, is_demo FROM vuln_findings WHERE id=?", (vid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    if row['is_demo']:
        return jsonify({'error': 'This is demo data and cannot be deleted. Go to Settings and turn off "Show demo data" to hide it instead.'}), 403
    if data.get('confirm_name', '').strip() != row['plugin_name']:
        return jsonify({'error': 'Confirmation text does not match'}), 400
    db.execute("DELETE FROM vuln_hosts WHERE plugin_id=(SELECT plugin_id FROM vuln_findings WHERE id=?)", (vid,))
    db.execute("DELETE FROM vuln_activity WHERE vuln_id=?", (vid,))
    db.execute("DELETE FROM vuln_evidence_files WHERE vuln_id=?", (vid,))
    db.execute("DELETE FROM vuln_findings WHERE id=?", (vid,))
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/vuln/scans', methods=['GET'])
def list_vuln_scans():
    db = get_db()
    rows = db.execute("SELECT * FROM vuln_scans ORDER BY uploaded_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/vuln/scans/<int:scan_id>', methods=['DELETE'])
def delete_vuln_scan(scan_id):
    u = get_current_user()
    if u.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can permanently delete a scan upload'}), 403
    db = get_db()
    scan = db.execute("SELECT * FROM vuln_scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    data = request.json or {}
    if data.get('confirm_name', '').strip() != scan['filename']:
        return jsonify({'error': 'Confirmation text does not match the filename'}), 400

    # Find plugin IDs whose hosts came from this scan
    affected_plugins = [r['plugin_id'] for r in db.execute(
        "SELECT DISTINCT plugin_id FROM vuln_hosts WHERE scan_id=?", (scan_id,)
    ).fetchall()]

    # Remove the hosts this scan contributed
    db.execute("DELETE FROM vuln_hosts WHERE scan_id=?", (scan_id,))

    removed_findings = 0
    for plugin_id in affected_plugins:
        remaining = db.execute("SELECT COUNT(*) FROM vuln_hosts WHERE plugin_id=?", (plugin_id,)).fetchone()[0]
        vuln = db.execute("SELECT id FROM vuln_findings WHERE plugin_id=?", (plugin_id,)).fetchone()
        if not vuln:
            continue
        if remaining == 0:
            # This vulnerability existed only because of this scan - remove it entirely
            db.execute("DELETE FROM vuln_activity WHERE vuln_id=?", (vuln['id'],))
            db.execute("DELETE FROM vuln_evidence_files WHERE vuln_id=?", (vuln['id'],))
            db.execute("DELETE FROM vuln_findings WHERE id=?", (vuln['id'],))
            removed_findings += 1
        else:
            db.execute("UPDATE vuln_findings SET host_count=? WHERE id=?", (remaining, vuln['id']))

    db.execute("DELETE FROM vuln_scans WHERE id=?", (scan_id,))
    db.commit()
    return jsonify({'ok': True, 'removed_findings': removed_findings})


@app.route('/api/vuln/hosts', methods=['GET'])
def list_vuln_hosts():
    db = get_db()
    rows = db.execute('''
        SELECT host_ip, hostname, COUNT(DISTINCT plugin_id) as vuln_count, MAX(last_seen) as last_seen
        FROM vuln_hosts GROUP BY host_ip ORDER BY vuln_count DESC
    ''').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/vuln/hosts/<host_ip>', methods=['GET'])
def get_vuln_host_detail(host_ip):
    db = get_db()
    rows = db.execute('''
        SELECT vf.*, vh.port, vh.protocol, vh.hostname, vh.last_seen as host_last_seen
        FROM vuln_hosts vh JOIN vuln_findings vf ON vf.plugin_id = vh.plugin_id
        WHERE vh.host_ip=?
        ORDER BY CASE vf.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END
    ''', (host_ip,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/vuln/stats', methods=['GET'])
def vuln_stats():
    db = get_db()
    demo_visible = db.execute("SELECT value FROM app_settings WHERE key='demo_data_visible'").fetchone()
    demo_filter = "" if (demo_visible and demo_visible['value'] == 'true') else " AND is_demo=0"
    total = db.execute(f"SELECT COUNT(*) FROM vuln_findings WHERE archived=0{demo_filter}").fetchone()[0]
    by_sev = {}
    open_by_sev = {}
    for s in ['Critical','High','Medium','Low','Informational']:
        by_sev[s] = db.execute(f"SELECT COUNT(*) FROM vuln_findings WHERE severity=? AND archived=0{demo_filter}", (s,)).fetchone()[0]
        open_by_sev[s] = db.execute(f"SELECT COUNT(*) FROM vuln_findings WHERE severity=? AND status='Open' AND archived=0{demo_filter}", (s,)).fetchone()[0]
    host_count = db.execute("SELECT COUNT(DISTINCT host_ip) FROM vuln_hosts").fetchone()[0]
    resolved = db.execute(f"SELECT COUNT(*) FROM vuln_findings WHERE status IN ('Resolved','Patched','Likely Resolved','False Positive','Compensating Control') AND archived=0{demo_filter}").fetchone()[0]
    scan_count = db.execute(f"SELECT COUNT(*) FROM vuln_scans WHERE 1=1{demo_filter}").fetchone()[0]

    # Actionable = everything except Informational severity (doesn't count toward progress %)
    actionable_total = db.execute("SELECT COUNT(*) FROM vuln_findings WHERE severity!='Informational' AND archived=0").fetchone()[0]
    actionable_total = db.execute(f"SELECT COUNT(*) FROM vuln_findings WHERE severity!='Informational' AND archived=0{demo_filter}").fetchone()[0]
    actionable_resolved = db.execute(f"SELECT COUNT(*) FROM vuln_findings WHERE severity!='Informational' AND status IN ('Resolved','Patched','Likely Resolved','Risk Accepted','False Positive','Compensating Control') AND archived=0{demo_filter}").fetchone()[0]
    completion_pct = round(actionable_resolved / actionable_total * 100) if actionable_total else 0

    scans = db.execute(f"SELECT id, scan_date, filename, scope FROM vuln_scans WHERE 1=1{demo_filter} ORDER BY scan_date ASC").fetchall()
    last_scan_date = scans[-1]['scan_date'] if scans else None
    open_criticals = db.execute(f"SELECT id, plugin_name, host_count FROM vuln_findings WHERE severity='Critical' AND status='Open' AND archived=0{demo_filter} ORDER BY host_count DESC LIMIT 10").fetchall()
    return jsonify({
        'total': total, 'by_severity': by_sev, 'open_by_severity': open_by_sev,
        'host_count': host_count, 'resolved': resolved, 'scan_count': scan_count,
        'last_scan_date': last_scan_date, 'open_criticals': [dict(c) for c in open_criticals],
        'actionable_total': actionable_total, 'actionable_resolved': actionable_resolved,
        'completion_pct': completion_pct,
        'scans': [dict(s) for s in scans]
    })

@app.route('/api/vuln/trend', methods=['GET'])
def vuln_trend():

    db = get_db()
    period = request.args.get('period', 'weekly')  # weekly, monthly, yearly
    demo_visible = db.execute("SELECT value FROM app_settings WHERE key='demo_data_visible'").fetchone()
    demo_filter = "" if (demo_visible and demo_visible['value'] == 'true') else " AND vs.is_demo=0"
    rows = db.execute(
        f"SELECT s.snapshot_date, s.open_critical, s.open_high, s.open_medium, s.open_low, "
        f"s.resolved_total, s.total_findings, s.completion_pct FROM vuln_snapshots s "
        f"JOIN vuln_scans vs ON s.scan_id=vs.id WHERE 1=1{demo_filter} ORDER BY s.snapshot_date ASC"
    ).fetchall()

    if not rows:
        return jsonify({'points': [], 'summary': None})

    # Group by period bucket, keeping the LAST snapshot in each bucket
    from datetime import datetime as dt
    buckets = {}
    for r in rows:
        try:
            d = dt.strptime(r['snapshot_date'], '%Y-%m-%d')
        except ValueError:
            continue
        if period == 'yearly':
            key = d.strftime('%Y')
        elif period == 'monthly':
            key = d.strftime('%Y-%m')
        else:  # weekly
            key = d.strftime('%Y-W%W')
        buckets[key] = r  # later rows overwrite earlier ones in same bucket

    points = []
    for key in sorted(buckets.keys()):
        r = buckets[key]
        points.append({
            'period': key,
            'date': r['snapshot_date'],
            'open_critical': r['open_critical'],
            'open_high': r['open_high'],
            'open_medium': r['open_medium'],
            'open_low': r['open_low'],
            'resolved_total': r['resolved_total'],
            'total_findings': r['total_findings'],
            'completion_pct': r['completion_pct'],
        })

    summary = None
    if len(points) >= 1:
        first = points[0]
        last = points[-1]
        summary = {
            'start_date': first['date'], 'end_date': last['date'],
            'start_pct': first['completion_pct'], 'end_pct': last['completion_pct'],
            'pct_change': last['completion_pct'] - first['completion_pct'],
            'start_total': first['total_findings'], 'end_total': last['total_findings'],
            'start_resolved': first['resolved_total'], 'end_resolved': last['resolved_total'],
        }

    return jsonify({'points': points, 'summary': summary})



@app.route('/api/upload', methods=['POST'])
def upload_pdf():
    u = get_current_user()
    if u.get('role') == 'auditor':
        return jsonify({'error': 'Auditors cannot import findings'}), 403
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    fname_lower = f.filename.lower()

    # Nessus CSV
    if fname_lower.endswith('.csv'):
        csv_content = f.read().decode('utf-8', errors='replace')
        findings = _parse_nessus_csv(csv_content)
        db = get_db()
        src_name = os.path.splitext(f.filename)[0]
        cur = db.execute(
            "INSERT INTO engagements (name,type,vendor,eng_date) VALUES (?,?,?,?)",
            (src_name, 'Internal Vulnerability Scan', 'Nessus/Tenable', str(date.today()))
        )
        eng_id = cur.lastrowid
        db.commit()
        return jsonify({'findings': findings, 'engagement_id': eng_id, 'source': src_name})

    if not fname_lower.endswith('.pdf'):
        return jsonify({'error': 'PDF or CSV files only'}), 400

    os.makedirs('/opt/sectrack/tmp', exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False, dir='/opt/sectrack/tmp') as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        src_name   = os.path.splitext(f.filename)[0]
        vendor_key = request.form.get('vendor', 'generic').lower()

        vendor_map = {
            'securin':  ('Securin',            'External Pen Test',           _parse_securin),
            'nodezero': ('NodeZero / Horizon3', 'External Pen Test',           _parse_nodezero),
            'nessus':   ('Nessus / Tenable',    'Internal Vulnerability Scan', _parse_pdf),
            'rapid7':   ('Rapid7',              'External Pen Test',           _parse_pdf),
            'generic':  ('Uploaded',            'External Pen Test',           None),
        }

        vendor_label, eng_type, parser_fn = vendor_map.get(vendor_key, vendor_map['generic'])

        try:
            if parser_fn:
                findings = parser_fn(tmp_path)
            else:
                results  = [_parse_securin(tmp_path), _parse_nodezero(tmp_path), _parse_pdf(tmp_path)]
                findings = max(results, key=len)
        except Exception as parse_err:
            return jsonify({'error': f'PDF parsing failed: {str(parse_err)}'}), 400

        db  = get_db()
        # Use user-supplied engagement details if provided
        eng_name   = request.form.get('eng_name', '').strip() or src_name
        eng_date   = request.form.get('eng_date', '') or str(date.today())
        eng_type_f = request.form.get('eng_type', '').strip() or eng_type
        eng_vendor = request.form.get('eng_vendor', '').strip() or vendor_label
        cur = db.execute(
            "INSERT INTO engagements (name,type,vendor,eng_date) VALUES (?,?,?,?)",
            (eng_name, eng_type_f, eng_vendor, eng_date)
        )
        eng_id = cur.lastrowid
        db.commit()
        return jsonify({'findings': findings, 'engagement_id': eng_id, 'source': src_name})
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

def _parse_pdf(pdf_path):
    import pdfplumber, re
    findings = []
    risk_patterns = {
        'Critical': re.compile(r'\bcritical\b', re.I),
        'High':     re.compile(r'\bhigh\b', re.I),
        'Medium':   re.compile(r'\bmedium\b|\bmoderate\b', re.I),
        'Low':      re.compile(r'\blow\b', re.I),
    }
    cve_pat = re.compile(r'CVE-\d{4}-\d+', re.I)
    skip_pat = re.compile(r'^(table of contents|executive summary|scope|methodology|appendix|page \d|confidential|prepared)', re.I)
    seen = set()
    with pdfplumber.open(pdf_path) as pdf:
        lines = '\n'.join(p.extract_text() or '' for p in pdf.pages).split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line or len(line) < 8 or skip_pat.match(line):
            i += 1; continue
        risk = next((r for r, p in risk_patterns.items() if p.search(line)), None)
        cves = cve_pat.findall(line)
        if risk or cves:
            title = re.sub(r'\b(critical|high|medium|low|moderate)\b', '', line, flags=re.I)
            title = re.sub(r'CVE-\d{4}-\d+', '', title)
            title = re.sub(r'\s+', ' ', title).strip(' :-|')[:100]
            if cves: title = (title + ' (' + ', '.join(cves[:2]) + ')').strip()
            if len(title) < 5: title = ', '.join(cves) if cves else line[:80]
            desc = ' '.join(lines[j].strip() for j in range(i+1, min(i+4, len(lines))) if lines[j].strip())[:400]
            key = title.lower()[:40]
            if key not in seen and len(title) > 5:
                seen.add(key)
                findings.append({'title': title, 'risk': risk or 'Medium', 'description': desc, 'cves': cves})
        i += 1
    return findings[:50]
@app.route('/upload-simple', methods=['GET','POST'])
def upload_simple():
    if request.method == 'GET':
        return '''<!DOCTYPE html>
<html><head><title>Upload PDF</title>
<style>body{font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:40px;max-width:600px;margin:0 auto}
h2{margin-bottom:20px}
input[type=file]{display:block;margin:16px 0;padding:10px;background:#1e2535;border:1px solid #3a4560;border-radius:8px;color:#e2e8f0;width:100%}
button{padding:10px 24px;background:#534AB7;color:white;border:none;border-radius:8px;cursor:pointer;font-size:14px}
.back{color:#7c6ff7;text-decoration:none;display:block;margin-top:20px}
</style></head>
<body>
<h2>Upload Pen Test PDF</h2>
<form method="POST" enctype="multipart/form-data">
  <input type="file" name="file" accept=".pdf" required>
  <button type="submit">Upload &amp; Parse</button>
</form>
<a class="back" href="/">← Back to SecTrack</a>
</body></html>'''
    u = get_current_user()
    if u.get('role') == 'auditor':
        return 'Auditors cannot import findings', 403
    import json as _json
    f = request.files.get('file')
    if not f:
        return 'No file uploaded', 400
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False, dir='/opt/sectrack/tmp') as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name
    try:
        findings = _parse_pdf(tmp_path)
        db = get_db()
        src_name = os.path.splitext(f.filename)[0]
        cur = db.execute(
            "INSERT INTO engagements (name,type,vendor,eng_date) VALUES (?,?,?,?)",
            (src_name, 'External Pen Test', 'Uploaded', str(date.today()))
        )
        eng_id = cur.lastrowid
        actor = get_current_user().get('display','System')
        for finding in findings:
            fid  = next_finding_id(db)
            risk = finding.get('risk','Medium')
            cves = finding.get('cves') or ''
            if isinstance(cves, list):
                cves = ', '.join(cves)
            db.execute('''INSERT INTO findings (id,title,description,engagement_id,source_label,risk,status,is_new,owner,due_date,remediation,evidence,affected_hosts,cves,in_poam)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (fid, finding['title'], finding.get('description',''),
                 eng_id, src_name, risk,
                 'Open', 1, get_setting('default_finding_owner', 'Unassigned'), auto_due_date(risk),
                 '', '', '', cves, 0))
            log_activity(db, fid, actor, 'Imported from PDF upload')
        db.commit()
        return f'''<!DOCTYPE html>
<html><head><title>Upload Complete</title>
<style>body{{font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:40px;max-width:600px;margin:0 auto}}
.back{{color:#7c6ff7;text-decoration:none;display:block;margin-top:20px}}
</style></head>
<body>
<h2>✓ Import complete</h2>
<p style="color:#94a3b8;margin-top:12px">Imported <strong>{len(findings)}</strong> findings from <strong>{src_name}</strong>.</p>
<p style="color:#94a3b8;margin-top:8px">Go to Findings to review, edit, and assign owners.</p>
<a class="back" href="/">← Back to SecTrack dashboard</a>
</body></html>'''
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

@app.route('/api/engagements/<int:eid>', methods=['DELETE'])
def delete_engagement(eid):
    u = get_current_user()
    if u.get('role') != 'master_admin':
        return jsonify({'error': 'Only a master admin can permanently delete an engagement. Use Archive instead.'}), 403

    data = request.json or {}
    db   = get_db()
    eng  = db.execute("SELECT name FROM engagements WHERE id=?", (eid,)).fetchone()
    if not eng:
        return jsonify({'error': 'Engagement not found'}), 404

    if data.get('confirm_name', '').strip() != eng['name']:
        return jsonify({'error': 'Confirmation text does not match the engagement name'}), 400

    findings = db.execute("SELECT id FROM findings WHERE engagement_id=?", (eid,)).fetchall()
    for f in findings:
        fid = f['id']
        ev_rows = db.execute("SELECT filename, mime_type FROM evidence_files WHERE finding_id=?", (fid,)).fetchall()
        for ev in ev_rows:
            file_path = os.path.join(UPLOADS_PATH, fid, ev['filename'])
            try:
                os.unlink(file_path)
            except FileNotFoundError:
                pass
            if ev['mime_type'] == 'application/pdf':
                base_id  = os.path.splitext(ev['filename'])[0]
                dest_dir = os.path.join(UPLOADS_PATH, fid)
                try:
                    for fn in os.listdir(dest_dir):
                        if fn.startswith(f"{base_id}-page"):
                            os.unlink(os.path.join(dest_dir, fn))
                except FileNotFoundError:
                    pass
        try:
            os.rmdir(os.path.join(UPLOADS_PATH, fid))
        except (FileNotFoundError, OSError):
            pass
        db.execute("DELETE FROM evidence_files WHERE finding_id=?", (fid,))
        db.execute("DELETE FROM activity WHERE finding_id=?", (fid,))

    db.execute("DELETE FROM findings WHERE engagement_id=?", (eid,))
    db.execute("DELETE FROM engagements WHERE id=?", (eid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/changelog', methods=['GET'])
def get_changelog():
    # CHANGELOG.json is generated from git history by .github/workflows/changelog.yml
    # and baked into the image at /opt/sectrack/CHANGELOG.json — it is not seeded into the DB.
    changelog_path = os.environ.get('SECTRACK_CHANGELOG', '/opt/sectrack/CHANGELOG.json')
    if not os.path.exists(changelog_path):
        return jsonify([])
    with open(changelog_path) as f:
        return jsonify(json.load(f))
@app.route('/api/version', methods=['GET'])
def get_version():
    try:
        with open('/opt/sectrack/VERSION') as f:
            parts = f.read().strip().split(' ', 1)
        return jsonify({'commit': parts[0], 'build_date': parts[1] if len(parts) > 1 else 'unknown'})
    except FileNotFoundError:
        return jsonify({'commit': 'unknown', 'build_date': 'unknown'})

@app.route('/api/version/check', methods=['GET'])
def check_version():
    import urllib.request, json as jsonlib
    try:
        with open('/opt/sectrack/VERSION') as f:
            current = f.read().strip().split(' ')[0]
    except FileNotFoundError:
        current = 'unknown'
    try:
        req = urllib.request.Request(
            'https://api.github.com/repos/cybersecninjatools/tracepatch/commits/main',
            headers={'User-Agent': 'TracePatch'}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = jsonlib.loads(resp.read())
        latest = data['sha'][:7]
        return jsonify({
            'current': current,
            'latest': latest,
            'update_available': current != latest and current != 'unknown',
            'compare_url': f'https://github.com/cybersecninjatools/tracepatch/compare/{current}...{latest}' if current != 'unknown' else None
        })
    except Exception as e:
        return jsonify({'current': current, 'latest': None, 'update_available': False, 'error': str(e)})

@app.route('/logout')
def logout():
    return 'Logged out', 401, {'WWW-Authenticate': f'Basic realm="{app.config["ORG_NAME"]} SecTrack"'}


@app.route('/logged-out')
def logged_out():
    return '''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Signed out</title>
<style>body{font-family:sans-serif;background:#0f1117;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center;padding:40px;background:#161b27;border:1px solid #2a3347;border-radius:12px}
h2{margin-bottom:8px}p{color:#94a3b8;margin-bottom:20px}
a{display:inline-block;padding:8px 20px;background:#534AB7;color:#fff;border-radius:8px;text-decoration:none}
a:hover{background:#3C3489}</style></head>
<body><div class="box"><h2>You have been signed out</h2>
<p>Your session has ended. Please close this browser tab.</p>
<a href="/">Sign in again</a></div></body></html>''', 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
