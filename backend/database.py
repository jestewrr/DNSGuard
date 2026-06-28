import os
import json
import uuid
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash

# Fetch the database URL from the environment (defaulting to a local string if needed)
# Render will automatically supply this as DATABASE_URL
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://localhost/dnsguard')

def get_db_connection():
    # Use DictCursor so rows behave like dictionaries (similar to sqlite3.Row)
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
    return conn

# ──────────────────────────────────────────────
# Database Initialization
# ──────────────────────────────────────────────

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # ── Users ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL DEFAULT '',
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Viewer/User',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')

        # Safely add new columns for existing databases
        new_user_cols = {
            'full_name': "ALTER TABLE Users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''",
            'email': "ALTER TABLE Users ADD COLUMN email TEXT DEFAULT ''",
            'created_at': "ALTER TABLE Users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            'last_login': "ALTER TABLE Users ADD COLUMN last_login TIMESTAMP",
            'is_active': "ALTER TABLE Users ADD COLUMN is_active BOOLEAN DEFAULT TRUE",
        }
        for col, sql in new_user_cols.items():
            cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name=%s", (col,))
            if not cursor.fetchone():
                cursor.execute(sql)

        # ── Logs ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Logs (
                id SERIAL PRIMARY KEY,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_id INTEGER,
                breakdown JSONB
            )
        ''')
        cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name='logs' AND column_name='breakdown'")
        if not cursor.fetchone():
            cursor.execute('ALTER TABLE Logs ADD COLUMN breakdown JSONB')

        # ── Blacklist ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Blacklist (
                id SERIAL PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE
            )
        ''')

        # ── Whitelist ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Whitelist (
                id SERIAL PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE
            )
        ''')

        # ── Password Resets ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS PasswordResets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMP NOT NULL
            )
        ''')

        # Insert some dummy blacklist entries if empty
        cursor.execute('SELECT COUNT(*) FROM Blacklist')
        if cursor.fetchone()[0] == 0:
            dummy_blacklist = ['malicious-site.com', 'phishing-example.net', 'bad-domain.org']
            for domain in dummy_blacklist:
                cursor.execute('INSERT INTO Blacklist (domain) VALUES (%s) ON CONFLICT DO NOTHING', (domain,))

        # Insert default users if empty
        cursor.execute('SELECT COUNT(*) FROM Users')
        if cursor.fetchone()[0] == 0:
            default_users = [
                ('Admin User', 'admin', 'admin@dnsguard.local', generate_password_hash('admin123'), 'Administrator'),
                ('Analyst User', 'analyst', 'analyst@dnsguard.local', generate_password_hash('analyst123'), 'Security Analyst'),
                ('Viewer User', 'viewer', 'viewer@dnsguard.local', generate_password_hash('viewer123'), 'Viewer/User'),
            ]
            for u in default_users:
                cursor.execute(
                    'INSERT INTO Users (full_name, username, email, password_hash, role) VALUES (%s, %s, %s, %s, %s)',
                    u
                )

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Skipping DB initialization (likely missing valid Postgres connection): {e}")

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────

def log_request(url, domain, status, ip_address, user_id=None, breakdown=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        breakdown_json = json.dumps(breakdown) if breakdown else None
        cursor.execute(
            'INSERT INTO Logs (url, domain, status, ip_address, user_id, breakdown) VALUES (%s, %s, %s, %s, %s, %s)',
            (url, domain, status, ip_address, user_id, breakdown_json)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging request: {e}")

def get_recent_logs(limit=100, user_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if user_id:
            cursor.execute('SELECT * FROM Logs WHERE user_id = %s ORDER BY timestamp DESC LIMIT %s', (user_id, limit))
        else:
            cursor.execute('SELECT * FROM Logs ORDER BY timestamp DESC LIMIT %s', (limit,))
        logs = cursor.fetchall()
        conn.close()
        return [dict(log) for log in logs]
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return []

def reclassify_log(log_id, new_status):
    """Allows a Security Analyst to reclassify a log entry."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Logs SET status = %s WHERE id = %s', (new_status, log_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error reclassifying log: {e}")
        return False

def get_log_stats(user_id=None):
    """Get aggregated stats for the dashboard."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if user_id:
            cursor.execute("""
                SELECT status, COUNT(*) as count FROM Logs WHERE user_id = %s GROUP BY status
            """, (user_id,))
        else:
            cursor.execute("SELECT status, COUNT(*) as count FROM Logs GROUP BY status")
        rows = cursor.fetchall()
        conn.close()
        stats = {'total': 0, 'safe': 0, 'suspicious': 0, 'malicious': 0}
        for row in rows:
            s = row['status'].lower()
            if s in stats:
                stats[s] = row['count']
            stats['total'] += row['count']
        return stats
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {'total': 0, 'safe': 0, 'suspicious': 0, 'malicious': 0}

# ──────────────────────────────────────────────
# Blacklist / Whitelist
# ──────────────────────────────────────────────

def is_blacklisted(domain):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM Blacklist WHERE domain = %s', (domain,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        print(f"Error checking blacklist: {e}")
        return False

def is_whitelisted(domain):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM Whitelist WHERE domain = %s', (domain,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        print(f"Error checking whitelist: {e}")
        return False

def get_blacklist():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Blacklist ORDER BY domain')
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error getting blacklist: {e}")
        return []

def get_whitelist():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Whitelist ORDER BY domain')
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error getting whitelist: {e}")
        return []

def add_to_blacklist(domain):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO Blacklist (domain) VALUES (%s) ON CONFLICT DO NOTHING', (domain,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error adding to blacklist: {e}")
        return False

def remove_from_blacklist(domain_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM Blacklist WHERE id = %s', (domain_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error removing from blacklist: {e}")
        return False

def add_to_whitelist(domain):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO Whitelist (domain) VALUES (%s) ON CONFLICT DO NOTHING', (domain,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error adding to whitelist: {e}")
        return False

def remove_from_whitelist(domain_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM Whitelist WHERE id = %s', (domain_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error removing from whitelist: {e}")
        return False

# ──────────────────────────────────────────────
# User Management
# ──────────────────────────────────────────────

def verify_user(username, password):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE username = %s AND is_active = TRUE', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            return dict(user)
        return None
    except Exception as e:
        print(f"Error verifying user: {e}")
        return None

def get_user_by_id(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

def create_user(full_name, username, email, password, role='Viewer/User'):
    """Register a new user. Returns (success, message)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Check if username or email already exists
        cursor.execute('SELECT id FROM Users WHERE username = %s', (username,))
        if cursor.fetchone():
            conn.close()
            return False, 'Username already exists'
        cursor.execute('SELECT id FROM Users WHERE email = %s', (email,))
        if cursor.fetchone():
            conn.close()
            return False, 'Email already registered'
        cursor.execute(
            'INSERT INTO Users (full_name, username, email, password_hash, role) VALUES (%s, %s, %s, %s, %s) RETURNING id',
            (full_name, username, email, generate_password_hash(password), role)
        )
        new_id = cursor.fetchone()[0]
        conn.commit()
        conn.close()
        return True, new_id
    except Exception as e:
        print(f"Error creating user: {e}")
        return False, str(e)

def get_all_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, full_name, username, email, role, created_at, last_login, is_active FROM Users ORDER BY id')
        users = cursor.fetchall()
        conn.close()
        return [dict(u) for u in users]
    except Exception as e:
        print(f"Error getting users: {e}")
        return []

def update_user(user_id, full_name=None, email=None, role=None, is_active=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        updates = []
        values = []
        if full_name is not None:
            updates.append('full_name = %s')
            values.append(full_name)
        if email is not None:
            updates.append('email = %s')
            values.append(email)
        if role is not None:
            updates.append('role = %s')
            values.append(role)
        if is_active is not None:
            updates.append('is_active = %s')
            values.append(is_active)
        if not updates:
            conn.close()
            return False
        values.append(user_id)
        cursor.execute(f"UPDATE Users SET {', '.join(updates)} WHERE id = %s", values)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating user: {e}")
        return False

def delete_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM Users WHERE id = %s', (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False

def update_last_login(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Users SET last_login = CURRENT_TIMESTAMP WHERE id = %s', (user_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error updating last login: {e}")

# ──────────────────────────────────────────────
# Password Reset
# ──────────────────────────────────────────────

def create_reset_token(email):
    """Create a password reset token. Returns (success, token_or_message)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM Users WHERE email = %s AND is_active = TRUE', (email,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return False, 'No account found with that email'
        token = uuid.uuid4().hex
        expires = datetime.utcnow() + timedelta(hours=1)
        # Delete any existing tokens for this user
        cursor.execute('DELETE FROM PasswordResets WHERE user_id = %s', (user['id'],))
        cursor.execute(
            'INSERT INTO PasswordResets (user_id, token, expires_at) VALUES (%s, %s, %s)',
            (user['id'], token, expires)
        )
        conn.commit()
        conn.close()
        return True, token
    except Exception as e:
        print(f"Error creating reset token: {e}")
        return False, str(e)

def verify_reset_token(token):
    """Verify a password reset token. Returns user_id or None."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM PasswordResets WHERE token = %s', (token,))
        reset = cursor.fetchone()
        if not reset:
            conn.close()
            return None
        if reset['expires_at'] < datetime.utcnow():
            cursor.execute('DELETE FROM PasswordResets WHERE id = %s', (reset['id'],))
            conn.commit()
            conn.close()
            return None
        conn.close()
        return reset['user_id']
    except Exception as e:
        print(f"Error verifying reset token: {e}")
        return None

def reset_password(token, new_password):
    """Reset a user's password using a valid token."""
    try:
        user_id = verify_reset_token(token)
        if not user_id:
            return False
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Users SET password_hash = %s WHERE id = %s', (generate_password_hash(new_password), user_id))
        cursor.execute('DELETE FROM PasswordResets WHERE token = %s', (token,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error resetting password: {e}")
        return False


if __name__ == '__main__':
    init_db()
    print("Database initialization attempted.")
