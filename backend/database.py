import os
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

def init_db():
    # Only attempt to initialize if DATABASE_URL is set or we are running this script directly
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # In PostgreSQL, AUTOINCREMENT is SERIAL.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Logs (
                id SERIAL PRIMARY KEY,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_id INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Blacklist (
                id SERIAL PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE
            )
        ''')
        
        # Insert some dummy blacklist entries if empty
        cursor.execute('SELECT COUNT(*) FROM Blacklist')
        if cursor.fetchone()[0] == 0:
            dummy_blacklist = ['malicious-site.com', 'phishing-example.net', 'bad-domain.org']
            for domain in dummy_blacklist:
                cursor.execute('INSERT INTO Blacklist (domain) VALUES (%s)', (domain,))
                
        # Insert default users if empty
        cursor.execute('SELECT COUNT(*) FROM Users')
        if cursor.fetchone()[0] == 0:
            default_users = [
                ('admin', generate_password_hash('admin123'), 'Administrator'),
                ('analyst', generate_password_hash('analyst123'), 'Security Analyst'),
                ('viewer', generate_password_hash('viewer123'), 'Viewer/User')
            ]
            cursor.executemany('INSERT INTO Users (username, password_hash, role) VALUES (%s, %s, %s)', default_users)
                
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Skipping DB initialization (likely missing valid Postgres connection): {e}")

def log_request(url, domain, status, ip_address, user_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO Logs (url, domain, status, ip_address, user_id) VALUES (%s, %s, %s, %s, %s)',
            (url, domain, status, ip_address, user_id)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging request: {e}")

def get_recent_logs(limit=50, user_id=None):
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

def verify_user(username, password):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE username = %s', (username,))
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

if __name__ == '__main__':
    init_db()
    print("Database initialization attempted.")
