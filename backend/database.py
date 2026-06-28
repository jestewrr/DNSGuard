import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            status TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    try:
        cursor.execute('ALTER TABLE Logs ADD COLUMN user_id INTEGER')
    except sqlite3.OperationalError:
        pass # Column might already exist
        
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE
        )
    ''')
    
    # Insert some dummy blacklist entries if empty
    cursor.execute('SELECT COUNT(*) FROM Blacklist')
    if cursor.fetchone()[0] == 0:
        dummy_blacklist = ['malicious-site.com', 'phishing-example.net', 'bad-domain.org']
        for domain in dummy_blacklist:
            cursor.execute('INSERT INTO Blacklist (domain) VALUES (?)', (domain,))
            
    # Insert default users if empty
    cursor.execute('SELECT COUNT(*) FROM Users')
    if cursor.fetchone()[0] == 0:
        default_users = [
            ('admin', generate_password_hash('admin123'), 'Administrator'),
            ('analyst', generate_password_hash('analyst123'), 'Security Analyst'),
            ('viewer', generate_password_hash('viewer123'), 'Viewer/User')
        ]
        cursor.executemany('INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)', default_users)
            
    conn.commit()
    conn.close()

def log_request(url, domain, status, ip_address, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO Logs (url, domain, status, ip_address, user_id) VALUES (?, ?, ?, ?, ?)',
        (url, domain, status, ip_address, user_id)
    )
    conn.commit()
    conn.close()

def get_recent_logs(limit=50, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if user_id:
        cursor.execute('SELECT * FROM Logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?', (user_id, limit))
    else:
        cursor.execute('SELECT * FROM Logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    logs = cursor.fetchall()
    conn.close()
    return [dict(log) for log in logs]

def is_blacklisted(domain):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM Blacklist WHERE domain = ?', (domain,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def verify_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        return dict(user)
    return None

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

if __name__ == '__main__':
    init_db()
    print("Database initialized.")
