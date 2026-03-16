import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'security_logs.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Table for all requests
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            path TEXT,
            method TEXT,
            payload_size INTEGER,
            anomaly_score REAL,
            status TEXT,
            reason TEXT
        )
    ''')
    # Table for blocked IPs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_address TEXT PRIMARY KEY,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_request(ip, path, method, payload_size, anomaly_score, status, reason=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO requests (ip_address, path, method, payload_size, anomaly_score, status, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ip, path, method, payload_size, anomaly_score, status, reason)
    )
    conn.commit()
    conn.close()

def block_ip(ip, reason):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)", (ip, reason))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # Already blocked
    conn.close()

def is_ip_blocked(ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM blocked_ips WHERE ip_address = ?", (ip,))
    blocked = cursor.fetchone() is not None
    conn.close()
    return blocked

# Initialize on import
init_db()
