import sqlite3
import pandas as pd

if __name__ == "__main__":
    try:
        conn = sqlite3.connect("security_logs.db")
        df = pd.read_sql_query("SELECT id, strftime('%H:%M:%S', timestamp) as time, status, reason, anomaly_score, payload_size FROM requests ORDER BY id DESC LIMIT 15", conn)
        print("----- LATEST REQUESTS -----")
        print(df)
        
        df_blocks = pd.read_sql_query("SELECT * FROM blocked_ips", conn)
        print("\n----- BLOCKED IPS -----")
        print(df_blocks)
        conn.close()
    except Exception as e:
        print("DB Check Error:", e)
