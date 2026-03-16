import streamlit as st
import sqlite3
import pandas as pd
import os

st.set_page_config(page_title="API Security Gateway Dashboard", layout="wide")

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'security_logs.db')

def get_data(query):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

st.title("🛡️ API Security Gateway Dashboard")
st.markdown("Real-time monitoring of API traffic, WAF blocks, and ML Anomaly Detection.")

col1, col2 = st.columns([8, 1])
with col2:
    if st.button("🔄 Refresh"):
        st.rerun()

if os.path.exists(DB_PATH):
    try:
        total_requests = get_data("SELECT COUNT(*) as count FROM requests").iloc[0]['count']
        blocked_requests = get_data("SELECT COUNT(*) as count FROM requests WHERE status='BLOCKED'").iloc[0]['count']
        blocked_ips = get_data("SELECT COUNT(*) as count FROM blocked_ips").iloc[0]['count']
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Requests", total_requests)
        col2.metric("Blocked Requests", blocked_requests)
        col3.metric("Blocked IPs", blocked_ips)
        
        detection_rate = f"{(blocked_requests / total_requests * 100):.1f}%" if total_requests > 0 else "0%"
        col4.metric("Threat Detection Rate", detection_rate)

        st.subheader("Recent Blocked Activity (WAF & ML)")
        blocked_df = get_data("SELECT timestamp, ip_address, path, reason FROM requests WHERE status='BLOCKED' ORDER BY timestamp DESC LIMIT 10")
        st.dataframe(blocked_df, use_container_width=True)

        st.subheader("IP Blocklist")
        ip_df = get_data("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
        st.dataframe(ip_df, use_container_width=True)

        st.subheader("Recent Traffic Logs")
        all_df = get_data("SELECT timestamp, ip_address, method, path, status, anomaly_score FROM requests ORDER BY timestamp DESC LIMIT 50")
        st.dataframe(all_df, use_container_width=True)

    except Exception as e:
        st.error(f"Error loading dashboard data: {e}. If the tables don't exist yet, start sending traffic to the gateway.")
else:
    st.info("Waiting for traffic to generate security logs database...")
