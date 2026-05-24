import pandas as pd
import sqlite3

# 1. Load your lightweight sample data
try:
    df = pd.read_csv("network_logs_sample.csv")
    print("✅ Loaded 'network_logs_sample.csv' successfully.")
except FileNotFoundError:
    print("❌ Error: 'network_logs_sample.csv' not found. Did you run step1_explore.py?")
    exit()

# 2. Clean column names for SQL compatibility 
# Replaces spaces and slashes with underscores so SQL queries don't break
df.columns = [c.strip().replace(' ', '_').replace('/', '_').replace('-', '_') for c in df.columns]

# 3. Create a temporary in-memory SQL database
conn = sqlite3.connect(':memory:')
df.to_sql('network_traffic', conn, index=False, if_exists='replace')

print("🗄️ Temporary SQL table 'network_traffic' is ready. Running queries...\n")
print("=" * 60)

# ----------------------------------------------------------------------------------
# QUERY 1: Distribution of Traffic Protocols
# 6 = TCP, 17 = UDP, 1 = ICMP. Let's see what dominates your network sample.
# ----------------------------------------------------------------------------------
query_protocols = """
SELECT Protocol, COUNT(*) as connection_count, Label
FROM network_traffic
GROUP BY Protocol, Label
ORDER BY connection_count DESC;
"""

print("📊 SQL QUERY 1: TRAFFIC BY PROTOCOL TYPE")
try:
    protocol_data = pd.read_sql_query(query_protocols, conn)
    print(protocol_data)
except Exception as e:
    print(f"⚠️ Query 1 failed. Error: {e}")
print("-" * 60)

# ----------------------------------------------------------------------------------
# QUERY 2: Tracking High SYN Flag Counts
# A SYN flag is a handshake request. A high volume of SYN flags with no follow-through
# is the classic signature of a SYN Flood DDoS attack or network scan.
# ----------------------------------------------------------------------------------
query_flags = """
SELECT SYN_Flag_Count, Label, COUNT(*) as total_occurrences
FROM network_traffic
GROUP BY SYN_Flag_Count, Label
ORDER BY SYN_Flag_Count DESC;
"""

print("🚨 SQL QUERY 2: SYN FLAG ANALYTICS (Looking for Handshake Storms)")
try:
    flag_data = pd.read_sql_query(query_flags, conn)
    print(flag_data)
except Exception as e:
    print(f"⚠️ Query 2 failed. Error: {e}")

print("=" * 60)

# Clean up connection
conn.close()