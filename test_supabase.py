# quick test file
import os
from dotenv import load_dotenv
import psycopg2

load_dotenv()

try:
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        port=os.getenv("DB_PORT", "5432"),
        sslmode="require"
    )
    cur = conn.cursor()
    cur.execute("SELECT NOW();")
    print("✅ Connected to Supabase! Current time:", cur.fetchone())
    cur.close()
    conn.close()
except Exception as e:
    print("❌ Connection failed:", e)
