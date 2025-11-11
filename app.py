from flask import Flask, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": os.getenv("ALLOWED_ORIGINS", "*")}})

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS"),
    "port": os.getenv("DB_PORT", "5432"),
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG, sslmode="require")

@app.route("/")
def home():
    return jsonify({"message":"CVE backend running"})

@app.route("/cves/list")
def list_cves():
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    # fetch up to 100 rows (frontend will paginate)
    cur.execute("SELECT * FROM cves ORDER BY published DESC NULLS LAST LIMIT 100;")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)

@app.route("/cves/<cve_id>")
def get_cve(cve_id):
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM cves WHERE cve_id = %s;", (cve_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({"error":"Not found"}), 404
    return jsonify(row)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
