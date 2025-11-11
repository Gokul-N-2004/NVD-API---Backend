import requests
import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS"),
    "port": os.getenv("DB_PORT", "5432"),
}

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PARAMS = {"resultsPerPage": 1000}  

def get_cve_list():
    r = requests.get(NVD_URL, params=PARAMS, timeout=30)
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])

def upsert_cves(cves):
    conn = psycopg2.connect(**DB_CONFIG, sslmode="require")
    cur = conn.cursor()
    for item in cves:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        published = cve.get("published", "")[:10] or None
        modified = cve.get("lastModified", "")[:10] or None

        metrics = cve.get("metrics", {}) or {}
        cvss_score = 0.0
        severity = None
        impact_score = None
        exploit_score = None
        vector_string = None  

        
        if "cvssMetricV31" in metrics:
            data3 = metrics["cvssMetricV31"][0]
            cvss_score = data3.get("cvssData", {}).get("baseScore", 0)
            severity = data3.get("cvssData", {}).get("baseSeverity", None)
            vector_string = data3.get("cvssData", {}).get("vectorString", None)
            impact_score = data3.get("impactScore", None)
            exploit_score = data3.get("exploitabilityScore", None)
        elif "cvssMetricV30" in metrics:
            data3 = metrics["cvssMetricV30"][0]
            cvss_score = data3.get("cvssData", {}).get("baseScore", 0)
            severity = data3.get("cvssData", {}).get("baseSeverity", None)
            vector_string = data3.get("cvssData", {}).get("vectorString", None)
            impact_score = data3.get("impactScore", None)
            exploit_score = data3.get("exploitabilityScore", None)
        elif "cvssMetricV2" in metrics:
            data2 = metrics["cvssMetricV2"][0]
            cvss_score = data2.get("cvssData", {}).get("baseScore", 0)
            vector_string = data2.get("cvssData", {}).get("vectorString", None)
            severity = data2.get("baseSeverity", None)
            impact_score = data2.get("impactScore", None)
            exploit_score = data2.get("exploitabilityScore", None)

        cur.execute("""
            INSERT INTO cves (
                cve_id, description, published, last_modified,
                cvss_v3, severity, impact_score, exploitability_score,
                vector_string, status
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (cve_id) DO UPDATE SET
                description = EXCLUDED.description,
                last_modified = EXCLUDED.last_modified,
                cvss_v3 = EXCLUDED.cvss_v3,
                severity = EXCLUDED.severity,
                impact_score = EXCLUDED.impact_score,
                exploitability_score = EXCLUDED.exploitability_score,
                vector_string = EXCLUDED.vector_string,
                status = EXCLUDED.status;
        """, (cve_id, desc, published, modified, cvss_score, severity,
              impact_score, exploit_score, vector_string, "Analyzed"))

    conn.commit()
    cur.close()
    conn.close()

if __name__ == "__main__":
    print("Fetching from NVD...")
    cves = get_cve_list()
    print(f"Got {len(cves)} records. Inserting to DB...")
    upsert_cves(cves)
    print("Successfully fetched and inserted in DB")
