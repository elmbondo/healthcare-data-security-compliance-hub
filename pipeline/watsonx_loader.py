"""
watsonx.data loader

Takes the normalized events produced by pipeline_validator.py's run_pipeline()
and appends them to the audit_log table in watsonx.data (Apache Iceberg),
matching the schema documented in the README:
  event_id, event_timestamp, user_id, user_role, action, record_type,
  record_id, facility_id, golden_id, authorized, is_violation, risk_tier,
  masking_applied, source_system, ingested_at

Setup:
    pip install presto-python-client
"""

from datetime import datetime, timezone
import prestodb
import os

from dotenv import load_dotenv
load_dotenv()

# CONFIG - from Configurations > Connectivity > Connection information
AUTH_USERNAME = os.environ.get("WXD_USER")
API_KEY = os.environ.get("WXD_API_KEY")
HOST = "5509bdee-4681-4462-8555-d955f928f702.d4mn75il0dt1ob8mmlug.lakehouse.ibmappdomain.cloud"
PORT = 31329
DISPLAY_USER = "fidel"
CATALOG = "healthcare_security_catalog"
SCHEMA = "default"
TABLE = "audit_log"

_connection = None

if not AUTH_USERNAME or not API_KEY:
    raise RuntimeError("Set WXD_USER and WXD_API_KEY environment variables before running this.")


def get_connection():
    global _connection
    if _connection is None:
        _connection = prestodb.dbapi.connect(
            host=HOST,
            port=PORT,
            user=DISPLAY_USER,
            catalog=CATALOG,
            schema=SCHEMA,
            http_scheme="https",
            auth=prestodb.auth.BasicAuthentication(AUTH_USERNAME, API_KEY),
        )
    return _connection

def ensure_schema():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {CATALOG}.{SCHEMA}")
    cursor.fetchall()


def ensure_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {CATALOG}.{SCHEMA}.{TABLE} (
            event_id VARCHAR,
            event_timestamp VARCHAR,
            user_id VARCHAR,
            user_role VARCHAR,
            action VARCHAR,
            record_type VARCHAR,
            record_id VARCHAR,
            facility_id VARCHAR,
            golden_id VARCHAR,
            authorized BOOLEAN,
            is_violation BOOLEAN,
            risk_tier VARCHAR,
            masking_applied BOOLEAN,
            source_system VARCHAR,
            ingested_at VARCHAR
        )
    """)
    cursor.fetchall()


def load_event(result: dict):
    """
    Takes one result dict from pipeline_validator.run_pipeline() - status,
    stage, issues, event - and appends the event to the audit_log table.
    Call this for CLEAN and FLAGGED results; skip DROPPED ones (nothing
    usable to log).
    """
    event = result["event"]
    if event is None:
        return

    conn = get_connection()
    cursor = conn.cursor()

    is_violation = result["status"] == "FLAGGED" or event.get("authorized") is False
    masking_applied = bool(event.get("masking_applied", False))
    ingested_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    cursor.execute(f"""
        INSERT INTO {CATALOG}.{SCHEMA}.{TABLE}
        (event_id, event_timestamp, user_id, user_role, action, record_type,
         record_id, facility_id, golden_id, authorized, is_violation,
         risk_tier, masking_applied, source_system, ingested_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("event_id"),
        event.get("timestamp"),
        event.get("user_id"),
        event.get("user_role"),
        event.get("action"),
        event.get("record_type"),
        event.get("record_id"),
        event.get("facility_id"),
        event.get("golden_id"),
        event.get("authorized"),
        is_violation,
        event.get("risk_tier"),
        masking_applied,
        event.get("source_system"),
        ingested_at,
    ))
    cursor.fetchall()
