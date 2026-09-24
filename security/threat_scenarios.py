"""
Healthcare Cybersecurity Attack & Threat Scenarios
--------------------------------------------------
Curated realistic healthcare security scenarios demonstrating QRadar SIEM
anomaly detection rules and Guardium real-time PHI dynamic data masking.

Author: Joyline Kamoing (Cybersecurity Track)
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_unauthorized_chart_view_scenario() -> List[Dict[str, Any]]:
    """
    Scenario 1: Billing clerk attempting to view clinical psychiatric patient chart.
    Expected: QRadar fires QR-RULE-101 (Unauthorized Chart View), Guardium masks medical history.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": now,
            "user_id": "user_4012",
            "user_role": "billing_clerk",
            "action": "view_chart",
            "patient_id": "pt_10002",
            "record_type": "EHR",
            "authorized": False,
            "source_system": "qradar_ehr_stream",
            "source_ip": "10.240.15.22",
            "details": "Billing clerk attempted to open raw clinical psychiatric chart notes.",
            "sql_query": "SELECT ssn, diagnosis_code, medical_history FROM ehr_patients WHERE patient_id = 'pt_10002';"
        }
    ]


def generate_bulk_download_scenario() -> List[Dict[str, Any]]:
    """
    Scenario 2: Rogue staff downloading bulk patient records off-hours.
    Expected: QRadar fires QR-RULE-102 (Bulk Download Anomaly) and QR-RULE-104 (Off-Hours).
    """
    now = datetime.now(timezone.utc).replace(hour=23, minute=15).isoformat().replace("+00:00", "Z")
    events = []
    for i in range(6):
        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": now,
            "user_id": "user_8821",
            "user_role": "nurse",
            "action": "bulk_download",
            "patient_id": f"pt_200{i:02d}",
            "record_type": "EHR",
            "authorized": False,
            "source_system": "qradar_siem",
            "source_ip": "10.240.18.99",
            "details": f"Mass export of oncology patient batch {i+1} at 23:15 UTC.",
            "sql_query": f"SELECT * FROM ehr_patients WHERE department = 'Oncology' LIMIT 100 OFFSET {i*100};"
        })
    return events


def generate_vip_snooping_scenario() -> List[Dict[str, Any]]:
    """
    Scenario 3: Unassigned staff snooping on VIP / celebrity patient.
    Expected: QRadar fires QR-RULE-103 (VIP Patient Privacy Snooping Alert).
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": now,
            "user_id": "user_3309",
            "user_role": "lab_tech",
            "action": "view_chart",
            "patient_id": "pt_99999",  # VIP Patient
            "record_type": "EHR",
            "authorized": False,
            "source_system": "qradar_guardium_bridge",
            "source_ip": "10.240.12.40",
            "details": "Lab tech not on care team opened Senator Marcus Vance VIP record.",
            "sql_query": "SELECT full_name, ssn, diagnosis_code, medical_history FROM ehr_patients WHERE patient_id = 'pt_99999';"
        }
    ]


def generate_sqli_scenario() -> List[Dict[str, Any]]:
    """
    Scenario 4: SQL Injection attack on database portal.
    Expected: Guardium intercepts and blocks query (GD-POL-04) and generates CRITICAL alert.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": now,
            "user_id": "guest_user",
            "user_role": "guest",
            "action": "query_patient_search",
            "patient_id": "pt_all",
            "record_type": "portal_auth",
            "authorized": False,
            "source_system": "guardium_stap",
            "source_ip": "198.51.100.44",
            "details": "Patient portal search input contained SQL injection payload.",
            "sql_query": "SELECT * FROM ehr_patients WHERE patient_id = '' OR '1'='1' --"
        }
    ]


def generate_scraping_scenario() -> List[Dict[str, Any]]:
    """
    Scenario 5: Multi-patient sequential automated crawling / scraping.
    Expected: QRadar fires QR-RULE-105 (Multi-Patient Scraping Anomaly).
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events = []
    for i in range(6):
        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": now,
            "user_id": "user_6610",
            "user_role": "billing_clerk",
            "action": "query_patient_search",
            "patient_id": f"pt_910{i:02d}",
            "record_type": "EHR",
            "authorized": True,
            "source_system": "qradar_siem",
            "source_ip": "10.240.22.10",
            "details": f"Rapid lookup on patient pt_910{i:02d}",
            "sql_query": f"SELECT patient_id, ssn FROM ehr_patients WHERE patient_id = 'pt_910{i:02d}';"
        })
    return events


def generate_authorized_baseline_scenario() -> List[Dict[str, Any]]:
    """
    Scenario 6: Normal, authorized clinical workflow by attending physician.
    Expected: Full clinical access, no SIEM offenses, legitimate audit log.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": now,
            "user_id": "user_1001",  # Attending Physician
            "user_role": "physician",
            "action": "view_chart",
            "patient_id": "pt_10001",
            "record_type": "EHR",
            "authorized": True,
            "source_system": "qradar_guardium_bridge",
            "source_ip": "10.240.10.15",
            "details": "Routine cardiology follow-up chart review.",
            "sql_query": "SELECT ssn, diagnosis_code, medical_history FROM ehr_patients WHERE patient_id = 'pt_10001';"
        }
    ]


ALL_SCENARIOS = {
    "unauthorized_chart_view": generate_unauthorized_chart_view_scenario,
    "bulk_download": generate_bulk_download_scenario,
    "vip_snooping": generate_vip_snooping_scenario,
    "sql_injection": generate_sqli_scenario,
    "scraping": generate_scraping_scenario,
    "authorized_baseline": generate_authorized_baseline_scenario,
}
