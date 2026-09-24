"""
IBM Security Guardium Real-Time Database Activity Monitoring (DAM) & S-TAP Engine
----------------------------------------------------------------------------------
Simulates IBM Security Guardium S-TAP protocol-level database inspection,
SQL injection detection, policy enforcement, and dynamic PHI masking.

Author: Joyline Kamoing (Cybersecurity Track)
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from security.guardium.phi_masker import PHIMasker
except ImportError:
    from phi_masker import PHIMasker


# Sample in-memory clinical records representing an EHR database
SAMPLE_EHR_DATABASE = [
    {
        "patient_id": "pt_10001",
        "full_name": "Alice Johnson",
        "ssn": "123-45-6789",
        "diagnosis_code": "I10",
        "medical_history": "Essential hypertension, Stage 2 chronic kidney disease",
        "prescription": "Lisinopril 20mg Daily, Amlodipine 5mg",
        "department": "Cardiology",
    },
    {
        "patient_id": "pt_10002",
        "full_name": "Robert Davis",
        "ssn": "987-65-4321",
        "diagnosis_code": "F32.9",
        "medical_history": "Major depressive disorder, recurrent, with acute anxiety episodes",
        "prescription": "Sertraline 50mg, Clonazepam 0.5mg PRN",
        "department": "Psychiatry",
    },
    {
        "patient_id": "pt_99999",  # VIP patient
        "full_name": "Senator Marcus Vance (VIP)",
        "ssn": "888-99-0001",
        "diagnosis_code": "C34.90",
        "medical_history": "Malignant neoplasm of unspecified part of bronchus or lung",
        "prescription": "Osimertinib 80mg, Dexamethasone 4mg",
        "department": "Oncology",
    }
]


class GuardiumEngine:
    """Simulates Guardium DAM S-TAP policy execution and dynamic masking."""

    SQLI_PATTERNS = [
        re.compile(r"(?i)(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)"),
        re.compile(r"(?i)(\bunion\b\s+\bselect\b)"),
        re.compile(r"(?i)(\bdrop\b\s+\btable\b)"),
        re.compile(r"(?i)(--|;--|/\*)"),
        re.compile(r"(?i)(\binformation_schema\b)"),
    ]

    RESTRICTED_TABLES = {"ehr_patients", "patient_medical_history", "prescriptions", "billing_accounts"}
    UNAUTHORIZED_DB_USERS = {"reporting_readonly", "guest_user", "etl_temp_user", "anonymous"}

    def __init__(self, policy_file: Optional[str] = None):
        self.policy_file = policy_file
        self.audit_log: List[Dict[str, Any]] = []
        self.alerts_generated: List[Dict[str, Any]] = []
        self.total_queries_monitored = 0
        self.total_masked_queries = 0

    def inspect_sql(self, sql_query: str) -> Tuple[bool, List[str]]:
        """Checks for SQL injection or malicious patterns."""
        threats = []
        for pattern in self.SQLI_PATTERNS:
            if pattern.search(sql_query):
                threats.append(f"SQLI_PATTERN_MATCH: {pattern.pattern}")
        return len(threats) > 0, threats

    def execute_monitored_query(
        self,
        sql_query: str,
        db_user: str,
        user_role: str,
        client_ip: str = "10.0.4.12",
        target_patient_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Intercepts and evaluates a database query through Guardium DAM S-TAP.
        Returns query execution result, masking metadata, and generated security events.
        """
        self.total_queries_monitored += 1
        query_id = f"QRY-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # 1. SQL Injection / Extrusion check
        is_sqli, sqli_reasons = self.inspect_sql(sql_query)
        if is_sqli:
            alert = {
                "alert_id": f"GD-ALERT-{uuid.uuid4().hex[:6].upper()}",
                "timestamp": timestamp,
                "policy_id": "GD-POL-04",
                "policy_name": "SQL Injection & Malicious Signature Detection",
                "severity": "CRITICAL",
                "db_user": db_user,
                "user_role": user_role,
                "client_ip": client_ip,
                "sql_query": sql_query,
                "reasons": sqli_reasons,
                "action_taken": "BLOCK_SESSION_AND_ALERT",
            }
            self.alerts_generated.append(alert)
            return {
                "status": "BLOCKED",
                "query_id": query_id,
                "error": "Guardium S-TAP Security Violation: Malicious query pattern detected. Session blocked.",
                "rows": [],
                "masked_fields_count": 0,
                "guardium_alert": alert,
            }

        # 2. Direct Unauthorized DB User Access Check
        if db_user.lower() in self.UNAUTHORIZED_DB_USERS:
            alert = {
                "alert_id": f"GD-ALERT-{uuid.uuid4().hex[:6].upper()}",
                "timestamp": timestamp,
                "policy_id": "GD-POL-01",
                "policy_name": "Direct Access to Restricted PHI Tables",
                "severity": "HIGH",
                "db_user": db_user,
                "user_role": user_role,
                "client_ip": client_ip,
                "sql_query": sql_query,
                "action_taken": "ALERT_AND_FORWARD_KAFKA",
            }
            self.alerts_generated.append(alert)

        # 3. Simulate Query Execution against EHR Database
        raw_rows = []
        if target_patient_id:
            raw_rows = [p for p in SAMPLE_EHR_DATABASE if p["patient_id"] == target_patient_id]
        else:
            raw_rows = list(SAMPLE_EHR_DATABASE)

        # 4. Dynamic PHI Masking for the user role
        masked_rows, masked_count = PHIMasker.mask_result_set(raw_rows, user_role)
        if masked_count > 0:
            self.total_masked_queries += 1

        # 5. Build Guardium DAM Audit Record
        audit_entry = {
            "query_id": query_id,
            "timestamp": timestamp,
            "db_user": db_user,
            "user_role": user_role,
            "client_ip": client_ip,
            "sql_query": sql_query,
            "row_count": len(masked_rows),
            "masked_cells": masked_count,
            "phi_masked": masked_count > 0,
            "status": "ALLOWED_WITH_MASKING" if masked_count > 0 else "ALLOWED_CLEAN",
        }
        self.audit_log.append(audit_entry)

        return {
            "status": "SUCCESS",
            "query_id": query_id,
            "rows": masked_rows,
            "masked_fields_count": masked_count,
            "audit_entry": audit_entry,
            "guardium_alert": self.alerts_generated[-1] if self.alerts_generated else None,
        }

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_queries_monitored": self.total_queries_monitored,
            "total_masked_queries": self.total_masked_queries,
            "total_alerts": len(self.alerts_generated),
            "audit_log_size": len(self.audit_log),
        }
