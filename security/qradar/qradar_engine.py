"""
QRadar SIEM Custom Rules Engine (CRE) & Offense Correlation Simulator
---------------------------------------------------------------------
Simulates IBM QRadar SIEM real-time rule evaluation, stateful correlation,
and Offense generation for healthcare EHR security events.

Author: Joyline Kamoing (Cybersecurity Track)
"""

import json
import os
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid


DEFAULT_VIP_PATIENTS = {"pt_99999", "pt_88888", "pt_77777", "pt_vip_01", "pt_vip_02"}
DEFAULT_CARE_TEAMS = {
    "pt_99999": {"user_1001", "user_1002"},
    "pt_88888": {"user_1003"},
}


class QRadarEngine:
    def __init__(self, rules_file: Optional[str] = None):
        self.rules = self._load_rules(rules_file)
        self.vip_patients: Set[str] = set(DEFAULT_VIP_PATIENTS)
        self.patient_care_teams: Dict[str, Set[str]] = defaultdict(set, DEFAULT_CARE_TEAMS)

        # Stateful sliding windows: user_id -> deque of (timestamp, event_id, patient_id, action)
        self.user_event_window: Dict[str, deque] = defaultdict(deque)
        self.active_offenses: List[Dict[str, Any]] = []
        self.total_events_analyzed = 0
        self.total_offenses_generated = 0

    def _load_rules(self, rules_file: Optional[str]) -> List[Dict[str, Any]]:
        if rules_file and os.path.exists(rules_file):
            try:
                with open(rules_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("rules", [])
            except Exception as e:
                print(f"[QRadarEngine] Warning: Failed to load {rules_file} ({e}), using defaults.")

        # Default rules mirror qradar_rules.json
        return [
            {
                "id": "QR-RULE-101",
                "name": "EHR: Unauthorized Staff Viewing Patient Chart",
                "severity": 7,
                "credibility": 8,
                "relevance": 9,
                "tags": ["HIPAA Section 164.312(a)(1)", "Minimum Necessary Rule"]
            },
            {
                "id": "QR-RULE-102",
                "name": "EHR: Bulk Patient Record Download / Exfiltration Anomaly",
                "severity": 9,
                "credibility": 9,
                "relevance": 10,
                "tags": ["HIPAA Section 164.312(b)", "Breach Notification Rule"]
            },
            {
                "id": "QR-RULE-103",
                "name": "EHR: VIP or High-Profile Patient Record Snooping",
                "severity": 8,
                "credibility": 8,
                "relevance": 9,
                "tags": ["HIPAA Section 164.502", "Privacy Rule"]
            },
            {
                "id": "QR-RULE-104",
                "name": "EHR: Off-Hours High-Volume EHR Query Anomaly",
                "severity": 7,
                "credibility": 7,
                "relevance": 8,
                "tags": ["HIPAA Section 164.308(a)(1)(ii)(D)", "Audit Review"]
            },
            {
                "id": "QR-RULE-105",
                "name": "EHR: Multi-Patient Sequential Crawling / Automated Scraping",
                "severity": 8,
                "credibility": 8,
                "relevance": 9,
                "tags": ["HIPAA Section 164.312(e)(1)", "Transmission Security"]
            }
        ]

    def _parse_timestamp(self, ts_str: Optional[str]) -> datetime:
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.now(timezone.utc)

    def _update_sliding_window(self, user_id: str, ts: datetime, event_id: str, patient_id: str, action: str):
        cutoff = ts.timestamp() - 300  # 5-minute rolling window
        dq = self.user_event_window[user_id]
        dq.append((ts.timestamp(), event_id, patient_id, action))
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def evaluate_event(self, event: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Evaluates an EHR security event against QRadar CRE rules.
        Returns:
            (triggered_offenses, enriched_event)
        """
        self.total_events_analyzed += 1
        triggered_offenses: List[Dict[str, Any]] = []

        event_id = event.get("event_id", str(uuid.uuid4()))
        user_id = event.get("user_id", "unknown_user")
        user_role = str(event.get("user_role", "")).lower()
        action = str(event.get("action", ""))
        patient_id = event.get("patient_id", "")
        authorized = event.get("authorized", True)
        ts = self._parse_timestamp(event.get("timestamp"))

        # Update sliding window state
        self._update_sliding_window(user_id, ts, event_id, patient_id, action)
        recent_window = list(self.user_event_window[user_id])

        # -------------------------------------------------------------
        # Rule 101: Unauthorized Staff Viewing Patient Chart
        # -------------------------------------------------------------
        if action in ("view_chart", "edit_chart") and (not authorized or user_role not in ("physician", "nurse")):
            offense = self._create_offense(
                rule_id="QR-RULE-101",
                rule_name="EHR: Unauthorized Staff Viewing Patient Chart",
                description=f"Staff member {user_id} ({user_role}) attempted unauthorized {action} on chart {patient_id}",
                severity=7,
                credibility=8,
                relevance=9,
                source_ip=event.get("source_ip", "10.240.12.55"),
                indexed_by={"user_id": user_id, "patient_id": patient_id},
                event_ids=[event_id],
                tags=["HIPAA Section 164.312(a)(1)", "Minimum Necessary Rule"]
            )
            triggered_offenses.append(offense)

        # -------------------------------------------------------------
        # Rule 102: Bulk Patient Record Download / Exfiltration
        # -------------------------------------------------------------
        bulk_actions_count = sum(1 for item in recent_window if item[3] in ("bulk_download", "export_records"))
        if action in ("bulk_download", "export_records"):
            if not authorized or bulk_actions_count >= 3:
                offense = self._create_offense(
                    rule_id="QR-RULE-102",
                    rule_name="EHR: Bulk Patient Record Download / Exfiltration Anomaly",
                    description=f"Mass exfiltration / bulk download detected for user {user_id} ({bulk_actions_count} downloads in 5m)",
                    severity=9,
                    credibility=9,
                    relevance=10,
                    source_ip=event.get("source_ip", "10.240.14.88"),
                    indexed_by={"user_id": user_id},
                    event_ids=[item[1] for item in recent_window if item[3] in ("bulk_download", "export_records")],
                    tags=["HIPAA Section 164.312(b)", "Breach Notification Rule"]
                )
                triggered_offenses.append(offense)

        # -------------------------------------------------------------
        # Rule 103: VIP / High-Profile Patient Record Snooping
        # -------------------------------------------------------------
        if patient_id in self.vip_patients and action in ("view_chart", "view_prescription", "view_lab_result", "query_patient_search"):
            assigned_team = self.patient_care_teams.get(patient_id, set())
            if user_id not in assigned_team or not authorized:
                offense = self._create_offense(
                    rule_id="QR-RULE-103",
                    rule_name="EHR: VIP or High-Profile Patient Record Snooping",
                    description=f"Unauthorized staff {user_id} ({user_role}) accessed VIP patient {patient_id} record without care team assignment",
                    severity=8,
                    credibility=8,
                    relevance=9,
                    source_ip=event.get("source_ip", "10.240.12.90"),
                    indexed_by={"patient_id": patient_id, "user_id": user_id},
                    event_ids=[event_id],
                    tags=["HIPAA Section 164.502", "Privacy Rule"]
                )
                triggered_offenses.append(offense)

        # -------------------------------------------------------------
        # Rule 104: Off-Hours High-Volume EHR Query Anomaly (22:00-05:00 UTC)
        # -------------------------------------------------------------
        hour = ts.hour
        is_off_hours = (hour >= 22 or hour < 5)
        if is_off_hours and action in ("view_chart", "query_patient_search", "bulk_download", "export_records"):
            if not authorized or user_role in ("billing_clerk", "lab_tech", "pharmacist"):
                offense = self._create_offense(
                    rule_id="QR-RULE-104",
                    rule_name="EHR: Off-Hours High-Volume EHR Query Anomaly",
                    description=f"Suspicious off-hours ({hour:02d}:00 UTC) access attempt by {user_id} ({user_role}) for {action}",
                    severity=7,
                    credibility=7,
                    relevance=8,
                    source_ip=event.get("source_ip", "192.168.1.105"),
                    indexed_by={"user_id": user_id},
                    event_ids=[event_id],
                    tags=["HIPAA Section 164.308(a)(1)(ii)(D)", "Audit Review"]
                )
                triggered_offenses.append(offense)

        # -------------------------------------------------------------
        # Rule 105: Multi-Patient Sequential Crawling / Automated Scraping
        # -------------------------------------------------------------
        cutoff_60s = ts.timestamp() - 60
        patients_in_60s = {item[2] for item in recent_window if item[0] >= cutoff_60s and item[2]}
        if len(patients_in_60s) >= 4 and action in ("view_chart", "query_patient_search", "view_prescription"):
            offense = self._create_offense(
                rule_id="QR-RULE-105",
                rule_name="EHR: Multi-Patient Sequential Crawling / Automated Scraping",
                description=f"Automated scraping pattern: user {user_id} queried {len(patients_in_60s)} distinct patient records in <60s",
                severity=8,
                credibility=8,
                relevance=9,
                source_ip=event.get("source_ip", "10.240.19.12"),
                indexed_by={"user_id": user_id},
                event_ids=[item[1] for item in recent_window if item[0] >= cutoff_60s],
                tags=["HIPAA Section 164.312(e)(1)", "Transmission Security"]
            )
            triggered_offenses.append(offense)

        # Build enriched event payload
        enriched_event = dict(event)
        enriched_event["qradar_analyzed"] = True
        enriched_event["qradar_offense_count"] = len(triggered_offenses)
        enriched_event["qradar_offense_ids"] = [o["offense_id"] for o in triggered_offenses]
        if triggered_offenses:
            enriched_event["max_severity"] = max(o["severity"] for o in triggered_offenses)
            enriched_event["compliance_violations"] = list({t for o in triggered_offenses for t in o["compliance_tags"]})
        else:
            enriched_event["max_severity"] = 1
            enriched_event["compliance_violations"] = []

        return triggered_offenses, enriched_event

    def _create_offense(
        self,
        rule_id: str,
        rule_name: str,
        description: str,
        severity: int,
        credibility: int,
        relevance: int,
        source_ip: str,
        indexed_by: Dict[str, Any],
        event_ids: List[str],
        tags: List[str]
    ) -> Dict[str, Any]:
        self.total_offenses_generated += 1
        magnitude = int(round((severity + credibility + relevance) / 3.0))

        offense = {
            "offense_id": f"OFF-{self.total_offenses_generated:05d}",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "rule_id": rule_id,
            "rule_name": rule_name,
            "description": description,
            "severity": severity,
            "credibility": credibility,
            "relevance": relevance,
            "magnitude": magnitude,
            "status": "OPEN",
            "source_ip": source_ip,
            "indexed_by": indexed_by,
            "events_correlated": list(set(event_ids)),
            "event_count": len(event_ids),
            "compliance_tags": tags,
        }
        self.active_offenses.append(offense)
        return offense

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_events_analyzed": self.total_events_analyzed,
            "total_offenses_generated": self.total_offenses_generated,
            "active_offenses": len(self.active_offenses),
            "rules_loaded": len(self.rules),
        }
