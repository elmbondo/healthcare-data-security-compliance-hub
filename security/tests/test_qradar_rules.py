"""
Unit tests for QRadar SIEM Custom Rules Engine & Anomaly Detection
Author: Joyline Kamoing (Cybersecurity Track)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from security.qradar.qradar_engine import QRadarEngine


class TestQRadarRules(unittest.TestCase):
    def setUp(self):
        self.engine = QRadarEngine()

    def test_unauthorized_chart_view_triggers_rule_101(self):
        """Rule 101 should trigger when billing clerk or unassigned staff views chart."""
        event = {
            "event_id": "evt-001",
            "timestamp": "2026-09-22T14:30:00Z",
            "user_id": "user_billing_99",
            "user_role": "billing_clerk",
            "action": "view_chart",
            "patient_id": "pt_10001",
            "record_type": "EHR",
            "authorized": False,
        }
        offenses, enriched = self.engine.evaluate_event(event)
        self.assertTrue(len(offenses) >= 1)
        rule_ids = [o["rule_id"] for o in offenses]
        self.assertIn("QR-RULE-101", rule_ids)
        self.assertEqual(enriched["max_severity"], 7)
        self.assertIn("HIPAA Section 164.312(a)(1)", enriched["compliance_violations"])

    def test_authorized_physician_chart_view_generates_no_offense(self):
        """Authorized physician chart view should NOT trigger offenses."""
        event = {
            "event_id": "evt-002",
            "timestamp": "2026-09-22T10:15:00Z",
            "user_id": "user_physician_01",
            "user_role": "physician",
            "action": "view_chart",
            "patient_id": "pt_10001",
            "record_type": "EHR",
            "authorized": True,
        }
        offenses, enriched = self.engine.evaluate_event(event)
        self.assertEqual(len(offenses), 0)
        self.assertEqual(enriched["max_severity"], 1)

    def test_bulk_download_triggers_rule_102(self):
        """Unauthorized bulk download should trigger Rule 102 (High severity 9)."""
        event = {
            "event_id": "evt-003",
            "timestamp": "2026-09-22T11:00:00Z",
            "user_id": "user_nurse_44",
            "user_role": "nurse",
            "action": "bulk_download",
            "patient_id": "pt_20001",
            "record_type": "EHR",
            "authorized": False,
        }
        offenses, enriched = self.engine.evaluate_event(event)
        self.assertTrue(any(o["rule_id"] == "QR-RULE-102" for o in offenses))
        self.assertEqual(enriched["max_severity"], 9)

    def test_vip_snooping_triggers_rule_103(self):
        """Accessing VIP patient (pt_99999) by non-care-team member triggers Rule 103."""
        event = {
            "event_id": "evt-004",
            "timestamp": "2026-09-22T13:45:00Z",
            "user_id": "user_labtech_12",
            "user_role": "lab_tech",
            "action": "view_chart",
            "patient_id": "pt_99999",
            "record_type": "EHR",
            "authorized": False,
        }
        offenses, enriched = self.engine.evaluate_event(event)
        rule_ids = [o["rule_id"] for o in offenses]
        self.assertIn("QR-RULE-103", rule_ids)

    def test_off_hours_access_triggers_rule_104(self):
        """Off-hours unauthorized access (e.g. 23:30 UTC) triggers Rule 104."""
        event = {
            "event_id": "evt-005",
            "timestamp": "2026-09-22T23:30:00Z",
            "user_id": "user_billing_88",
            "user_role": "billing_clerk",
            "action": "query_patient_search",
            "patient_id": "pt_10005",
            "record_type": "EHR",
            "authorized": False,
        }
        offenses, enriched = self.engine.evaluate_event(event)
        rule_ids = [o["rule_id"] for o in offenses]
        self.assertIn("QR-RULE-104", rule_ids)


if __name__ == "__main__":
    unittest.main()
