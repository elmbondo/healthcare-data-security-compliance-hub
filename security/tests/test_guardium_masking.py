"""
Unit tests for IBM Security Guardium Dynamic PHI Masking & Real-Time Monitoring
Author: Joyline Kamoing (Cybersecurity Track)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from security.guardium.guardium_engine import GuardiumEngine
from security.guardium.phi_masker import PHIMasker


class TestGuardiumMasking(unittest.TestCase):
    def setUp(self):
        self.engine = GuardiumEngine()

    def test_ssn_masking_for_nurse_vs_billing(self):
        """Billing clerk sees partial SSN, Nurse sees completely masked SSN."""
        raw_ssn = "123-45-6789"
        masked_nurse, was_masked_n = PHIMasker.mask_ssn(raw_ssn, role="nurse")
        self.assertEqual(masked_nurse, "XXX-XX-XXXX")
        self.assertTrue(was_masked_n)

        masked_billing, was_masked_b = PHIMasker.mask_ssn(raw_ssn, role="billing_clerk")
        self.assertEqual(masked_billing, "***-**-6789")
        self.assertFalse(was_masked_b)

    def test_medical_history_masking_for_billing_vs_physician(self):
        """Physician sees clinical history, Billing clerk sees redacted medical text."""
        raw_history = "Acute myocardial infarction, Type 2 Diabetes"
        masked_doc, was_masked_d = PHIMasker.mask_medical_history(raw_history, role="physician")
        self.assertEqual(masked_doc, raw_history)
        self.assertFalse(was_masked_d)

        masked_bill, was_masked_b = PHIMasker.mask_medical_history(raw_history, role="billing_clerk")
        self.assertIn("RESTRICTED MEDICAL HISTORY", masked_bill)
        self.assertTrue(was_masked_b)

    def test_guardium_sql_injection_blocking(self):
        """Guardium S-TAP blocks SQL injection queries and creates CRITICAL alert."""
        malicious_query = "SELECT * FROM ehr_patients WHERE patient_id = '' OR 1=1 --"
        res = self.engine.execute_monitored_query(
            sql_query=malicious_query,
            db_user="guest_user",
            user_role="guest",
        )
        self.assertEqual(res["status"], "BLOCKED")
        self.assertIsNotNone(res["guardium_alert"])
        self.assertEqual(res["guardium_alert"]["severity"], "CRITICAL")
        self.assertEqual(len(res["rows"]), 0)

    def test_guardium_monitored_query_with_dynamic_masking(self):
        """Monitored query returns dynamically masked rows for unauthorized roles."""
        query = "SELECT patient_id, full_name, ssn, diagnosis_code, medical_history FROM ehr_patients;"
        res = self.engine.execute_monitored_query(
            sql_query=query,
            db_user="user_clerk_1",
            user_role="billing_clerk",
            target_patient_id="pt_10001"
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res["masked_fields_count"] > 0)
        row = res["rows"][0]
        self.assertEqual(row["ssn"], "***-**-6789")
        self.assertIn("RESTRICTED MEDICAL HISTORY", row["medical_history"])


if __name__ == "__main__":
    unittest.main()
