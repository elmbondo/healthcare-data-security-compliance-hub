"""
End-to-End Integration Test: Cybersecurity Events -> DataStage Pipeline Validation
Tests that all QRadar and Guardium threat scenarios emit valid events
consumable by Fidelmah's DataStage pipeline validator.

Author: Joyline Kamoing (Cybersecurity Track)
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from pipeline.pipeline_validator import run_pipeline
from security.threat_ingestion import ThreatIngestionService
from security.threat_scenarios import ALL_SCENARIOS


class TestPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.service = ThreatIngestionService()

    def test_all_scenarios_produce_valid_datastage_records(self):
        """Every threat scenario event should parse cleanly into DataStage schema."""
        for scenario_name, generator in ALL_SCENARIOS.items():
            events = generator()
            for event in events:
                result = self.service.process_security_event(event, send_kafka=False)
                enriched = result["enriched_event"]

                # Target Kafka payload formatted for DataStage ingestion
                kafka_payload = {
                    "event_id": enriched.get("event_id"),
                    "timestamp": enriched.get("timestamp"),
                    "user_id": enriched.get("user_id"),
                    "user_role": enriched.get("user_role"),
                    "action": enriched.get("action"),
                    "patient_id": enriched.get("patient_id"),
                    "record_type": enriched.get("record_type"),
                    "authorized": enriched.get("authorized"),
                    "source_system": enriched.get("source_system", "qradar_guardium_stream"),
                }

                raw_bytes = json.dumps(kafka_payload).encode("utf-8")
                pipeline_result = run_pipeline(raw_bytes)

                self.assertNotEqual(
                    pipeline_result["status"],
                    "DROPPED",
                    f"Event from {scenario_name} was unexpectedly DROPPED by DataStage parser: {pipeline_result['issues']}"
                )

                # Check that fields conform to target schema
                norm = pipeline_result["event"]
                self.assertIsNotNone(norm["event_id"])
                self.assertIsNotNone(norm["timestamp"])
                self.assertIsNotNone(norm["user_id"])
                self.assertIsNotNone(norm["user_role"])
                self.assertIsNotNone(norm["action"])
                self.assertIsNotNone(norm["patient_id"])
                self.assertIsNotNone(norm["record_type"])
                self.assertIsInstance(norm["authorized"], bool)


if __name__ == "__main__":
    unittest.main()
