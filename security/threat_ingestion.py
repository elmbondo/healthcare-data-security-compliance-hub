"""
Unified Threat Ingestion & Kafka Event Forwarder (Joyline)
----------------------------------------------------------
Coordinates QRadar SIEM rule evaluation and Guardium DAM real-time PHI masking,
forwarding correlated security intelligence into the Kafka topic
'healthcare-security-events' for DataStage ingestion and watsonx.data loading.

Author: Joyline Kamoing (Cybersecurity Track)
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure project paths are resolvable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security.qradar.qradar_engine import QRadarEngine
from security.guardium.guardium_engine import GuardiumEngine
from security.threat_scenarios import ALL_SCENARIOS


def format_json(obj: Any) -> str:
    return json.dumps(obj, indent=2)


class ThreatIngestionService:
    def __init__(self, bootstrap_server: str = "localhost:9092", topic: str = "healthcare-security-events"):
        self.bootstrap_server = bootstrap_server
        self.topic = topic
        self.qradar = QRadarEngine()
        self.guardium = GuardiumEngine()
        self.producer = None

    def init_kafka(self) -> bool:
        try:
            from kafka import KafkaProducer
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_server,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                request_timeout_ms=5000,
            )
            print(f"[ThreatIngestion] Connected to Kafka broker at {self.bootstrap_server}, topic: '{self.topic}'")
            return True
        except Exception as e:
            print(f"[ThreatIngestion] Notice: Kafka connection to {self.bootstrap_server} failed ({e}).")
            print("[ThreatIngestion] Continuing in dry-run simulation mode.")
            self.producer = None
            return False

    def process_security_event(self, raw_event: Dict[str, Any], send_kafka: bool = False) -> Dict[str, Any]:
        """
        Executes full security pipeline:
        1. Guardium S-TAP Query Inspection & Dynamic PHI Masking
        2. QRadar SIEM CRE Rule Evaluation & Offense Correlation
        3. Event Enactment & Kafka Forwarding
        """
        event = dict(raw_event)
        sql_query = event.get("sql_query")
        user_role = event.get("user_role", "guest")
        user_id = event.get("user_id", "unknown_user")
        patient_id = event.get("patient_id")
        client_ip = event.get("source_ip", "10.240.10.1")

        guardium_result = None
        if sql_query:
            guardium_result = self.guardium.execute_monitored_query(
                sql_query=sql_query,
                db_user=user_id,
                user_role=user_role,
                client_ip=client_ip,
                target_patient_id=patient_id if patient_id != "pt_all" else None
            )

        # QRadar CRE rule evaluation
        offenses, enriched_event = self.qradar.evaluate_event(event)

        # Attach Guardium telemetry
        if guardium_result:
            enriched_event["guardium_status"] = guardium_result.get("status")
            enriched_event["phi_masked_cells"] = guardium_result.get("masked_fields_count", 0)
            if guardium_result.get("guardium_alert"):
                enriched_event["guardium_alert_id"] = guardium_result["guardium_alert"]["alert_id"]
                enriched_event["guardium_policy"] = guardium_result["guardium_alert"]["policy_name"]

        # Forward to Kafka if requested & producer available
        if send_kafka and self.producer:
            # Send the clean schema-compliant event (matching DataStage / pipeline validator requirements)
            kafka_payload = {
                "event_id": enriched_event.get("event_id"),
                "timestamp": enriched_event.get("timestamp"),
                "user_id": enriched_event.get("user_id"),
                "user_role": enriched_event.get("user_role"),
                "action": enriched_event.get("action"),
                "patient_id": enriched_event.get("patient_id"),
                "record_type": enriched_event.get("record_type"),
                "authorized": enriched_event.get("authorized"),
                "source_system": enriched_event.get("source_system", "qradar_guardium_stream"),
            }
            try:
                self.producer.send(self.topic, value=kafka_payload)
            except Exception as e:
                print(f"[ThreatIngestion] Kafka send error: {e}")

        return {
            "enriched_event": enriched_event,
            "offenses": offenses,
            "guardium_result": guardium_result,
        }

    def run_scenario(self, scenario_name: str, send_kafka: bool = False):
        print(f"\n{'='*75}")
        print(f"  EXECUTING THREAT SCENARIO: {scenario_name.upper()}")
        print(f"{'='*75}")

        generator = ALL_SCENARIOS.get(scenario_name)
        if not generator:
            print(f"Unknown scenario: {scenario_name}. Available: {list(ALL_SCENARIOS.keys())}")
            return

        events = generator()
        for idx, event in enumerate(events, 1):
            print(f"\n--- [Event {idx}/{len(events)}] User: {event['user_id']} ({event['user_role']}) | Action: {event['action']} | Patient: {event.get('patient_id')} ---")
            print(f"Raw Scenario Detail: {event.get('details')}")
            if event.get("sql_query"):
                print(f"Executing SQL: {event['sql_query']}")

            result = self.process_security_event(event, send_kafka=send_kafka)
            guardium_res = result["guardium_result"]
            offenses = result["offenses"]

            # Display Guardium S-TAP & Masking status
            if guardium_res:
                if guardium_res["status"] == "BLOCKED":
                    print(f"[BLOCKED] GUARDIUM S-TAP ACTION: BLOCKED! {guardium_res.get('error')}")
                    print(f"   Alert: {guardium_res['guardium_alert']['policy_name']} [Severity: {guardium_res['guardium_alert']['severity']}]")
                else:
                    masked_count = guardium_res.get("masked_fields_count", 0)
                    print(f"[PROTECTED] GUARDIUM DDM STATUS: {guardium_res['status']} ({masked_count} PHI fields masked)")
                    if guardium_res.get("rows"):
                        first_row = guardium_res["rows"][0]
                        print(f"   Sample Result Row:")
                        for k, v in first_row.items():
                            print(f"     - {k}: {v}")

            # Display QRadar SIEM Offense status
            if offenses:
                print(f"[ALERT] QRADAR SIEM OFFENSES TRIGGERED: {len(offenses)}")
                for off in offenses:
                    print(f"   * [{off['offense_id']}] {off['rule_name']} (Magnitude: {off['magnitude']}/10, Severity: {off['severity']}/10)")
                    print(f"     Description: {off['description']}")
                    print(f"     Compliance Tags: {', '.join(off['compliance_tags'])}")
            else:
                print("[OK] QRADAR SIEM: No offenses triggered (Authorized / Normal traffic).")

        if send_kafka and self.producer:
            self.producer.flush()

    def print_summary(self):
        q_sum = self.qradar.get_summary()
        g_sum = self.guardium.get_summary()
        print(f"\n{'='*75}")
        print("  JOYLINE'S CYBERSECURITY ENGINE EXECUTION SUMMARY")
        print(f"{'='*75}")
        print(f"Total Events Analyzed by QRadar SIEM: {q_sum['total_events_analyzed']}")
        print(f"Total QRadar Offenses Generated:       {q_sum['total_offenses_generated']}")
        print(f"Total Database Queries Intercepted:   {g_sum['total_queries_monitored']}")
        print(f"Total Queries Protected by PHI Mask:  {g_sum['total_masked_queries']}")
        print(f"Total Guardium Security Alerts:       {g_sum['total_alerts']}")
        print(f"{'='*75}\n")


def main():
    parser = argparse.ArgumentParser(description="Healthcare Threat Ingestion & SIEM Analysis Service (Joyline)")
    parser.add_argument("--scenario", default="all", choices=list(ALL_SCENARIOS.keys()) + ["all"],
                        help="Attack scenario to simulate")
    parser.add_argument("--mode", default="dry-run", choices=["dry-run", "kafka"],
                        help="Run mode: dry-run or send live to Kafka broker")
    parser.add_argument("--bootstrap-server", default="localhost:9092",
                        help="Kafka bootstrap server")
    parser.add_argument("--topic", default="healthcare-security-events",
                        help="Kafka topic for compliance data ingestion")
    args = parser.parse_args()

    service = ThreatIngestionService(bootstrap_server=args.bootstrap_server, topic=args.topic)
    send_kafka = (args.mode == "kafka")

    if send_kafka:
        service.init_kafka()

    scenarios_to_run = list(ALL_SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]

    print("==========================================================================")
    print("  Healthcare Data Security & Compliance Hub - Cybersecurity Track")
    print("  Engineer: Joyline Kamoing (IBM watsonx.ai Phase 3 / Team 2)")
    print("==========================================================================")

    for scn in scenarios_to_run:
        service.run_scenario(scn, send_kafka=send_kafka)
        time.sleep(0.3)

    service.print_summary()


if __name__ == "__main__":
    main()
