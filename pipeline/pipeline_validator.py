"""
Local Pipeline Validator (DataStage logic dry-run) - v2
Updated to validate against the real Sita Sector healthtech schema
(record_type/record_id/facility_id/golden_id) instead of the earlier
generic invented fields.

Setup:
    pip install kafka-python

Usage:
    python pipeline_validator.py
    python pipeline_validator.py --max-events 100
    python pipeline_validator.py --from-beginning
"""

import argparse
import json
from datetime import datetime, timezone

from kafka import KafkaConsumer

# Schema definition, grounded in the real reference models

REQUIRED_FIELDS = ["event_id", "timestamp", "user_id", "user_role",
                    "action", "record_type", "record_id", "facility_id", "authorized"]

VALID_ROLES = {"physician", "nurse", "lab_tech", "billing_clerk", "admin", "pharmacist"}
VALID_RECORD_TYPES = {"patient", "encounter", "lab_result", "referral"}
VALID_ACTIONS = {
    "view_patient", "edit_patient", "mdm_resolve",
    "view_encounter", "edit_encounter", "create_encounter",
    "view_lab_result", "create_lab_result",
    "view_referral", "dispatch_referral",
}


# Step 1: Parse

def parse_event(raw_bytes: bytes):
    try:
        event = json.loads(raw_bytes.decode("utf-8"))
        return event, None
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return None, f"parse_error: {e}"

# Step 2: Cleanse / standardize

def cleanse_event(event: dict):
    notes = []

    ts = event.get("timestamp")
    if ts:
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            event["timestamp"] = dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            notes.append(f"unparseable_timestamp: {ts!r}")

    if "user_role" in event and isinstance(event["user_role"], str):
        event["user_role"] = event["user_role"].strip().lower()

    if "record_type" in event and isinstance(event["record_type"], str):
        event["record_type"] = event["record_type"].strip().lower()

    if "action" in event and isinstance(event["action"], str):
        event["action"] = event["action"].strip().lower()

    if isinstance(event.get("authorized"), str):
        event["authorized"] = event["authorized"].strip().lower() in ("true", "1", "yes")

    return notes


# Step 3: Normalize schema

def normalize_event(event: dict) -> dict:
    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "user_id": event.get("user_id"),
        "user_role": event.get("user_role"),
        "action": event.get("action"),
        "record_type": event.get("record_type"),
        "record_id": event.get("record_id"),
        "facility_id": event.get("facility_id"),
        "golden_id": event.get("golden_id"),
        "authorized": event.get("authorized"),
        "source_system": event.get("source_system", "kafka_stream"),
    }


# Step 4: Quality check

def quality_check(event: dict):
    issues = []

    for field in REQUIRED_FIELDS:
        if event.get(field) in (None, ""):
            issues.append(f"missing_field:{field}")

    if event.get("user_role") and event["user_role"] not in VALID_ROLES:
        issues.append(f"invalid_role:{event['user_role']}")

    if event.get("record_type") and event["record_type"] not in VALID_RECORD_TYPES:
        issues.append(f"invalid_record_type:{event['record_type']}")

    if event.get("action") and event["action"] not in VALID_ACTIONS:
        issues.append(f"invalid_action:{event['action']}")

    if event.get("authorized") is not None and not isinstance(event["authorized"], bool):
        issues.append("invalid_authorized_type")

    return issues


# Risk tier (draft logic, matches datastage-design.md)

def compute_risk_tier(event: dict) -> str:
    if event.get("authorized"):
        return "low"
    if event.get("action") in ("mdm_resolve", "dispatch_referral") or event.get("golden_id"):
        return "high"
    return "medium"


# Pipeline runner

def run_pipeline(raw_bytes: bytes):
    event, parse_error = parse_event(raw_bytes)
    if parse_error:
        return {"status": "DROPPED", "stage": "parse", "issues": [parse_error], "event": None}

    cleanse_notes = cleanse_event(event)
    normalized = normalize_event(event)
    issues = quality_check(normalized)
    normalized["risk_tier"] = compute_risk_tier(normalized)

    status = "FLAGGED" if issues else "CLEAN"

    return {
        "status": status,
        "stage": "quality_check",
        "issues": cleanse_notes + issues,
        "event": normalized,
    }


def main():
    parser = argparse.ArgumentParser(description="Validate the local pipeline transform logic against Kafka events.")
    parser.add_argument("--bootstrap-server", default="localhost:9092")
    parser.add_argument("--topic", default="healthcare-security-events")
    parser.add_argument("--group-id", default="pipeline-validator")
    parser.add_argument("--max-events", type=int, default=None)
    parser.add_argument("--from-beginning", action="store_true")
    args = parser.parse_args()

    consumer = KafkaConsumer(
        args.topic,
        bootstrap_servers=args.bootstrap_server,
        group_id=args.group_id if not args.from_beginning else None,
        auto_offset_reset="earliest" if args.from_beginning else "latest",
        enable_auto_commit=True,
    )

    print(f"Listening on '{args.topic}' as consumer group '{args.group_id}'...")
    print("(waiting for events -- run mock_event_generator.py in another terminal if the topic is empty)\n")

    counts = {"CLEAN": 0, "FLAGGED": 0, "DROPPED": 0}
    processed = 0

    try:
        for message in consumer:
            result = run_pipeline(message.value)
            counts[result["status"]] += 1
            processed += 1

            tag = result["status"].ljust(7)
            if result["issues"]:
                print(f"[{processed}] {tag} | issues: {result['issues']} | event: {result['event']}")
            else:
                print(f"[{processed}] {tag} | event: {result['event']}")

            if args.max_events and processed >= args.max_events:
                break
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        consumer.close()

    print(f"\n--- Summary ---")
    print(f"Total processed: {processed}")
    print(f"Clean:   {counts['CLEAN']}")
    print(f"Flagged: {counts['FLAGGED']}")
    print(f"Dropped: {counts['DROPPED']}")


if __name__ == "__main__":
    main()