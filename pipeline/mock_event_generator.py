"""
Mock Healthcare Security Event Generator (v2 - grounded in Sita Sector reference model)
Simulates QRadar/Guardium-style access events against the real healthtech
data model from the sector reference codebase (Patient, Encounter,
LabResult, Referral), not a generic invented schema.

Setup:
    pip install kafka-python

Usage:
    python mock_event_generator.py
    python mock_event_generator.py --count 200
    python mock_event_generator.py --anomaly-rate 0.3
"""

import argparse
import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone

from kafka import KafkaProducer

# Reference data, grounded in the real models (patient.py, encounter.py,
# lab_result.py, referral.py)

USER_ROLES = ["physician", "nurse", "lab_tech", "billing_clerk", "admin", "pharmacist"]

# record_type now matches the real model names exactly
RECORD_TYPES = ["patient", "encounter", "lab_result", "referral"]

# actions grounded in what each model actually supports
ACTIONS_BY_RECORD_TYPE = {
    "patient": ["view_patient", "edit_patient", "mdm_resolve"],
    "encounter": ["view_encounter", "edit_encounter", "create_encounter"],
    "lab_result": ["view_lab_result", "create_lab_result"],
    "referral": ["view_referral", "dispatch_referral"],
}

# Which actions a role would normally perform, across record types
ROLE_ALLOWED_ACTIONS = {
    "physician": {"view_patient", "edit_patient", "view_encounter", "edit_encounter",
                  "create_encounter", "view_lab_result", "view_referral", "dispatch_referral"},
    "nurse": {"view_patient", "view_encounter", "view_lab_result", "view_referral"},
    "lab_tech": {"view_lab_result", "create_lab_result"},
    "billing_clerk": {"view_patient", "view_encounter"},
    "pharmacist": {"view_patient", "view_lab_result"},
    "admin": {"view_patient", "edit_patient", "mdm_resolve", "view_referral",
              "dispatch_referral", "view_encounter", "view_lab_result"},
}

# High-risk regardless of role: bulk/cross-facility operations
ANOMALOUS_ACTIONS = {"mdm_resolve", "dispatch_referral", "edit_patient"}

FACILITY_IDS = [f"FAC-{n:03d}" for n in range(1, 16)]


def random_timestamp(anomalous: bool) -> str:
    now = datetime.now(timezone.utc)
    if anomalous and random.random() < 0.6:
        hour = random.choice(list(range(22, 24)) + list(range(0, 5)))
        base = now.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
    else:
        hour = random.randint(6, 21)
        base = now.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
    base -= timedelta(days=random.randint(0, 3))
    return base.isoformat()


def make_event(anomaly_rate: float) -> dict:
    is_anomalous = random.random() < anomaly_rate
    role = random.choice(USER_ROLES)
    record_type = random.choice(RECORD_TYPES)

    if is_anomalous:
        if random.random() < 0.5:
            outside = [a for a in ACTIONS_BY_RECORD_TYPE[record_type]
                       if a not in ROLE_ALLOWED_ACTIONS[role]]
            action = random.choice(outside) if outside else random.choice(list(ANOMALOUS_ACTIONS))
        else:
            candidates = [a for a in ANOMALOUS_ACTIONS if a in ACTIONS_BY_RECORD_TYPE[record_type]]
            action = random.choice(candidates) if candidates else random.choice(ACTIONS_BY_RECORD_TYPE[record_type])
        authorized = False
    else:
        allowed = [a for a in ACTIONS_BY_RECORD_TYPE[record_type] if a in ROLE_ALLOWED_ACTIONS[role]]
        if not allowed:
            allowed = ACTIONS_BY_RECORD_TYPE[record_type]
        action = random.choice(allowed)
        authorized = True

    # Real UUIDs, matching the model's primary key types
    record_id = str(uuid.uuid4())

    # ~30% of patient-record events simulate an MDM-resolved "golden" patient
    # (cross-facility identity)- these carry higher inherent risk if accessed without authorization, per mdm_sync.py's golden_id concept
    is_golden = record_type == "patient" and random.random() < 0.3

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": random_timestamp(is_anomalous),
        "user_id": f"clinician_{random.randint(1000, 9999)}",
        "user_role": role,
        "action": action,
        "record_type": record_type,
        "record_id": record_id,
        "facility_id": random.choice(FACILITY_IDS),
        "golden_id": f"GOLDEN-{random.randint(100000, 999999)}" if is_golden else None,
        "authorized": authorized,
    }

    # Occasionally inject a malformed / incomplete record for the quality
    # check stage to catch
    if random.random() < 0.05:
        drop_field = random.choice(["user_id", "record_id", "timestamp"])
        event.pop(drop_field, None)

    return event


def main():
    parser = argparse.ArgumentParser(description="Generate mock healthcare security events onto Kafka.")
    parser.add_argument("--bootstrap-server", default="localhost:9092")
    parser.add_argument("--topic", default="healthcare-security-events")
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--rate", type=float, default=0.5)
    parser.add_argument("--anomaly-rate", type=float, default=0.25)
    args = parser.parse_args()

    producer = KafkaProducer(
        bootstrap_servers=args.bootstrap_server,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    print(f"Sending {args.count} events to topic '{args.topic}' "
          f"(anomaly rate: {args.anomaly_rate:.0%})...\n")

    sent, anomalous_sent = 0, 0
    try:
        for i in range(args.count):
            event = make_event(args.anomaly_rate)
            producer.send(args.topic, value=event)
            sent += 1
            if not event.get("authorized", True):
                anomalous_sent += 1

            flag = "ANOMALY" if not event.get("authorized", True) else "normal "
            print(f"[{i+1}/{args.count}] ({flag}) {event}")

            if args.rate > 0:
                time.sleep(args.rate)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        producer.flush()
        producer.close()

    print(f"\nDone. Sent {sent} events ({anomalous_sent} anomalous / unauthorized).")


if __name__ == "__main__":
    main()