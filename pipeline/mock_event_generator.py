"""
Mock Healthcare Security Event Generator

Simulates QRadar/Guardium-style events (EHR access, clinician logins,
patient portal auth, prescription record access) and publishes them
to a local Kafka topic for DataStage pipeline testing.

Setup:
    pip install kafka-python

Usage:
    python mock_event_generator.py                 # 50 events, 0.5s apart
    python mock_event_generator.py --count 200      # 200 events
    python mock_event_generator.py --rate 0         # fire as fast as possible
    python mock_event_generator.py --anomaly-rate 0.3   # 30% anomalous events
"""

import argparse
import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone

from kafka import KafkaProducer


# Reference data used to build realistic-looking events

USER_ROLES = ["physician", "nurse", "lab_tech", "billing_clerk", "admin", "pharmacist"]

ACTIONS = [
    "view_chart",
    "edit_chart",
    "view_prescription",
    "create_prescription",
    "bulk_download",
    "login",
    "logout",
    "view_lab_result",
    "query_patient_search",
    "export_records",
]

RECORD_TYPES = ["EHR", "prescription", "lab_result", "portal_auth", "billing"]

# Actions a role is normally allowed to do. Anything outside this map,or done by an "unauthorized" flag, represents the anomalous case.
ROLE_ALLOWED_ACTIONS = {
    "physician": {"view_chart", "edit_chart", "view_prescription", "create_prescription",
                  "view_lab_result", "login", "logout", "query_patient_search"},
    "nurse": {"view_chart", "view_prescription", "view_lab_result", "login", "logout",
              "query_patient_search"},
    "lab_tech": {"view_lab_result", "login", "logout"},
    "billing_clerk": {"login", "logout", "query_patient_search"},
    "pharmacist": {"view_prescription", "create_prescription", "login", "logout"},
    "admin": {"login", "logout", "export_records", "bulk_download", "query_patient_search"},
}

ANOMALOUS_ACTIONS = {"bulk_download", "export_records"}


def random_timestamp(anomalous: bool) -> str:
    """Anomalous events are more likely to land off-hours (10pm-5am)."""
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

    if is_anomalous:
        # Either pick an action outside this role's normal permissions, or pick a naturally high-risk action (bulk download / export).
        if random.random() < 0.5:
            outside = [a for a in ACTIONS if a not in ROLE_ALLOWED_ACTIONS[role]]
            action = random.choice(outside) if outside else random.choice(list(ANOMALOUS_ACTIONS))
        else:
            action = random.choice(list(ANOMALOUS_ACTIONS))
        authorized = False
    else:
        action = random.choice(list(ROLE_ALLOWED_ACTIONS[role]))
        authorized = True

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": random_timestamp(is_anomalous),
        "user_id": f"user_{random.randint(1000, 9999)}",
        "user_role": role,
        "action": action,
        "patient_id": f"pt_{random.randint(10000, 99999)}",
        "record_type": random.choice(RECORD_TYPES),
        "authorized": authorized,
    }

    # Occasionally inject an incomplete record so the DataStage quality-check step has something real to catch.
    if random.random() < 0.05:
        drop_field = random.choice(["user_id", "patient_id", "timestamp"])
        event.pop(drop_field, None)

    return event


def main():
    parser = argparse.ArgumentParser(description="Generate mock healthcare security events onto Kafka.")
    parser.add_argument("--bootstrap-server", default="localhost:9092")
    parser.add_argument("--topic", default="healthcare-security-events")
    parser.add_argument("--count", type=int, default=50, help="Number of events to send")
    parser.add_argument("--rate", type=float, default=0.5, help="Seconds to sleep between events (0 = no delay)")
    parser.add_argument("--anomaly-rate", type=float, default=0.25,
                         help="Fraction of events that should be anomalous/unauthorized (0.0-1.0)")
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