# Handoff Notes - Pipeline & Data Layer (Fidelmah)

These notes cover the Kafka ingestion, mock event generation, and pipeline
transform validation work in `pipeline/`. The goal is that anyone (a
teammate, an instructor, or future-me) can pick this up, understand what
exists, why it was built this way, and how to run it, without needing to
ask.

## What this covers

- Local Kafka broker setup (Docker)
- Mock QRadar/Guardium-style event generator
- Local validation of the DataStage transform logic (parse, cleanse,
  normalize, quality check)

It does **not** yet cover the real DataStage job, watsonx.data/Iceberg
loading, or the Cognos dashboard - those are built directly in the
TechZone/Cloud Pak for Data environment, not locally, and will get their
own notes once built.

## Why things were built this way

- **DataStage has no free, offline local install** (unlike QRadar
  Community Edition). The only trial requires credit card information.
  So instead of installing DataStage locally, the transform *logic* was
  proven in a plain Python script that mirrors DataStage's stages
  exactly (parse → cleanse → normalize → quality check). This satisfies
  the "validate locally before using TechZone" instruction without
  needing DataStage itself to be local.
- **Synthetic/mock data** is used throughout, confirmed as the right
  approach for this project (not real-world datasets).
- **Kafka runs in Docker using KRaft mode** (no separate Zookeeper
  container) - simpler for local dev, one container instead of two.

## Setup

Requirements: Docker Desktop, Python 3.x, `pip install kafka-python`

1. From `pipeline/`, start Kafka:
   ```
   docker compose up -d
   ```
2. Create the topic (first time only):
   ```
   docker exec -it healthcare-kafka /opt/kafka/bin/kafka-topics.sh --create --topic healthcare-security-events --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
   ```
3. Generate mock events:
   ```
   python mock_event_generator.py --count 100 --rate 0.2 --anomaly-rate 0.3
   ```
4. Run the transform validation logic against them:
   ```
   python pipeline_validator.py --from-beginning
   ```

See comments at the top of each script for the full list of flags.

## What the mock event generator produces

Events shaped like QRadar/Guardium output: `event_id`, `timestamp`,
`user_id`, `user_role`, `action`, `patient_id`, `record_type`,
`authorized`.

Notable behavior (not just random data):
- Each `user_role` has a defined set of normally-allowed actions.
  Anomalous events either break that (wrong role doing an action) or hit
  inherently high-risk actions (`bulk_download`, `export_records`).
- Anomalous events are weighted toward off-hours (10pm–5am).
- ~5% of events have a randomly missing field, simulating real-world bad
  data, so the quality-check stage has something genuine to catch.

## What the pipeline validator proves

It mirrors the four DataStage stages the real job will need to perform:

1. **Parse** - decode raw JSON, catch malformed messages
2. **Cleanse** - standardize timestamps to UTC ISO-8601, lowercase
   roles, normalize casing, coerce `authorized` to a real boolean
3. **Normalize** - map everything to one common output schema
4. **Quality check** - flag missing required fields, invalid roles,
   invalid record types, bad data types

Each event is tagged `CLEAN`, `FLAGGED`, or `DROPPED`. Tested against
100+ events including a live continuous-mode run (validator listening
while the generator produced new events in real time), confirming it
works the way DataStage's continuous-mode Kafka connector will need to.

**Important distinction:** the quality check validates whether a record
is *well-formed*, not whether the *action* was authorized. An
unauthorized bulk download is a complete, valid record - it's a
security event for QRadar/Guardium to catch, not a data quality problem
for this layer to flag. Keeping these separate matches the division of
responsibility between the pipeline (Fidelmah) and threat detection
(Joyline).

## Known open items / not yet solved

- **Kafka reachability from TechZone**: once DataStage runs in
  TechZone (cloud), it can't reach `localhost:9092` on this laptop
  directly. Still need to resolve this - either run Kafka inside the
  TechZone/OpenShift environment itself, or tunnel the local Kafka out
  (e.g. ngrok). Not yet solved as of this write-up.
- **Sector reference table**: mentioned as existing somewhere for
  design guidance on the Healthcare sector data model. Location not yet
  confirmed - check with the instructor/supervisor before assuming the
  event schema above is final.

## Files in this folder

| File | Purpose |
|---|---|
| `docker-compose.yml` | Defines the local Kafka broker (KRaft mode) |
| `mock_event_generator.py` | Produces realistic mock security events onto the Kafka topic |
| `pipeline_validator.py` | Consumes from Kafka and runs the parse/cleanse/normalize/quality-check logic, printing per-event results and a summary |