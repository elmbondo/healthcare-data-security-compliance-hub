# Handoff Notes - Pipeline, watsonx.data & Dashboard (Fidelmah)

These notes cover the Kafka ingestion, mock event generation, pipeline
transform validation, watsonx.data (Apache Iceberg) loading, and the
Streamlit dashboard work. The goal is that anyone (a teammate, an
instructor, or future-me) can pick this up, understand what exists, why
it was built this way, and how to run it, without needing to ask.

## What this covers

- Local Kafka broker setup (Docker)
- Mock QRadar/Guardium-style event generator
- Local validation of the DataStage transform logic (parse, cleanse,
  normalize, quality check)
- watsonx.data Iceberg table creation and record loading
- Clinical Security Officer Dashboard (Streamlit) - deployed live
- End-to-end flow from event generation to dashboard visualization

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
- **The dashboard runs on Streamlit Community Cloud** rather than Cognos.
  This was a deliberate pivot after the TechZone reservation expired. See
  the "Dashboard Delivery" section below for details.

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

## watsonx.data Load Summary

The cleansed events were loaded into **IBM watsonx.data** backed by
**Apache Iceberg**:

- **Catalog:** `healthcare_security_catalog`
- **Schema:** `default`
- **Table:** `audit_log`
- **Partitioning:** by `event_date` for efficient temporal queries
- **Immutability:** append-only; no `UPDATE` or `DELETE` operations

The loader in `pipeline/watsonx_loader.py` connects via Presto and writes
records using environment variables for credentials (see `.env.example`).
The connection uses the watsonx.data Presto endpoint with basic auth.

Sample queries run against the table during the live reservation window
included:
- Daily violation trends (`event_date` grouping)
- Risk tier distribution (`risk_tier` breakdown)
- Top policy violators (`user_id`, `user_role` grouping)
- Audit investigation feed (last 25 high/critical events)

The full query definitions live in `docs/datastage-design.md` and are
also documented inline in `dashboard/dashboard_app.py`.

## Dashboard Delivery

The **Clinical Security Officer Dashboard** was originally planned for
IBM Cognos, but was delivered as a **Streamlit app** deployed to
Streamlit Community Cloud. This pivot happened after the TechZone
reservation expired and Cognos was no longer reachable.

- **Live URL:** https://clinical-compliance-dashboard.streamlit.app/
- **Source:** `dashboard/dashboard_app.py`
- **Dependencies:** `dashboard/requirements.txt`
  (`streamlit`, `pandas`, `plotly`)
- **Deployment:** Streamlit Community Cloud, connected to the project's
  GitHub repository, main branch, file path `dashboard/dashboard_app.py`

The dashboard displays real results pulled from watsonx.data while the
environment was live, including:
- Violation trends (daily and hourly)
- Risk tier breakdown (pie chart)
- Violation rate by facility (horizontal bar)
- Top policy violators (stacked bar by role)
- Audit investigation feed (recent medium/high risk events)

Each chart has the underlying SQL query documented in code comments so
the data source is transparent.

### Reconnecting to a Live Environment

The dashboard runs with `USE_LIVE_DATA = False`. When a new watsonx.data
environment is available:

1. Set `USE_LIVE_DATA = True` in `dashboard/dashboard_app.py`
2. Fill in the connection details in the `run_live_query()` function
   (host, port, user, API key)
3. Optionally store credentials as Streamlit secrets instead of
   hardcoding them

No other code changes are required to switch back to live queries.

## Final State & Known Limitations

**What works:**
- Local Kafka ingestion with synthetic realistic events
- 4-stage DataStage transform logic validated against live stream
- watsonx.data Iceberg table loaded with real audit events
- Compliance analytics queries returning correct results
- Streamlit dashboard deployed and publicly accessible
- All 10 unit and integration tests passing

**Known limitations:**
- The TechZone reservation for watsonx.data has expired, so the
  dashboard currently shows captured results rather than live queries.
  The `run_live_query()` function is ready to reconnect when a new
  environment is provisioned.
- Kafka reachability from TechZone was never solved. The workaround was
  to run Kafka locally and stream to watsonx.data during the live
  reservation window. For a fully cloud-native deployment, Kafka would
  need to run inside the OpenShift environment or be tunneled.
- The sector reference table mentioned in early planning was never
  formally located; the event schema was designed based on common
  healthcare data models (Patient, Encounter, LabResult, Referral) and
  cross-checked with Joyline's security scenarios.

## Files in this folder

| File | Purpose |
|---|---|
| `docker-compose.yml` | Defines the local Kafka broker (KRaft mode) |
| `mock_event_generator.py` | Produces realistic mock security events onto the Kafka topic |
| `pipeline_validator.py` | Consumes from Kafka and runs the parse/cleanse/normalize/quality-check logic, printing per-event results and a summary |
| `watsonx_loader.py` | Connects to watsonx.data and loads cleansed events into the `audit_log` Iceberg table |
| `.env.example` | Template for watsonx.data connection credentials |

## Related Documentation

- `docs/datastage-design.md` - DataStage stage design and Iceberg schema
- `docs/qradar-guardium-architecture.md` - Joyline's security track
- `dashboard/dashboard_app.py` - Streamlit dashboard source with inline SQL
- `README.md` - Project overview and end-to-end architecture