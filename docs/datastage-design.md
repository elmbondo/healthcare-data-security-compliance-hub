# DataStage job plan (before I actually have access)

Writing this up now while I wait on the environment, based on the logic
I already proved out in pipeline_validator.py. Idea is that when I
finally get into DataStage, I'm just rebuilding something I've already
figured out, not designing from scratch under time pressure.

## How the job should flow

Kafka connector pulls from `healthcare-security-events` in continuous
mode, same as I tested locally.

Then it goes through basically the same four stages as my Python script:

1. **Parse** - decode the JSON, send anything malformed to a reject link
   instead of crashing the job
2. **Cleanse** - fix up timestamps (UTC, ISO format), lowercase the
   user_role, normalize record_type casing, make sure authorized is an
   actual boolean and not a string
3. **Normalize** - map everything into one consistent schema regardless
   of which source it came from, add a source_system column
4. **Quality check** - flag records missing required fields or with
   invalid roles/types. These get routed to a "flagged" link, not just
   dropped

Then it loads into watsonx.data as Iceberg tables.

Basically: parse_event() → Kafka source + parse stage, cleanse_event()
→ transformer stage, normalize_event() → another transformer/modify
stage, quality_check() → a constraint stage with a reject link. So the
work isn't really "design DataStage from zero," it's "translate what I
already built."

## Tables in watsonx.data

**security_events** - the main table. event_id, event_timestamp,
user_id, user_role, action, patient_id, record_type, authorized,
source_system, ingested_at, and a quality_status column (CLEAN or
FLAGGED). Partitioned by date so trend queries stay fast.

**audit_log** - append-only, every event that comes through whether
clean or flagged. Same columns plus risk_tier and is_violation, since
this is what the compliance analytics side actually queries against.

## Queries the dashboard will need

Wrote these out now so building the actual Cognos dashboard later is
just wiring it up, not figuring out the SQL under deadline pressure.

- Violation count by day (for the trend chart)
- Count grouped by risk_tier (for the risk breakdown)
- Top 10 unauthorized actions
- Most recent 25 high-risk events, for a live incident feed

## Risk tier, roughly

- High: unauthorized bulk_download or export_records
- Medium: any other unauthorized action, or authorized bulk_download/export_records
- Low: everything else authorized (logins, normal views, etc.)

Might end up computing this in DataStage itself, or as a view in
watsonx.data - will decide once I see what's easier to show live in the
demo.

## Still unresolved

- Kafka connectivity from the DataStage environment, waiting on Peter
- Haven't confirmed the sector reference table doesn't want something
  different from this schema
- Haven't confirmed Cognos is actually available once CP4D is up