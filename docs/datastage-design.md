# DataStage job plan (v2, updated against the real reference model)

Updating this after finding the actual healthtech reference codebase
(Patient, Encounter, LabResult, Referral models, plus mdm_sync and
referral_dispatcher services in the SitaSector files). My first version
of this used a schema I basically made up (EHR/portal/prescription
categories, invented patient_id format). This version is grounded in
the real thing instead.

## What changed and why

- record_type now matches the actual model names: patient, encounter,
  lab_result, referral. Not categories I invented.
- record_id is a real UUID now, matching how patient_id, encounter_id,
  result_id, and referral_id are actually defined in the reference code
  (they're all UUIDFields).
- Added facility_id, since basically every real model ties back to a
  facility one way or another (registered_facility_id,
  destination_facility_id).
- Added golden_id. Turns out mdm_sync.py resolves duplicate patients
  across facilities into a "golden" identity with a confidence score.
  Unauthorized access to a golden (cross-facility) patient record is
  arguably a bigger deal than a single-facility one, so this feeds into
  how I'm scoring risk now.
- Actions are grounded in what the real services actually do now
  (view/edit_patient, mdm_resolve, view/edit/create_encounter,
  view/create_lab_result, view_referral, dispatch_referral) instead of
  actions I guessed at.
- Also noticed referral_dispatcher.py sends the patient's actual name
  across facilities as part of the referral summary. That's real PHI
  moving between systems, which is exactly the kind of thing Guardium
  is supposed to catch and mask for unauthorized roles.

## How the job flows

Same four stages as before, just running against the updated fields:

1. Parse - decode JSON, malformed stuff goes to a reject link
2. Cleanse - standardize timestamps to UTC, lowercase role/record_type/action
3. Normalize - map everything into one common schema, add source_system
4. Quality check - flag missing fields, invalid roles, invalid
   record_type, invalid action

Then it loads into watsonx.data as Iceberg tables.

## Tables in watsonx.data

security_events - event_id, event_timestamp, user_id, user_role,
action, record_type, record_id, facility_id, golden_id, authorized,
source_system, ingested_at, quality_status. Partitioned by date.

audit_log - same fields, append-only, plus risk_tier and is_violation,
which is what the analytics queries actually run against.

## Risk tier, updated

- High: unauthorized, and either the action is mdm_resolve or
  dispatch_referral, or the record has a golden_id (cross-facility
  identity)
- Medium: any other unauthorized action
- Low: authorized

Already built and working in pipeline_validator.py's
compute_risk_tier(), tested against mock data.

## Queries the dashboard needs

Same list as before, just pointed at the updated columns:

- Violation count by day
- Count grouped by risk_tier
- Top 10 unauthorized actions
- Most recent 25 high-risk events

## Still not sorted

- Kafka connectivity from wherever DataStage ends up running, waiting
  on Peter/AskTZ
- Whether the IBMxMCStudioProgram cohort repo replaces or sits
  alongside the team repo
- Haven't looked at settings.py or the api/serializers and api/views
  files yet, might be worth a quick check in case they show field
  names or validation rules I should also be matching