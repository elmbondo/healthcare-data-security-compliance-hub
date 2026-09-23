# Healthcare Data Security & Compliance Hub

**IBM watsonx.ai Phase 3 Cornerstone Project, Team 2**

## Overview

A compliance and security monitoring platform for healthcare data, built around a Clinical Security Officer Dashboard backed by a live compliance analytics layer. The system ingests EHR access logs, clinician activity, and patient portal authentication events, detects and flags unauthorized or anomalous access in real time, and gives compliance officers a live view of violation trends and risk exposure.

## Pathway, Sector & Audience Feature

- **Pathway:** DataStage / watsonx.data (Fidelmah) + Guardium / QRadar (Joyline)
- **Sector:** Healthcare / Healthtech, covering EHR data, patient intake logs, and prescription data
- **Audience Feature:** Clinical Security Officer Dashboard with an underlying compliance analytics layer

## Team

| Name | Track | Responsibility |
|---|---|---|
| Fidelmah Mbondo | Data Science & Analysis | Kafka ingestion, DataStage transforms, watsonx.data (Iceberg), compliance analytics layer |
| Joyline Kamoing | Cybersecurity | QRadar anomaly detection, Guardium real time DB monitoring and PHI masking |

**Supervisor:** Peter Youngren

## Architecture

1. **Ingestion.** QRadar and Guardium forward events to a Kafka topic (`healthcare-security-events`). DataStage's Kafka connector consumes them in continuous mode.
2. **Transform (DataStage).** Parse raw JSON/CSV, cleanse and standardize fields, normalize schema across EHR, portal, and prescription sources, then run data quality checks.
3. **Storage.** Cleansed data loads into watsonx.data using Iceberg tables. An immutable audit log is stored alongside it.
4. **Threat detection (QRadar/Guardium).** QRadar flags anomalous behavior such as unauthorized chart views or bulk downloads. Guardium monitors database queries in real time and auto masks PHI for unauthorized roles.
5. **Governance.** HIPAA style role based access control is enforced throughout.
6. **Compliance analytics and dashboard.** An aggregated analytics layer (violation trends, risk tier breakdowns) is queried live off watsonx.data and visualized in an IBM Cognos dashboard.

## Repository structure

pipeline/ Fidelmah's work: Kafka setup, mock event generator, pipeline
validation logic, DataStage job exports

security/ Joyline's work: QRadar rules, Guardium policies, configs
dashboard/ Cognos dashboard exports and configuration
docs/ Handoff notes and documentation


## Status

- [x] Local Kafka broker running (Docker, KRaft mode) with the `healthcare-security-events` topic
- [x] Mock event generator producing realistic QRadar/Guardium style events, including role based anomalies, off hours weighting, and malformed record injection
- [x] Pipeline transform logic (parse, cleanse, normalize, quality check) validated locally in continuous consumption mode
- [x] Event schema grounded in the real Sita Sector healthtech reference model (Patient, Encounter, LabResult, Referral), not an invented schema
- [ ] DataStage job built in TechZone, connected to Kafka
- [ ] watsonx.data Iceberg tables loaded
- [ ] Compliance analytics queries (violation trends, risk tiers)
- [ ] Cognos dashboard
- [ ] QRadar / Guardium build (Joyline)
- [ ] End to end incident flow demo

## Demo flow (10 to 15 minutes)

1. Problem and setup (2 min)
2. Pipeline walkthrough, Fidelmah (3 min)
3. Threat detection, Joyline (4 min)
4. Compliance analytics, Fidelmah (3 min)
5. End to end incident flow, both (2 min)
6. Wrap up (1 min)