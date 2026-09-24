# Security Track: QRadar SIEM & Guardium DAM (Joyline)

This directory contains the threat ingestion, QRadar SIEM anomaly detection rules, IBM Security Guardium DAM policies, dynamic PHI masking engines, and integration tests for the Healthcare Data Security & Compliance Hub.

## Directory Structure

```
security/
├── qradar/
│   ├── qradar_rules.json       # QRadar Custom Rules Engine (CRE) rules (JSON)
│   ├── qradar_rules.xml        # QRadar CRE XML Content Management Export
│   ├── aql_queries.sql         # Ariel Query Language (AQL) SOC hunting queries
│   └── qradar_engine.py        # QRadar SIEM evaluation and offense simulator
├── guardium/
│   ├── guardium_policies.yaml  # Guardium DAM & S-TAP security policies (YAML)
│   ├── guardium_policies.json  # Guardium DAM policies (JSON)
│   ├── phi_masker.py           # Role-based dynamic PHI masking engine
│   └── guardium_engine.py      # Guardium S-TAP real-time DB monitor & SQLi guard
├── tests/
│   ├── test_qradar_rules.py    # Unit tests for QRadar anomaly rules
│   ├── test_guardium_masking.py# Unit tests for Guardium PHI masking & DAM
│   └── test_pipeline_integration.py # E2E test verifying DataStage ingestion
├── threat_scenarios.py         # Curated realistic healthcare attack scenarios
├── threat_ingestion.py         # Main CLI service for threat analysis & Kafka forwarder
└── README.md                   # This file
```

## Quick Start

### 1. Run Automated Test Suite
```bash
python -m unittest discover -s security/tests -p "test_*.py" -v
```

### 2. Simulate Threat Scenarios (Dry Run)
```bash
python security/threat_ingestion.py --mode dry-run --scenario all
```

### 3. Forward Security Telemetry to Kafka
```bash
python security/threat_ingestion.py --mode kafka --scenario all
```
