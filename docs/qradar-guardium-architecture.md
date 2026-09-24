# QRadar SIEM & IBM Security Guardium Architecture (Joyline)

**Track:** Cybersecurity / IBM watsonx.ai Phase 3, Team 2  
**Author:** Joyline Kamoing  
**Core Responsibilities:** QRadar SIEM anomaly detection rules, IBM Security Guardium real-time Database Activity Monitoring (DAM), Dynamic Protected Health Information (PHI) masking, and HIPAA-compliant telemetry generation for immutable audit logging.

---

## 1. Cybersecurity Architecture Overview

The threat detection and security analytics layer inspects raw EHR access logs, database transactions, clinician authentication events, and patient portal activities. It implements a dual-layer defense model:

1. **IBM QRadar SIEM (Application & Behavioral Layer):** Correlates user actions, historical baselines, time windows, and care-team reference sets to flag anomalous behaviors (e.g., unauthorized chart views, mass downloads, VIP snooping, off-hours access).
2. **IBM Security Guardium DAM (Database Protocol Layer):** Uses Software TAP (S-TAP) to inspect live SQL queries against clinical data stores in real time, block SQL injection attacks, and apply dynamic data masking (DDM) to redact PHI fields (such as SSNs and psychiatric histories) before results leave the database engine.

```mermaid
flowchart TD
    subgraph Sources & Endpoints
        EHR[EHR Application / Web Portal]
        Client[Clinicians / Billing Staff]
        DB[(Clinical Database / EHR Data Store)]
    end

    subgraph Security Layer (Joyline)
        subgraph Guardium DAM
            STAP[Guardium S-TAP Protocol Inspection]
            DDM[Dynamic PHI Masking Engine\nSSN, Medical History, Rx]
            SQLiFilter[SQL Injection & Policy Guard]
            STAP --> SQLiFilter --> DDM
        end

        subgraph QRadar SIEM
            CRE[Custom Rules Engine - CRE]
            Rule101[QR-RULE-101: Unauthorized Chart View]
            Rule102[QR-RULE-102: Bulk Download Anomaly]
            Rule103[QR-RULE-103: VIP Snooping]
            Rule104[QR-RULE-104: Off-Hours Query Anomaly]
            Rule105[QR-RULE-105: Automated Scraping]
            CRE --> Rule101 & Rule102 & Rule103 & Rule104 & Rule105
        end

        Forwarder[Threat Ingestion & Kafka Event Bridge]
    end

    subgraph Data & Analytics Pipeline (Fidelmah)
        Kafka[(Kafka Topic:\nhealthcare-security-events)]
        DataStage[DataStage ETL: Cleanse & Quality Check]
        Watsonx[(watsonx.data / Iceberg Immutable Audit Log)]
        Cognos[Cognos Clinical Security Dashboard]
    end

    Client --> EHR
    EHR --> DB
    DB -.->|Protocol Tap| STAP
    EHR --> CRE
    DDM --> Forwarder
    CRE --> Forwarder
    Forwarder --> Kafka
    Kafka --> DataStage --> Watsonx --> Cognos
```

---

## 2. HIPAA-Style Role-Based Access Control (RBAC) Enforcement

The system implements rigorous role-based access controls mapped to **HIPAA Privacy and Security Rules (45 CFR § 164.312(a)(1) & 45 CFR § 164.502(b))**:

### A. Role Hierarchy & Boundaries
- **Physicians (`physician`):** Full read/write access to clinical charts, medical histories, and prescriptions for assigned patients. SSN is fully redacted (`XXX-XX-XXXX`).
- **Nurses (`nurse`):** Full read access to clinical records and prescriptions for assigned department patients. SSN is fully redacted (`XXX-XX-XXXX`).
- **Billing Clerks (`billing_clerk`):** Access strictly restricted to patient billing demographics and partial SSN (`***-**-6789`). Medical histories and clinical diagnoses are automatically masked (`[RESTRICTED MEDICAL HISTORY]`).
- **Pharmacists (`pharmacist`):** Access restricted to active prescriptions and medication regimens. Diagnostic narratives and billing histories are masked.
- **Lab Technicians (`lab_tech`):** Access restricted to lab orders and test results.
- **Compliance / Admin (`admin`):** Access restricted to audit telemetry, access logs, and partial identifiers; clinical charts are redacted.

### B. Dynamic PHI Masking Matrix

| Role | Social Security Number (SSN) | Medical History & Diagnoses | Prescriptions & Controlled Substances | Financial / Billing Details |
|---|---|---|---|---|
| **Physician** | Full Mask (`XXX-XX-XXXX`) | **Full Access (Unmasked)** | **Full Access (Unmasked)** | Restricted |
| **Nurse** | Full Mask (`XXX-XX-XXXX`) | **Full Access (Unmasked)** | **Full Access (Unmasked)** | Restricted |
| **Billing Clerk** | **Partial Mask (`***-**-6789`)** | **Masked (`[RESTRICTED MEDICAL HISTORY]`)\*** | Restricted | **Full Access** |
| **Pharmacist** | Full Mask (`XXX-XX-XXXX`) | Masked (`[RESTRICTED MEDICAL HISTORY]`) | **Full Access (Unmasked)** | Restricted |
| **Lab Tech** | Full Mask (`XXX-XX-XXXX`) | Masked (`[RESTRICTED MEDICAL HISTORY]`) | Restricted | Restricted |
| **Admin / Compliance** | **Partial Mask (`***-**-6789`)** | Masked (`[RESTRICTED MEDICAL HISTORY]`) | Restricted | **Full Access** |
| **Guest / External** | Full Mask (`XXX-XX-XXXX`) | Masked (`[RESTRICTED MEDICAL HISTORY]`) | Restricted | Restricted |

*\* Enforces the HIPAA Minimum Necessary Standard (45 CFR § 164.502(b)): Non-clinical billing staff only receive billing codes, not sensitive raw psychiatric or clinical notes.*

---

## 3. QRadar SIEM Custom Rules Engine (CRE)

Located in [`security/qradar/qradar_rules.json`](file:///c:/Users/Administrator/healthcare-data-security-compliance-hub/security/qradar/qradar_rules.json) and [`security/qradar/qradar_rules.xml`](file:///c:/Users/Administrator/healthcare-data-security-compliance-hub/security/qradar/qradar_rules.xml).

| Rule ID | Rule Name | Trigger Conditions | Severity / Magnitude | Compliance Tag |
|---|---|---|---|---|
| **QR-RULE-101** | **Unauthorized Staff Viewing Patient Chart** | Action is `view_chart` or `edit_chart` AND user role is NOT in `[physician, nurse]` AND `authorized = false`. | Severity: 7 / Mag: 8 | HIPAA Section 164.312(a)(1) (Access Control), Minimum Necessary Rule |
| **QR-RULE-102** | **Bulk Record Download / Mass Exfiltration** | Action is `bulk_download` or `export_records` AND (unauthorized OR count >= 5 in 300s window). | Severity: 9 / Mag: 10 | HIPAA Section 164.312(b) (Audit Controls), Breach Notification Rule |
| **QR-RULE-103** | **VIP / High-Profile Patient Record Snooping** | Access to patient in reference set `VIP_AND_RESTRICTED_PATIENTS` by staff not in reference map `PATIENT_ASSIGNED_CARE_TEAM`. | Severity: 8 / Mag: 8 | HIPAA Section 164.502 (Privacy Rule) |
| **QR-RULE-104** | **Off-Hours High-Volume EHR Query Anomaly** | Access between 22:00-05:00 UTC by non-night shift roles (billing, lab tech) with `authorized = false`. | Severity: 7 / Mag: 7 | HIPAA Section 164.308(a)(1)(ii)(D) (Audit Review) |
| **QR-RULE-105** | **Multi-Patient Sequential Scraping** | User queries >= 4 distinct patient records in < 60 seconds (automated harvesting behavior). | Severity: 8 / Mag: 8 | HIPAA Section 164.312(e)(1) (Transmission Security) |

### Ariel Query Language (AQL) Threat Hunting Queries

Exported in [`security/qradar/aql_queries.sql`](file:///c:/Users/Administrator/healthcare-data-security-compliance-hub/security/qradar/aql_queries.sql) for SOC analysts and compliance investigators.

---

## 4. IBM Security Guardium Real-Time DAM & S-TAP Policies

Located in [`security/guardium/phi_masker.py`](file:///c:/Users/Administrator/healthcare-data-security-compliance-hub/security/guardium/phi_masker.py), [`security/guardium/guardium_policies.yaml`](file:///c:/Users/Administrator/healthcare-data-security-compliance-hub/security/guardium/guardium_policies.yaml), and [`security/guardium/guardium_engine.py`](file:///c:/Users/Administrator/healthcare-data-security-compliance-hub/security/guardium/guardium_engine.py).

- **GD-POL-01:** Direct DB Table Access by Unauthorized Accounts (`reporting_readonly`, `guest_user`).
- **GD-POL-02:** Dynamic Data Masking for SSNs and National Identifiers.
- **GD-POL-03:** Dynamic Data Masking for Clinical Diagnoses & Psychiatric Notes.
- **GD-POL-04:** Real-time SQL Injection pattern matching and session termination.
- **GD-POL-05:** Rate monitoring for mass queries (> 100 rows / minute).

---

## 5. Immutable Audit Logging Pipeline to watsonx.data

Every access request, database query, authentication attempt, and policy violation generates a cryptographically indexed event payload sent over Kafka:

1. **Event Capture:** User identity, role, timestamp, requested table/patient, query text, authorization status, and dynamic masking status.
2. **Kafka Streaming:** Streamed to `healthcare-security-events` in real time.
3. **DataStage Standardization:** Cleansed, normalized, and validated across 4 processing stages.
4. **watsonx.data Iceberg Storage:** Appended to an immutable Apache Iceberg audit log table with snapshot isolation, providing an indelible audit trail for forensic investigation and live compliance dashboarding.

---

## 6. Threat Ingestion & Scenarios

The simulator in [`security/threat_ingestion.py`](file:///c:/Users/Administrator/healthcare-data-security-compliance-hub/security/threat_ingestion.py) provides 6 curated scenarios:

1. `unauthorized_chart_view`: Billing clerk snooping on clinical psychiatric chart.
2. `bulk_download`: Nurse executing mass oncology export at 23:15 UTC.
3. `vip_snooping`: Lab tech snooping on Senator Marcus Vance (VIP).
4. `sql_injection`: Portal SQL injection attack (`' OR '1'='1'`).
5. `scraping`: Multi-patient rapid record discovery.
6. `authorized_baseline`: Attending physician routine cardiology review.

### Running Joyline's Security Suite

```bash
# 1. Run all unit and integration tests
python -m unittest discover -s security/tests -p "test_*.py" -v

# 2. Run threat simulator in dry-run mode
python security/threat_ingestion.py --mode dry-run --scenario all

# 3. Stream live security events into Kafka
python security/threat_ingestion.py --mode kafka --scenario all
```

---

## 7. Demo Walkthrough Script (Joyline - 4 Minutes)

1. **Slide / Context (1 min):**
   - Explain the clinical security challenge: HIPAA compliance mandates the "Minimum Necessary" rule and real-time detection of insider snooping.
2. **QRadar Anomaly Detection (1.5 min):**
   - Demonstrate `QR-RULE-101` and `QR-RULE-102` triggering on unauthorized chart lookups and mass exfiltrations.
   - Show how offenses automatically tag HIPAA citation numbers and index by offending `user_id`.
3. **Guardium Dynamic PHI Masking (1.5 min):**
   - Show a live SQL query executed by a Billing Clerk vs Physician:
     - Physician sees full clinical diagnosis and history.
     - Billing Clerk sees auto-redacted `[RESTRICTED MEDICAL HISTORY]` and masked SSN `***-**-6789`.
   - Show Guardium blocking a SQL injection attempt on the patient portal.
4. **Handoff to Fidelmah:**
   - Correlated telemetry forwards to Kafka topic `healthcare-security-events`, feeding DataStage and watsonx.data's immutable audit log.
