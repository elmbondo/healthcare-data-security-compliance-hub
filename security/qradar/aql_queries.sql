-- ==============================================================================
-- IBM QRadar Ariel Query Language (AQL) Compliance & Threat Hunting Queries
-- Author: Joyline Kamoing (Cybersecurity Track)
-- Description: AQL queries for investigating unauthorized EHR access, bulk downloads,
--              snooping, and compliance reporting in IBM QRadar SIEM.
-- ==============================================================================

-- 1. Top Unauthorized EHR Access Violations by User Role & Action
SELECT
    "user_role" AS "Staff Role",
    "user_id" AS "User ID",
    "action" AS "Attempted Action",
    COUNT(*) AS "Violation Count",
    DATEFORMAT(MIN("starttime"), 'YYYY-MM-dd HH:mm:ss') AS "First Seen",
    DATEFORMAT(MAX("starttime"), 'YYYY-MM-dd HH:mm:ss') AS "Last Seen"
FROM events
WHERE
    "authorized" = 'false'
    AND "devicetype" = 'Healthcare EHR System'
GROUP BY "user_role", "user_id", "action"
ORDER BY "Violation Count" DESC
LAST 24 HOURS;

-- 2. Detect Mass Patient Record Downloads / Exfiltration
SELECT
    "user_id" AS "Suspect User",
    "user_role" AS "Role",
    COUNT(DISTINCT "patient_id") AS "Unique Patients Touched",
    COUNT(*) AS "Total Download Events",
    DATEFORMAT("starttime", 'YYYY-MM-dd HH:mm:ss') AS "Timestamp"
FROM events
WHERE
    "action" IN ('bulk_download', 'export_records')
GROUP BY "user_id", "user_role"
HAVING COUNT(*) >= 5 OR COUNT(DISTINCT "patient_id") >= 5
ORDER BY "Total Download Events" DESC
LAST 6 HOURS;

-- 3. High-Risk Off-Hours Access (10:00 PM - 5:00 AM UTC)
SELECT
    "event_id",
    "user_id",
    "user_role",
    "patient_id",
    "action",
    "record_type",
    DATEFORMAT("starttime", 'YYYY-MM-dd HH:mm:ss') AS "Event Time UTC"
FROM events
WHERE
    (DATEFORMAT("starttime", 'HH') >= 22 OR DATEFORMAT("starttime", 'HH') < 5)
    AND "authorized" = 'false'
ORDER BY "starttime" DESC
LAST 7 DAYS;

-- 4. VIP & High-Profile Patient Record Access Audit (Reference Set Match)
SELECT
    "patient_id" AS "VIP Patient ID",
    "user_id" AS "Accessing User",
    "user_role" AS "Staff Role",
    "action" AS "Action",
    "authorized" AS "Authorized Status",
    DATEFORMAT("starttime", 'YYYY-MM-dd HH:mm:ss') AS "Access Timestamp"
FROM events
WHERE
    INCIDENTSUBSET('VIP_AND_RESTRICTED_PATIENTS', "patient_id")
    AND NOT INCIDENTSUBSET('PATIENT_ASSIGNED_CARE_TEAM', "user_id")
ORDER BY "starttime" DESC
LAST 30 DAYS;

-- 5. Multi-Patient Rapid Crawling / Scraping Investigation
SELECT
    "user_id",
    COUNT(DISTINCT "patient_id") AS "Distinct Patients Accessed",
    COUNT(*) AS "Total Queries",
    AVG("duration") AS "Avg Query Duration (ms)"
FROM events
WHERE
    "action" IN ('view_chart', 'query_patient_search', 'view_prescription')
GROUP BY "user_id"
HAVING COUNT(DISTINCT "patient_id") >= 10
ORDER BY "Distinct Patients Accessed" DESC
LAST 1 HOURS;
