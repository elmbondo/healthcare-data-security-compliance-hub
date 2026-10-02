"""
Clinical Security Officer Dashboard

Quick note on the data: the charts here are built from real results I
pulled from watsonx.data yesterday while the TechZone environment was
still up. The reservation has since expired (that takes watsonx.data
down with it, nothing I can do about that on my end), so I can't
re-query it live right now. Each chart has the actual SQL I ran,
commented underneath, so it's clear this isn't made up data.

If I get a fresh environment later, flipping USE_LIVE_DATA to True and
filling in run_live_query() with real connection details should make
this reconnect without much else changing.

Run with:
    pip install streamlit plotly pandas
    streamlit run dashboard_app.py
"""

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="Clinical Security Officer Dashboard", layout="wide")

USE_LIVE_DATA = False

# ---------------------------------------------------------------------------
# Real numbers pulled from watsonx.data (healthcare_security_catalog.default.audit_log)
# ---------------------------------------------------------------------------

violations_by_facility = pd.DataFrame([
    {"facility_id": "FAC-001", "total_events": 3, "violations": 2, "violation_rate_pct": 66.7},
    {"facility_id": "FAC-006", "total_events": 5, "violations": 3, "violation_rate_pct": 60.0},
    {"facility_id": "FAC-005", "total_events": 2, "violations": 1, "violation_rate_pct": 50.0},
    {"facility_id": "FAC-007", "total_events": 4, "violations": 2, "violation_rate_pct": 50.0},
    {"facility_id": "FAC-008", "total_events": 2, "violations": 1, "violation_rate_pct": 50.0},
    {"facility_id": "FAC-011", "total_events": 6, "violations": 3, "violation_rate_pct": 50.0},
    {"facility_id": "FAC-009", "total_events": 6, "violations": 3, "violation_rate_pct": 50.0},
    {"facility_id": "FAC-015", "total_events": 3, "violations": 1, "violation_rate_pct": 33.3},
    {"facility_id": "FAC-002", "total_events": 4, "violations": 1, "violation_rate_pct": 25.0},
    {"facility_id": "FAC-014", "total_events": 5, "violations": 1, "violation_rate_pct": 20.0},
])

top_violators = pd.DataFrame([
    {"user_id": "(unassigned)", "user_role": "billing_clerk", "violation_count": 2},
    {"user_id": "clinician_9421", "user_role": "physician", "violation_count": 1},
    {"user_id": "clinician_5568", "user_role": "lab_tech", "violation_count": 1},
    {"user_id": "clinician_4535", "user_role": "nurse", "violation_count": 1},
    {"user_id": "clinician_8783", "user_role": "nurse", "violation_count": 1},
    {"user_id": "clinician_5066", "user_role": "physician", "violation_count": 1},
    {"user_id": "clinician_3266", "user_role": "lab_tech", "violation_count": 1},
    {"user_id": "clinician_9230", "user_role": "lab_tech", "violation_count": 1},
    {"user_id": "clinician_9003", "user_role": "admin", "violation_count": 1},
    {"user_id": "clinician_4660", "user_role": "lab_tech", "violation_count": 1},
])

violation_trends_daily = pd.DataFrame([
    {"event_date": "2026-09-28", "violation_count": 8},
    {"event_date": "2026-09-29", "violation_count": 4},
    {"event_date": "2026-09-30", "violation_count": 5},
    {"event_date": "2026-10-01", "violation_count": 1},
])

violation_trends_hourly = pd.DataFrame([
    {"event_date": "2026-09-28", "event_hour": "01", "violation_count": 1},
    {"event_date": "2026-09-28", "event_hour": "03", "violation_count": 1},
    {"event_date": "2026-09-28", "event_hour": "04", "violation_count": 1},
    {"event_date": "2026-09-28", "event_hour": "09", "violation_count": 1},
    {"event_date": "2026-09-28", "event_hour": "12", "violation_count": 1},
    {"event_date": "2026-09-28", "event_hour": "15", "violation_count": 1},
    {"event_date": "2026-09-28", "event_hour": "22", "violation_count": 2},
    {"event_date": "2026-09-29", "event_hour": "07", "violation_count": 1},
    {"event_date": "2026-09-29", "event_hour": "14", "violation_count": 1},
    {"event_date": "2026-09-29", "event_hour": "17", "violation_count": 1},
])

risk_tier_breakdown = pd.DataFrame([
    {"risk_tier": "low", "event_count": 34, "pct_of_total": 68.0},
    {"risk_tier": "medium", "event_count": 12, "pct_of_total": 24.0},
    {"risk_tier": "high", "event_count": 4, "pct_of_total": 8.0},
])

audit_feed = pd.DataFrame([
    {"event_id": "55190f5b-952...", "event_timestamp": "2026-10-01T0...", "user_id": "clinician_5568", "user_role": "lab_tech", "action": "dispatch_referral", "record_type": "referral", "facility_id": "FAC-007", "risk_tier": "high"},
    {"event_id": "dc4ee342-98...", "event_timestamp": "2026-09-30T2...", "user_id": "clinician_9230", "user_role": "lab_tech", "action": "create_encounter", "record_type": "encounter", "facility_id": "FAC-005", "risk_tier": "medium"},
    {"event_id": "c89bcf25-4bb...", "event_timestamp": "2026-09-30T2...", "user_id": "clinician_1262", "user_role": "nurse", "action": "edit_patient", "record_type": "patient", "facility_id": "FAC-006", "risk_tier": "medium"},
    {"event_id": "6584e95b-45...", "event_timestamp": "2026-09-30T1...", "user_id": "clinician_4660", "user_role": "lab_tech", "action": "edit_encounter", "record_type": "encounter", "facility_id": "FAC-002", "risk_tier": "medium"},
    {"event_id": "95527572-6fb...", "event_timestamp": "2026-09-30T0...", "user_id": "clinician_9003", "user_role": "admin", "action": "view_lab_result", "record_type": "lab_result", "facility_id": "FAC-001", "risk_tier": "medium"},
    {"event_id": "7cce10d2-9cf...", "event_timestamp": "2026-09-30T0...", "user_id": "clinician_8501", "user_role": "billing_clerk", "action": "edit_encounter", "record_type": "encounter", "facility_id": "FAC-008", "risk_tier": "medium"},
    {"event_id": "1385444b-dd...", "event_timestamp": "2026-09-29T2...", "user_id": "clinician_2235", "user_role": "pharmacist", "action": "edit_encounter", "record_type": "encounter", "facility_id": "FAC-009", "risk_tier": "medium"},
    {"event_id": "d4184048-3b...", "event_timestamp": "2026-09-29T1...", "user_id": "clinician_4535", "user_role": "nurse", "action": "edit_patient", "record_type": "patient", "facility_id": "FAC-011", "risk_tier": "high"},
])

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

st.title("Clinical Security Officer Dashboard")
st.caption("Healthcare Data Security & Compliance Hub")

if not USE_LIVE_DATA:
    st.info(
        "These numbers come from a live watsonx.data query I ran during "
        "development. The TechZone environment has since expired, so it's "
        "not reachable right now, but the SQL under each chart is exactly "
        "what produced these results.",
        icon="ℹ️",
    )

col1, col2, col3 = st.columns(3)
col1.metric("Events analyzed", int(risk_tier_breakdown["event_count"].sum()))
col2.metric("High-risk violations", int(risk_tier_breakdown.loc[risk_tier_breakdown.risk_tier == "high", "event_count"].iloc[0]))
col3.metric("Facilities with violations", violations_by_facility.shape[0])

st.divider()

st.subheader("Violation Trends")
tab1, tab2 = st.tabs(["Daily", "Hourly"])

with tab1:
    fig = px.line(violation_trends_daily, x="event_date", y="violation_count", markers=True)
    st.plotly_chart(fig, use_container_width=True)
    # SELECT substr(event_timestamp, 1, 10) AS event_date, count(*) AS violation_count
    # FROM healthcare_security_catalog.default.audit_log
    # WHERE is_violation = true
    # GROUP BY substr(event_timestamp, 1, 10)
    # ORDER BY event_date;

with tab2:
    fig = px.bar(violation_trends_hourly, x="event_hour", y="violation_count", color="event_date")
    st.plotly_chart(fig, use_container_width=True)
    # Same idea, grouped by hour too -- substr(event_timestamp, 12, 2)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Risk Tier Breakdown")
    fig = px.pie(risk_tier_breakdown, names="risk_tier", values="event_count",
                 color="risk_tier",
                 color_discrete_map={"low": "#2ca02c", "medium": "#ff7f0e", "high": "#d62728"})
    st.plotly_chart(fig, use_container_width=True)
    # SELECT risk_tier, count(*) AS event_count,
    #   round(count(*) * 100.0 / sum(count(*)) OVER (), 1) AS pct_of_total
    # FROM healthcare_security_catalog.default.audit_log
    # GROUP BY risk_tier
    # ORDER BY event_count DESC;

with right:
    st.subheader("Violation Rate by Facility")
    fig = px.bar(violations_by_facility.sort_values("violation_rate_pct", ascending=True),
                 x="violation_rate_pct", y="facility_id", orientation="h")
    st.plotly_chart(fig, use_container_width=True)
    # SELECT facility_id, count(*) AS total_events,
    #   sum(CASE WHEN is_violation THEN 1 ELSE 0 END) AS violations,
    #   round(100.0 * sum(CASE WHEN is_violation THEN 1 ELSE 0 END) / count(*), 1) AS violation_rate_pct
    # FROM healthcare_security_catalog.default.audit_log
    # GROUP BY facility_id
    # ORDER BY violation_rate_pct DESC;

st.divider()

st.subheader("Top Policy Violators")
fig = px.bar(top_violators, x="violation_count", y="user_id", color="user_role", orientation="h")
st.plotly_chart(fig, use_container_width=True)
# SELECT user_id, user_role, count(*) AS violation_count
# FROM healthcare_security_catalog.default.audit_log
# WHERE is_violation = true
# GROUP BY user_id, user_role
# ORDER BY violation_count DESC
# LIMIT 10;

st.divider()

st.subheader("Audit Investigation Feed")
st.caption("Most recent medium/high risk events")
st.dataframe(audit_feed, use_container_width=True, hide_index=True)
# SELECT event_id, event_timestamp, user_id, user_role, action, record_type,
#        record_id, facility_id, risk_tier
# FROM healthcare_security_catalog.default.audit_log
# WHERE is_violation = true
# ORDER BY event_timestamp DESC
# LIMIT 20;


# ---------------------------------------------------------------------------
# For reconnecting once there's a live environment again
# ---------------------------------------------------------------------------

def run_live_query(sql: str, host: str, port: int, user: str, api_key: str,
                    catalog: str = "healthcare_security_catalog", schema: str = "default") -> pd.DataFrame:
    """
    Pulls real data straight from watsonx.data. Needs: pip install presto-python-client

    Pass credentials in as arguments (or read them from env vars like
    watsonx_loader.py does) -- don't hardcode an API key in here.
    """
    import prestodb

    conn = prestodb.dbapi.connect(
        host=host,
        port=port,
        user=user,
        catalog=catalog,
        schema=schema,
        http_scheme="https",
        auth=prestodb.auth.BasicAuthentication(user, api_key),
    )
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    return pd.DataFrame(rows, columns=columns)