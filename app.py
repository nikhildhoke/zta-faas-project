#!/usr/bin/env python3
"""
Streamlit dashboard for Zero Trust on FaaS.

Requirements:
  pip install streamlit boto3 pandas

Run:
  streamlit run app.py

Env:
  AWS_REGION   (e.g. eu-west-1)
"""
import os, time, pandas as pd, streamlit as st, boto3
from datetime import datetime, timedelta

REGION   = os.getenv("AWS_REGION","eu-west-1")
NS       = "ZTA-FaaS"
LOG_GROUP = "/aws/lambda/secureZTAFunction"  # update if different

cw   = boto3.client("cloudwatch", region_name=REGION)
logs = boto3.client("logs",       region_name=REGION)

st.set_page_config(page_title="Zero Trust on FaaS", layout="wide")
st.title("Zero Trust on FaaS — Latency & Security")

lookback_m = st.sidebar.slider("Lookback minutes", 5, 240, 60, step=5)
end   = datetime.utcnow()
start = end - timedelta(minutes=lookback_m)
period = st.sidebar.selectbox("Metric period (seconds)", [60,120,300], index=2)

loads = ["N50","N100","N500"]
stages = ["Baseline","ZTA"]

# ---------- CloudWatch Metrics helpers ----------
def get_metric(ns, name, dims, stat="Average"):
    q = {
      "Id": f"id{name.lower()}{int(time.time()*1000)%100000}",
      "MetricStat":{
        "Metric":{
          "Namespace": ns,
          "MetricName": name,
          "Dimensions":[{"Name":k,"Value":v} for k,v in dims.items()]
        },
        "Period": period,
        "Stat": stat
      },
      "ReturnData": True
    }
    resp = cw.get_metric_data(
        MetricDataQueries=[q],
        StartTime=start, EndTime=end, ScanBy="TimestampAscending"
    )
    points = resp["MetricDataResults"][0]
    return pd.DataFrame({"t":points["Timestamps"], "v":points["Values"]})

def latest_number(df: pd.DataFrame) -> float:
    return float(df["v"].iloc[-1]) if not df.empty else 0.0

# ---------- LATENCY ----------
st.header("Latency — Baseline vs ZTA")
lat_cols = st.columns(3)
for i, L in enumerate(loads):
    with lat_cols[i]:
        st.subheader(f"Load {L[1:]} reqs")
        base = get_metric(NS,"LatencyAvgMs", {"Stage":"Baseline","Load":L})
        zta  = get_metric(NS,"LatencyAvgMs", {"Stage":"ZTA","Load":L})
        if base.empty and zta.empty:
            st.info("No data yet. Run benchmark for this load.")
        else:
            chart = pd.DataFrame({"Baseline":base.set_index("t")["v"]}).join(
                     pd.DataFrame({"ZTA":zta.set_index("t")["v"]}), how="outer")
            st.line_chart(chart, height=220)

# ---------- SECURITY ----------
st.header("Security improvements (ZTA only)")
sec_cols = st.columns(3)
for i, L in enumerate(loads):
    with sec_cols[i]:
        st.subheader(f"Load {L[1:]}")
        allow = latest_number(get_metric(NS,"AllowedCount", {"Stage":"ZTA","Load":L}, stat="Sum"))
        deny  = latest_number(get_metric(NS,"PolicyDeny403", {"Stage":"ZTA","Load":L}, stat="Sum"))
        n401a = latest_number(get_metric(NS,"AuthNoToken401", {"Stage":"ZTA","Load":L}, stat="Sum"))
        n401t = latest_number(get_metric(NS,"AuthWrongType401", {"Stage":"ZTA","Load":L}, stat="Sum"))
        total = latest_number(get_metric(NS,"TotalCount", {"Stage":"ZTA","Load":L}, stat="Sum"))
        edgeb = latest_number(get_metric(NS,"EdgeBlockedPct", {"Stage":"ZTA","Load":L}, stat="Average"))
        st.metric("Allowed (200)", int(allow))
        st.metric("Denied by Policy (403)", int(deny))
        st.metric("401 (no token)", int(n401a))
        st.metric("401 (wrong type)", int(n401t))
        st.metric("Total", int(total))
        st.progress(min(1.0, edgeb/100.0), text=f"Edge blocked {edgeb:.1f}%")

# ---------- Server-side policy details from Logs ----------
st.header("Server-side policy (OPA)")
def logs_query(q: str) -> pd.DataFrame:
    qid = logs.start_query(
        logGroupName=LOG_GROUP,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()),
        queryString=q
    )["queryId"]
    # poll
    while True:
        r = logs.get_query_results(queryId=qid)
        if r["status"] in ("Complete","Failed","Cancelled"):
            break
        time.sleep(0.6)
    rows=[]
    for line in r.get("results", []):
        rows.append({f["field"]: f["value"] for f in line})
    return pd.DataFrame(rows)

c1,c2 = st.columns([1,1])
with c1:
    st.subheader("OPA eval latency (ms)")
    q = """
fields @timestamp, opa_ms
| filter kind="opa_decision"
| stats pct(opa_ms,50) as p50, pct(opa_ms,95) as p95, max(opa_ms) as max, count() as calls
"""
    df = logs_query(q)
    if df.empty:
        st.info("No OPA logs found in this window.")
    else:
        st.table(df)

with c2:
    st.subheader("Deny & auth error breakdown")
    q = """
fields @timestamp, kind, reason, decision
| filter kind in ["auth_error","policy_error"] or decision="deny"
| stats count() as c by coalesce(kind, "opa_decision"), reason
| sort c desc
"""
    df = logs_query(q)
    st.table(df if not df.empty else pd.DataFrame([{"kind":"-", "reason":"-", "c":0}]))

# ---------- ZTA Feature explainer ----------
st.header("What ZTA enforcement adds (your Lambda path)")
st.markdown("""
- **Identity verification (JWT)**: signature + issuer verified, **token_use must be `access`**.
- **Client binding**: token `client_id` must match the expected app client (prevents cross-app token replay).
- **Least privilege routes**: only allow-listed `(method, path)` pairs are accepted; others are **403** (policy deny).
- **Scopes per method**: e.g., `GET` requires `openid` (customize in policy); missing → **403**.
- **Fail closed**: OPA errors or preflight failures return **403** with a safe message (no data leakage).
- **Edge blocking**: many invalid requests are rejected at API Gateway or early in Lambda before business logic runs.

Use the sections above to show: higher **edge blocked %**, **deny counts** on disallowed routes, and low
**OPA p50/p95** latency (policy overhead). These are the **security gains** you present alongside
the latency trade-off.
""")
