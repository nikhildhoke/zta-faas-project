#!/usr/bin/env python3
from datetime import datetime, timedelta, UTC
import statistics as stats
import time
import json
import argparse
import requests
import boto3

CW_NS_DEFAULT = "ZTA/FaaSBench"

def put_point(cw, ns, metric, value, dims, ts, unit):
    """Publish a single CloudWatch metric point."""
    cw.put_metric_data(
        Namespace=ns,
        MetricData=[{
            "MetricName": metric,
            "Dimensions": [{"Name": k, "Value": str(v)} for k, v in dims.items()],
            "Timestamp": ts,
            "StorageResolution": 1,   # high-res points -> nicer lines
            "Value": float(value),
            "Unit": unit
        }]
    )

def run_batch(cw, ns, *, url, token, size, mode):
    """Run one batch of requests and publish per-request points."""
    latencies = []
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Spread the points over the last ~60s so 1m widgets draw lines
    end_ts = datetime.now(UTC)
    span_sec = max(60, min(size, 120))          # ~1 minute span (more if huge)
    step = max(span_sec // max(size, 1), 1)     # at least 1s spacing

    dims = {"Batch": str(size), "Mode": mode}   # IMPORTANT: widgets will query exactly these

    # Per-request counters for security series (as booleans per sample)
    zta_allowed = 0
    lift_denied = 0
    deny401_no_token = 0
    deny401_wrong_type = 0

    for i in range(size):
        ts = end_ts - timedelta(seconds=span_sec - i * step)

        t0 = time.perf_counter()
        r = requests.get(url, headers=headers, timeout=10)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt_ms)

        # Emit the latency point (one per request)
        put_point(cw, ns, "LatencyMs", dt_ms, dims, ts, unit="Milliseconds")

        # Emit a 1/0 point per request for each security series (so we get lines/sums)
        if mode == "ZTA":
            allowed = 1 if r.status_code == 200 else 0
            put_point(cw, ns, "ZTAAllowed", allowed, dims, ts, unit="Count")
            if r.status_code == 403:
                put_point(cw, ns, "LiftDenied", 1, dims, ts, unit="Count")
            else:
                put_point(cw, ns, "LiftDenied", 0, dims, ts, unit="Count")

            if r.status_code == 401:
                if not token:
                    put_point(cw, ns, "Deny401NoToken", 1, dims, ts, unit="Count")
                    put_point(cw, ns, "Deny401WrongType", 0, dims, ts, unit="Count")
                else:
                    put_point(cw, ns, "Deny401NoToken", 0, dims, ts, unit="Count")
                    put_point(cw, ns, "Deny401WrongType", 1, dims, ts, unit="Count")
            else:
                put_point(cw, ns, "Deny401NoToken", 0, dims, ts, unit="Count")
                put_point(cw, ns, "Deny401WrongType", 0, dims, ts, unit="Count")

    return {
        "avg": stats.mean(latencies),
        "p95": (stats.quantiles(latencies, n=100)[94] if len(latencies) >= 20 else max(latencies)),
        "count": len(latencies),
        "allowed": zta_allowed,
        "lift_denied": lift_denied,
        "deny401_no_token": deny401_no_token,
        "deny401_wrong_type": deny401_wrong_type,
    }

def put_clean_dashboard(region, ns, name):
    """Create/replace a neat 2×3 dashboard. Widgets match the exact dimensions above."""
    cw = boto3.client("cloudwatch", region_name=region)

    def lat_widget(batch, x, y):
        return {
            "type": "metric", "x": x, "y": y, "width": 12, "height": 6,
            "properties": {
                "title": f"Latency — Baseline vs ZTA (Size {batch})",
                "region": region,
                "view": "timeSeries",
                "setPeriodToTimeRange": True,
                "stat": "Average",
                "period": 60,
                "stacked": False,
                "metrics": [
                    [ ns, "LatencyMs", "Batch", str(batch), "Mode", "Baseline", {"label": "Baseline avg (ms)"} ],
                    [ ".", "LatencyMs", "Batch", str(batch), "Mode", "ZTA",      {"label": "ZTA avg (ms)"} ]
                ],
                "yAxis": { "left": {"label": "ms", "showUnits": True } }
            }
        }

    def sec_widget(batch, x, y):
        return {
            "type": "metric", "x": x, "y": y, "width": 12, "height": 6,
            "properties": {
                "title": f"Security lift (Size {batch})",
                "region": region,
                "view": "timeSeries",
                "setPeriodToTimeRange": True,
                "stat": "Sum",
                "period": 60,
                "stacked": False,
                "metrics": [
                    [ ns, "ZTAAllowed",       "Batch", str(batch), "Mode", "ZTA", {"label": "ZTA allowed (200)"} ],
                    [ ".", "LiftDenied",      "Batch", str(batch), "Mode", "ZTA", {"label": "Lift: baseline-allowed but ZTA denied"} ],
                    [ ".", "Deny401NoToken",  "Batch", str(batch), "Mode", "ZTA", {"label": "401 (no token)"} ],
                    [ ".", "Deny401WrongType","Batch", str(batch), "Mode", "ZTA", {"label": "401 (wrong type)"} ],
                ],
                "yAxis": { "left": {"label": "count"} }
            }
        }

    body = {
        "widgets": [
            lat_widget(50,  0,  0),  sec_widget(50,  12, 0),
            lat_widget(100, 0,  6),  sec_widget(100, 12, 6),
            lat_widget(500, 0, 12),  sec_widget(500, 12, 12),
        ]
    }

    cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body))
    print(f"Updated CloudWatch dashboard: {name}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline-url", required=True)
    ap.add_argument("--zta-url", required=True)
    ap.add_argument("--token", default="")
    ap.add_argument("--region", required=True)
    ap.add_argument("--namespace", default=CW_NS_DEFAULT)
    ap.add_argument("--samples", default="50,100,500")
    ap.add_argument("--dashboard", default="ZTA-FaaS-Benchmark")
    args = ap.parse_args()

    cw = boto3.client("cloudwatch", region_name=args.region)
    sizes = [int(s) for s in args.samples.split(",")]

    print("=== Running benchmark ===")
    for size in sizes:
        print(f"\n-- Batch {size} --")
        b = run_batch(cw, args.namespace, url=args.baseline_url, token="",             size=size, mode="Baseline")
        print(f"Baseline:   avg={b['avg']:.1f}ms  p95={b['p95']:.1f}ms  N={b['count']}")
        z = run_batch(cw, args.namespace, url=args.zta_url,       token=args.token,    size=size, mode="ZTA")
        print(f"ZTA:        avg={z['avg']:.1f}ms  p95={z['p95']:.1f}ms  N={z['count']}")

    put_clean_dashboard(args.region, args.namespace, args.dashboard)

if __name__ == "__main__":
    main()
