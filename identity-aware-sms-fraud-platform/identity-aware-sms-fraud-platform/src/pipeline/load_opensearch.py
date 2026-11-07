"""Bulk-load alert CSVs into OpenSearch (lab setup, security plugin disabled).

NOTE: not exercised in this repo's automated tests (needs a running OpenSearch).
Only alerts are indexed. Raw CDR rows and full MSISDNs never leave the Python pipeline.

Usage: python -m src.pipeline.load_opensearch [--url http://localhost:9200]
"""
from __future__ import annotations
import argparse
import json
import pandas as pd
import requests

INDEXES = {"out/cdr_alerts.csv": "sms-alerts", "out/iam_alerts.csv": "iam-alerts"}


def bulk(url: str, index: str, df: pd.DataFrame):
    lines = []
    for rec in df.to_dict("records"):
        for k, v in list(rec.items()):
            if isinstance(v, pd.Timestamp):
                rec[k] = v.isoformat()
            elif pd.isna(v):
                rec[k] = None
        lines += [json.dumps({"index": {"_index": index, "_id": rec["alert_id"]}}), json.dumps(rec, default=str)]
    r = requests.post(f"{url}/_bulk", data="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=30)
    r.raise_for_status()
    if r.json().get("errors"):
        raise RuntimeError("bulk load reported errors: " + r.text[:500])
    print(f"indexed {len(df)} docs into {index}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:9200")
    a = p.parse_args()
    for path, index in INDEXES.items():
        bulk(a.url, index, pd.read_csv(path, parse_dates=["window_start", "window_end"]))


if __name__ == "__main__":
    main()
