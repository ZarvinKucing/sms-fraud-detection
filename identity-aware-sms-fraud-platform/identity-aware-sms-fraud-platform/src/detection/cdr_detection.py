"""Rule-based (no ML) detection on SMS CDR data, scored per connection per time window.

Design notes
- Every rule is a plain function over a DataFrame; thresholds come from config/rules.yaml.
- Baselines are statistical (median/MAD per connection, peer medians), easy to explain and audit.
- Output = indicators of suspicious traffic, not proof of fraud. A CDR cannot show whether an OTP was used.
"""
from __future__ import annotations
import json
import numpy as np
import pandas as pd

ALERT_COLUMNS = ["alert_id", "connection", "client", "window_start", "window_end", "score", "severity",
                 "rules", "recommended_action", "evidence"]


def _hit(rule_id, conn, ts, **evidence):
    return {"rule_id": rule_id, "connection": conn, "window_start": ts, "evidence": evidence}


def prepare(df_raw: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    df = df_raw.copy()
    df["received_time"] = pd.to_datetime(df["received_time"])
    df = df[df["traffic_type"].isin(cfg["applies_to_traffic_types"])].copy()
    df["window_start"] = df["received_time"].dt.floor(f'{int(cfg["window_minutes"])}min')
    df["failed"] = df["dlr_status"].ne("DELIVRD")
    return df


def r001_volume_spike(df, p, cfg, baseline_end):
    w = f'{int(cfg["window_minutes"])}min'
    idx = pd.date_range(df["window_start"].min(), df["window_start"].max(), freq=w)
    counts = (df.groupby(["window_start", "client_connection_name"]).size()
              .unstack(fill_value=0).reindex(idx, fill_value=0))
    hits = []
    for conn in counts.columns:
        s = counts[conn]
        med = float(s.median())
        mad = float((s - med).abs().median())
        z = 0.6745 * (s - med) / max(mad, 1.0)
        flag = (z >= p["z_threshold"]) & (s >= p["min_messages"])
        for ts in s.index[flag]:
            hits.append(_hit("R001_volume_spike", conn, ts, count=int(s[ts]),
                             baseline_median=med, robust_z=round(float(z[ts]), 1)))
    return hits


def r002_sequential_range(df, p, cfg, baseline_end):
    n = int(p["block_size_digits"])
    d = df.assign(block=df["destination_addr"].astype(str).str[:-n])
    g = d.groupby(["client_connection_name", "window_start", "block"])["destination_addr"].nunique()
    g = g[g >= p["min_distinct_in_block"]]
    return [_hit("R002_sequential_range", c, ts, block_prefix=b, distinct_numbers=int(v))
            for (c, ts, b), v in g.items()]


def r003_failure_rate(df, p, cfg, baseline_end):
    g = (df.groupby(["client_connection_name", "window_start"])
         .agg(n=("failed", "size"), ratio=("failed", "mean")).reset_index())
    peer = g[g["n"] >= 5].groupby("window_start")["ratio"].median().rename("peer_ratio")
    g = g.join(peer, on="window_start")
    g["peer_ratio"] = g["peer_ratio"].fillna(0.0)
    m = g[(g["n"] >= p["min_messages"]) & (g["ratio"] >= p["min_fail_ratio"])
          & (g["ratio"] - g["peer_ratio"] >= p["min_delta_vs_peers"])]
    return [_hit("R003_failure_rate", r.client_connection_name, r.window_start, messages=int(r.n),
                 fail_ratio=round(float(r.ratio), 2), peer_median_ratio=round(float(r.peer_ratio), 2))
            for r in m.itertuples()]


def r004_new_country(df, p, cfg, baseline_end):
    base = df[df["received_time"] < baseline_end]
    post = df[df["received_time"] >= baseline_end]
    profile = {}
    for conn, grp in base.groupby("client_connection_name"):
        if len(grp) < p["min_baseline_messages"]:
            continue
        share = grp["country"].value_counts(normalize=True)
        profile[conn] = set(share[share >= p["profile_min_share"]].index)
    counts = post.groupby(["client_connection_name", "window_start", "country"]).size()
    return [_hit("R004_new_destination_country", c, ts, country=country, messages=int(n),
                 known_countries=sorted(profile[c]))
            for (c, ts, country), n in counts.items()
            if c in profile and country not in profile[c] and n >= p["min_messages"]]


def r005_financial_anomaly(df, p, cfg, baseline_end):
    med = df.groupby(["client_connection_name", "country"])["price"].transform("median")
    mult = df["price"] / med
    flag = (mult >= p["price_multiple"]) | (df["margin"] < 0)
    f = df[flag].assign(mult=mult[flag], neg=df.loc[flag, "margin"] < 0)
    g = (f.groupby(["client_connection_name", "window_start"])
         .agg(n=("mult", "size"), max_mult=("mult", "max"), neg=("neg", "sum")).reset_index())
    g = g[g["n"] >= p["min_messages"]]
    return [_hit("R005_financial_anomaly", r.client_connection_name, r.window_start, flagged_messages=int(r.n),
                 max_price_multiple=round(float(r.max_mult), 1), negative_margin=int(r.neg))
            for r in g.itertuples()]


def r006_new_sender_burst(df, p, cfg, baseline_end):
    first = df.groupby(["client_connection_name", "source_addr"])["received_time"].transform("min")
    new = df[first >= baseline_end]
    g = new.groupby(["client_connection_name", "window_start", "source_addr"]).size()
    return [_hit("R006_new_sender_burst", c, ts, sender=s, messages=int(n))
            for (c, ts, s), n in g.items() if n >= p["min_messages"]]


REGISTRY = {
    "R001_volume_spike": r001_volume_spike,
    "R002_sequential_range": r002_sequential_range,
    "R003_failure_rate": r003_failure_rate,
    "R004_new_destination_country": r004_new_country,
    "R005_financial_anomaly": r005_financial_anomaly,
    "R006_new_sender_burst": r006_new_sender_burst,
}


def run_detection(df_raw: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    t0 = pd.to_datetime(df_raw["received_time"]).min()
    baseline_end = t0 + pd.Timedelta(hours=cfg["baseline_hours"])
    df = prepare(df_raw, cfg)
    hits = []
    for rule_id, fn in REGISTRY.items():
        p = cfg["rules"].get(rule_id, {})
        if p.get("enabled", True):
            hits += fn(df, p, cfg, baseline_end)
    if not hits:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    client = df_raw.drop_duplicates("client_connection_name").set_index("client_connection_name")["client_name"]
    wmin = pd.Timedelta(minutes=int(cfg["window_minutes"]))
    sev = cfg["severity"]
    rows = []
    for (conn, ts), grp in pd.DataFrame(hits).groupby(["connection", "window_start"]):
        rules = sorted(set(grp["rule_id"]))
        score = min(100, sum(cfg["rules"][r]["weight"] for r in rules))
        level = "high" if score >= sev["high"] else "medium" if score >= sev["medium"] else "low"
        evidence = {}
        for r in grp.itertuples():
            evidence.setdefault(r.rule_id, []).append(r.evidence)
        rows.append(dict(connection=conn, client=client.get(conn, ""), window_start=ts, window_end=ts + wmin,
                         score=score, severity=level, rules=";".join(rules),
                         recommended_action=cfg["actions"][level],
                         evidence=json.dumps(evidence, default=str)))
    out = pd.DataFrame(rows).sort_values(["window_start", "connection"]).reset_index(drop=True)
    out.insert(0, "alert_id", [f"A-{i + 1:05d}" for i in range(len(out))])
    return out[ALERT_COLUMNS]


def evaluate(alerts: pd.DataFrame, truth: pd.DataFrame) -> dict:
    """Compare alerts with injected ground truth (connection + time overlap)."""
    a = alerts.copy()
    a["window_start"] = pd.to_datetime(a["window_start"])
    a["window_end"] = pd.to_datetime(a["window_end"])
    t = truth.copy()
    t["start"], t["end"] = pd.to_datetime(t["start"]), pd.to_datetime(t["end"])

    def overlap(alert, row):
        return (alert["connection"] == row.connection) & (alert["window_start"] < row.end) & (alert["window_end"] > row.start)

    scen, matched = [], pd.Series(False, index=a.index)
    for row in t.itertuples():
        m = overlap(a, row) if len(a) else pd.Series(dtype=bool)
        matched = matched | m if len(a) else matched
        hit_rules = set(";".join(a.loc[m, "rules"]).split(";")) - {""} if len(a) else set()
        expected = set(row.expected_rules.split(";"))
        scen.append(dict(scenario=row.scenario, detected=bool(m.any()) if len(a) else False,
                         expected_rules_hit=expected <= hit_rules, rules_hit=sorted(hit_rules),
                         max_severity=(a.loc[m, "severity"].map({"low": 0, "medium": 1, "high": 2}).max()
                                       if len(a) and m.any() else None)))
    fp = a[~matched] if len(a) else a
    return dict(scenarios=scen, alerts=len(a), alerts_unmatched=len(fp),
                detected=sum(s["detected"] for s in scen), total=len(scen), false_positive_alerts=fp)
