"""Detection rules over identity events (Keycloak login/admin events + application audit events).

Normalised event: {"time": ISO8601Z, "source": "keycloak"|"app", "type": str, "user": str, "ip": str|None, "details": {}}
Each alert carries the MITRE ATT&CK technique it maps to (verify IDs at attack.mitre.org).
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import pandas as pd
from src.iam.access import find_sod_conflicts

ATTACK = {
    "IAM001_brute_force": "T1110",
    "IAM002_password_spraying": "T1110.003",
    "IAM003_off_hours_login": "T1078",
    "IAM004_privileged_role_grant": "T1098",
    "IAM005_excessive_unmask": "T1213",
    "IAM006_sod_violation": "T1098",
}
ALERT_COLUMNS = ["alert_id", "rule_id", "severity", "user", "ip", "window_start", "window_end",
                 "attack_technique", "description"]


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _sliding(items, window, threshold):
    """items: sorted [(time, key)]. Non-overlapping windows with >= threshold DISTINCT keys."""
    out, i, n = [], 0, len(items)
    while i < n:
        j, keys = i, set()
        while j < n and items[j][0] - items[i][0] <= window:
            keys.add(items[j][1])
            j += 1
        if len(keys) >= threshold:
            out.append((items[i][0], items[j - 1][0], len(keys)))
            i = j
        else:
            i += 1
    return out


def detect_iam(events, cfg, user_roles, roles_cfg) -> pd.DataFrame:
    rules = cfg["rules"]
    tz = ZoneInfo(cfg["timezone"])
    hours = cfg["business_hours"]
    privileged_roles = set(cfg["privileged_roles"])
    evs = sorted(({**e, "_t": _t(e["time"])} for e in events), key=lambda e: e["_t"])
    alerts = []

    def add(rule_id, sev, user, ip, start, end, desc):
        alerts.append(dict(rule_id=rule_id, severity=sev, user=user, ip=ip, window_start=start, window_end=end,
                           attack_technique=ATTACK[rule_id], description=desc))

    # IAM001: many failed logins for one user
    p = rules["IAM001_brute_force"]
    by_user = defaultdict(list)
    for e in evs:
        if e["type"] == "LOGIN_ERROR":
            by_user[e["user"]].append((e["_t"], e["_t"]))   # key=time -> every failure counts
    for user, items in by_user.items():
        for s, e_, n in _sliding(items, timedelta(minutes=p["window_minutes"]), p["threshold"]):
            add("IAM001_brute_force", "high", user, None, s, e_, f"{n} failed logins for {user}")

    # IAM002: one IP failing against many distinct users
    p = rules["IAM002_password_spraying"]
    by_ip = defaultdict(list)
    for e in evs:
        if e["type"] == "LOGIN_ERROR" and e.get("ip"):
            by_ip[e["ip"]].append((e["_t"], e["user"]))
    for ip, items in by_ip.items():
        for s, e_, n in _sliding(items, timedelta(minutes=p["window_minutes"]), p["threshold"]):
            add("IAM002_password_spraying", "high", None, ip, s, e_, f"{n} distinct accounts failed from {ip}")

    # IAM003: successful login outside business hours
    if rules["IAM003_off_hours_login"].get("enabled", True):
        for e in evs:
            if e["type"] == "LOGIN":
                h = e["_t"].astimezone(tz).hour
                if not (hours["start"] <= h < hours["end"]):
                    priv = bool(user_roles.get(e["user"], set()) & privileged_roles)
                    add("IAM003_off_hours_login", "high" if priv else "medium", e["user"], e.get("ip"), e["_t"], e["_t"],
                        f"login at {e['_t'].astimezone(tz):%H:%M} local" + (" by a privileged account" if priv else ""))

    # IAM004 / IAM006: privileged role grants, and static separation-of-duties conflicts they create
    current = {u: set(r) for u, r in user_roles.items()}
    for e in evs:
        if e["type"] != "ROLE_GRANT":
            continue
        role, actor, target = e["details"]["role"], e["details"].get("actor"), e["user"]
        current.setdefault(target, set()).add(role)
        if rules["IAM004_privileged_role_grant"].get("enabled", True) and role in privileged_roles:
            selfg = actor == target
            add("IAM004_privileged_role_grant", "high" if selfg else "medium", target, e.get("ip"), e["_t"], e["_t"],
                f"{actor} granted {role} to {target}" + (" (self-grant)" if selfg else ""))
        if rules["IAM006_sod_violation"].get("enabled", True):
            for pair in find_sod_conflicts(current[target], roles_cfg):
                add("IAM006_sod_violation", "high", target, e.get("ip"), e["_t"], e["_t"],
                    f"{target} now holds conflicting permissions {pair[0]} + {pair[1]}")

    # IAM005: unusually many unmask actions by one user
    p = rules["IAM005_excessive_unmask"]
    um = defaultdict(list)
    for e in evs:
        if e["type"] == "UNMASK_MSISDN":
            um[e["user"]].append((e["_t"], e["_t"]))
    for user, items in um.items():
        for s, e_, n in _sliding(items, timedelta(minutes=p["window_minutes"]), p["threshold"]):
            add("IAM005_excessive_unmask", "medium", user, None, s, e_, f"{n} MSISDN unmasks in {p['window_minutes']} min")

    if not alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    out = pd.DataFrame(alerts).sort_values("window_start").reset_index(drop=True)
    out.insert(0, "alert_id", [f"I-{i + 1:05d}" for i in range(len(out))])
    return out[ALERT_COLUMNS]


def evaluate_iam(alerts: pd.DataFrame, truth: list[dict], slack_minutes: int = 2) -> dict:
    pad = timedelta(minutes=slack_minutes)
    scen, matched = [], set()
    for t in truth:
        s, e = _t(t["start"]) - pad, _t(t["end"]) + pad
        sub = alerts[(alerts["window_start"] <= e) & (alerts["window_end"] >= s)] if len(alerts) else alerts
        hit = set(sub["rule_id"]) if len(sub) else set()
        matched |= set(sub["alert_id"]) if len(sub) else set()
        exp = set(t["expected_rules"].split(";"))
        scen.append(dict(scenario=t["scenario"], detected=bool(exp & hit), expected_rules_hit=exp <= hit, rules_hit=sorted(hit)))
    unmatched = alerts[~alerts["alert_id"].isin(matched)] if len(alerts) else alerts
    return dict(scenarios=scen, alerts=len(alerts), alerts_unmatched=len(unmatched),
                detected=sum(s["detected"] for s in scen), total=len(scen), false_positive_alerts=unmatched)
