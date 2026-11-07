"""Synthetic identity events (Keycloak-style logins + app audit events) with injected abuse."""
from __future__ import annotations
import numpy as np
from datetime import datetime, timedelta, timezone

USERS = ["analyst1", "investigator1", "engineer1", "manager1", "auditor1", "admin1"]
UTC7 = timezone(timedelta(hours=7))  # Asia/Jakarta


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ev(dt, source, typ, user, ip=None, **details):
    return {"time": _iso(dt), "source": source, "type": typ, "user": user, "ip": ip, "details": details}


def generate(seed: int = 11):
    """Return (events, truth). Week of Mon 2026-01-05; business hours 07:00-19:00 UTC+7."""
    rng = np.random.default_rng(seed)
    events, truth = [], []
    days = [datetime(2026, 1, 5 + i, tzinfo=UTC7) for i in range(5)]

    for d in days:  # normal behaviour
        for i, u in enumerate(USERS):
            ip = f"10.20.0.{10 + i}"
            login = d + timedelta(hours=8, minutes=int(rng.integers(0, 90)))
            if rng.random() < 0.15:  # a typo before a successful login
                events.append(_ev(login - timedelta(minutes=1), "keycloak", "LOGIN_ERROR", u, ip, error="invalid_user_credentials"))
            events.append(_ev(login, "keycloak", "LOGIN", u, ip))
        for _ in range(int(rng.integers(3, 9))):  # investigator's routine, justified unmasks
            t = d + timedelta(hours=9, minutes=int(rng.integers(0, 420)))
            events.append(_ev(t, "app", "UNMASK_MSISDN", "investigator1"))

    def add_truth(sid, start, end, rules, desc):
        truth.append(dict(scenario=sid, start=_iso(start), end=_iso(end), expected_rules=";".join(rules), description=desc))

    # I1: brute force against one account, then a successful login from the same external IP
    t = days[1] + timedelta(hours=16)
    for k in range(12):
        events.append(_ev(t + timedelta(seconds=15 * k), "keycloak", "LOGIN_ERROR", "manager1", "203.0.113.50", error="invalid_user_credentials"))
    events.append(_ev(t + timedelta(minutes=4), "keycloak", "LOGIN", "manager1", "203.0.113.50"))
    add_truth("I1_brute_force", t, t + timedelta(minutes=4), ["IAM001_brute_force"], "12 failed logins in 3 min, then success from external IP")

    # I2: password spraying - one IP, many accounts, one or two attempts each
    t = days[2] + timedelta(hours=17)
    targets = USERS + ["root", "guest"]
    for k, u in enumerate(targets):
        events.append(_ev(t + timedelta(seconds=30 * k), "keycloak", "LOGIN_ERROR", u, "198.51.100.77", error="invalid_user_credentials"))
    add_truth("I2_password_spraying", t, t + timedelta(minutes=4), ["IAM002_password_spraying"], "8 distinct accounts failing from one IP")

    # I3: privileged account logs in at 02:30 local time
    t = days[3] + timedelta(days=1, hours=2, minutes=30)
    events.append(_ev(t, "keycloak", "LOGIN", "admin1", "10.20.0.15"))
    add_truth("I3_off_hours_admin", t, t + timedelta(minutes=1), ["IAM003_off_hours_login"], "platform_admin login at 02:30 local")

    # I4: engineer grants themselves the approver role (self-grant + SoD conflict)
    t = days[3] + timedelta(hours=12)
    events.append(_ev(t, "keycloak", "ROLE_GRANT", "engineer1", "10.20.0.12", role="fraud_manager", actor="engineer1"))
    add_truth("I4_self_escalation", t, t + timedelta(minutes=1), ["IAM004_privileged_role_grant", "IAM006_sod_violation"],
              "rule_engineer self-assigns fraud_manager (propose + approve in one identity)")

    # I5: investigator unmasks 60 numbers in 20 minutes (bulk exfiltration pattern)
    t = days[4] + timedelta(hours=13)
    for k in range(60):
        events.append(_ev(t + timedelta(seconds=20 * k), "app", "UNMASK_MSISDN", "investigator1"))
    add_truth("I5_bulk_unmask", t, t + timedelta(minutes=20), ["IAM005_excessive_unmask"], "60 unmasks in 20 minutes vs 3-8 per day normally")

    events.sort(key=lambda e: e["time"])
    return events, truth
