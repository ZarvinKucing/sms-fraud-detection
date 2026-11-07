"""Pull login + admin events from Keycloak's Admin REST API and normalise them for iam_detection.

NOTE: written against the documented Admin API but NOT verified in automated tests (needs a running Keycloak).
Adjust field mapping if your Keycloak version differs.

Usage: python -m src.pipeline.fetch_keycloak_events --url http://localhost:8080 --realm sms-fraud
Env:   KC_ADMIN_USER, KC_ADMIN_PASSWORD
"""
from __future__ import annotations
import argparse
import json
import os
from datetime import datetime, timezone
import requests


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8080")
    p.add_argument("--realm", default="sms-fraud")
    p.add_argument("--out", default="data/synthetic/iam_events_keycloak.jsonl")
    a = p.parse_args()

    tok = requests.post(f"{a.url}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": os.environ["KC_ADMIN_USER"], "password": os.environ["KC_ADMIN_PASSWORD"]}, timeout=15)
    tok.raise_for_status()
    h = {"Authorization": f"Bearer {tok.json()['access_token']}"}
    base = f"{a.url}/admin/realms/{a.realm}"

    users = {u["id"]: u["username"] for u in requests.get(f"{base}/users", params={"max": 1000}, headers=h, timeout=15).json()}
    events = []
    for e in requests.get(f"{base}/events", params={"type": ["LOGIN", "LOGIN_ERROR"], "max": 1000}, headers=h, timeout=15).json():
        events.append({"time": _iso(e["time"]), "source": "keycloak", "type": e["type"],
                       "user": (e.get("details") or {}).get("username") or users.get(e.get("userId"), "unknown"),
                       "ip": e.get("ipAddress"), "details": {"error": e.get("error")}})
    for e in requests.get(f"{base}/admin-events", params={"resourceTypes": "REALM_ROLE_MAPPING", "operationTypes": "CREATE", "max": 1000}, headers=h, timeout=15).json():
        path = e.get("resourcePath", "")          # users/<id>/role-mappings/realm
        target = users.get(path.split("/")[1], "unknown") if path.startswith("users/") else "unknown"
        actor = users.get((e.get("authDetails") or {}).get("userId"), "admin")
        for role in json.loads(e.get("representation") or "[]"):
            events.append({"time": _iso(e["time"]), "source": "keycloak", "type": "ROLE_GRANT", "user": target,
                           "ip": (e.get("authDetails") or {}).get("ipAddress"), "details": {"role": role["name"], "actor": actor}})
    events.sort(key=lambda x: x["time"])
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(json.dumps(x) for x in events))
    print(f"wrote {len(events)} normalised events -> {a.out}")


if __name__ == "__main__":
    main()
