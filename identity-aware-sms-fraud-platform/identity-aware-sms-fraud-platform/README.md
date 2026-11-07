# Identity-Aware SMS Fraud Detection Platform

A lab project that combines **rule-based SMS fraud detection** with **identity and access management (IAM)** and **identity-threat detection**. It extends an earlier internship-based SMS fraud project into a platform where *who is sending*, *who may investigate*, and *who may act* are first-class concerns.

> **Status: lab / portfolio project.** All data is synthetic. Thresholds are illustrative demo defaults, not production values. Detection uses plain rules and statistics, **no machine learning**.

## Why this exists

SMS traffic abuse (e.g. SMS pumping / artificially inflated traffic) is carried out through *legitimate, authorised* sender connections. That makes it an identity problem as much as a fraud problem:

1. **Detect** abusive behaviour per client connection.
2. **Respond** at the identity level (throttle / suspend a connection) with a second-person approval.
3. **Control** who can see subscriber numbers and who can change rules (RBAC, separation of duties, audit).
4. **Watch the watchers**: detect brute force, spraying, privilege escalation and bulk data access against the platform itself.

## What's in the box

| Area | What it does | Where |
|---|---|---|
| SMS fraud rules | 6 explainable rules, scored per connection per 5-min window | `src/detection/cdr_detection.py`, `config/rules.yaml` |
| Identity-threat rules | 6 rules (brute force, spraying, off-hours, privileged grant, bulk unmask, SoD violation) mapped to MITRE ATT&CK | `src/detection/iam_detection.py` |
| Access layer | Role -> permission checks, masking, justified unmask, request/approve workflow | `src/iam/access.py`, `config/roles.yaml` |
| Audit log | Hash-chained, tamper-evident | `src/iam/audit.py` |
| Keycloak realm | 6 roles, 6 demo users, TOTP required, password policy, brute-force lockout, events on | `iam/keycloak/realm-export.json` |
| Dashboards | OpenSearch + Grafana with Keycloak SSO and role mapping | `docker-compose.yml`, `grafana/` |
| Synthetic data | CDR and identity events with injected scenarios and ground truth | `src/synth/` |
| Docs | Architecture, rule catalog, role matrix, threat model, ATT&CK mapping, data handling | `docs/` |

## Quick start (no Docker needed)

```bash
pip install -r requirements.txt
python -m src.cli demo      # generate data -> run detection -> score against ground truth
python -m pytest -q         # 19 tests
```

Expected output: every injected scenario detected for both detectors, with no alerts unexplained by an injected scenario.

## Run the full stack (Docker)

```bash
cp .env.example .env        # change every value
docker compose up -d        # Keycloak, OpenSearch, Grafana (localhost only)
python -m src.cli demo
python -m src.pipeline.load_opensearch
```

Then open Grafana at <http://localhost:3000> and sign in through Keycloak (demo users in `docs/role-permission-matrix.md`; the first login forces a password change and TOTP enrolment).

## How detection is validated

Synthetic data includes five injected SMS scenarios (pumping to a sequential range, new-sender burst, route failures, price anomaly, new destination country) and five identity scenarios, each with ground truth. A benign P2P look-alike (many senders to ~40 numbers in one block) checks that traffic-type scoping prevents false positives. Tests assert detection of all scenarios across several random seeds.

**Read this correctly:** these scores prove the rules behave as designed on data built to contain those patterns. They do not measure real-world accuracy. A CDR also cannot show whether an OTP was actually used, so alerts are indicators for human review.

## Verified vs not verified

| Component | Status |
|---|---|
| Detection rules, access layer, audit log, synthetic generators, CLI | Automated tests (CI) |
| `docker-compose.yml`, Keycloak realm import, Grafana OIDC/role mapping | Written to documentation; syntax checked, **not run end to end** |
| `src/pipeline/load_opensearch.py`, `fetch_keycloak_events.py` | **Not exercised** against live services |
| Dashboards | Datasources provisioned; no dashboard JSON shipped yet |

## Data and confidentiality

No real CDRs or employer rules are included or accepted into this repo. See `docs/data-handling.md`.

## Roadmap

- Ship Grafana dashboards (alert timeline, per-connection risk, access-review view)
- Detect "successful login after a failure burst" (likely compromise)
- Access review report (who holds which role, last used)
- Real OIDC token validation in the access layer (currently roles are passed in)
- Ship the audit-log head hash to OpenSearch as a tamper anchor

## License

MIT
