# Role-permission matrix

_Generated from `config/roles.yaml` by `scripts/gen_role_matrix.py`. Do not edit by hand._

| Permission | fraud_analyst | fraud_investigator | rule_engineer | fraud_manager | auditor | platform_admin |
|---|---|---|---|---|---|---|
| `alerts.annotate` | ✔ | ✔ |  |  |  |  |
| `alerts.read` | ✔ | ✔ |  | ✔ | ✔ |  |
| `audit.read` |  |  |  |  | ✔ |  |
| `connection.action.approve` |  |  |  | ✔ |  |  |
| `connection.action.request` |  | ✔ |  |  |  |  |
| `msisdn.unmask` |  | ✔ |  |  |  |  |
| `rules.approve` |  |  |  | ✔ |  |  |
| `rules.propose` |  |  | ✔ |  |  |  |
| `rules.read` |  |  | ✔ | ✔ | ✔ |  |
| `system.configure` |  |  |  |  |  | ✔ |
| `users.manage` |  |  |  |  |  | ✔ |

## Roles

- **fraud_analyst**: First-line monitoring. Sees masked data only.
- **fraud_investigator**: Investigates alerts; may unmask numbers (justified + audited) and request connection actions.
- **rule_engineer**: Proposes detection rule/threshold changes. Cannot approve them.
- **fraud_manager**: Approves rule changes and connection actions (throttle/suspend).
- **auditor**: Read-only oversight, including the audit log.
- **platform_admin**: Manages identities and the platform. Deliberately has NO access to fraud data.

## Separation of duties

Static rule: one identity must not hold both permissions of a pair (checked by `find_sod_conflicts`, and by detection rule `IAM006` when a role grant creates a conflict).

- `rules.propose` + `rules.approve`
- `connection.action.request` + `connection.action.approve`
- `users.manage` + `alerts.read`

Dynamic rule: the person who requests a connection action cannot approve it (enforced in `AccessController.approve_action`).
