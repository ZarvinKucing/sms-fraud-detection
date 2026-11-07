# Threat model (STRIDE, lab scope)

Scope: the fraud-detection platform itself (analysts, data, rules, accounts), not the telecom network.

| Threat | Example | Mitigation here | Residual risk |
|---|---|---|---|
| **S**poofing | Stolen analyst credentials | Keycloak MFA (TOTP required), password policy, brute-force lockout, IAM001/002/003 detection | TOTP can be phished; no phishing-resistant factor yet |
| **T**ampering | Insider edits a rule threshold to hide fraud; edits audit history | Rules in git, propose/approve split, hash-chained audit log | Log tail truncation undetectable without an external anchor |
| **R**epudiation | "I never unmasked that number" | Every allow/deny logged with actor, role, justification | Local file; needs shipping to the SIEM |
| **I**nformation disclosure | Bulk export of subscriber numbers | Masked by default, justified unmask, only alerts indexed, IAM005 | Investigators legitimately see numbers; detection is after-the-fact |
| **D**enial of service | Wrongly throttling a legitimate customer | Throttle needs a second approver; `medium` is review-only | Approver fatigue |
| **E**levation of privilege | Engineer self-assigns approver role | Static SoD rules, IAM004 + IAM006 | Relies on Keycloak admin events being collected |

## Assumptions and non-goals
- Lab setup: no TLS, OpenSearch security plugin off, dev-mode Keycloak. Not a hardened deployment.
- No network-layer, SS7/SMPP, or endpoint security coverage.
- Demo credentials in `realm-export.json` are temporary and force a change plus TOTP enrolment; rotate the Grafana client secret.
