# Rule catalog

All thresholds are **demo defaults** in `config/rules.yaml`, tuned on synthetic data. They are not production values.

## SMS traffic rules (per connection, per 5-minute window, A2P traffic only)

| ID | Signal | Logic | Why it matters |
|---|---|---|---|
| R001 | Volume spike | Robust z-score (median/MAD) of window count vs the connection's own history, plus a minimum count | Artificial traffic inflation |
| R002 | Sequential number range | Many distinct destination numbers sharing all but the last 3 digits | Pumping into a number block the attacker controls |
| R003 | Failure rate | Failed-delivery ratio above an absolute floor **and** well above the peer median | Route abuse or degradation |
| R004 | New destination country | Traffic to a country absent from the connection's baseline profile | Traffic steered to high-payout destinations |
| R005 | Financial anomaly | Price >= N x the connection+country median, or negative margin | Billing manipulation, revenue leakage |
| R006 | New sender burst | Sender ID first seen after the baseline sends a burst immediately | Throwaway senders |

**Scoring:** score = sum of weights of triggered rules (cap 100). `high` >= 70 (throttle request, needs approval), `medium` >= 30 (analyst review), else `low` (monitor).

**Limits:** a CDR shows traffic, not outcomes. It cannot prove an OTP went unused, so alerts are indicators for a human to review.

## Identity rules (ATT&CK mapping in `attack-mapping.md`)

| ID | Signal | Severity |
|---|---|---|
| IAM001 | >= 8 failed logins for one user in 5 min | high |
| IAM002 | >= 5 distinct users failing from one IP in 10 min | high |
| IAM003 | Successful login outside business hours (07:00-19:00 Asia/Jakarta) | high if privileged, else medium |
| IAM004 | Privileged role granted (self-grant escalates severity) | medium / high |
| IAM005 | >= 25 MSISDN unmasks by one user in 30 min | medium |
| IAM006 | A role grant creates a static separation-of-duties conflict | high |
