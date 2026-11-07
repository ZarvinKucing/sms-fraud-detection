# MITRE ATT&CK mapping (identity rules)

| Rule | Technique | Name | Rationale |
|---|---|---|---|
| IAM001 | T1110 | Brute Force | Many failures against one account |
| IAM002 | T1110.003 | Brute Force: Password Spraying | One source, many accounts, few attempts each |
| IAM003 | T1078 | Valid Accounts | Legitimate credentials used at an unusual time |
| IAM004 | T1098 | Account Manipulation | Privilege added to an account |
| IAM005 | T1213 | Data from Information Repositories | Bulk access to sensitive records by an authorised user |
| IAM006 | T1098 | Account Manipulation | Role change that defeats separation of duties |

Verify technique IDs and names against <https://attack.mitre.org> before citing them externally; the framework is revised periodically.
