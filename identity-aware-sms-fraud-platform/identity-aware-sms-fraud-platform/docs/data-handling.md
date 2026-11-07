# Data handling

- **This repository contains only synthetic data.** All client names, numbers, prices and routes are invented by `src/synth/`.
- **Real CDRs, including samples and "just a small extract", must never be committed.** They can contain client identities, commercial terms and subscriber numbers. `data/raw/` is git-ignored for local-only work; better still, keep real data outside the repo.
- **Rules and thresholds from any employer or internship are confidential.** Values in `config/rules.yaml` are demo defaults and say so in the file.
- **Number handling:** masked in views, pseudonymised (HMAC) when correlation is needed, never written to the audit log in clear.
- CI runs a secret scan (gitleaks). If something sensitive is ever committed, rotate it and rewrite history; deleting the file in a later commit is not enough.
