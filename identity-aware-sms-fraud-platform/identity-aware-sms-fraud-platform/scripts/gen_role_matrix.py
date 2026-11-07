"""Regenerate docs/role-permission-matrix.md from config/roles.yaml (keeps docs and code in sync)."""
from pathlib import Path
import yaml

cfg = yaml.safe_load(Path("config/roles.yaml").read_text())
roles = list(cfg["roles"])
perms = sorted({p for r in cfg["roles"].values() for p in r["permissions"]})
lines = ["# Role-permission matrix", "",
         "_Generated from `config/roles.yaml` by `scripts/gen_role_matrix.py`. Do not edit by hand._", "",
         "| Permission | " + " | ".join(roles) + " |", "|---|" + "---|" * len(roles)]
for p in perms:
    lines.append(f"| `{p}` | " + " | ".join("✔" if p in cfg["roles"][r]["permissions"] else "" for r in roles) + " |")
lines += ["", "## Roles", ""] + [f"- **{r}**: {v['description']}" for r, v in cfg["roles"].items()]
lines += ["", "## Separation of duties", "",
          "Static rule: one identity must not hold both permissions of a pair (checked by `find_sod_conflicts`, "
          "and by detection rule `IAM006` when a role grant creates a conflict).", ""]
lines += [f"- `{a}` + `{b}`" for a, b in cfg["separation_of_duties"]]
lines += ["", "Dynamic rule: the person who requests a connection action cannot approve it "
          "(enforced in `AccessController.approve_action`).", ""]
Path("docs/role-permission-matrix.md").write_text("\n".join(lines), encoding="utf-8")
print("written")
