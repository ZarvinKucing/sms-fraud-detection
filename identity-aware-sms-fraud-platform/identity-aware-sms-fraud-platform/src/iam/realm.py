from __future__ import annotations
import json
from pathlib import Path
from src.common.config import ROOT

DEFAULT_REALM = ROOT / "iam" / "keycloak" / "realm-export.json"


def load_user_roles(path: str | Path = DEFAULT_REALM) -> dict[str, set[str]]:
    """username -> realm roles, read from the Keycloak realm export (single source of truth for the lab)."""
    realm = json.loads(Path(path).read_text(encoding="utf-8"))
    return {u["username"]: set(u.get("realmRoles", [])) for u in realm.get("users", [])}
