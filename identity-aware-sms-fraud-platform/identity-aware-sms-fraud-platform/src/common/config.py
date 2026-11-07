from __future__ import annotations
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]


def load_yaml(name: str | Path):
    p = Path(name)
    if not p.is_absolute():
        p = ROOT / "config" / p
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)
