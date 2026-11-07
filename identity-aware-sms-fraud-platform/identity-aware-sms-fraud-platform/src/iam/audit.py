"""Tamper-evident audit log: every entry carries the hash of the previous one."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(entry: dict) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict] = []
        if self.path and self.path.exists():
            with open(self.path, encoding="utf-8") as f:
                self.entries = [json.loads(line) for line in f if line.strip()]

    def append(self, actor: str, action: str, target: str, outcome: str, **details) -> dict:
        entry = {
            "seq": len(self.entries),
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actor": actor,
            "action": action,
            "target": target,
            "outcome": outcome,
            "details": details,
            "prev": self.entries[-1]["hash"] if self.entries else GENESIS,
        }
        entry["hash"] = _digest(entry)
        self.entries.append(entry)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (True, None) if the chain is intact, else (False, index_of_first_bad_entry).

        Limitation: truncating the END of the log is not detectable from the log alone.
        In a real deployment, ship the head hash to an external system (e.g. the SIEM).
        """
        prev = GENESIS
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("prev") != prev or _digest(body) != e.get("hash"):
                return False, i
            prev = e["hash"]
        return True, None

    def export_events(self) -> list[dict]:
        """Normalised events for the IAM detection rules (successful unmasks)."""
        return [
            {"time": e["ts"].replace("+00:00", "Z"), "source": "app", "type": "UNMASK_MSISDN",
             "user": e["actor"], "ip": None, "details": {}}
            for e in self.entries if e["action"] == "msisdn.unmask" and e["outcome"] == "allow"
        ]
