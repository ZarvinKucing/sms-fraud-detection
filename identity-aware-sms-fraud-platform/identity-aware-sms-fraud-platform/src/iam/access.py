"""Application-level authorisation (the 'what may you do' layer behind Keycloak's 'who are you').

In a deployment the user's roles come from the validated OIDC token issued by Keycloak.
Here they are passed in explicitly so the logic is testable without any infrastructure.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from src.common.masking import mask_frame, mask_msisdn
from src.iam.audit import AuditLog


def permissions_for(roles, cfg) -> set[str]:
    perms: set[str] = set()
    for r in roles:
        perms |= set(cfg["roles"].get(r, {}).get("permissions", []))
    return perms


def find_sod_conflicts(roles, cfg) -> list[tuple[str, str]]:
    """Static separation-of-duties check: permission pairs that one identity must not hold together."""
    perms = permissions_for(roles, cfg)
    return [tuple(pair) for pair in cfg.get("separation_of_duties", []) if set(pair) <= perms]


@dataclass
class PendingAction:
    action_id: str
    connection: str
    action: str
    requested_by: str
    reason: str
    status: str = "pending"
    approved_by: str | None = None


@dataclass
class AccessController:
    cfg: dict
    audit: AuditLog
    pending: dict[str, PendingAction] = field(default_factory=dict)

    def _deny(self, user, roles, perm, target, why):
        self.audit.append(user, perm, target, "deny", roles=sorted(roles), why=why)
        raise PermissionError(f"{perm} denied: {why}")

    def view_alerts(self, user, roles, df, msisdn_cols=("destination_addr", "source_addr")):
        if "alerts.read" not in permissions_for(roles, self.cfg):
            self._deny(user, roles, "alerts.read", "alerts", "missing permission")
        self.audit.append(user, "alerts.read", "alerts", "allow", roles=sorted(roles))
        return mask_frame(df, msisdn_cols)  # always masked; unmasking is a separate, justified action

    def unmask(self, user, roles, msisdn: str, reason: str) -> str:
        target = mask_msisdn(msisdn)  # never write the raw number into the audit log
        if "msisdn.unmask" not in permissions_for(roles, self.cfg):
            self._deny(user, roles, "msisdn.unmask", target, "missing permission")
        if len((reason or "").strip()) < 10:
            self._deny(user, roles, "msisdn.unmask", target, "written justification required")
        self.audit.append(user, "msisdn.unmask", target, "allow", roles=sorted(roles), reason=reason)
        return str(msisdn)

    def request_action(self, user, roles, connection: str, action: str, reason: str) -> PendingAction:
        if "connection.action.request" not in permissions_for(roles, self.cfg):
            self._deny(user, roles, "connection.action.request", connection, "missing permission")
        act = PendingAction(f"ACT-{len(self.pending) + 1:04d}", connection, action, user, reason)
        self.pending[act.action_id] = act
        self.audit.append(user, "connection.action.request", connection, "allow",
                          roles=sorted(roles), requested_action=action, action_id=act.action_id, reason=reason)
        return act

    def approve_action(self, user, roles, action_id: str) -> PendingAction:
        act = self.pending[action_id]
        if "connection.action.approve" not in permissions_for(roles, self.cfg):
            self._deny(user, roles, "connection.action.approve", act.connection, "missing permission")
        if act.requested_by == user:  # dynamic separation of duties
            self._deny(user, roles, "connection.action.approve", act.connection,
                       "separation of duties: requester cannot approve own action")
        act.status, act.approved_by = "approved", user
        self.audit.append(user, "connection.action.approve", act.connection, "allow",
                          roles=sorted(roles), action_id=action_id)
        return act
