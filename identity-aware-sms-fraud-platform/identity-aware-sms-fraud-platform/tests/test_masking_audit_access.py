import pytest
from src.common.config import load_yaml
from src.common.masking import mask_msisdn, pseudonymize
from src.iam.access import AccessController, find_sod_conflicts
from src.iam.audit import AuditLog

CFG = load_yaml("roles.yaml")


def test_mask_and_pseudonymize():
    assert mask_msisdn("628123456789") == "6281******89"
    assert mask_msisdn("12345") == "*****"
    k = b"k" * 16
    assert pseudonymize("628123456789", k) == pseudonymize("628123456789", k)
    assert pseudonymize("628123456789", k) != pseudonymize("628123456780", k)
    with pytest.raises(ValueError):
        pseudonymize("x", b"")


def test_audit_chain_detects_tampering():
    log = AuditLog()
    for i in range(5):
        log.append("u", "alerts.read", "alerts", "allow", n=i)
    assert log.verify() == (True, None)
    log.entries[2]["outcome"] = "deny"          # edit history
    assert log.verify() == (False, 2)


def test_analyst_cannot_unmask_and_denial_is_audited():
    ac = AccessController(CFG, AuditLog())
    with pytest.raises(PermissionError):
        ac.unmask("alice", ["fraud_analyst"], "628123456789", "checking a suspicious number")
    last = ac.audit.entries[-1]
    assert last["outcome"] == "deny" and "628123456789" not in str(last)   # raw number never logged


def test_unmask_requires_justification():
    ac = AccessController(CFG, AuditLog())
    with pytest.raises(PermissionError):
        ac.unmask("bob", ["fraud_investigator"], "628123456789", "")
    assert ac.unmask("bob", ["fraud_investigator"], "628123456789", "case 1042: sender range review") == "628123456789"
    assert ac.audit.entries[-1]["outcome"] == "allow"


def test_requester_cannot_approve_own_action():
    ac = AccessController(CFG, AuditLog())
    act = ac.request_action("bob", ["fraud_investigator"], "cn-x-01", "throttle", "sequential range burst")
    with pytest.raises(PermissionError):
        ac.approve_action("bob", ["fraud_investigator", "fraud_manager"], act.action_id)   # SoD: same person
    assert ac.approve_action("carol", ["fraud_manager"], act.action_id).status == "approved"
    assert ac.audit.verify()[0]


def test_admin_has_no_data_access():
    ac = AccessController(CFG, AuditLog())
    import pandas as pd
    with pytest.raises(PermissionError):
        ac.view_alerts("root", ["platform_admin"], pd.DataFrame({"destination_addr": ["628123456789"]}))


def test_view_alerts_masks_numbers():
    import pandas as pd
    ac = AccessController(CFG, AuditLog())
    out = ac.view_alerts("alice", ["fraud_analyst"], pd.DataFrame({"destination_addr": ["628123456789"]}))
    assert out["destination_addr"][0] == "6281******89"


def test_static_sod_conflicts():
    assert find_sod_conflicts(["rule_engineer"], CFG) == []
    assert ("rules.propose", "rules.approve") in find_sod_conflicts(["rule_engineer", "fraud_manager"], CFG)
    assert ("users.manage", "alerts.read") in find_sod_conflicts(["platform_admin", "auditor"], CFG)
