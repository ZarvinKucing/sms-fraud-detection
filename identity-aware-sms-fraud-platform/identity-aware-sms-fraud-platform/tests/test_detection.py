import pandas as pd
import pytest
from src.common.config import load_yaml
from src.detection.cdr_detection import evaluate, run_detection
from src.detection.iam_detection import detect_iam, evaluate_iam
from src.iam.realm import load_user_roles
from src.synth import generate_cdr, generate_iam_events

RULES = load_yaml("rules.yaml")


@pytest.fixture(scope="module")
def cdr():
    return generate_cdr.generate(seed=7)


def test_generator_is_deterministic():
    a, _ = generate_cdr.generate(seed=3)
    b, _ = generate_cdr.generate(seed=3)
    assert a.equals(b)


def test_all_injected_cdr_scenarios_detected(cdr):
    df, truth = cdr
    r = evaluate(run_detection(df, RULES["cdr"]), truth)
    assert r["detected"] == r["total"] == 5
    assert all(s["expected_rules_hit"] for s in r["scenarios"])


def test_pumping_scenario_is_high_severity(cdr):
    df, truth = cdr
    r = evaluate(run_detection(df, RULES["cdr"]), truth)
    pump = next(s for s in r["scenarios"] if s["scenario"] == "S1_pumping_range")
    assert pump["max_severity"] == 2


def test_p2p_lookalike_is_not_flagged(cdr):
    df, _ = cdr
    alerts = run_detection(df, RULES["cdr"])
    assert "cn-p2p-hub-01" not in set(alerts["connection"])


def test_p2p_would_false_positive_without_scoping(cdr):
    """Why traffic-type scoping exists: dropping it makes the benign P2P block look like pumping."""
    df, _ = cdr
    cfg = {**RULES["cdr"], "applies_to_traffic_types": ["A2P", "P2P"]}
    assert "cn-p2p-hub-01" in set(run_detection(df, cfg)["connection"])


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_no_unexplained_alerts_across_seeds(seed):
    df, truth = generate_cdr.generate(seed=seed)
    r = evaluate(run_detection(df, RULES["cdr"]), truth)
    assert r["detected"] == r["total"]
    assert r["alerts_unmatched"] == 0


def test_all_injected_identity_scenarios_detected():
    events, truth = generate_iam_events.generate()
    alerts = detect_iam(events, RULES["iam"], load_user_roles(), load_yaml("roles.yaml"))
    r = evaluate_iam(alerts, truth)
    assert r["detected"] == r["total"] == 5
    assert all(s["expected_rules_hit"] for s in r["scenarios"])
    assert r["alerts_unmatched"] == 0
    assert set(alerts["attack_technique"]) >= {"T1110", "T1110.003", "T1078", "T1098", "T1213"}
