import pytest

from aegis.simulator.response_lab import (
    ACTIONS,
    COST_WEIGHTS,
    RESPONSE_MODELS,
    calculate_response_cost,
    compare_strategies,
    simulate_response,
)


def _scenario(**overrides):
    base = {
        "scenario_id": "T-001",
        "initial_risk": 100,
        "initial_availability": 100,
    }
    base.update(overrides)
    return base


# --- basics ---------------------------------------------------------------

def test_three_actions_are_defined():
    assert set(ACTIONS) == {
        "disable_identity",
        "isolate_service",
        "revoke_privilege",
    }


def test_unknown_strategy_is_rejected():
    with pytest.raises(ValueError):
        simulate_response("not_a_strategy", _scenario())


def test_missing_scenario_fields_are_rejected():
    with pytest.raises(ValueError):
        simulate_response("disable_identity", {"scenario_id": "X"})


def test_invalid_initial_risk_is_rejected():
    with pytest.raises(ValueError):
        simulate_response("disable_identity", _scenario(initial_risk=150))


# --- base behaviour (no features) ----------------------------------------

def test_absent_features_fall_through_to_base_table():
    outcome = simulate_response("disable_identity", _scenario())
    assert outcome["risk_reduction"] == RESPONSE_MODELS["disable_identity"]["risk_reduction"]
    assert outcome["availability_loss"] == RESPONSE_MODELS["disable_identity"]["availability_loss"]
    assert outcome["recovery_minutes"] == RESPONSE_MODELS["disable_identity"]["recovery_minutes"]


def test_residual_risk_and_availability_are_computed():
    outcome = simulate_response("isolate_service", _scenario())
    assert outcome["residual_risk"] == outcome["initial_risk"] - outcome["risk_reduction"]
    assert outcome["service_availability"] == outcome["initial_availability"] - outcome["availability_loss"]


# --- attack type ----------------------------------------------------------

def test_attack_type_changes_risk_reduction():
    brute = simulate_response("isolate_service", _scenario(attack_type="brute_force"))
    exfil = simulate_response("isolate_service", _scenario(attack_type="data_exfiltration"))
    assert exfil["risk_reduction"] > brute["risk_reduction"]


def test_privilege_escalation_improves_revoke_relative_to_other_attacks():
    """
    Revoke_privilege does not out-perform disable_identity in absolute terms —
    disable is a bigger hammer. What the model asserts is that revoke is
    more effective against privilege escalation than against other attacks.
    """
    revoke_brute = simulate_response(
        "revoke_privilege", _scenario(attack_type="brute_force")
    )
    revoke_priv = simulate_response(
        "revoke_privilege", _scenario(attack_type="privilege_escalation")
    )
    revoke_exfil = simulate_response(
        "revoke_privilege", _scenario(attack_type="data_exfiltration")
    )

    # Priv-esc must be revoke's best-case attack type.
    assert revoke_priv["risk_reduction"] > revoke_brute["risk_reduction"]
    assert revoke_priv["risk_reduction"] > revoke_exfil["risk_reduction"]


# --- detection confidence -------------------------------------------------

def test_confidence_scales_risk_reduction():
    low = simulate_response("disable_identity", _scenario(detection_confidence="low"))
    high = simulate_response("disable_identity", _scenario(detection_confidence="high"))
    assert high["risk_reduction"] > low["risk_reduction"]


def test_confidence_does_not_affect_availability_or_recovery():
    low = simulate_response("disable_identity", _scenario(detection_confidence="low"))
    high = simulate_response("disable_identity", _scenario(detection_confidence="high"))
    assert low["availability_loss"] == high["availability_loss"]
    assert low["recovery_minutes"] == high["recovery_minutes"]


# --- criticality ----------------------------------------------------------

def test_criticality_raises_availability_loss_and_recovery():
    low = simulate_response("disable_identity", _scenario(criticality="low"))
    high = simulate_response("disable_identity", _scenario(criticality="high"))
    assert high["availability_loss"] > low["availability_loss"]
    assert high["recovery_minutes"] > low["recovery_minutes"]


def test_criticality_does_not_change_risk_reduction():
    low = simulate_response("isolate_service", _scenario(criticality="low"))
    high = simulate_response("isolate_service", _scenario(criticality="high"))
    assert low["risk_reduction"] == high["risk_reduction"]


# --- compromise scope -----------------------------------------------------

def test_narrow_scope_favours_revoke():
    narrow = simulate_response(
        "revoke_privilege",
        _scenario(compromise_scope="single_identity",
                  attack_type="privilege_escalation",
                  detection_confidence="high"),
    )
    broad = simulate_response(
        "revoke_privilege",
        _scenario(compromise_scope="multiple_identities",
                  attack_type="privilege_escalation",
                  detection_confidence="high"),
    )
    assert narrow["risk_reduction"] > broad["risk_reduction"]


# --- capping --------------------------------------------------------------

def test_risk_reduction_is_capped_by_initial_risk():
    outcome = simulate_response(
        "disable_identity",
        _scenario(initial_risk=20,
                  attack_type="brute_force",
                  detection_confidence="high",
                  compromise_scope="single_identity"),
    )
    assert outcome["risk_reduction"] <= 20
    assert outcome["residual_risk"] >= 0


def test_availability_loss_is_capped_by_initial_availability():
    outcome = simulate_response(
        "disable_identity",
        _scenario(initial_availability=10, criticality="high"),
    )
    assert outcome["availability_loss"] <= 10
    assert outcome["service_availability"] >= 0


# --- cost -----------------------------------------------------------------

def test_cost_uses_documented_weights():
    outcome = simulate_response("revoke_privilege", _scenario())
    manual = (
        COST_WEIGHTS["residual_risk"] * outcome["residual_risk"]
        + COST_WEIGHTS["availability_loss"] * outcome["availability_loss"]
        + COST_WEIGHTS["recovery_time"]
          * (min(outcome["recovery_minutes"], 120) / 120 * 100)
    )
    assert abs(outcome["decision_score"] - round(manual, 4)) < 1e-9


def test_cost_rejects_missing_fields():
    with pytest.raises(ValueError):
        calculate_response_cost({"residual_risk": 10})


# --- recommendation flips -------------------------------------------------

def test_default_scenario_recommends_disable():
    assert compare_strategies(_scenario())["recommended_strategy"] == "disable_identity"


def test_exfil_scenario_recommends_isolate():
    s = _scenario(
        attack_type="data_exfiltration",
        criticality="high",
        detection_confidence="high",
        compromise_scope="service_affected",
    )
    assert compare_strategies(s)["recommended_strategy"] == "isolate_service"